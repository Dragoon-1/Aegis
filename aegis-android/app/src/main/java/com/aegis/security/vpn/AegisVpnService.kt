package com.aegis.security.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.aegis.security.AegisApplication
import com.aegis.security.data.repository.ThreatRepository
import com.aegis.security.domain.model.Severity
import com.aegis.security.domain.model.ThreatEvent
import com.aegis.security.domain.model.ThreatType
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.UUID
import javax.inject.Inject

/**
 * AEGIS MICRO-VPN — DNS Sinkhole
 *
 * Creates a local VPN tunnel that intercepts all DNS queries from every app.
 * Malicious domains are sinkholed (0.0.0.0) before any connection is made.
 * Requires NO root — uses Android's VpnService API with user consent only.
 */
@AndroidEntryPoint
class AegisVpnService : VpnService() {

    @Inject lateinit var threatRepository: ThreatRepository

    private var vpnInterface: ParcelFileDescriptor? = null
    private var scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // In-memory blocklist — O(1) lookup
    private val blockedDomains = HashSet<String>(60_000)

    // Stats (read by HomeViewModel)
    @Volatile var queriesTotal   = 0L
    @Volatile var queriesBlocked = 0L

    companion object {
        const val ACTION_START = "com.aegis.START_VPN"
        const val ACTION_STOP  = "com.aegis.STOP_VPN"
        private  const val TAG         = "AegisVPN"
        private  const val NOTIFY_ID   = 1001
        private  const val VPN_ADDRESS = "10.200.200.1"
        private  const val UPSTREAM_DNS = "9.9.9.9"   // Quad9 as upstream fallback
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> { stopVpn(); START_NOT_STICKY }
            else -> {
                // Accept new domains pushed from BlocklistSyncWorker
                val newDomains = intent?.getStringArrayListExtra("new_domains")
                if (newDomains != null) {
                    blockedDomains.addAll(newDomains.map { it.lowercase() })
                    updateNotification("Active — ${blockedDomains.size} domains blocked")
                    return START_STICKY
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    startForeground(NOTIFY_ID, buildNotification("Starting…"), android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
                } else {
                    startForeground(NOTIFY_ID, buildNotification("Starting…"))
                }
                scope.launch {
                    loadBundledBlocklists()
                    startVpnTunnel()
                }
                START_STICKY
            }
        }
    }

    override fun onDestroy() { stopVpn(); super.onDestroy() }

    // ── VPN setup ─────────────────────────────────────────────────────────────

    private suspend fun startVpnTunnel() = withContext(Dispatchers.IO) {
        try {
            val builder = Builder()
                .addAddress(VPN_ADDRESS, 32)
                .addAddress("fd00:1:fd00:1:fd00:1:fd00:1", 128) // IPv6 support
                .addRoute("10.200.200.2", 32)       // Only our fake DNS IP
                .addRoute("fd00:1:fd00:1:fd00:1:fd00:2", 128)
                .addDnsServer("10.200.200.2")
                .addDnsServer("fd00:1:fd00:1:fd00:1:fd00:2")

            // Dynamically route all system DNS servers to prevent parallel query bypass
            try {
                val cm = getSystemService(android.content.Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
                val activeNetwork = cm.activeNetwork
                val linkProperties = cm.getLinkProperties(activeNetwork)
                linkProperties?.dnsServers?.forEach { dnsServer ->
                    val ip = dnsServer.hostAddress
                    if (ip != null) {
                        if (ip.contains(":")) builder.addRoute(ip, 128)
                        else builder.addRoute(ip, 32)
                    }
                }
            } catch (e: Exception) { Log.e(TAG, "Failed to route system DNS: ${e.message}") }

            // Route common DoH and Public DNS providers to intercept their queries and kill DoH
            listOf(
                "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
                "94.140.14.14", "94.140.15.15", "2001:4860:4860::8888", "2001:4860:4860::8844",
                "2606:4700:4700::1111", "2606:4700:4700::1001"
            ).forEach { ip ->
                try {
                    if (ip.contains(":")) builder.addRoute(ip, 128)
                    else builder.addRoute(ip, 32)
                } catch (e: Exception) {}
            }

            vpnInterface = builder
                .setMtu(1500)
                .setSession("Aegis Security")
                .setBlocking(true)
                .apply { addDisallowedApplication(packageName) }
                .establish()

            updateNotification("Active — ${blockedDomains.size} domains blocked")
            Log.i(TAG, "VPN tunnel up. Blocklist: ${blockedDomains.size}")
            processPackets()
        } catch (e: Exception) {
            Log.e(TAG, "VPN failed: ${e.message}")
        }
    }

    private fun stopVpn() {
        scope.cancel()
        vpnInterface?.close()
        vpnInterface = null
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        stopForeground(true)
        stopSelf()
    }

    // ── Packet loop ───────────────────────────────────────────────────────────

    private suspend fun processPackets() = withContext(Dispatchers.IO) {
        val fd  = vpnInterface ?: return@withContext
        val inp = FileInputStream(fd.fileDescriptor)
        val out = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)

        while (isActive) {
            try {
                val len = inp.read(buf)
                if (len <= 0) break  // fd closed

                val version = (buf[0].toInt() and 0xF0) shr 4

                // Kill TCP to DNS/DoT/DoH ports — IPv4
                if (version == 4) {
                    val protocol = buf[9].toInt() and 0xFF
                    if (protocol == 6) { // TCP
                        val ipHdrLen = (buf[0].toInt() and 0x0F) * 4
                        val dstPort = ((buf[ipHdrLen + 2].toInt() and 0xFF) shl 8) or (buf[ipHdrLen + 3].toInt() and 0xFF)
                        if (dstPort == 853 || dstPort == 53 || dstPort == 443) {
                            out.write(buildTcpRst(buf, len, ipHdrLen))
                            continue
                        }
                    }
                }
                // Kill TCP to DNS/DoT/DoH ports — IPv6
                if (version == 6 && len >= 60) {
                    val nextHeader = buf[6].toInt() and 0xFF
                    if (nextHeader == 6) { // TCP over IPv6
                        val dstPort = ((buf[42].toInt() and 0xFF) shl 8) or (buf[43].toInt() and 0xFF)
                        if (dstPort == 853 || dstPort == 53 || dstPort == 443) {
                            out.write(buildTcpRstV6(buf, len))
                            continue
                        }
                    }
                }

                val domain = extractDnsQuery(buf, len)
                if (domain != null) {
                    queriesTotal++
                    if (isDomainBlocked(domain)) {
                        queriesBlocked++
                        Log.d(TAG, "BLOCKED: $domain")

                        val threat = ThreatEvent(
                            id = UUID.randomUUID().toString(),
                            type = ThreatType.NETWORK_THREAT,
                            severity = Severity.HIGH,
                            title = "Malicious Domain Blocked",
                            description = "Blocked connection to $domain",
                            timestamp = System.currentTimeMillis(),
                            actionTaken = "Domain sinkholed (0.0.0.0)"
                        )
                        threatRepository.save(threat)

                        // Return 0.0.0.0 / :: instead of NXDOMAIN.
                        // NXDOMAIN triggers retry logic in Android's resolver,
                        // which then asks the real DNS and bypasses our block.
                        // A sinkhole A-record is accepted immediately.
                        out.write(buildSinkholeResponse(buf, len))
                    } else {
                        val resp = forwardDns(buf, len)
                        if (resp != null) out.write(resp)
                    }
                }
            } catch (e: CancellationException) { break }
            catch (e: Exception) {
                if (!isActive) break
                Log.w(TAG, "Packet err: ${e.message}")
            }
        }
    }

    private fun buildTcpRst(original: ByteArray, len: Int, ipHdrLen: Int): ByteArray {
        val tcpOff = ipHdrLen
        val resp = ByteArray(ipHdrLen + 20)
        System.arraycopy(original, 0, resp, 0, ipHdrLen)
        
        // Total Length
        resp[2] = 0
        resp[3] = (ipHdrLen + 20).toByte()
        
        // Swap IP
        for (i in 0 until 4) {
            val tmp = resp[12 + i]
            resp[12 + i] = resp[16 + i]
            resp[16 + i] = tmp
        }
        
        // IP Checksum
        resp[10] = 0; resp[11] = 0
        var cksum = 0L
        for (i in 0 until ipHdrLen step 2) {
            cksum += ((resp[i].toInt() and 0xFF) shl 8) or (resp[i + 1].toInt() and 0xFF)
        }
        while (cksum shr 16 != 0L) cksum = (cksum and 0xFFFF) + (cksum shr 16)
        val ck = (cksum.inv() and 0xFFFF).toInt()
        resp[10] = (ck shr 8).toByte(); resp[11] = ck.toByte()

        // Swap TCP ports
        resp[tcpOff] = original[tcpOff + 2]
        resp[tcpOff + 1] = original[tcpOff + 3]
        resp[tcpOff + 2] = original[tcpOff]
        resp[tcpOff + 3] = original[tcpOff + 1]
        
        // Sequence number = original ACK
        resp[tcpOff + 4] = original[tcpOff + 8]
        resp[tcpOff + 5] = original[tcpOff + 9]
        resp[tcpOff + 6] = original[tcpOff + 10]
        resp[tcpOff + 7] = original[tcpOff + 11]
        
        // Ack number = original Seq + 1
        var seq = 0L
        for (i in 0 until 4) seq = (seq shl 8) or (original[tcpOff + 4 + i].toLong() and 0xFF)
        seq = (seq + 1) and 0xFFFFFFFFL
        resp[tcpOff + 8] = (seq shr 24).toByte()
        resp[tcpOff + 9] = (seq shr 16).toByte()
        resp[tcpOff + 10] = (seq shr 8).toByte()
        resp[tcpOff + 11] = seq.toByte()
        
        // Data offset & Flags (RST | ACK = 0x14)
        resp[tcpOff + 12] = 0x50.toByte()
        resp[tcpOff + 13] = 0x14.toByte()
        
        // Window, Checksum, Urgent = 0
        for (i in 14 until 20) resp[tcpOff + i] = 0
        
        // TCP Checksum
        var tcpCksum = 0L
        for (i in 12 until 20 step 2) { // pseudo-header IPs
            tcpCksum += ((resp[i].toInt() and 0xFF) shl 8) or (resp[i + 1].toInt() and 0xFF)
        }
        tcpCksum += 6 + 20 // pseudo-header proto + len
        for (i in 0 until 20 step 2) { // tcp header
            tcpCksum += ((resp[tcpOff + i].toInt() and 0xFF) shl 8) or (resp[tcpOff + i + 1].toInt() and 0xFF)
        }
        while (tcpCksum shr 16 != 0L) tcpCksum = (tcpCksum and 0xFFFF) + (tcpCksum shr 16)
        val tCk = (tcpCksum.inv() and 0xFFFF).toInt()
        resp[tcpOff + 16] = (tCk shr 8).toByte(); resp[tcpOff + 17] = tCk.toByte()
        
        return resp
    }

    private fun buildTcpRstV6(original: ByteArray, len: Int): ByteArray {
        val tcpOff = 40
        val resp = ByteArray(60)  // 40 IPv6 header + 20 TCP header
        System.arraycopy(original, 0, resp, 0, 40)

        // Payload length = 20 (TCP RST header)
        resp[4] = 0; resp[5] = 20

        // Swap IPv6 src <-> dst
        for (i in 0 until 16) {
            val tmp = resp[8 + i]; resp[8 + i] = resp[24 + i]; resp[24 + i] = tmp
        }

        // Swap TCP ports
        resp[tcpOff] = original[tcpOff + 2]
        resp[tcpOff + 1] = original[tcpOff + 3]
        resp[tcpOff + 2] = original[tcpOff]
        resp[tcpOff + 3] = original[tcpOff + 1]

        // Seq = original ACK
        for (i in 4 until 8) resp[tcpOff + i] = original[tcpOff + i + 4]

        // Ack = original Seq + 1
        var seq = 0L
        for (i in 0 until 4) seq = (seq shl 8) or (original[tcpOff + 4 + i].toLong() and 0xFF)
        seq = (seq + 1) and 0xFFFFFFFFL
        resp[tcpOff + 8] = (seq shr 24).toByte()
        resp[tcpOff + 9] = (seq shr 16).toByte()
        resp[tcpOff + 10] = (seq shr 8).toByte()
        resp[tcpOff + 11] = seq.toByte()

        // Data offset & Flags: RST|ACK
        resp[tcpOff + 12] = 0x50.toByte()
        resp[tcpOff + 13] = 0x14.toByte()
        for (i in 14 until 20) resp[tcpOff + i] = 0

        // TCP checksum with IPv6 pseudo-header
        var ck = 0L
        for (i in 8 until 40 step 2) {
            ck += ((resp[i].toInt() and 0xFF) shl 8) or (resp[i + 1].toInt() and 0xFF)
        }
        ck += 20 + 6  // payload len + next-header (TCP=6)
        for (i in 0 until 20 step 2) {
            ck += ((resp[tcpOff + i].toInt() and 0xFF) shl 8) or (resp[tcpOff + i + 1].toInt() and 0xFF)
        }
        while (ck shr 16 != 0L) ck = (ck and 0xFFFF) + (ck shr 16)
        val tCk = (ck.inv() and 0xFFFF).toInt()
        resp[tcpOff + 16] = (tCk shr 8).toByte()
        resp[tcpOff + 17] = tCk.toByte()

        return resp
    }

    // ── Domain blocking ───────────────────────────────────────────────────────

    private fun isDomainBlocked(domain: String): Boolean {
        if (blockedDomains.contains(domain)) return true
        // Subdomain inheritance: if "evil.com" blocked, "cdn.evil.com" is too
        var dot = domain.indexOf('.')
        while (dot >= 0) {
            if (blockedDomains.contains(domain.substring(dot + 1))) return true
            dot = domain.indexOf('.', dot + 1)
        }
        return false
    }

    // ── DNS parsing (simplified) ──────────────────────────────────────────────

    private fun extractDnsQuery(packet: ByteArray, len: Int): String? {
        return try {
            if (len < 40) return null
            val version = (packet[0].toInt() and 0xF0) shr 4
            val isIPv6 = (version == 6)
            val ipHdrLen = if (isIPv6) 40 else (packet[0].toInt() and 0x0F) * 4
            val protocol = if (isIPv6) packet[6].toInt() and 0xFF else packet[9].toInt() and 0xFF
            
            if (protocol != 17) return null  // not UDP
            val dstPort = ((packet[ipHdrLen + 2].toInt() and 0xFF) shl 8) or
                          (packet[ipHdrLen + 3].toInt() and 0xFF)
            if (dstPort != 53) return null  // not DNS

            var pos = ipHdrLen + 8 + 12  // IP + UDP + DNS header
            val sb  = StringBuilder()
            while (pos < len) {
                val labelLen = packet[pos].toInt() and 0xFF
                if (labelLen == 0) break
                if (sb.isNotEmpty()) sb.append('.')
                sb.append(String(packet, pos + 1, labelLen))
                pos += labelLen + 1
            }
            if (sb.isEmpty()) null else sb.toString().lowercase()
        } catch (_: Exception) { null }
    }

    /**
     * Returns a valid DNS response with 0.0.0.0 (A) or :: (AAAA) instead of NXDOMAIN.
     *
     * Why not NXDOMAIN?  Android's stub resolver treats NXDOMAIN as "this server
     * doesn't know — ask the next one".  It then retries via the underlying
     * network's real DNS, completely bypassing our block.  A sinkhole A-record
     * with RCODE=0 (NOERROR) is accepted as authoritative.  The browser tries
     * to TCP-connect to 0.0.0.0, gets instant RST → "This site can't be reached".
     */
    private fun buildSinkholeResponse(original: ByteArray, len: Int): ByteArray {
        val version = (original[0].toInt() and 0xF0) shr 4
        val isIPv6 = (version == 6)
        val ipHdrLen = if (isIPv6) 40 else (original[0].toInt() and 0x0F) * 4
        val dnsOff = ipHdrLen + 8

        // ── Walk past the question section to find QTYPE ──────────────
        var pos = dnsOff + 12  // start of QNAME
        while (pos < len) {
            val labelLen = original[pos].toInt() and 0xFF
            if (labelLen == 0) { pos++; break }
            pos += labelLen + 1
        }
        val qtype = ((original[pos].toInt() and 0xFF) shl 8) or
                    (original[pos + 1].toInt() and 0xFF)
        pos += 4  // skip QTYPE + QCLASS → end of question section

        // ── Build answer record ───────────────────────────────────────
        val isA = (qtype == 1)
        val isAAAA = (qtype == 28)
        
        val ancount = if (isA || isAAAA) 1 else 0
        val rdataLen = if (isAAAA) 16 else 4
        // Name-ptr(2) + Type(2) + Class(2) + TTL(4) + RDLen(2) + RData
        val answerLen = if (ancount == 1) 2 + 2 + 2 + 4 + 2 + rdataLen else 0
        
        val respLen = pos + answerLen
        val resp = ByteArray(respLen)
        System.arraycopy(original, 0, resp, 0, pos)  // IP+UDP+DNS hdr+question

        if (ancount == 1) {
            var a = pos
            resp[a++] = 0xC0.toByte(); resp[a++] = 0x0C  // pointer → QNAME
            resp[a++] = 0; resp[a++] = if (isAAAA) 28 else 1  // TYPE
            resp[a++] = 0; resp[a++] = 1                       // CLASS IN
            resp[a++] = 0; resp[a++] = 0; resp[a++] = 0; resp[a++] = 60 // TTL 60s
            resp[a++] = 0; resp[a++] = rdataLen.toByte()
            if (isAAAA) {
                for (i in 0 until 15) resp[a++] = 0
                resp[a++] = 1 // ::1 (localhost IPv6)
            } else {
                resp[a++] = 127; resp[a++] = 0; resp[a++] = 0; resp[a++] = 1 // 127.0.0.1
            }
        }

        // ── DNS header: NOERROR ───────────────────────────────────────
        resp[dnsOff + 2] = 0x81.toByte()   // QR=1  RD=1
        resp[dnsOff + 3] = 0x80.toByte()   // RA=1  RCODE=0 (NOERROR)
        resp[dnsOff + 6] = 0; resp[dnsOff + 7] = ancount.toByte()   // ANCOUNT
        resp[dnsOff + 8] = 0; resp[dnsOff + 9] = 0   // NSCOUNT = 0
        resp[dnsOff + 10] = 0; resp[dnsOff + 11] = 0 // ARCOUNT = 0

        // ── IP length + address swap ──────────────────────────────────
        if (isIPv6) {
            val payloadLen = respLen - 40
            resp[4] = ((payloadLen shr 8) and 0xFF).toByte()
            resp[5] = (payloadLen and 0xFF).toByte()
            for (i in 0 until 16) {
                val tmp = resp[8 + i]; resp[8 + i] = resp[24 + i]; resp[24 + i] = tmp
            }
        } else {
            resp[2] = ((respLen shr 8) and 0xFF).toByte()
            resp[3] = (respLen and 0xFF).toByte()
            for (i in 0 until 4) {
                val tmp = resp[12 + i]; resp[12 + i] = resp[16 + i]; resp[16 + i] = tmp
            }
            resp[10] = 0; resp[11] = 0
            var cksum = 0L
            for (i in 0 until ipHdrLen step 2) {
                cksum += ((resp[i].toInt() and 0xFF) shl 8) or (resp[i + 1].toInt() and 0xFF)
            }
            while (cksum shr 16 != 0L) cksum = (cksum and 0xFFFF) + (cksum shr 16)
            val ck = (cksum.inv() and 0xFFFF).toInt()
            resp[10] = ((ck shr 8) and 0xFF).toByte()
            resp[11] = (ck and 0xFF).toByte()
        }

        // ── Swap UDP ports + update UDP length ────────────────────────
        val tp0 = resp[ipHdrLen]; val tp1 = resp[ipHdrLen + 1]
        resp[ipHdrLen] = resp[ipHdrLen + 2]; resp[ipHdrLen + 1] = resp[ipHdrLen + 3]
        resp[ipHdrLen + 2] = tp0; resp[ipHdrLen + 3] = tp1
        val udpLen = respLen - ipHdrLen
        resp[ipHdrLen + 4] = ((udpLen shr 8) and 0xFF).toByte()
        resp[ipHdrLen + 5] = (udpLen and 0xFF).toByte()

        setUdpChecksum(resp, ipHdrLen, isIPv6)
        return resp
    }

    private fun forwardDns(packet: ByteArray, len: Int): ByteArray? {
        return try {
            val version = (packet[0].toInt() and 0xF0) shr 4
            val isIPv6 = (version == 6)
            val ipHdrLen = if (isIPv6) 40 else (packet[0].toInt() and 0x0F) * 4
            val dnsStart = ipHdrLen + 8
            val dnsPayload = packet.copyOfRange(dnsStart, len)

            val sock = DatagramSocket().apply { soTimeout = 3000 }
            // Protect socket from VPN routing loop
            protect(sock)
            sock.send(DatagramPacket(dnsPayload, dnsPayload.size,
                InetAddress.getByName(UPSTREAM_DNS), 53))
            val recv = ByteArray(1024)
            val resp = DatagramPacket(recv, recv.size)
            sock.receive(resp)
            sock.close()

            // Reconstruct full IP+UDP packet for the TUN interface.
            val dnsResponse = recv.copyOf(resp.length)
            val totalLen = ipHdrLen + 8 + dnsResponse.size
            val result = ByteArray(totalLen)

            System.arraycopy(packet, 0, result, 0, ipHdrLen)

            if (isIPv6) {
                // Update IPv6 payload length (excludes 40-byte header)
                val payloadLen = 8 + dnsResponse.size
                result[4] = ((payloadLen shr 8) and 0xFF).toByte()
                result[5] = (payloadLen and 0xFF).toByte()
                
                // Swap IPv6 src and dst
                for (i in 0 until 16) {
                    val tmp = result[8 + i]
                    result[8 + i] = result[24 + i]
                    result[24 + i] = tmp
                }
            } else {
                // Update IPv4 total length
                result[2] = ((totalLen shr 8) and 0xFF).toByte()
                result[3] = (totalLen and 0xFF).toByte()

                // Swap IPv4 src and dst
                for (i in 0 until 4) {
                    val tmp = result[12 + i]
                    result[12 + i] = result[16 + i]
                    result[16 + i] = tmp
                }

                // Reset IP header checksum (set to 0, then compute)
                result[10] = 0
                result[11] = 0
                var ipChecksum = 0L
                for (i in 0 until ipHdrLen step 2) {
                    ipChecksum += ((result[i].toInt() and 0xFF) shl 8) or (result[i + 1].toInt() and 0xFF)
                }
                while (ipChecksum shr 16 != 0L) {
                    ipChecksum = (ipChecksum and 0xFFFF) + (ipChecksum shr 16)
                }
                val ipCk = (ipChecksum.inv() and 0xFFFF).toInt()
                result[10] = ((ipCk shr 8) and 0xFF).toByte()
                result[11] = (ipCk and 0xFF).toByte()
            }

            // Swap UDP src/dst ports
            result[ipHdrLen] = packet[ipHdrLen + 2]
            result[ipHdrLen + 1] = packet[ipHdrLen + 3]
            result[ipHdrLen + 2] = packet[ipHdrLen]
            result[ipHdrLen + 3] = packet[ipHdrLen + 1]

            // Update UDP length
            val udpLen = 8 + dnsResponse.size
            result[ipHdrLen + 4] = ((udpLen shr 8) and 0xFF).toByte()
            result[ipHdrLen + 5] = (udpLen and 0xFF).toByte()

            // Copy DNS response payload
            System.arraycopy(dnsResponse, 0, result, ipHdrLen + 8, dnsResponse.size)
            
            setUdpChecksum(result, ipHdrLen, isIPv6)

            result
        } catch (_: Exception) { null }
    }

    // ── Blocklist loading ─────────────────────────────────────────────────────

    private fun loadBundledBlocklists() {
        // Always add hardcoded demo domains so the VPN has something to block
        // even if the bundled asset files are empty or missing
        val demoDomains = listOf(
            // Malware distribution
            "malware-download.com", "malware-domain.com", "evil-download.net",
            "ransomware-c2.com", "trojan-payload.net", "botnet-c2-server.com",
            "cryptolocker-payment.net", "spyware-install.com",
            // Phishing
            "login-verify-account.com", "secure-banking-update.net",
            "paypal-verify-identity.com", "apple-id-locked-verify.com",
            "amazon-order-confirm.net", "netflix-billing-update.com",
            "microsoft-365-verify.net", "google-security-alert.com",
            "facebook-login-verify.net", "sbi-kyc-update.net",
            "hdfc-verify-account.com", "icici-secure-login.net",
            // Ads / tracking / scams
            "tracking-pixel.com", "ad-delivery-network.com",
            "user-tracking-analytics.net", "malicious-redirect.com",
            "crypto-miner-script.net", "clickjacking-overlay.com",
            "fake-antivirus-scan.net", "tech-support-scam.com",
            "lottery-winner-claim.net", "nigerian-prince-offer.com",
            "fake-shopping-deals.net", "credential-stealer.net",
            // Well-known test domains for DNS blocking verification
            "malware.testcategory.com", "test-malware.com"
        )
        blockedDomains.addAll(demoDomains)
        Log.i(TAG, "Added ${demoDomains.size} hardcoded demo domains")

        // Load from assets bundled in APK (populated during build)
        listOf("blocklists/abuse_ch.txt", "blocklists/phishtank.txt",
                "blocklists/oisd_basic.txt", "blocklists/phishing_tunnels.txt").forEach { path ->
            try {
                var count = 0
                assets.open(path).bufferedReader().forEachLine { line ->
                    val trimmed = line.trim()
                    if (trimmed.isNotEmpty() && !trimmed.startsWith("#")) {
                        val domain = if (" " in trimmed) trimmed.split(" ").last() else trimmed
                        blockedDomains.add(domain.lowercase())
                        count++
                    }
                }
                Log.i(TAG, "Loaded $count domains from $path")
            } catch (e: Exception) {
                Log.w(TAG, "Could not load $path: ${e.message}")
            }
        }

        // Load cached community threats
        val prefs = getSharedPreferences("aegis_blocklist", MODE_PRIVATE)
        val cached = prefs.getStringSet("domains", emptySet()) ?: emptySet()
        blockedDomains.addAll(cached)

        Log.i(TAG, "Blocklist total: ${blockedDomains.size} domains")
        updateNotification("Active — ${blockedDomains.size} domains blocked")
    }

    // ── Notification ──────────────────────────────────────────────────────────

    private fun buildNotification(status: String): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            (getSystemService(NotificationManager::class.java))
                .createNotificationChannel(
                    NotificationChannel(AegisApplication.CHANNEL_VPN,
                        "VPN Shield", NotificationManager.IMPORTANCE_LOW)
                )
        }
        return Notification.Builder(this, AegisApplication.CHANNEL_VPN)
            .setContentTitle("Aegis Shield Active")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(status: String) =
        (getSystemService(NotificationManager::class.java))
            .notify(NOTIFY_ID, buildNotification(status))

    private fun setUdpChecksum(packet: ByteArray, ipHdrLen: Int, isIPv6: Boolean) {
        packet[ipHdrLen + 6] = 0
        packet[ipHdrLen + 7] = 0
        if (!isIPv6) return
        
        var udpCksum = 0L
        for (i in 8 until 40 step 2) {
            udpCksum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
        }
        val payloadLen = ((packet[4].toInt() and 0xFF) shl 8) or (packet[5].toInt() and 0xFF)
        udpCksum += payloadLen
        udpCksum += 17 // Next Header (UDP)
        
        val totalLen = 40 + payloadLen
        for (i in 40 until totalLen step 2) {
            if (i == totalLen - 1) {
                udpCksum += ((packet[i].toInt() and 0xFF) shl 8)
            } else {
                udpCksum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            }
        }
        while (udpCksum shr 16 != 0L) {
            udpCksum = (udpCksum and 0xFFFF) + (udpCksum shr 16)
        }
        var uCk = (udpCksum.inv() and 0xFFFF).toInt()
        if (uCk == 0) uCk = 0xFFFF
        packet[ipHdrLen + 6] = (uCk shr 8).toByte()
        packet[ipHdrLen + 7] = uCk.toByte()
    }
}
