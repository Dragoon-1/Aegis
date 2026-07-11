package com.aegis.security.honeytoken

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.ContentValues
import android.content.Context
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.File
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AEGIS HONEY-TOKEN CANARY ENGINE
 *
 * Core Innovation: Deploys hidden decoy files designed to attract ransomware
 * and spyware. When any process accesses these files, we immediately flag it
 * as malicious and alert the user — catching zero-day threats signature scanners
 * would miss entirely.
 *
 * Strategy:
 *   1. Files named alphabetically-first (e.g. "!IMPORTANT_DOCS.txt") since
 *      ransomware typically scans directory listings alphabetically.
 *   2. Files contain convincing fake credentials/financial data.
 *   3. FileObserver triggers on ACCESS, OPEN, MODIFY, DELETE events.
 *   4. ContentObserver catches bulk storage changes (ransomware signature).
 *
 * Does NOT require root access. Uses Android FileObserver + MediaStore APIs.
 *
 * Reference: Gómez-Hernández et al. (2024) "Lightweight Crypto-Ransomware
 * Detection in Android Based on Reactive Honeyfile Monitoring" — MDPI Sensors.
 * This implementation extends that academic work into a consumer-grade product.
 */
@Singleton
class HoneyTokenManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val threatRepository: ThreatRepository,
    private val blockchainReporter: BlockchainReporter
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val observers = mutableListOf<FileObserver>()
    private val deployedTraps = mutableListOf<File>()
    private lateinit var mediaObserver: MediaChangeObserver

    // File names ordered alphabetically-first to be scanned by ransomware first
    private val trapConfigs = listOf(
        TrapConfig("!AEGIS_CANARY_PRIVATE.txt",   TrapContent.CREDENTIALS),
        TrapConfig("!IMPORTANT_DOCUMENTS.txt",      TrapContent.FINANCIAL),
        TrapConfig("000_account_passwords.csv",     TrapContent.PASSWORDS),
        TrapConfig("000_backup_keys.json",          TrapContent.API_KEYS),
        TrapConfig("aaa_confidential_2024.docx",   TrapContent.DOCUMENT),
        TrapConfig(".aegis_hidden_canary",          TrapContent.MINIMAL),  // Hidden trap
    )

    companion object {
        private const val TAG = "AegisHoneyToken"
        private const val CHANNEL_ID = "aegis_critical_threats"
        private const val RAPID_ACCESS_WINDOW_MS = 5_000L // 5 seconds
        private const val RAPID_ACCESS_THRESHOLD = 3     // 3 traps in 5s = bulk ransomware scan
    }

    // Track rapid multi-trap access (bulk file scan pattern)
    private val recentTriggers = ArrayDeque<Long>()

    // ─────────────────────────────────────────────────────────────────────────
    // Initialization
    // ─────────────────────────────────────────────────────────────────────────

    fun initialize() {
        createNotificationChannel()
        deployTrapFiles()
        startFileObservers()
        startMediaObserver()
        Log.i(TAG, "Honey-Token Canary system initialized with ${deployedTraps.size} traps")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Trap File Deployment
    // ─────────────────────────────────────────────────────────────────────────

    private fun deployTrapFiles() {
        // Primary location: app-specific external storage (no permission needed Android 4.4+)
        val primaryDir = context.getExternalFilesDir(null) ?: context.filesDir

        trapConfigs.forEach { config ->
            val trap = File(primaryDir, config.filename)
            try {
                if (!trap.exists()) {
                    trap.createNewFile()
                    trap.writeText(config.content.generate())
                    Log.d(TAG, "Deployed trap: ${trap.absolutePath}")
                }
                deployedTraps.add(trap)
            } catch (e: Exception) {
                Log.w(TAG, "Could not deploy ${config.filename}: ${e.message}")
            }
        }

        // Secondary location: Downloads via MediaStore (Android 10+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            deployCanaryToDownloads()
        }
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun deployCanaryToDownloads() {
        try {
            val resolver = context.contentResolver
            // Check if already deployed
            val existing = resolver.query(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                arrayOf(MediaStore.Downloads._ID),
                "${MediaStore.Downloads.DISPLAY_NAME} = ?",
                arrayOf("!AEGIS_SECURITY_CANARY.txt"),
                null
            )
            if (existing?.count ?: 0 > 0) { existing?.close(); return }
            existing?.close()

            val cv = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, "!AEGIS_SECURITY_CANARY.txt")
                put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv) ?: return
            resolver.openOutputStream(uri)?.use { stream ->
                stream.write(TrapContent.FINANCIAL.generate().toByteArray())
            }
            cv.clear()
            cv.put(MediaStore.Downloads.IS_PENDING, 0)
            resolver.update(uri, cv, null, null)
            Log.d(TAG, "Deployed canary to Downloads")
        } catch (e: Exception) {
            Log.w(TAG, "Downloads deployment failed: ${e.message}")
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // File Observation
    // ─────────────────────────────────────────────────────────────────────────

    private fun startFileObservers() {
        val watchMask = FileObserver.OPEN or
                FileObserver.ACCESS or
                FileObserver.MODIFY or
                FileObserver.ATTRIB or
                FileObserver.DELETE

        deployedTraps.forEach { trap ->
            val observer = object : FileObserver(trap, watchMask) {
                override fun onEvent(event: Int, path: String?) {
                    val eventType = when (event and FileObserver.ALL_EVENTS) {
                        FileObserver.OPEN    -> TrapAccessType.OPENED
                        FileObserver.ACCESS  -> TrapAccessType.READ
                        FileObserver.MODIFY  -> TrapAccessType.MODIFIED
                        FileObserver.ATTRIB  -> TrapAccessType.ATTRIBUTE_CHANGED
                        FileObserver.DELETE  -> TrapAccessType.DELETED
                        else                 -> return // Ignore other events
                    }
                    onTrapTriggered(trap.name, eventType)
                }
            }
            observer.startWatching()
            observers.add(observer)
        }
    }

    private fun startMediaObserver() {
        mediaObserver = MediaChangeObserver()
        context.contentResolver.registerContentObserver(
            MediaStore.Files.getContentUri("external"),
            true,
            mediaObserver
        )
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Threat Response
    // ─────────────────────────────────────────────────────────────────────────

    private fun onTrapTriggered(filename: String, accessType: TrapAccessType) {
        val now = System.currentTimeMillis()

        // Track rapid-access pattern (multiple traps accessed in quick succession)
        recentTriggers.addLast(now)
        while (recentTriggers.isNotEmpty() &&
            now - recentTriggers.first() > RAPID_ACCESS_WINDOW_MS) {
            recentTriggers.removeFirst()
        }

        val isRapidScan = recentTriggers.size >= RAPID_ACCESS_THRESHOLD
        val severity = if (isRapidScan) Severity.CRITICAL else Severity.HIGH

        val threat = ThreatEvent(
            id = UUID.randomUUID().toString(),
            type = if (isRapidScan) ThreatType.RANSOMWARE_CONFIRMED else ThreatType.RANSOMWARE_ATTEMPT,
            severity = severity,
            title = if (isRapidScan) "🚨 Ransomware Confirmed" else "⚠️ Suspicious File Access",
            description = buildString {
                append("Honey-token '${filename}' was ${accessType.label}. ")
                if (isRapidScan) {
                    append("${recentTriggers.size} trap files accessed in ${RAPID_ACCESS_WINDOW_MS/1000}s — ")
                    append("this matches active ransomware scan behavior.")
                } else {
                    append("A process is probing your sensitive files.")
                }
            },
            timestamp = now,
            actionTaken = "Trap triggered. Monitoring for further activity."
        )

        scope.launch {
            threatRepository.save(threat)
            blockchainReporter.reportAnonymized(threat) // Share with network
            showThreatNotification(threat)
        }

        Log.w(TAG, "TRAP TRIGGERED: $filename ($accessType) — Severity: $severity")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Notifications
    // ─────────────────────────────────────────────────────────────────────────

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Security Threats",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Critical security threat notifications from Aegis"
                enableVibration(true)
                setShowBadge(true)
            }
            (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(channel)
        }
    }

    private fun showThreatNotification(threat: ThreatEvent) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(threat.title)
            .setContentText(threat.description)
            .setStyle(NotificationCompat.BigTextStyle().bigText(threat.description))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .build()
        nm.notify(threat.id.hashCode(), notification)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cleanup
    // ─────────────────────────────────────────────────────────────────────────

    fun shutdown() {
        observers.forEach { it.stopWatching() }
        observers.clear()
        context.contentResolver.unregisterContentObserver(mediaObserver)
        scope.cancel()
        Log.i(TAG, "Honey-Token Canary system shut down")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Inner types
    // ─────────────────────────────────────────────────────────────────────────

    inner class MediaChangeObserver : ContentObserver(Handler(Looper.getMainLooper())) {
        private var changeCount = 0
        private var windowStart = System.currentTimeMillis()
        private val BULK_THRESHOLD = 20 // 20 file changes in 10 seconds

        override fun onChange(selfChange: Boolean, uri: Uri?) {
            val now = System.currentTimeMillis()
            if (now - windowStart > 10_000L) {
                changeCount = 0
                windowStart = now
            }
            changeCount++
            if (changeCount >= BULK_THRESHOLD) {
                Log.w(TAG, "BULK FILE CHANGE DETECTED: $changeCount changes in 10s")
                onTrapTriggered("MediaStore:bulk", TrapAccessType.BULK_MODIFICATION)
                changeCount = 0 // Reset to avoid spam
            }
        }
    }

    data class TrapConfig(val filename: String, val content: TrapContent)

    enum class TrapAccessType(val label: String) {
        OPENED("opened"), READ("read"), MODIFIED("modified"),
        ATTRIBUTE_CHANGED("attribute-changed"), DELETED("deleted"),
        BULK_MODIFICATION("bulk-modified")
    }

    enum class TrapContent {
        CREDENTIALS {
            override fun generate() = """
                CONFIDENTIAL — DO NOT SHARE
                Email: admin@company.com
                Password: Tr0ub4dor&3
                2FA Backup: 834-291-056
                Last changed: 2024-11-15
            """.trimIndent()
        },
        FINANCIAL {
            override fun generate() = """
                Account Summary — PRIVATE
                Bank: National Bank Ltd
                Account No: 4523-8821-0047-1199
                Routing: 021000021
                Balance: $142,890.44
                PIN: 7823
            """.trimIndent()
        },
        PASSWORDS {
            override fun generate() = buildString {
                appendLine("Service,Username,Password,2FA")
                appendLine("Gmail,john.doe@gmail.com,P@ssw0rd!2024,enabled")
                appendLine("Amazon,john.doe@gmail.com,Amaz0n#2024,disabled")
                appendLine("Banking,johndoe_bank,B@nk$ecure99,enabled")
            }
        },
        API_KEYS {
            override fun generate() = """
                {
                  "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
                  "aws_secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                  "stripe_key": "sk_live_TRAP_AEGIS_CANARY_FILE",
                  "openai_key": "sk-AEGIS_HONEYTOKEN_DO_NOT_ENCRYPT",
                  "created": "2024-01-15"
                }
            """.trimIndent()
        },
        DOCUMENT {
            override fun generate() = "This document is monitored. Unauthorized access is logged and reported."
        },
        MINIMAL {
            override fun generate() = "AEGIS_CANARY_v1"
        };

        abstract fun generate(): String
    }
}

// Supporting data classes (put in separate files in real project)

data class ThreatEvent(
    val id: String,
    val type: ThreatType,
    val severity: Severity,
    val title: String,
    val description: String,
    val timestamp: Long,
    val actionTaken: String
)

enum class ThreatType {
    RANSOMWARE_ATTEMPT, RANSOMWARE_CONFIRMED, SPYWARE, PHISHING_SMS,
    MALICIOUS_URL, MALICIOUS_OVERLAY, PERMISSION_ABUSE, NETWORK_THREAT
}

enum class Severity { LOW, MEDIUM, HIGH, CRITICAL }
