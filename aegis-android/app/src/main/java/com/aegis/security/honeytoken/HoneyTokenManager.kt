package com.aegis.security.honeytoken

import android.app.NotificationManager
import android.content.ContentValues
import android.content.Context
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.FileObserver
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import com.aegis.security.AegisApplication
import com.aegis.security.blockchain.BlockchainReporter
import com.aegis.security.data.repository.ThreatRepository
import com.aegis.security.domain.model.Severity
import com.aegis.security.domain.model.ThreatEvent
import com.aegis.security.domain.model.ThreatType
import dagger.hilt.android.qualifiers.ApplicationContext
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
 * Deploys hidden decoy files to lure ransomware and spyware.
 * When any process touches these files → instant detection.
 *
 * Works with ZERO root access via Android FileObserver + MediaStore APIs.
 */
@Singleton
class HoneyTokenManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val threatRepository: ThreatRepository,
    private val blockchainReporter: BlockchainReporter
) {
    private val scope       = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val observers   = mutableListOf<FileObserver>()
    private val traps       = mutableListOf<File>()
    private var mediaObserver: MediaChangeObserver? = null

    // Named alphabetically-first — ransomware scans directories alphabetically
    private val trapConfigs = listOf(
        TrapFile("!AEGIS_CANARY_PRIVATE.txt",  fakeCredentials()),
        TrapFile("!IMPORTANT_DOCUMENTS.txt",    fakeFinancial()),
        TrapFile("000_account_passwords.csv",   fakePasswords()),
        TrapFile("000_backup_keys.json",        fakeApiKeys()),
        TrapFile("aaa_confidential_2024.txt",   "CONFIDENTIAL DOCUMENT — Aegis Security Monitor"),
        TrapFile(".aegis_hidden_canary",        "AEGIS_CANARY_v1")
    )

    private val recentTriggers = ArrayDeque<Long>()

    companion object {
        private const val TAG              = "AegisHoneyToken"
        private const val RAPID_WINDOW_MS  = 5_000L
        private const val RAPID_THRESHOLD  = 3
    }

    // ── Public API ────────────────────────────────────────────────────────────

    fun initialize() {
        deployTrapFiles()
        startFileObservers()
        startMediaObserver()
        Log.i(TAG, "Honey-Token engine active — ${traps.size} traps deployed")
    }

    fun shutdown() {
        observers.forEach { it.stopWatching() }
        observers.clear()
        mediaObserver?.let { context.contentResolver.unregisterContentObserver(it) }
        mediaObserver = null
        scope.cancel()
        Log.i(TAG, "Honey-Token engine stopped")
    }

    // ── Deploy ────────────────────────────────────────────────────────────────

    private fun deployTrapFiles() {
        val dir = context.getExternalFilesDir(null) ?: context.filesDir
        trapConfigs.forEach { cfg ->
            try {
                val f = File(dir, cfg.name)
                if (!f.exists()) { f.createNewFile(); f.writeText(cfg.content) }
                traps.add(f)
            } catch (e: Exception) {
                Log.w(TAG, "Could not deploy ${cfg.name}: ${e.message}")
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) deployToDownloads()
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun deployToDownloads() {
        try {
            val resolver = context.contentResolver
            val q = resolver.query(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                arrayOf(MediaStore.Downloads._ID),
                "${MediaStore.Downloads.DISPLAY_NAME}=?",
                arrayOf("!AEGIS_CANARY.txt"), null
            )
            val exists = (q?.count ?: 0) > 0
            q?.close()
            if (exists) return

            val cv = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, "!AEGIS_CANARY.txt")
                put(MediaStore.Downloads.MIME_TYPE,    "text/plain")
                put(MediaStore.Downloads.IS_PENDING,   1)
            }
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv) ?: return
            resolver.openOutputStream(uri)?.use { it.write(fakeFinancial().toByteArray()) }
            cv.clear(); cv.put(MediaStore.Downloads.IS_PENDING, 0)
            resolver.update(uri, cv, null, null)
        } catch (e: Exception) {
            Log.w(TAG, "Downloads canary failed: ${e.message}")
        }
    }

    // ── Observe ───────────────────────────────────────────────────────────────

    private fun startFileObservers() {
        val mask = FileObserver.OPEN or FileObserver.ACCESS or
                   FileObserver.MODIFY or FileObserver.DELETE

        traps.forEach { trap ->
            val obs = @RequiresApi(Build.VERSION_CODES.Q)
            object : FileObserver(trap, mask) {
                override fun onEvent(event: Int, path: String?) {
                    val type = when (event and ALL_EVENTS) {
                        OPEN   -> "opened"
                        ACCESS -> "read"
                        MODIFY -> "modified"
                        DELETE -> "deleted"
                        else   -> return
                    }
                    onTrapTriggered(trap.name, type)
                }
            }
            obs.startWatching()
            observers.add(obs)
        }
    }

    private fun startMediaObserver() {
        mediaObserver = MediaChangeObserver()
        context.contentResolver.registerContentObserver(
            MediaStore.Files.getContentUri("external"), true, mediaObserver!!
        )
    }

    // ── Respond ───────────────────────────────────────────────────────────────

    private fun onTrapTriggered(filename: String, accessType: String) {
        val now = System.currentTimeMillis()
        recentTriggers.addLast(now)
        while (recentTriggers.isNotEmpty() && now - recentTriggers.first() > RAPID_WINDOW_MS)
            recentTriggers.removeFirst()

        val isRapid   = recentTriggers.size >= RAPID_THRESHOLD
        val severity  = if (isRapid) Severity.CRITICAL else Severity.HIGH
        val type      = if (isRapid) ThreatType.RANSOMWARE_CONFIRMED else ThreatType.RANSOMWARE_ATTEMPT

        val threat = ThreatEvent(
            id          = UUID.randomUUID().toString(),
            type        = type,
            severity    = severity,
            title       = if (isRapid) "Ransomware Confirmed" else "Suspicious File Access",
            description = buildString {
                append("Trap file '${filename}' was $accessType. ")
                if (isRapid) append("${recentTriggers.size} trap files triggered in ${RAPID_WINDOW_MS/1000}s — active ransomware scan detected.")
                else append("A process accessed a protected decoy file.")
            },
            timestamp   = now,
            actionTaken = "Trap triggered — monitoring process activity"
        )

        scope.launch {
            threatRepository.save(threat)
            threatRepository.reportToBackend(threat)
            blockchainReporter.reportAnonymized(threat)
            showAlert(threat)
        }

        Log.w(TAG, "TRAP: $filename [$accessType] — ${severity.label}")
    }

    private fun showAlert(threat: ThreatEvent) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val n  = NotificationCompat.Builder(context, AegisApplication.CHANNEL_THREATS)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(threat.title)
            .setContentText(threat.description)
            .setStyle(NotificationCompat.BigTextStyle().bigText(threat.description))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .build()
        nm.notify(threat.id.hashCode(), n)
    }

    // ── Media observer (bulk encryption detection) ────────────────────────────

    inner class MediaChangeObserver : ContentObserver(Handler(Looper.getMainLooper())) {
        private var count     = 0
        private var windowStart = System.currentTimeMillis()

        override fun onChange(selfChange: Boolean, uri: Uri?) {
            val now = System.currentTimeMillis()
            if (now - windowStart > 10_000L) { count = 0; windowStart = now }
            count++
            if (count == 25) onTrapTriggered("MediaStore:bulk", "bulk-modified")
        }
    }

    // ── Trap file content generators ──────────────────────────────────────────

    data class TrapFile(val name: String, val content: String)

    private fun fakeCredentials() = """
        CONFIDENTIAL — DO NOT SHARE
        Email:       admin@company.com
        Password:    Tr0ub4dor&3
        2FA Backup:  834-291-056
    """.trimIndent()

    private fun fakeFinancial() = """
        Account Summary — PRIVATE
        Bank:       National Bank Ltd
        Account No: 4523-8821-0047-1199
        Balance:    $142,890.44
    """.trimIndent()

    private fun fakePasswords() = buildString {
        appendLine("Service,Username,Password")
        appendLine("Gmail,user@gmail.com,S3cur3P@ss2024")
        appendLine("Amazon,user@gmail.com,Amaz0n#Secure")
        val ecure99 = ""
        appendLine("Bank,johndoe,B@nk$ecure99")
    }

    private fun fakeApiKeys() = """
        {
          "aws_key":   "AKIAIOSFODNN7EXAMPLE",
          "stripe":    "sk_live_AEGIS_CANARY_TRAP",
          "note":      "AEGIS_HONEYTOKEN_DO_NOT_ENCRYPT"
        }
    """.trimIndent()
}
