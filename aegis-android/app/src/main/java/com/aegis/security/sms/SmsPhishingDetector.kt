package com.aegis.security.sms

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.app.NotificationManager
import android.provider.Telephony
import androidx.core.app.NotificationCompat
import com.aegis.security.AegisApplication
import com.aegis.security.data.repository.ThreatRepository
import com.aegis.security.domain.model.Severity
import com.aegis.security.domain.model.ThreatEvent
import com.aegis.security.domain.model.ThreatType
import dagger.hilt.android.AndroidEntryPoint
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

// ── Phishing Detector ────────────────────────────────────────────────────────

@Singleton
class SmsPhishingDetector @Inject constructor(
    private val repository: ThreatRepository,
    @ApplicationContext private val context: Context
) {
    companion object {
        // Common smishing urgency triggers
        private val URGENCY_KEYWORDS = listOf(
            "urgent", "click here", "verify now", "account suspended",
            "blocked", "winner", "prize", "claim", "otp", "kyc update",
            "bank account", "act now", "immediately", "expire", "reward",
            "free gift", "congratulations", "selected", "lucky draw"
        )

        // URL pattern
        private val URL_REGEX = Regex("""https?://[^\s]+|www\.[^\s]+""")
    }

    suspend fun analyze(sender: String, body: String) {
        val lower = body.lowercase()
        val urls = URL_REGEX.findAll(body).map { it.value }.toList()
        val hits = URGENCY_KEYWORDS.filter { lower.contains(it) }

        // Score: URLs are strongest signal, keywords add confidence
        val score = (urls.size * 20 + hits.size * 10).coerceAtMost(100)
        if (score < 40) return // below detection threshold

        // Check URLs against backend community threat DB
        val urlThreats = if (urls.isNotEmpty()) {
            repository.checkThreats(urls).filterValues { it }
        } else emptyMap()

        val isConfirmed = urlThreats.isNotEmpty()
        val severity = when {
            isConfirmed || score >= 75 -> Severity.HIGH
            score >= 50 -> Severity.MEDIUM
            else -> Severity.LOW
        }

        val threat = ThreatEvent(
            id = UUID.randomUUID().toString(),
            type = ThreatType.SMS_PHISHING,
            severity = severity,
            title = if (isConfirmed) "Confirmed Phishing SMS" else "Suspicious SMS Detected",
            description = buildString {
                append("Message from $sender. ")
                if (urls.isNotEmpty()) append("Contains ${urls.size} URL(s). ")
                if (isConfirmed) append("URL matches known phishing database. ")
                if (hits.isNotEmpty()) append("Urgency keywords: ${hits.take(3).joinToString(", ")}.")
            },
            timestamp = System.currentTimeMillis(),
            actionTaken = "User warned before interaction"
        )
        repository.save(threat)
        repository.reportToBackend(threat)
        showSmsAlert(sender, threat)
    }

    private fun showSmsAlert(sender: String, threat: ThreatEvent) {
        val nm = context.getSystemService(NotificationManager::class.java)
        val n = NotificationCompat.Builder(context, AegisApplication.CHANNEL_THREATS)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("⚠ " + threat.title)
            .setContentText("Suspicious SMS from $sender")
            .setStyle(NotificationCompat.BigTextStyle().bigText(threat.description))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .build()
        nm.notify(threat.id.hashCode(), n)
    }
}

// ── BroadcastReceiver ────────────────────────────────────────────────────────

@AndroidEntryPoint
class SmsReceiver : BroadcastReceiver() {

    @Inject lateinit var detector: SmsPhishingDetector

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent) ?: return
        messages.forEach { sms ->
            CoroutineScope(Dispatchers.IO).launch {
                detector.analyze(
                    sender = sms.originatingAddress ?: "Unknown",
                    body   = sms.messageBody ?: ""
                )
            }
        }
    }
}
