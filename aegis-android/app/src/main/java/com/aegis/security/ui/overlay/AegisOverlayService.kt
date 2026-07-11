package com.aegis.security.ui.overlay

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.NotificationManager
import android.content.Intent
import android.graphics.PixelFormat
import android.graphics.Rect
import android.util.Log
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityWindowInfo
import androidx.core.app.NotificationCompat
import com.aegis.security.AegisApplication
import com.aegis.security.data.local.AegisDatabase
import com.aegis.security.data.repository.ThreatRepository
import com.aegis.security.domain.model.Severity
import com.aegis.security.domain.model.ThreatEvent
import com.aegis.security.domain.model.ThreatType
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.UUID
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

/**
 * AEGIS ANTI-CLICKJACKING SHIELD
 *
 * Monitors for TYPE_APPLICATION_OVERLAY windows placed over the current app.
 * Clickjacking attacks use transparent overlays to hijack taps —
 * e.g., you tap "Allow", but a hidden layer captures the touch for a malicious
 * permission grant underneath.
 *
 * Declared in AndroidManifest as an AccessibilityService.
 * User must enable it manually in Settings → Accessibility → Aegis Shield.
 *
 * Note: Add to AndroidManifest.xml:
 * <service
 *     android:name=".ui.overlay.AegisOverlayService"
 *     android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
 *     android:exported="true">
 *     <intent-filter>
 *         <action android:name="android.accessibilityservice.AccessibilityService" />
 *     </intent-filter>
 *     <meta-data
 *         android:name="android.accessibilityservice"
 *         android:resource="@xml/accessibility_service_config" />
 * </service>
 */
@AndroidEntryPoint
class AegisOverlayService : AccessibilityService() {

    @Inject lateinit var threatRepository: ThreatRepository

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val recentlyAlerted = mutableSetOf<String>()  // cooldown per package

    companion object {
        private const val TAG            = "AegisOverlay"
        private const val ALERT_COOLDOWN = 30_000L        // 30s between alerts per app
    }

    override fun onServiceConnected() {
        serviceInfo = AccessibilityServiceInfo().apply {
            eventTypes  = AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED or
                          AccessibilityEvent.TYPE_WINDOWS_CHANGED
            feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC
            flags        = AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
            notificationTimeout = 100L
        }
        Log.i(TAG, "Anti-clickjacking service connected")
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event ?: return
        if (event.eventType != AccessibilityEvent.TYPE_WINDOWS_CHANGED &&
            event.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return

        checkForOverlays()
    }

    override fun onInterrupt() {
        Log.w(TAG, "Accessibility service interrupted")
    }

    // ── Core overlay detection ────────────────────────────────────────────────

    private fun checkForOverlays() {
        val windows = windows ?: return

        // Find the currently active app window
        val activeAppWindow = windows.firstOrNull {
            it.type == AccessibilityWindowInfo.TYPE_APPLICATION && it.isActive
        } ?: return

        val activeAppBounds = Rect()
        activeAppWindow.getBoundsInScreen(activeAppBounds)

        // Look for suspicious overlay windows
        windows.filter { win ->
            win.type == AccessibilityWindowInfo.TYPE_SYSTEM ||
            win.type == AccessibilityWindowInfo.TYPE_ACCESSIBILITY_OVERLAY
        }.forEach { overlayWindow ->

            val overlayBounds = Rect()
            overlayWindow.getBoundsInScreen(overlayBounds)

            // Check if overlay significantly covers the active app
            val intersection = Rect(activeAppBounds)
            val overlaps = intersection.intersect(overlayBounds)

            if (overlaps) {
                val overlapArea  = intersection.width() * intersection.height()
                val activeArea   = activeAppBounds.width() * activeAppBounds.height()
                val coverPercent = if (activeArea > 0) (overlapArea * 100) / activeArea else 0

                // Flag if overlay covers >30% of the active window
                if (coverPercent > 30) {
                    val suspectPkg = overlayWindow.root?.packageName?.toString()
                        ?: "unknown"
                    val activePkg  = activeAppWindow.root?.packageName?.toString()
                        ?: "unknown"

                    // Don't flag Aegis itself or the system UI
                    if (suspectPkg != packageName &&
                        suspectPkg != "com.android.systemui" &&
                        !recentlyAlerted.contains(suspectPkg)) {

                        Log.w(TAG, "OVERLAY DETECTED: $suspectPkg covers $coverPercent% of $activePkg")
                        flagOverlayThreat(suspectPkg, activePkg, coverPercent)

                        // Cooldown — don't spam the same app
                        recentlyAlerted.add(suspectPkg)
                        scope.launch {
                            kotlinx.coroutines.delay(ALERT_COOLDOWN)
                            recentlyAlerted.remove(suspectPkg)
                        }
                    }
                }
            }
        }
    }

    // ── Threat logging + notification ─────────────────────────────────────────

    private fun flagOverlayThreat(suspectPkg: String, targetPkg: String, coverage: Int) {
        val appLabel = try {
            packageManager.getApplicationLabel(
                packageManager.getApplicationInfo(suspectPkg, 0)
            ).toString()
        } catch (_: Exception) { suspectPkg }

        val threat = ThreatEvent(
            id          = UUID.randomUUID().toString(),
            type        = ThreatType.MALICIOUS_OVERLAY,
            severity    = Severity.HIGH,
            title       = "Overlay Attack Detected",
            description = "'$appLabel' is drawing a window over '${targetPkg.substringAfterLast('.')}' " +
                          "covering $coverage% of the screen. This may be a clickjacking attempt " +
                          "designed to capture your taps and grant hidden permissions.",
            timestamp   = System.currentTimeMillis(),
            actionTaken = "User alerted. Overlay app identified: $suspectPkg"
        )

        scope.launch {
            try {
                threatRepository.save(threat)
            } catch (_: Exception) {}
        }

        showOverlayAlert(appLabel, coverage)
    }

    private fun showOverlayAlert(appName: String, coverage: Int) {
        val nm = getSystemService(NotificationManager::class.java)
        val n  = NotificationCompat.Builder(this, AegisApplication.CHANNEL_THREATS)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("⚠ Overlay Attack Detected")
            .setContentText("'$appName' is drawing over your screen ($coverage% coverage)")
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                "'$appName' is placing a window over your current app, covering $coverage% " +
                "of your screen. This is a clickjacking technique used to steal taps. " +
                "Go to Settings → Apps → '$appName' and revoke 'Display over other apps' permission."
            ))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .build()
        nm.notify(appName.hashCode(), n)
    }
}
