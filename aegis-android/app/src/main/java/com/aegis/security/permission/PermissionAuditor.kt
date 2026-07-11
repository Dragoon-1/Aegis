package com.aegis.security.permission

import android.content.Context
import android.content.pm.PackageManager
import com.aegis.security.domain.model.AppPermissionInfo
import com.aegis.security.domain.model.Severity
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class PermissionAuditor @Inject constructor(
    @ApplicationContext private val context: Context
) {
    companion object {
        // Each permission mapped to a danger weight (1-30)
        private val DANGEROUS_PERM_WEIGHTS = mapOf(
            "android.permission.CAMERA"                    to 10,
            "android.permission.RECORD_AUDIO"              to 10,
            "android.permission.ACCESS_FINE_LOCATION"      to 15,
            "android.permission.ACCESS_BACKGROUND_LOCATION" to 20,
            "android.permission.READ_CONTACTS"             to 10,
            "android.permission.WRITE_CONTACTS"            to 12,
            "android.permission.READ_SMS"                  to 20,
            "android.permission.SEND_SMS"                  to 20,
            "android.permission.RECEIVE_SMS"               to 15,
            "android.permission.READ_CALL_LOG"             to 15,
            "android.permission.PROCESS_OUTGOING_CALLS"    to 20,
            "android.permission.BIND_DEVICE_ADMIN"         to 30,
            "android.permission.BIND_ACCESSIBILITY_SERVICE" to 25,
            "android.permission.SYSTEM_ALERT_WINDOW"       to 20,
            "android.permission.WRITE_SETTINGS"            to 15,
            "android.permission.REQUEST_INSTALL_PACKAGES"  to 15,
            "android.permission.USE_BIOMETRIC"             to 10,
            "android.permission.READ_PHONE_STATE"          to 12,
            "android.permission.CALL_PHONE"                to 18,
        )

        // Combination multipliers — certain combinations are exponentially riskier
        private data class CombinationRule(
            val perms: List<String>,
            val extraScore: Int,
            val reason: String
        )

        private val COMBINATION_RULES = listOf(
            CombinationRule(
                listOf("android.permission.CAMERA", "android.permission.RECORD_AUDIO"),
                15, "Can silently record audio and video"
            ),
            CombinationRule(
                listOf("android.permission.READ_SMS", "android.permission.SEND_SMS"),
                20, "Can intercept and forward OTP messages (banking fraud risk)"
            ),
            CombinationRule(
                listOf("android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"),
                25, "Classic overlay + accessibility attack combination — possible banking Trojan"
            ),
            CombinationRule(
                listOf("android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.RECEIVE_SMS"),
                20, "Can silently install APKs triggered by SMS — dropper malware pattern"
            ),
            CombinationRule(
                listOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION"),
                15, "Can track your location continuously in background"
            ),
        )
    }

    fun auditAllApps(): List<AppPermissionInfo> {
        val pm = context.packageManager

        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)

        return packages
            .filter { it.packageName != context.packageName }
            .mapNotNull { pkg ->
                val requested = pkg.requestedPermissions?.toList() ?: return@mapNotNull null
                val dangerous = requested.filter { DANGEROUS_PERM_WEIGHTS.containsKey(it) }
                if (dangerous.isEmpty()) return@mapNotNull null

                val baseScore = dangerous
                    .sumOf { DANGEROUS_PERM_WEIGHTS[it] ?: 0 }
                    .coerceAtMost(70)

                // Apply combination bonuses
                val comboScore = COMBINATION_RULES
                    .filter { rule -> rule.perms.all { dangerous.contains(it) } }
                    .sumOf { it.extraScore }

                val finalScore = (baseScore + comboScore).coerceAtMost(100)
                val reasons = buildRiskReasons(dangerous)

                val appLabel = try {
                    pm.getApplicationLabel(pkg.applicationInfo).toString()
                } catch (e: Exception) { pkg.packageName }

                AppPermissionInfo(
                    packageName        = pkg.packageName,
                    appName            = appLabel,
                    riskScore          = finalScore,
                    riskLevel          = when {
                        finalScore >= 70 -> Severity.CRITICAL
                        finalScore >= 50 -> Severity.HIGH
                        finalScore >= 25 -> Severity.MEDIUM
                        else             -> Severity.LOW
                    },
                    dangerousPermissions = dangerous,
                    riskReasons          = reasons
                )
            }
            .sortedByDescending { it.riskScore }
    }

    private fun buildRiskReasons(perms: List<String>): List<String> {
        val reasons = mutableListOf<String>()

        // Individual permission reasons
        if (perms.contains("android.permission.BIND_DEVICE_ADMIN"))
            reasons.add("Has device administrator — can lock or wipe your device")
        if (perms.contains("android.permission.BIND_ACCESSIBILITY_SERVICE"))
            reasons.add("Can read all screen content and simulate taps")
        if (perms.contains("android.permission.READ_SMS"))
            reasons.add("Can read all your SMS messages including OTPs")
        if (perms.contains("android.permission.SYSTEM_ALERT_WINDOW"))
            reasons.add("Can draw overlays over other apps — clickjacking risk")
        if (perms.contains("android.permission.REQUEST_INSTALL_PACKAGES"))
            reasons.add("Can silently install additional apps")

        // Combination reasons
        COMBINATION_RULES
            .filter { rule -> rule.perms.all { perms.contains(it) } }
            .forEach { reasons.add(it.reason) }

        return reasons.distinct()
    }
}
