package com.aegis.security.ui.onboarding

import android.Manifest
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.aegis.security.ui.theme.*

data class PermissionStep(
    val icon: ImageVector,
    val title: String,
    val description: String,
    val color: Color,
    val isGranted: () -> Boolean,
    val onRequest: () -> Unit,
    val required: Boolean = false
)

/**
 * Shown once after install, before the dashboard. Walks the user through
 * granting every permission Aegis's modules need, one card at a time, with
 * a clear plain-language reason for each — instead of silently never asking.
 */
@Composable
fun PermissionOnboardingScreen(onFinished: () -> Unit) {
    val context = LocalContext.current
    var refreshTick by remember { mutableStateOf(0) } // bump to force isGranted() re-check

    // ── VPN consent launcher ──────────────────────────────────────────────────
    val vpnLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { refreshTick++ }

    // ── Runtime permission launcher (SMS, notifications) ──────────────────────
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { refreshTick++ }

    fun hasPermission(perm: String) =
        ContextCompat.checkSelfPermission(context, perm) == android.content.pm.PackageManager.PERMISSION_GRANTED

    fun isAccessibilityEnabled(): Boolean {
        val enabled = Settings.Secure.getString(
            context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: ""
        return enabled.contains(context.packageName)
    }

    val steps = remember(refreshTick) {
        buildList {
            add(
                PermissionStep(
                    icon = Icons.Default.Security,
                    title = "VPN Shield",
                    description = "Lets Aegis filter malicious domains system-wide before any app connects to them. Android will show a system consent dialog.",
                    color = AegisPurple,
                    isGranted = { VpnService.prepare(context) == null },
                    onRequest = {
                        val intent = VpnService.prepare(context)
                        if (intent != null) vpnLauncher.launch(intent) else refreshTick++
                    },
                    required = false
                )
            )
            add(
                PermissionStep(
                    icon = Icons.Default.Sms,
                    title = "SMS Phishing Filter",
                    description = "Scans incoming messages for phishing links the moment they arrive — nothing is read from your inbox history.",
                    color = AegisAmber,
                    isGranted = { hasPermission(Manifest.permission.RECEIVE_SMS) },
                    onRequest = { permissionLauncher.launch(arrayOf(Manifest.permission.RECEIVE_SMS)) },
                    required = false
                )
            )
            add(
                PermissionStep(
                    icon = Icons.Default.Mic,
                    title = "Voice Assistant",
                    description = "Lets you speak to your security assistant instead of typing — tap the mic on the AI Guard screen anytime.",
                    color = AegisPurpleLight,
                    isGranted = { hasPermission(Manifest.permission.RECORD_AUDIO) },
                    onRequest = { permissionLauncher.launch(arrayOf(Manifest.permission.RECORD_AUDIO)) },
                    required = false
                )
            )
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                add(
                    PermissionStep(
                        icon = Icons.Default.Notifications,
                        title = "Notifications",
                        description = "Required to alert you instantly when a threat is detected — ransomware traps, phishing SMS, risky apps.",
                        color = AegisCoralRed,
                        isGranted = { hasPermission(Manifest.permission.POST_NOTIFICATIONS) },
                        onRequest = { permissionLauncher.launch(arrayOf(Manifest.permission.POST_NOTIFICATIONS)) },
                        required = true
                    )
                )
            }
            add(
                PermissionStep(
                    icon = Icons.Default.Visibility,
                    title = "Anti-Clickjack Shield",
                    description = "Opens Accessibility settings — find 'Aegis Anti-Clickjack Shield' in the list and turn it on. This detects invisible overlay attacks.",
                    color = AegisTealLight,
                    isGranted = { isAccessibilityEnabled() },
                    onRequest = {
                        context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                    },
                    required = false
                )
            )
        }
    }

    val allRequiredGranted = steps.filter { it.required }.all { it.isGranted() }
    val grantedCount = steps.count { it.isGranted() }

    Box(
        modifier = Modifier.fillMaxSize().background(AegisBgDeep)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 20.dp, vertical = 32.dp)
        ) {
            Text(
                "Set up your protection",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = AegisOnBg
            )
            Spacer(Modifier.height(6.dp))
            Text(
                "$grantedCount of ${steps.size} granted — each one unlocks a real defense module. You can change these anytime in Settings.",
                style = MaterialTheme.typography.bodyMedium,
                color = AegisSubtext
            )
            Spacer(Modifier.height(24.dp))

            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                steps.forEach { step -> PermissionCard(step) }
            }

            Spacer(Modifier.height(16.dp))
            Button(
                onClick = onFinished,
                modifier = Modifier.fillMaxWidth().height(52.dp),
                shape = RoundedCornerShape(16.dp),
                colors = ButtonDefaults.buttonColors(containerColor = AegisPurple)
            ) {
                Text(
                    if (allRequiredGranted) "Continue to Dashboard" else "Skip for now",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }
}

@Composable
private fun PermissionCard(step: PermissionStep) {
    val granted = step.isGranted()

    Card(
        colors = CardDefaults.cardColors(containerColor = AegisSurfaceVar),
        shape = RoundedCornerShape(16.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.Top
        ) {
            Box(
                modifier = Modifier
                    .size(42.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(step.color.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(step.icon, null, tint = step.color, modifier = Modifier.size(22.dp))
            }
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(step.title, style = MaterialTheme.typography.titleSmall, color = AegisOnBg)
                    if (step.required) {
                        Spacer(Modifier.width(6.dp))
                        Text("Recommended", style = MaterialTheme.typography.labelSmall, color = AegisCoralRed)
                    }
                }
                Spacer(Modifier.height(4.dp))
                Text(step.description, style = MaterialTheme.typography.bodySmall, color = AegisSubtext)
                Spacer(Modifier.height(10.dp))

                AnimatedVisibility(visible = !granted) {
                    OutlinedButton(
                        onClick = step.onRequest,
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = step.color)
                    ) {
                        Text("Grant access")
                    }
                }
                AnimatedVisibility(visible = granted) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.CheckCircle, null, tint = AegisTealLight, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Granted", style = MaterialTheme.typography.labelMedium, color = AegisTealLight)
                    }
                }
            }
        }
    }
}
