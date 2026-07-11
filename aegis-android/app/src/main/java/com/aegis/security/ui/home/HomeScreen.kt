package com.aegis.security.ui.home

import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.layout.layout
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavController
import com.aegis.security.domain.model.AegisSettings
import com.aegis.security.domain.model.DashboardStats
import com.aegis.security.domain.model.Severity
import com.aegis.security.domain.model.ThreatEvent
import com.aegis.security.ui.theme.*
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    padding: PaddingValues,
    navController: NavController,
    viewModel: HomeViewModel = hiltViewModel()
) {
    val stats    by viewModel.stats.collectAsState()
    val settings by viewModel.settings.collectAsState()
    val threats  by viewModel.recentThreats.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        "AEGIS",
                        style = MaterialTheme.typography.titleLarge.copy(
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 3.sp
                        ),
                        color = AegisPurpleLight
                    )
                },
                actions = {
                    IconButton(onClick = { navController.navigate("settings") }) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings",
                            tint = AegisSubtext)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = AegisBgDeep
                )
            )
        },
        containerColor = AegisBgDeep
    ) { inner ->
        LazyColumn(
            contentPadding = PaddingValues(
                start  = 16.dp,
                end    = 16.dp,
                top    = inner.calculateTopPadding() + padding.calculateTopPadding() + 8.dp,
                bottom = inner.calculateBottomPadding() + padding.calculateBottomPadding() + 80.dp
            ),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // ── 1. Protection status ─────────────────────────────────────
            item { ProtectionStatusCard(stats, settings) }

            // ── 2. Stats row ─────────────────────────────────────────────
            item { StatsRow(stats) }

            // ── 3. Module toggles ────────────────────────────────────────
            item {
                SectionHeader("Protection Modules")
                Spacer(Modifier.height(8.dp))
                ModulesGrid(settings, viewModel, navController)
            }

            // ── 4. Recent threats ────────────────────────────────────────
            item { SectionHeader("Recent Threats") }

            if (threats.isEmpty()) {
                item {
                    EmptyThreatsCard()
                }
            } else {
                items(threats.take(10)) { threat ->
                    ThreatItemCard(threat)
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Protection Status Card
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun ProtectionStatusCard(stats: DashboardStats, settings: AegisSettings) {
    val activeModules = listOf(
        settings.honeyTokenEnabled,
        settings.vpnEnabled,
        settings.smsFilterEnabled,
        settings.permissionAuditEnabled
    ).count { it }

    val isProtected = activeModules >= 2
    val pulse by rememberInfiniteTransition(label = "pulse").animateFloat(
        initialValue = 0.6f,
        targetValue  = 1f,
        animationSpec = infiniteRepeatable(
            tween(2000, easing = FastOutSlowInEasing),
            RepeatMode.Reverse
        ), label = "pulse"
    )

    val glowColor = if (isProtected) AegisTeal.copy(alpha = pulse * 0.3f)
                    else AegisCoralRed.copy(alpha = pulse * 0.3f)

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .drawBehind {
                drawCircle(color = glowColor, radius = size.minDimension * 0.65f)
            },
        colors = CardDefaults.cardColors(containerColor = AegisSurfaceVar),
        shape  = RoundedCornerShape(20.dp)
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 28.dp, horizontal = 16.dp)
        ) {
            // Shield icon
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(88.dp)
                    .clip(CircleShape)
                    .background(
                        Brush.radialGradient(
                            listOf(
                                if (isProtected) AegisTeal.copy(0.3f) else AegisCoralRed.copy(0.3f),
                                Color.Transparent
                            )
                        )
                    )
            ) {
                Icon(
                    imageVector        = if (isProtected) Icons.Default.Shield else Icons.Default.ShieldMoon,
                    contentDescription = "Protection status",
                    tint               = if (isProtected) AegisTealLight else AegisCoralRed,
                    modifier           = Modifier.size(56.dp)
                )
            }

            Spacer(Modifier.height(16.dp))

            Text(
                text  = if (isProtected) "PROTECTED" else "AT RISK",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = if (isProtected) AegisTealLight else AegisCoralRed
            )

            Spacer(Modifier.height(4.dp))

            Text(
                text  = "$activeModules of 4 modules active",
                style = MaterialTheme.typography.bodyMedium,
                color = AegisSubtext
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stats Row
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun StatsRow(stats: DashboardStats) {
    Row(
        modifier             = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        StatCard(
            value  = stats.threatsDetected.toString(),
            label  = "Threats",
            color  = AegisCoralRed,
            icon   = Icons.Default.BugReport,
            modifier = Modifier.weight(1f)
        )
        StatCard(
            value  = stats.dnQueriesBlocked.toString(),
            label  = "DNS Blocked",
            color  = AegisPurpleLight,
            icon   = Icons.Default.Block,
            modifier = Modifier.weight(1f)
        )
        StatCard(
            value  = stats.smsPhishingBlocked.toString(),
            label  = "SMS Scanned",
            color  = AegisTealLight,
            icon   = Icons.Default.Sms,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun StatCard(
    value: String,
    label: String,
    color: Color,
    icon: ImageVector,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        colors   = CardDefaults.cardColors(containerColor = AegisSurfaceVar),
        shape    = RoundedCornerShape(14.dp)
    ) {
        Column(
            modifier            = Modifier.padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(icon, contentDescription = label, tint = color, modifier = Modifier.size(20.dp))
            Spacer(Modifier.height(4.dp))
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, color = color)
            Text(label, style = MaterialTheme.typography.labelSmall, color = AegisSubtext)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Modules Grid
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun ModulesGrid(
    settings:      AegisSettings,
    viewModel:     HomeViewModel,
    navController: NavController
) {
    val modules = listOf(
        ModuleInfo("Micro-VPN Shield",    Icons.Default.Security,     settings.vpnEnabled,             AegisPurple),
        ModuleInfo("Honey-Token Canary",  Icons.Default.Folder,       settings.honeyTokenEnabled,      AegisTeal),
        ModuleInfo("SMS Phish Filter",    Icons.Default.Sms,          settings.smsFilterEnabled,       AegisAmber),
        ModuleInfo("Permission Auditor",  Icons.Default.AdminPanelSettings, settings.permissionAuditEnabled, AegisCoralRed),
    )

    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "Tap any module to manage it in Settings",
                style = MaterialTheme.typography.labelSmall,
                color = AegisSubtext
            )
        }
        Spacer(Modifier.height(8.dp))
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            modules.chunked(2).forEach { row ->
                Row(
                    modifier              = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    row.forEach { module ->
                        ModuleCard(module, navController, Modifier.weight(1f))
                    }
                    if (row.size == 1) Spacer(Modifier.weight(1f))
                }
            }
        }
    }
}

private data class ModuleInfo(
    val name: String, val icon: ImageVector,
    val isOn: Boolean, val color: Color
)

@Composable
private fun ModuleCard(module: ModuleInfo, navController: NavController, modifier: Modifier) {
    Card(
        modifier = modifier.clickable {
            navController.navigate("settings")
        },
        colors   = CardDefaults.cardColors(containerColor = AegisSurfaceVar),
        shape    = RoundedCornerShape(14.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                verticalAlignment     = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier              = Modifier.fillMaxWidth()
            ) {
                Box(
                    modifier        = Modifier
                        .size(36.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .background(module.color.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(module.icon, contentDescription = null, tint = module.color, modifier = Modifier.size(20.dp))
                }
                // Read-only status dot instead of a second interactive switch —
                // toggling actually happens in Settings to avoid two sources of truth.
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(RoundedCornerShape(50))
                        .background(if (module.isOn) module.color else AegisOutline)
                )
            }
            Spacer(Modifier.height(8.dp))
            Text(module.name, style = MaterialTheme.typography.labelMedium, color = AegisOnBg, maxLines = 2)
            Text(
                if (module.isOn) "Active" else "Off — tap to enable",
                style = MaterialTheme.typography.labelSmall,
                color = if (module.isOn) module.color else AegisSubtext
            )
        }
    }
}

private fun Modifier.scale(scale: Float) = this.then(
    Modifier.layout { measurable, constraints ->
        val placeable = measurable.measure(constraints)
        layout(
            (placeable.width * scale).toInt(),
            (placeable.height * scale).toInt()
        ) {
            placeable.placeRelative(
                -((placeable.width  * (1 - scale)) / 2).toInt(),
                -((placeable.height * (1 - scale)) / 2).toInt()
            )
        }
    }
)

// ─────────────────────────────────────────────────────────────────────────────
// Threat Item Card
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun ThreatItemCard(threat: ThreatEvent) {
    val severityColor = when (threat.severity) {
        Severity.LOW      -> AegisGreen
        Severity.MEDIUM   -> AegisAmber
        Severity.HIGH     -> AegisCoralRed
        Severity.CRITICAL -> Color(0xFFCC0000)
        Severity.EMERGENCY-> Color(0xFF8B0000)
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = AegisSurface),
        shape  = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier          = Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Severity dot
            Box(
                modifier = Modifier
                    .size(10.dp)
                    .clip(CircleShape)
                    .background(severityColor)
            )
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(threat.title, style = MaterialTheme.typography.labelLarge, color = AegisOnBg)
                Text(
                    threat.description.take(70) + if (threat.description.length > 70) "…" else "",
                    style = MaterialTheme.typography.bodySmall, color = AegisSubtext,
                    maxLines = 2
                )
            }
            Spacer(Modifier.width(8.dp))
            Text(
                timeAgo(threat.timestamp),
                style = MaterialTheme.typography.labelSmall, color = AegisSubtext
            )
        }
    }
}

@Composable
private fun EmptyThreatsCard() {
    Card(
        colors   = CardDefaults.cardColors(containerColor = AegisSurface),
        shape    = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier          = Modifier.padding(20.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center
        ) {
            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = AegisTealLight)
            Spacer(Modifier.width(12.dp))
            Text("No threats detected yet — you're clean!", color = AegisSubtext,
                style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        title,
        style      = MaterialTheme.typography.titleSmall,
        color      = AegisSubtext,
        fontWeight = FontWeight.SemiBold,
        modifier   = Modifier.padding(vertical = 4.dp)
    )
}

private fun timeAgo(ts: Long): String {
    val diff = System.currentTimeMillis() - ts
    return when {
        diff < 60_000      -> "just now"
        diff < 3_600_000   -> "${diff / 60_000}m ago"
        diff < 86_400_000  -> "${diff / 3_600_000}h ago"
        else               -> SimpleDateFormat("MMM d", Locale.getDefault()).format(Date(ts))
    }
}
