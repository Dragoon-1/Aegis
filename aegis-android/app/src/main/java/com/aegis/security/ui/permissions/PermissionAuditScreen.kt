package com.aegis.security.ui.permissions

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.aegis.security.domain.model.AppPermissionInfo
import com.aegis.security.domain.model.Severity
import com.aegis.security.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PermissionAuditScreen(
    padding:   PaddingValues,
    viewModel: PermissionViewModel = hiltViewModel()
) {
    val apps     by viewModel.apps.collectAsState()
    val scanning by viewModel.scanning.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title   = { Text("Permission Auditor", style = MaterialTheme.typography.titleLarge) },
                actions = {
                    IconButton(onClick = { viewModel.scan() }) {
                        Icon(Icons.Default.Refresh, "Rescan", tint = AegisPurpleLight)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = AegisBgDeep)
            )
        },
        containerColor = AegisBgDeep
    ) { inner ->
        if (scanning) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(color = AegisPurple)
                    Spacer(Modifier.height(16.dp))
                    Text("Scanning all installed apps…", color = AegisSubtext)
                }
            }
            return@Scaffold
        }

        Column(modifier = Modifier.fillMaxSize().padding(inner).padding(padding)) {
            // Summary warning banner
            val critical = apps.count { it.riskLevel == Severity.CRITICAL || it.riskLevel == Severity.EMERGENCY }
            val high     = apps.count { it.riskLevel == Severity.HIGH }

            if (critical > 0 || high > 0) {
                Card(
                    colors   = CardDefaults.cardColors(containerColor = Color(0xFF4A1A0A)),
                    shape    = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)
                ) {
                    Row(modifier = Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Warning, null, tint = AegisCoralRed)
                        Spacer(Modifier.width(10.dp))
                        Column {
                            Text(
                                "$critical critical · $high high-risk apps found",
                                fontWeight = FontWeight.SemiBold, color = AegisCoralRed,
                                style = MaterialTheme.typography.labelLarge
                            )
                            Text(
                                "Review and uninstall any apps you don't recognise.",
                                color = Color(0xFFFFBBAA), style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
            }

            if (apps.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Default.CheckCircle, null, tint = AegisTealLight, modifier = Modifier.size(64.dp))
                        Spacer(Modifier.height(16.dp))
                        Text("No risky apps found!", color = AegisTealLight, style = MaterialTheme.typography.titleMedium)
                        Text("All installed apps look safe.", color = AegisSubtext, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            } else {
                LazyColumn(
                    contentPadding      = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(apps, key = { it.packageName }) { app -> AppRiskCard(app) }
                }
            }
        }
    }
}

@Composable
private fun AppRiskCard(app: AppPermissionInfo) {
    var expanded by remember { mutableStateOf(false) }

    val riskColor = when (app.riskLevel) {
        Severity.CRITICAL, Severity.EMERGENCY -> AegisCoralRed
        Severity.HIGH                         -> AegisAmber
        Severity.MEDIUM                       -> AegisPurpleLight
        else                                  -> AegisTealLight
    }

    Card(
        colors   = CardDefaults.cardColors(containerColor = AegisSurfaceVar),
        shape    = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded }
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier.size(44.dp).clip(RoundedCornerShape(10.dp))
                        .background(riskColor.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        "${app.riskScore}",
                        style      = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color      = riskColor
                    )
                }
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(app.appName, style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold, color = AegisOnBg, maxLines = 1)
                    Text(app.packageName, style = MaterialTheme.typography.labelSmall,
                        color = AegisSubtext, maxLines = 1)
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text(app.riskLevel.label, style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold, color = riskColor)
                    Text("${app.dangerousPermissions.size} perms",
                        style = MaterialTheme.typography.labelSmall, color = AegisSubtext)
                }
            }

            AnimatedVisibility(visible = expanded) {
                Column(modifier = Modifier.padding(top = 12.dp)) {
                    if (app.riskReasons.isNotEmpty()) {
                        Text("Why this is risky:", style = MaterialTheme.typography.labelMedium,
                            color = AegisSubtext, fontWeight = FontWeight.SemiBold)
                        Spacer(Modifier.height(6.dp))
                        app.riskReasons.forEach { reason ->
                            Row(verticalAlignment = Alignment.Top, modifier = Modifier.padding(vertical = 2.dp)) {
                                Icon(Icons.Default.Warning, null, tint = riskColor,
                                    modifier = Modifier.size(14.dp).padding(top = 1.dp))
                                Spacer(Modifier.width(6.dp))
                                Text(reason, style = MaterialTheme.typography.bodySmall, color = AegisOnBg)
                            }
                        }
                        Spacer(Modifier.height(10.dp))
                    }
                    Text("Dangerous permissions:", style = MaterialTheme.typography.labelMedium,
                        color = AegisSubtext, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(6.dp))
                    app.dangerousPermissions.forEach { perm ->
                        Text("• ${perm.removePrefix("android.permission.")}",
                            style = MaterialTheme.typography.labelSmall, color = AegisSubtext,
                            modifier = Modifier.padding(vertical = 1.dp))
                    }
                }
            }
        }
    }
}
