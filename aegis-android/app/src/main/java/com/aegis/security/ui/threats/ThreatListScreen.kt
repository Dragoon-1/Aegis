package com.aegis.security.ui.threats

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import com.aegis.security.domain.model.Severity
import com.aegis.security.domain.model.ThreatEvent
import com.aegis.security.domain.model.ThreatType
import com.aegis.security.ui.theme.*
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreatListScreen(
    padding: PaddingValues,
    viewModel: ThreatViewModel = hiltViewModel()
) {
    val threats by viewModel.threats.collectAsState()
    val filter  by viewModel.filter.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title  = { Text("Threat History", style = MaterialTheme.typography.titleLarge) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = AegisBgDeep)
            )
        },
        containerColor = AegisBgDeep
    ) { inner ->
        Column(modifier = Modifier.fillMaxSize().padding(inner).padding(padding)) {
            LazyRow(
                contentPadding        = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                item {
                    FilterChip(
                        selected = filter == null,
                        onClick  = { viewModel.setFilter(null) },
                        label    = { Text("All") },
                        colors   = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = AegisPurple,
                            selectedLabelColor     = Color.White
                        )
                    )
                }
                items(Severity.entries) { sev ->
                    FilterChip(
                        selected = filter == sev,
                        onClick  = { viewModel.setFilter(if (filter == sev) null else sev) },
                        label    = { Text(sev.label) },
                        colors   = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = Color(sev.color),
                            selectedLabelColor     = Color.White
                        )
                    )
                }
            }

            if (threats.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Default.CheckCircle, null, tint = AegisTealLight, modifier = Modifier.size(64.dp))
                        Spacer(Modifier.height(16.dp))
                        Text("No threats found", color = AegisSubtext, style = MaterialTheme.typography.titleMedium)
                        Text("Your device is clean!", color = AegisSubtext, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            } else {
                LazyColumn(
                    contentPadding      = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(threats, key = { it.id }) { threat ->
                        ThreatDetailCard(threat) { viewModel.resolve(threat.id) }
                    }
                }
            }
        }
    }
}

@Composable
fun ThreatDetailCard(threat: ThreatEvent, onResolve: () -> Unit) {
    val severityColor = Color(threat.severity.color)
    Card(
        colors   = CardDefaults.cardColors(containerColor = AegisSurfaceVar),
        shape    = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier.size(40.dp).clip(RoundedCornerShape(10.dp))
                        .background(severityColor.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(threatIcon(threat.type), null, tint = severityColor, modifier = Modifier.size(22.dp))
                }
                Spacer(Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(threat.title, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.SemiBold, color = AegisOnBg)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(Modifier.size(6.dp).clip(CircleShape).background(severityColor))
                        Spacer(Modifier.width(4.dp))
                        Text(threat.severity.label, style = MaterialTheme.typography.labelSmall, color = severityColor)
                    }
                }
                Text(fmtTime(threat.timestamp), style = MaterialTheme.typography.labelSmall, color = AegisSubtext)
            }
            Spacer(Modifier.height(10.dp))
            Text(threat.description, style = MaterialTheme.typography.bodySmall, color = AegisSubtext)
            if (threat.actionTaken.isNotBlank()) {
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Shield, null, tint = AegisTealLight, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(threat.actionTaken, style = MaterialTheme.typography.labelSmall, color = AegisTealLight)
                }
            }
            if (!threat.isResolved) {
                Spacer(Modifier.height(10.dp))
                TextButton(onClick = onResolve, modifier = Modifier.align(Alignment.End)) {
                    Text("Mark Resolved", color = AegisPurpleLight, style = MaterialTheme.typography.labelMedium)
                }
            }
        }
    }
}

private fun threatIcon(type: ThreatType): ImageVector = when (type) {
    ThreatType.RANSOMWARE_ATTEMPT, ThreatType.RANSOMWARE_CONFIRMED -> Icons.Default.FolderOff
    ThreatType.MALICIOUS_URL     -> Icons.Default.Link
    ThreatType.SMS_PHISHING      -> Icons.Default.Sms
    ThreatType.DANGEROUS_APP     -> Icons.Default.Apps
    ThreatType.MALICIOUS_OVERLAY -> Icons.Default.LayersClear
    ThreatType.NETWORK_THREAT    -> Icons.Default.Wifi
    ThreatType.PERMISSION_ABUSE  -> Icons.Default.Key
}

private fun fmtTime(ts: Long): String =
    SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()).format(Date(ts))
