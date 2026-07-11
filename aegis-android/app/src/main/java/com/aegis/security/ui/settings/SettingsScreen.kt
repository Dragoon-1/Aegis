package com.aegis.security.ui.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.datastore.preferences.core.edit
import androidx.hilt.navigation.compose.hiltViewModel
import com.aegis.security.data.remote.AegisApiService
import com.aegis.security.ui.assistant.LANGUAGES
import com.aegis.security.ui.home.HomeViewModel
import com.aegis.security.ui.home.PrefKeys
import com.aegis.security.ui.home.aegisDataStore
import com.aegis.security.ui.theme.*
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    padding:   PaddingValues,
    viewModel: HomeViewModel   = hiltViewModel(),
    api:       AegisApiService? = null          // injected via Hilt in real usage
) {
    val settings  by viewModel.settings.collectAsState()
    val scope     = rememberCoroutineScope()
    var showLang  by remember { mutableStateOf(false) }
    var reporting by remember { mutableStateOf(false) }
    var reportMsg by remember { mutableStateOf("") }

    Scaffold(
        topBar = {
            TopAppBar(
                title  = {
                    Column {
                        Text("Settings", style = MaterialTheme.typography.titleLarge)
                        Text(
                            "Turn modules on or off here — Dashboard just shows status",
                            style = MaterialTheme.typography.labelSmall,
                            color = AegisSubtext
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = AegisBgDeep)
            )
        },
        containerColor = AegisBgDeep
    ) { inner ->
        LazyColumn(
            contentPadding      = PaddingValues(
                start      = 16.dp,
                end        = 16.dp,
                top        = inner.calculateTopPadding() + padding.calculateTopPadding() + 8.dp,
                bottom     = inner.calculateBottomPadding() + padding.calculateBottomPadding() + 80.dp
            ),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {

            // ── Protection Modules ────────────────────────────────────────
            item { SettingsSectionHeader("Protection Modules") }

            item {
                ModuleToggle(
                    icon    = Icons.Default.Security,
                    label   = "Micro-VPN Shield",
                    desc    = "Block malicious domains system-wide via local DNS tunnel",
                    color   = AegisPurple,
                    checked = settings.vpnEnabled,
                    onCheck = { viewModel.toggleVpn(it) }
                )
            }
            item {
                ModuleToggle(
                    icon    = Icons.Default.Folder,
                    label   = "Honey-Token Canary",
                    desc    = "Trap files that detect ransomware before encryption begins",
                    color   = AegisTeal,
                    checked = settings.honeyTokenEnabled,
                    onCheck = { viewModel.toggleHoneyToken(it) }
                )
            }
            item {
                ModuleToggle(
                    icon    = Icons.Default.Sms,
                    label   = "SMS Phishing Filter",
                    desc    = "Scan incoming messages for phishing URLs and smishing patterns",
                    color   = AegisAmber,
                    checked = settings.smsFilterEnabled,
                    onCheck = { viewModel.toggleSmsFilter(it) }
                )
            }
            item {
                ModuleToggle(
                    icon    = Icons.Default.AdminPanelSettings,
                    label   = "Permission Auditor",
                    desc    = "Monitor installed apps for dangerous permission combinations",
                    color   = AegisCoralRed,
                    checked = settings.permissionAuditEnabled,
                    onCheck = { viewModel.togglePermissionAudit(it) }
                )
            }
            item {
                ModuleToggle(
                    icon    = Icons.Default.Hub,
                    label   = "Blockchain Threat Sharing",
                    desc    = "Share threat hashes anonymously — protect the whole community",
                    color   = Color(0xFF3B6D11),
                    checked = settings.blockchainReportingEnabled,
                    onCheck = { viewModel.toggleBlockchain(it) }
                )
            }

            // ── Preferences ───────────────────────────────────────────────
            item { Spacer(Modifier.height(8.dp)); SettingsSectionHeader("Preferences") }

            item {
                SettingsRow(
                    icon  = Icons.Default.Language,
                    label = "Assistant Language",
                    value = LANGUAGES[settings.language] ?: settings.language,
                    color = AegisPurpleLight,
                    onClick = { showLang = true }
                )
            }

            // ── Reporting ─────────────────────────────────────────────────
            item { Spacer(Modifier.height(8.dp)); SettingsSectionHeader("Cyber Police Reporting") }

            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = AegisSurfaceVar),
                    shape  = RoundedCornerShape(14.dp)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {

                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                modifier = Modifier
                                    .size(8.dp)
                                    .background(AegisTealLight, androidx.compose.foundation.shape.CircleShape)
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                "Automatic — runs on the backend, not on this device",
                                style = MaterialTheme.typography.labelMedium,
                                color = AegisTealLight, fontWeight = FontWeight.SemiBold
                            )
                        }

                        Spacer(Modifier.height(10.dp))
                        Text(
                            "Aegis does not send anything from your phone. When 100+ devices " +
                            "worldwide report the same threat hash on the blockchain, the contract " +
                            "fires a ThreatEscalated event. Our backend server picks that up, " +
                            "aggregates the data, and generates a CERT-In format PDF automatically.",
                            style = MaterialTheme.typography.bodySmall, color = AegisSubtext
                        )

                        Spacer(Modifier.height(14.dp))
                        HorizontalDivider(color = AegisOutline)
                        Spacer(Modifier.height(14.dp))

                        Text(
                            "Demo / testing only",
                            style = MaterialTheme.typography.labelMedium,
                            color = AegisAmber, fontWeight = FontWeight.SemiBold
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "Force the backend to generate a sample report right now without " +
                            "waiting for 100 real reports.",
                            style = MaterialTheme.typography.bodySmall, color = AegisSubtext
                        )

                        if (reportMsg.isNotEmpty()) {
                            Spacer(Modifier.height(8.dp))
                            Text(reportMsg, color = AegisTealLight,
                                style = MaterialTheme.typography.labelSmall)
                        }
                        Spacer(Modifier.height(10.dp))
                        OutlinedButton(
                            onClick = {
                                scope.launch {
                                    reporting = true
                                    try {
                                        api?.generatePoliceReport()
                                        reportMsg = "Demo report queued on backend — check /reports on the server."
                                    } catch (e: Exception) {
                                        reportMsg = "Could not reach backend server."
                                    } finally {
                                        reporting = false
                                    }
                                }
                            },
                            enabled = !reporting,
                            colors  = ButtonDefaults.outlinedButtonColors(contentColor = AegisAmber),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            if (reporting) {
                                CircularProgressIndicator(Modifier.size(18.dp), AegisAmber, 2.dp)
                                Spacer(Modifier.width(8.dp))
                            } else {
                                Icon(Icons.Default.Description, null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                            }
                            Text("Force Generate Now (Demo)")
                        }
                    }
                }
            }

            // ── About ─────────────────────────────────────────────────────
            item { Spacer(Modifier.height(8.dp)); SettingsSectionHeader("About") }

            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = AegisSurfaceVar),
                    shape  = RoundedCornerShape(14.dp)
                ) {
                    Column(modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        AboutRow("App version",   "1.0.0 (MVP)")
                        AboutRow("Blockchain",    "Polygon PoS — AegisThreatIntel.sol")
                        AboutRow("AI engine",     "Gemini (Google DeepMind)")
                        AboutRow("DNS Blocklists","abuse.ch · PhishTank · OISD")
                        AboutRow("Built for",     "Hack4Humanity Hackathon")
                        AboutRow("Privacy",       "Zero cloud scanning. All data stays on device.")
                    }
                }
            }
        }

        // Language picker dialog
        if (showLang) {
            AlertDialog(
                onDismissRequest = { showLang = false },
                title = { Text("Select Language") },
                text = {
                    LazyColumn {
                        val entries = LANGUAGES.entries.toList()
                        items(entries.size) { idx ->
                            val (code, name) = entries[idx]
                            Row(
                                modifier          = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        scope.launch {
                                            // update language in datastore
                                        }
                                        showLang = false
                                    }
                                    .padding(vertical = 10.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                RadioButton(
                                    selected = settings.language == code,
                                    onClick  = null
                                )
                                Spacer(Modifier.width(8.dp))
                                Text(name, color = AegisOnBg)
                            }
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { showLang = false }) { Text("Close") }
                },
                containerColor = AegisSurfaceVar
            )
        }
    }
}

@Composable
private fun ModuleToggle(
    icon:    ImageVector,
    label:   String,
    desc:    String,
    color:   Color,
    checked: Boolean,
    onCheck: (Boolean) -> Unit
) {
    Card(
        colors   = CardDefaults.cardColors(containerColor = AegisSurfaceVar),
        shape    = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier          = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(icon, contentDescription = null, tint = color,
                modifier = Modifier.size(22.dp))
            Spacer(Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(label, style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Medium, color = AegisOnBg)
                Text(desc, style = MaterialTheme.typography.bodySmall,
                    color = AegisSubtext, maxLines = 2)
            }
            Switch(
                checked         = checked,
                onCheckedChange = onCheck,
                colors          = SwitchDefaults.colors(
                    checkedThumbColor  = Color.White,
                    checkedTrackColor  = color,
                    uncheckedTrackColor = AegisOutline
                )
            )
        }
    }
}

@Composable
private fun SettingsRow(
    icon: ImageVector, label: String, value: String, color: Color, onClick: () -> Unit
) {
    Card(
        colors   = CardDefaults.cardColors(containerColor = AegisSurfaceVar),
        shape    = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth().clickable { onClick() }
    ) {
        Row(
            modifier          = Modifier.padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(icon, null, tint = color, modifier = Modifier.size(22.dp))
            Spacer(Modifier.width(14.dp))
            Text(label, style = MaterialTheme.typography.labelLarge,
                color = AegisOnBg, modifier = Modifier.weight(1f))
            Text(value, style = MaterialTheme.typography.labelMedium, color = color)
            Spacer(Modifier.width(4.dp))
            Icon(Icons.Default.ChevronRight, null, tint = AegisSubtext,
                modifier = Modifier.size(18.dp))
        }
    }
}

@Composable
private fun AboutRow(label: String, value: String) {
    Row(
        modifier              = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment     = Alignment.Top
    ) {
        Text(label, style = MaterialTheme.typography.labelMedium,
            color = AegisSubtext, modifier = Modifier.weight(0.4f))
        Text(value, style = MaterialTheme.typography.bodySmall,
            color = AegisOnBg, modifier = Modifier.weight(0.6f))
    }
}

@Composable
private fun SettingsSectionHeader(title: String) {
    Text(
        title.uppercase(),
        style      = MaterialTheme.typography.labelSmall,
        color      = AegisPurpleLight,
        fontWeight = FontWeight.SemiBold,
        modifier   = Modifier.padding(top = 12.dp, bottom = 4.dp, start = 4.dp)
    )
}
