package com.aegis.security.ui.home

import android.content.Context
import android.content.Intent
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.*
import androidx.datastore.preferences.preferencesDataStore
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.security.data.repository.ThreatRepository
import com.aegis.security.domain.model.AegisSettings
import com.aegis.security.domain.model.DashboardStats
import com.aegis.security.domain.model.ThreatEvent
import com.aegis.security.honeytoken.HoneyTokenManager
import com.aegis.security.vpn.AegisVpnService
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

// DataStore extension (declared once at package level)
val Context.aegisDataStore: DataStore<Preferences> by preferencesDataStore(name = "aegis_settings")

object PrefKeys {
    val VPN_ENABLED        = booleanPreferencesKey("vpn_enabled")
    val HONEY_ENABLED      = booleanPreferencesKey("honey_enabled")
    val SMS_ENABLED        = booleanPreferencesKey("sms_enabled")
    val PERM_ENABLED       = booleanPreferencesKey("perm_enabled")
    val BLOCKCHAIN_ENABLED = booleanPreferencesKey("blockchain_enabled")
    val LANGUAGE           = stringPreferencesKey("language")
    val DNS_BLOCKED_COUNT  = intPreferencesKey("dns_blocked_count")
    val SMS_SCANNED_COUNT  = intPreferencesKey("sms_scanned_count")
}

@HiltViewModel
class HomeViewModel @Inject constructor(
    private val repository: ThreatRepository,
    private val honeyTokenManager: HoneyTokenManager,
    @ApplicationContext private val context: Context
) : ViewModel() {

    private val dataStore = context.aegisDataStore

    // ── Settings ──────────────────────────────────────────────────────────

    val settings: StateFlow<AegisSettings> = dataStore.data
        .map { prefs ->
            AegisSettings(
                vpnEnabled             = prefs[PrefKeys.VPN_ENABLED]        ?: false,
                honeyTokenEnabled      = prefs[PrefKeys.HONEY_ENABLED]      ?: true,
                smsFilterEnabled       = prefs[PrefKeys.SMS_ENABLED]        ?: true,
                permissionAuditEnabled = prefs[PrefKeys.PERM_ENABLED]       ?: true,
                blockchainReportingEnabled = prefs[PrefKeys.BLOCKCHAIN_ENABLED] ?: true,
                language               = prefs[PrefKeys.LANGUAGE]           ?: "en",
            )
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), AegisSettings())

    // ── Threats ───────────────────────────────────────────────────────────

    val recentThreats: StateFlow<List<ThreatEvent>> = repository.getAllThreats()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val threatCount: StateFlow<Int> = repository.getThreatCount()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0)

    // ── Aggregated dashboard stats ─────────────────────────────────────────

    val stats: StateFlow<DashboardStats> = combine(
        threatCount,
        settings,
        dataStore.data
    ) { count, cfg, prefs ->
        DashboardStats(
            threatsDetected      = count,
            threatsBlocked       = count,
            dnQueriesBlocked     = prefs[PrefKeys.DNS_BLOCKED_COUNT]  ?: 0,
            smsPhishingBlocked   = prefs[PrefKeys.SMS_SCANNED_COUNT]  ?: 0,
            isVpnActive          = cfg.vpnEnabled,
            isHoneyTokenActive   = cfg.honeyTokenEnabled,
            appsAudited          = 0,
            highRiskApps         = 0,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), DashboardStats())

    // ── Module toggles ────────────────────────────────────────────────────

    fun toggleVpn(enable: Boolean) = viewModelScope.launch {
        dataStore.edit { it[PrefKeys.VPN_ENABLED] = enable }
        val intent = Intent(context, AegisVpnService::class.java)
        if (enable) {
            intent.action = AegisVpnService.ACTION_START
            context.startService(intent)
        } else {
            intent.action = AegisVpnService.ACTION_STOP
            context.startService(intent)
        }
    }

    fun toggleHoneyToken(enable: Boolean) = viewModelScope.launch {
        dataStore.edit { it[PrefKeys.HONEY_ENABLED] = enable }
        if (enable) honeyTokenManager.initialize() else honeyTokenManager.shutdown()
    }

    fun toggleSmsFilter(enable: Boolean) = viewModelScope.launch {
        dataStore.edit { it[PrefKeys.SMS_ENABLED] = enable }
    }

    fun togglePermissionAudit(enable: Boolean) = viewModelScope.launch {
        dataStore.edit { it[PrefKeys.PERM_ENABLED] = enable }
    }

    fun toggleBlockchain(enable: Boolean) = viewModelScope.launch {
        dataStore.edit { it[PrefKeys.BLOCKCHAIN_ENABLED] = enable }
    }
}
