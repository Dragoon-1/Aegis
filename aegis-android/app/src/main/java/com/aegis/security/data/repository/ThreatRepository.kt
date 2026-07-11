package com.aegis.security.data.repository

import android.content.Context
import android.content.SharedPreferences
import com.aegis.security.data.local.ThreatDao
import com.aegis.security.data.remote.AegisApiService
import com.aegis.security.domain.model.ThreatEvent
import com.aegis.security.domain.model.ThreatReportRequest
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ThreatRepository @Inject constructor(
    private val dao: ThreatDao,
    private val api: AegisApiService,
    @ApplicationContext private val context: Context
) {
    // ── Local DB operations ───────────────────────────────────────────────

    suspend fun save(threat: ThreatEvent) = dao.insert(threat)

    fun getAllThreats(): Flow<List<ThreatEvent>> = dao.getAllThreats()

    fun getActiveThreats(): Flow<List<ThreatEvent>> = dao.getActiveThreats()

    fun getThreatCount(): Flow<Int> = dao.getThreatCount()

    suspend fun resolve(id: String) = dao.resolve(id)

    // ── Report threat to backend (anonymised) ─────────────────────────────

    suspend fun reportToBackend(threat: ThreatEvent) = withContext(Dispatchers.IO) {
        try {
            val hash = sha256(threat.id + threat.type.name + threat.timestamp)
            api.reportThreat(
                ThreatReportRequest(
                    threat_hash  = hash,
                    threat_type  = threat.type.name,
                    severity     = threat.severity.level,
                    device_id    = getAnonymousDeviceId(),
                    metadata     = mapOf("title" to threat.title)
                )
            )
            dao.markReportedToBackend(threat.id)
        } catch (e: Exception) {
            // Silently fail — will retry on next launch
        }
    }

    // ── Check a URL or phone against backend ──────────────────────────────

    suspend fun checkThreats(indicators: List<String>): Map<String, Boolean> {
        return try {
            val hashes = indicators.map { sha256(it) }
            val results = api.batchCheckThreats(mapOf("hashes" to hashes))
            indicators.zip(hashes).associate { (raw, hash) ->
                raw to (results[hash]?.is_threat ?: false)
            }
        } catch (e: Exception) {
            indicators.associateWith { false }
        }
    }

    // ── Sync latest blocklist from backend ────────────────────────────────

    suspend fun syncBlocklist(): List<String> = withContext(Dispatchers.IO) {
        try {
            val threats = api.getRecentThreats(limit = 1000, type = "URL")
            threats.mapNotNull { it["hash"] as? String }
        } catch (e: Exception) {
            emptyList()
        }
    }

    // ── Dashboard stats from backend ──────────────────────────────────────

    suspend fun getBackendStats(): Map<String, Any> {
        return try {
            api.getDashboardStats()
        } catch (e: Exception) {
            emptyMap()
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    fun sha256(input: String): String {
        val bytes = MessageDigest.getInstance("SHA-256")
            .digest(input.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun getAnonymousDeviceId(): String {
        val prefs: SharedPreferences =
            context.getSharedPreferences("aegis_prefs", Context.MODE_PRIVATE)
        return prefs.getString("device_id", null) ?: run {
            val id = sha256(android.provider.Settings.Secure.getString(
                context.contentResolver,
                android.provider.Settings.Secure.ANDROID_ID
            ) + "aegis_salt_v1")
            prefs.edit().putString("device_id", id).apply()
            id
        }
    }
}
