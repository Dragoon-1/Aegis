package com.aegis.security

import android.content.Context
import android.content.Intent
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.aegis.security.data.repository.ThreatRepository
import com.aegis.security.vpn.AegisVpnService
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject

@HiltWorker
class BlocklistSyncWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val repository: ThreatRepository
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        return try {
            val domains = repository.syncBlocklist()
            if (domains.isNotEmpty()) {
                // Send to running VPN service
                val intent = Intent(applicationContext, AegisVpnService::class.java)
                    .putStringArrayListExtra("new_domains", ArrayList(domains))
                applicationContext.startService(intent)
            }
            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }
}

// ── Boot Receiver — restart services after phone reboot ──────────────────────

class BootReceiver : android.content.BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED ||
            intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            // Restart honey-token monitoring (handled by MainActivity on next open)
            // VPN requires user interaction to re-enable — cannot auto-start
            android.util.Log.i("AegisBoot", "Device rebooted — Aegis ready")
        }
    }
}
