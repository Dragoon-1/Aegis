package com.aegis.security

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import androidx.work.Configuration
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import dagger.hilt.android.HiltAndroidApp
import java.util.concurrent.TimeUnit
import javax.inject.Inject

@HiltAndroidApp
class AegisApplication : Application(), Configuration.Provider {

    @Inject lateinit var workerFactory: androidx.hilt.work.HiltWorkerFactory

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        scheduleBlocklistSync()
    }

    // ── WorkManager with Hilt ─────────────────────────────────────────────
    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(workerFactory)
            .build()

    // ── Notification channels ─────────────────────────────────────────────
    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(NotificationManager::class.java)

        val channels = listOf(
            NotificationChannel(
                CHANNEL_THREATS,
                "Security Threats",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Immediate alerts when Aegis detects an active threat"
                enableVibration(true)
                setShowBadge(true)
            },
            NotificationChannel(
                CHANNEL_VPN,
                "VPN Shield",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Persistent notification showing VPN shield status"
                setShowBadge(false)
            },
            NotificationChannel(
                CHANNEL_GENERAL,
                "General",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Updates, blocklist syncs, and weekly reports"
            }
        )
        nm.createNotificationChannels(channels)
    }

    // ── Background blocklist sync every 6 hours ───────────────────────────
    private fun scheduleBlocklistSync() {
        val syncRequest = PeriodicWorkRequestBuilder<BlocklistSyncWorker>(
            6, TimeUnit.HOURS
        ).build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "aegis_blocklist_sync",
            ExistingPeriodicWorkPolicy.KEEP,
            syncRequest
        )
    }

    companion object {
        const val CHANNEL_THREATS = "aegis_threats"
        const val CHANNEL_VPN     = "aegis_vpn"
        const val CHANNEL_GENERAL = "aegis_general"
    }
}
