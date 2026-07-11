package com.aegis.security.domain.model

import androidx.room.Entity
import androidx.room.PrimaryKey

// ─────────────────────────────────────────────────────────────────────────────
// Threat models
// ─────────────────────────────────────────────────────────────────────────────

enum class ThreatType {
    RANSOMWARE_ATTEMPT,
    RANSOMWARE_CONFIRMED,
    MALICIOUS_URL,
    SMS_PHISHING,
    DANGEROUS_APP,
    MALICIOUS_OVERLAY,
    NETWORK_THREAT,
    PERMISSION_ABUSE
}

enum class Severity(val level: Int, val label: String, val color: Long) {
    LOW(1, "Low", 0xFF3B6D11),
    MEDIUM(2, "Medium", 0xFFBA7517),
    HIGH(3, "High", 0xFF993C1D),
    CRITICAL(4, "Critical", 0xFFCC0000),
    EMERGENCY(5, "Emergency", 0xFF8B0000)
}

@Entity(tableName = "threats")
data class ThreatEvent(
    @PrimaryKey val id: String,
    val type: ThreatType,
    val severity: Severity,
    val title: String,
    val description: String,
    val timestamp: Long,
    val actionTaken: String,
    val isResolved: Boolean = false,
    val reportedToBackend: Boolean = false,
    val reportedToBlockchain: Boolean = false,
    val extraData: String = ""            // JSON for additional info
)

// ─────────────────────────────────────────────────────────────────────────────
// Permission models
// ─────────────────────────────────────────────────────────────────────────────

data class AppPermissionInfo(
    val packageName: String,
    val appName: String,
    val riskScore: Int,                   // 0-100
    val riskLevel: Severity,
    val dangerousPermissions: List<String>,
    val riskReasons: List<String>
)

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard / Stats models
// ─────────────────────────────────────────────────────────────────────────────

data class DashboardStats(
    val threatsDetected: Int = 0,
    val threatsBlocked: Int = 0,
    val dnQueriesBlocked: Int = 0,
    val smsPhishingBlocked: Int = 0,
    val appsAudited: Int = 0,
    val highRiskApps: Int = 0,
    val isVpnActive: Boolean = false,
    val isHoneyTokenActive: Boolean = false,
    val lastScan: Long = System.currentTimeMillis(),
    val communityThreatsReported: Int = 0
)

// ─────────────────────────────────────────────────────────────────────────────
// AI Assistant models
// ─────────────────────────────────────────────────────────────────────────────

enum class MessageRole { USER, ASSISTANT }

data class ChatMessage(
    val id: String = java.util.UUID.randomUUID().toString(),
    val role: MessageRole,
    val content: String,
    val timestamp: Long = System.currentTimeMillis(),
    val isLoading: Boolean = false
)

// ─────────────────────────────────────────────────────────────────────────────
// Network / API models
// ─────────────────────────────────────────────────────────────────────────────

data class ThreatReportRequest(
    val threat_hash: String,
    val threat_type: String,
    val severity: Int,
    val device_id: String,
    val region: String = "IN",
    val metadata: Map<String, String> = emptyMap()
)

data class AssistantRequest(
    val question: String,
    val language: String = "en",
    val threat_context: Map<String, Any> = emptyMap()
)

data class AssistantResponse(
    val answer: String,
    val language: String
)

data class ThreatCheckResult(
    val is_threat: Boolean,
    val severity: Int = 0,
    val report_count: Int = 0,
    val type: String = ""
)

// ─────────────────────────────────────────────────────────────────────────────
// Settings / Preferences model
// ─────────────────────────────────────────────────────────────────────────────

data class AegisSettings(
    val vpnEnabled: Boolean = false,
    val honeyTokenEnabled: Boolean = true,
    val smsFilterEnabled: Boolean = true,
    val permissionAuditEnabled: Boolean = true,
    val antiClickjackEnabled: Boolean = true,
    val blockchainReportingEnabled: Boolean = true,
    val aiAssistantEnabled: Boolean = true,
    val language: String = "en",
    val deviceId: String = "",
    val autoPoliceReport: Boolean = true,
    val notificationsEnabled: Boolean = true
)
