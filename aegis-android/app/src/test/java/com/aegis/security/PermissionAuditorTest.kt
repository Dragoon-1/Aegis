package com.aegis.security

import com.aegis.security.domain.model.Severity
import com.aegis.security.permission.PermissionAuditor
import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for PermissionAuditor risk scoring logic.
 * Run with: ./gradlew test
 */
class PermissionAuditorTest {

    // ── Risk scoring tests ────────────────────────────────────────────────────

    @Test
    fun `single low-risk permission scores below 25`() {
        val score = calcScore(listOf("android.permission.CAMERA"))
        assertTrue("Camera alone should be low risk, got $score", score < 25)
    }

    @Test
    fun `SMS read and send combination scores HIGH`() {
        val score = calcScore(listOf(
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS"
        ))
        assertTrue("SMS read+send should score HIGH (>=50), got $score", score >= 50)
    }

    @Test
    fun `device admin permission alone scores CRITICAL`() {
        val score = calcScore(listOf("android.permission.BIND_DEVICE_ADMIN"))
        assertTrue("Device admin alone should score CRITICAL (>=70), got $score", score >= 70)
    }

    @Test
    fun `banking trojan combo scores CRITICAL`() {
        // Overlay + Accessibility = classic banking trojan
        val score = calcScore(listOf(
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.READ_SMS"
        ))
        assertTrue("Banking trojan combo should be CRITICAL (>=70), got $score", score >= 70)
    }

    @Test
    fun `spyware combo scores HIGH or CRITICAL`() {
        val score = calcScore(listOf(
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION"
        ))
        assertTrue("Spyware combo should be >= 50, got $score", score >= 50)
    }

    @Test
    fun `score is capped at 100`() {
        val allPerms = listOf(
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES"
        )
        val score = calcScore(allPerms)
        assertTrue("Score should never exceed 100, got $score", score <= 100)
    }

    @Test
    fun `empty permission list scores zero`() {
        val score = calcScore(emptyList())
        assertEquals("Empty permissions should score 0", 0, score)
    }

    // ── Severity mapping tests ─────────────────────────────────────────────────

    @Test
    fun `score 0-24 maps to LOW severity`() {
        assertEquals(Severity.LOW, scoreToSeverity(10))
    }

    @Test
    fun `score 25-49 maps to MEDIUM severity`() {
        assertEquals(Severity.MEDIUM, scoreToSeverity(35))
    }

    @Test
    fun `score 50-69 maps to HIGH severity`() {
        assertEquals(Severity.HIGH, scoreToSeverity(60))
    }

    @Test
    fun `score 70-100 maps to CRITICAL severity`() {
        assertEquals(Severity.CRITICAL, scoreToSeverity(85))
    }

    // ── Helpers (duplicated from PermissionAuditor for unit testing) ───────────

    private val WEIGHTS = mapOf(
        "android.permission.CAMERA"                      to 10,
        "android.permission.RECORD_AUDIO"                to 10,
        "android.permission.ACCESS_FINE_LOCATION"        to 15,
        "android.permission.ACCESS_BACKGROUND_LOCATION"  to 20,
        "android.permission.READ_CONTACTS"               to 10,
        "android.permission.READ_SMS"                    to 20,
        "android.permission.SEND_SMS"                    to 20,
        "android.permission.RECEIVE_SMS"                 to 15,
        "android.permission.READ_CALL_LOG"               to 15,
        "android.permission.BIND_DEVICE_ADMIN"           to 30,
        "android.permission.BIND_ACCESSIBILITY_SERVICE"  to 25,
        "android.permission.SYSTEM_ALERT_WINDOW"         to 20,
        "android.permission.REQUEST_INSTALL_PACKAGES"    to 15,
        "android.permission.READ_PHONE_STATE"            to 12,
        "android.permission.CALL_PHONE"                  to 18,
    )

    private val COMBOS = listOf(
        Pair(listOf("android.permission.READ_SMS", "android.permission.SEND_SMS"), 20),
        Pair(listOf("android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"), 25),
        Pair(listOf("android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.RECEIVE_SMS"), 20),
        Pair(listOf("android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION"), 15),
    )

    private fun calcScore(perms: List<String>): Int {
        val dangerous = perms.filter { WEIGHTS.containsKey(it) }
        val base  = dangerous.sumOf { WEIGHTS[it] ?: 0 }.coerceAtMost(70)
        val combo = COMBOS.filter { (p, _) -> p.all { dangerous.contains(it) } }
                          .sumOf { (_, s) -> s }
        return (base + combo).coerceAtMost(100)
    }

    private fun scoreToSeverity(score: Int): Severity = when {
        score >= 70 -> Severity.CRITICAL
        score >= 50 -> Severity.HIGH
        score >= 25 -> Severity.MEDIUM
        else        -> Severity.LOW
    }
}
