package com.aegis.security

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for SMS phishing scoring logic.
 * Tests the keyword + URL scoring without needing Android context.
 * Run with: ./gradlew test
 */
class SmsPhishingDetectorTest {

    // Mirror of the scoring logic from SmsPhishingDetector
    private val URGENCY_KEYWORDS = listOf(
        "urgent", "click here", "verify now", "account suspended",
        "blocked", "winner", "prize", "claim", "otp", "kyc update",
        "bank account", "act now", "immediately", "expire", "reward",
        "free gift", "congratulations", "selected", "lucky draw"
    )
    private val URL_REGEX = Regex("""https?://[^\s]+|www\.[^\s]+""")

    private fun scoreMessage(body: String): Int {
        val lower = body.lowercase()
        val urls  = URL_REGEX.findAll(body).toList()
        val hits  = URGENCY_KEYWORDS.filter { lower.contains(it) }
        return (urls.size * 20 + hits.size * 10).coerceAtMost(100)
    }

    // ── Legitimate messages ────────────────────────────────────────────────────

    @Test
    fun `normal OTP message scores below threshold`() {
        val msg = "Your OTP for login is 482910. Valid for 10 minutes. Do not share."
        // "otp" is a keyword but no URLs — score = 10, below 40 threshold
        val score = scoreMessage(msg)
        assertTrue("Legit OTP should score below 40, got $score", score < 40)
    }

    @Test
    fun `delivery notification scores zero`() {
        val score = scoreMessage("Your Zomato order #Z12345 has been delivered. Rate your experience!")
        assertEquals("Delivery notification should score 0", 0, score)
    }

    @Test
    fun `family message scores zero`() {
        val score = scoreMessage("Hey, are you coming home for dinner tonight?")
        assertEquals("Personal message should score 0", 0, score)
    }

    // ── Phishing messages ──────────────────────────────────────────────────────

    @Test
    fun `classic banking phish scores above threshold`() {
        val msg = "URGENT: Your bank account has been blocked. Verify now at http://fake-bank.ru/login"
        val score = scoreMessage(msg)
        assertTrue("Banking phish should score >= 40, got $score", score >= 40)
    }

    @Test
    fun `prize scam scores above threshold`() {
        val msg = "Congratulations! You have been selected as a lucky draw winner. Claim your prize: https://win.scam.tk/prize"
        val score = scoreMessage(msg)
        assertTrue("Prize scam should score >= 40, got $score", score >= 40)
    }

    @Test
    fun `KYC update scam scores above threshold`() {
        val msg = "Your account will expire immediately. Complete KYC update: http://kyc-update.phish.com Act now!"
        val score = scoreMessage(msg)
        assertTrue("KYC scam should score >= 40, got $score", score >= 40)
    }

    @Test
    fun `multiple urgency keywords amplify score`() {
        val lowScore  = scoreMessage("urgent click here")
        val highScore = scoreMessage("urgent click here verify now act now immediately account suspended blocked")
        assertTrue("More keywords should produce higher score", highScore > lowScore)
    }

    @Test
    fun `URL alone does not cross threshold`() {
        val score = scoreMessage("Visit https://legitwebsite.com for more info")
        assertTrue("Single URL with no urgency keywords should be < 40, got $score", score < 40)
    }

    @Test
    fun `URL plus urgency keywords crosses threshold`() {
        val score = scoreMessage("Click here now: http://phish.com")
        assertTrue("URL + urgency keyword should be >= 40, got $score", score >= 40)
    }

    @Test
    fun `score is capped at 100`() {
        val msg = buildString {
            repeat(5) { append("https://evil$it.com ") }
            URGENCY_KEYWORDS.forEach { append("$it ") }
        }
        val score = scoreMessage(msg)
        assertEquals("Score must be capped at 100", 100, score)
    }

    // ── Edge cases ─────────────────────────────────────────────────────────────

    @Test
    fun `empty message scores zero`() {
        assertEquals(0, scoreMessage(""))
    }

    @Test
    fun `blank message scores zero`() {
        assertEquals(0, scoreMessage("   "))
    }

    @Test
    fun `case insensitive keyword matching`() {
        val lower = scoreMessage("urgent click here")
        val upper = scoreMessage("URGENT CLICK HERE")
        val mixed = scoreMessage("Urgent Click Here")
        assertEquals("Keyword matching must be case-insensitive", lower, upper)
        assertEquals("Keyword matching must be case-insensitive", lower, mixed)
    }
}
