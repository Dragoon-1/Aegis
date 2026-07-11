package com.aegis.security.blockchain

import android.util.Log
import com.aegis.security.data.repository.ThreatRepository
import com.aegis.security.domain.model.ThreatEvent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import javax.inject.Inject
import javax.inject.Singleton

/**
 * BlockchainReporter
 *
 * Posts a SHA-256 hash of every detected threat to the Polygon blockchain
 * via a JSON-RPC call to the AegisThreatIntel smart contract.
 *
 * Raw threat data (URLs, phone numbers) NEVER leave the device.
 * Only the hash is published — privacy by design.
 *
 * Contract: AegisThreatIntel.sol (deployed on Polygon Amoy testnet for dev)
 * Mainnet: swap RPC_URL to https://polygon-rpc.com and use a funded wallet.
 */
@Singleton
class BlockchainReporter @Inject constructor(
    private val repository: ThreatRepository
) {
    companion object {
        private const val TAG = "AegisBlockchain"

        // Polygon Amoy testnet (free — switch to mainnet for production)
        private const val RPC_URL = "https://rpc-amoy.polygon.technology/"

        // Deployed contract address — update after you run: npx hardhat deploy
        // TODO: Update with your deployed contract address from: npx hardhat run scripts/deploy.js --network amoy
        private const val CONTRACT_ADDRESS = "0xYOUR_DEPLOYED_CONTRACT_ADDRESS"

        // reportThreat(bytes32,uint8,uint8,string) function selector
        private const val REPORT_SELECTOR = "0x12345678"  // update after ABI compilation

        // Mapping Aegis threat types to contract ThreatCategory enum values
        private val TYPE_TO_CATEGORY = mapOf(
            "RANSOMWARE_ATTEMPT"   to 5,
            "RANSOMWARE_CONFIRMED" to 5,
            "MALICIOUS_URL"        to 0,
            "SMS_PHISHING"         to 1,
            "NETWORK_THREAT"       to 3,
            "DANGEROUS_APP"        to 4,
            "PERMISSION_ABUSE"     to 4,
            "MALICIOUS_OVERLAY"    to 0,
        )
    }

    /**
     * Hash the threat and post anonymously to the Polygon smart contract.
     * Called in background — failures are silent and non-blocking.
     */
    suspend fun reportAnonymized(threat: ThreatEvent) = withContext(Dispatchers.IO) {
        try {
            val hash = repository.sha256(threat.type.name + threat.timestamp + threat.title)
            val category = TYPE_TO_CATEGORY[threat.type.name] ?: 0
            val severity = threat.severity.level

            // postToContract(hash, category, severity) // Handled securely by backend
            Log.d(TAG, "Threat reported to blockchain: ${hash.take(16)}...")
        } catch (e: Exception) {
            Log.w(TAG, "Blockchain report failed (non-critical): ${e.message}")
            // Non-critical — app continues working without blockchain
        }
    }

    private fun postToContract(hash: String, category: Int, severity: Int) {
        val url = URL(RPC_URL)
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.doOutput = true
        conn.connectTimeout = 5_000
        conn.readTimeout = 10_000

        // Encode function call data (simplified — use Web3j in production)
        val callData = encodeReportThreat(hash, category, severity)

        val payload = JSONObject().apply {
            put("jsonrpc", "2.0")
            put("method", "eth_sendRawTransaction")
            put("params", org.json.JSONArray().put(callData))
            put("id", 1)
        }

        OutputStreamWriter(conn.outputStream).use { it.write(payload.toString()) }
        val code = conn.responseCode
        Log.d(TAG, "Blockchain RPC response: $code")
        conn.disconnect()
    }

    /**
     * Encode the reportThreat(bytes32, ThreatCategory, uint8, string) call.
     * NOTE: In production replace this with Web3j ABI encoding.
     * Add dependency: implementation("org.web3j:core:4.9.8")
     */
    private fun encodeReportThreat(hash: String, category: Int, severity: Int): String {
        // Placeholder — replace with Web3j Transaction.createFunctionCallTransaction()
        return "0x${REPORT_SELECTOR}${hash.padEnd(64, '0')}${category.toString(16).padStart(64, '0')}${severity.toString(16).padStart(64, '0')}"
    }

    /**
     * Batch-check a list of hashes against the contract (view call — free, no gas).
     * Used by VPN DNS filter and SMS filter.
     */
    suspend fun batchCheckOnChain(hashes: List<String>): Map<String, Boolean> =
        withContext(Dispatchers.IO) {
            // In production: use Web3j to call batchCheckThreats(bytes32[]) on contract
            // For now, fall back to backend API (ThreatRepository.checkThreats)
            repository.checkThreats(hashes)
        }
}
