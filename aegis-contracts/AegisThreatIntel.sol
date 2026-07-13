// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * AEGIS THREAT INTELLIGENCE NETWORK — Smart Contract
 *
 * Deployed on Polygon (MATIC) for low-cost, high-speed transactions.
 * Transactions cost ~$0.001 each vs ~$5+ on Ethereum mainnet.
 *
 * HOW THE SHARED THREAT NETWORK WORKS:
 *
 *   1. Device A detects a malicious URL / phone number / file hash
 *   2. Aegis hashes the indicator: SHA-256("https://phish.example.com") → 0xabc123...
 *   3. Device A calls reportThreat(hash, URL, severity=4)
 *   4. The hash is permanently recorded on Polygon blockchain
 *   5. All other Aegis devices query checkThreat(hash) before visiting any URL / opening SMS
 *   6. If the hash is found → WARN THE USER immediately
 *   7. When 100 devices report the same threat → ThreatEscalated event fires → backend
 *      generates PDF report for cyber police automatically
 *
 * PRIVACY: Raw URLs/phone numbers are NEVER stored on-chain.
 *          Only SHA-256 hashes. Original data stays on reporting device.
 *          Hash pre-image resistance ensures privacy.
 */
contract AegisThreatIntel {

    // ─────────────────────────────────────────────────────────────────────────
    // Data types
    // ─────────────────────────────────────────────────────────────────────────

    enum ThreatCategory {
        URL,            // 0 — Malicious or phishing URL
        PHONE_NUMBER,   // 1 — SMS phishing / smishing sender
        FILE_HASH,      // 2 — Hash of malware file
        IP_ADDRESS,     // 3 — Malicious server IP
        APP_PACKAGE,    // 4 — Malicious Android package name hash
        RANSOMWARE_PATH // 5 — File path pattern of known ransomware
    }

    struct ThreatEntry {
        bytes32   threatHash;       // SHA-256 of the raw threat indicator
        ThreatCategory category;
        uint32    reportCount;      // Total devices that reported this
        uint64    firstReported;    // Unix timestamp of first sighting
        uint64    lastReported;     // Unix timestamp of most recent report
        uint8     maxSeverity;      // 1=low, 2=medium, 3=high, 4=critical, 5=emergency
        bool      policeEscalated;  // Has this been escalated to authorities?
        string    region;           // ISO country/region code of first reporter (optional)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // State
    // ─────────────────────────────────────────────────────────────────────────

    mapping(bytes32 => ThreatEntry) public threats;
    bytes32[] private _threatIndex;   // Full ordered list for sync

    // Per-category indexes for efficient filtering
    mapping(uint8 => bytes32[]) private _categoryIndex;

    address public owner;
    bool public paused;

    // Thresholds
    uint32 public constant POLICE_THRESHOLD  = 100; // Reports before auto-escalation
    uint32 public constant MIN_REPORTS_PUBLIC = 3;   // Minimum before visible to network
    uint32 public constant EMERGENCY_THRESHOLD = 500; // Mass attack threshold

    // ─────────────────────────────────────────────────────────────────────────
    // Events — these are what other Aegis nodes listen to in real-time
    // ─────────────────────────────────────────────────────────────────────────

    event ThreatReported(
        bytes32 indexed threatHash,
        ThreatCategory indexed category,
        uint32  reportCount,
        uint8   severity
    );

    event NewThreatDiscovered(
        bytes32 indexed threatHash,
        ThreatCategory  category,
        string          region
    );

    event ThreatEscalated(
        bytes32 indexed threatHash,
        uint32          reportCount,
        uint8           maxSeverity
    );

    event MassAttackDetected(
        ThreatCategory indexed category,
        uint32          affectedDevices
    );

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Core: Report a threat
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Report a threat observed on your device.
     *         Any Aegis user can call this. Gas: ~50,000 (new) / ~30,000 (update).
     *
     * @param threatHash  SHA-256 of the raw threat indicator (URL, phone, file hash, etc.)
     * @param category    What kind of threat this is
     * @param severity    Severity 1 (low) to 5 (emergency)
     * @param region      ISO 3166-1 alpha-2 country code, empty string for anonymous
     */
    function reportThreat(
        bytes32        threatHash,
        ThreatCategory category,
        uint8          severity,
        string calldata region
    ) external {
        require(!paused, "Contract paused");
        require(threatHash != bytes32(0), "Empty hash");
        require(severity >= 1 && severity <= 5, "Invalid severity");

        ThreatEntry storage entry = threats[threatHash];

        if (entry.firstReported == 0) {
            // ── First time this threat is reported ──────────────────────────
            entry.threatHash    = threatHash;
            entry.category      = category;
            entry.reportCount   = 1;
            entry.firstReported = uint64(block.timestamp);
            entry.lastReported  = uint64(block.timestamp);
            entry.maxSeverity   = severity;
            entry.region        = region;

            _threatIndex.push(threatHash);
            _categoryIndex[uint8(category)].push(threatHash);

            emit NewThreatDiscovered(threatHash, category, region);
        } else {
            // ── Subsequent reports — increment counter ──────────────────────
            entry.reportCount++;
            entry.lastReported = uint64(block.timestamp);
            if (severity > entry.maxSeverity) {
                entry.maxSeverity = severity;
            }
        }

        emit ThreatReported(threatHash, category, entry.reportCount, severity);

        // ── Escalation checks ──────────────────────────────────────────────

        if (entry.reportCount >= POLICE_THRESHOLD && !entry.policeEscalated) {
            entry.policeEscalated = true;
            emit ThreatEscalated(threatHash, entry.reportCount, entry.maxSeverity);
        }

        if (entry.reportCount == EMERGENCY_THRESHOLD) {
            emit MassAttackDetected(category, entry.reportCount);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Core: Check a single threat
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Check if a hash is a community-confirmed threat.
     *         Requires MIN_REPORTS_PUBLIC to filter out false positives.
     *
     * @param  hash         SHA-256 to check
     * @return isThreat     True if confirmed threat
     * @return reportCount  How many devices reported it
     * @return severity     Maximum severity across all reports
     * @return category     Type of threat (URL, phone, etc.)
     */
    function checkThreat(bytes32 hash)
        external view
        returns (
            bool isThreat,
            uint32 reportCount,
            uint8  severity,
            uint8  category
        )
    {
        ThreatEntry memory e = threats[hash];
        if (e.firstReported == 0 || e.reportCount < MIN_REPORTS_PUBLIC) {
            return (false, 0, 0, 0);
        }
        return (true, e.reportCount, e.maxSeverity, uint8(e.category));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Core: Batch check (for SMS/URL scanning efficiency)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Check multiple hashes in a single call.
     *         Used by VPN service to batch-verify DNS queries.
     *         Gas-efficient: single STATICCALL instead of N calls.
     *
     * @param  hashes    Array of SHA-256 hashes to check
     * @return flags     True/false for each hash
     * @return severities Severity level for each (0 if not a threat)
     */
    function batchCheckThreats(bytes32[] calldata hashes)
        external view
        returns (bool[] memory flags, uint8[] memory severities)
    {
        flags      = new bool[](hashes.length);
        severities = new uint8[](hashes.length);

        for (uint256 i = 0; i < hashes.length; i++) {
            ThreatEntry memory e = threats[hashes[i]];
            if (e.firstReported > 0 && e.reportCount >= MIN_REPORTS_PUBLIC) {
                flags[i]      = true;
                severities[i] = e.maxSeverity;
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sync: Get recent threats for device update
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * @notice Paginated list of threats for device sync on startup.
     *         Devices call this to download the latest threat list.
     *
     * @param  offset  Start from the end minus offset
     * @param  limit   Maximum entries to return
     */
    function getRecentThreats(uint256 offset, uint256 limit)
        external view
        returns (
            bytes32[] memory hashes,
            uint8[]   memory categories,
            uint8[]   memory severities,
            uint32[]  memory counts
        )
    {
        uint256 total = _threatIndex.length;
        uint256 end   = total > offset ? total - offset : 0;
        uint256 start = end > limit    ? end - limit    : 0;
        uint256 n     = end - start;

        hashes     = new bytes32[](n);
        categories = new uint8[](n);
        severities = new uint8[](n);
        counts     = new uint32[](n);

        for (uint256 i = 0; i < n; i++) {
            bytes32 h           = _threatIndex[start + i];
            ThreatEntry memory e = threats[h];
            hashes[i]            = h;
            categories[i]        = uint8(e.category);
            severities[i]        = e.maxSeverity;
            counts[i]            = e.reportCount;
        }
    }

    /**
     * @notice Get threats filtered by category (e.g. only phone numbers for SMS filter).
     */
    function getThreatsByCategory(ThreatCategory category, uint256 limit)
        external view
        returns (bytes32[] memory hashes, uint8[] memory severities)
    {
        bytes32[] storage idx = _categoryIndex[uint8(category)];
        uint256 len = idx.length;
        uint256 n   = len < limit ? len : limit;

        hashes     = new bytes32[](n);
        severities = new uint8[](n);

        uint256 j = 0;
        for (uint256 i = len; i > 0 && j < n; i--) {
            bytes32 h = idx[i - 1];
            if (threats[h].reportCount >= MIN_REPORTS_PUBLIC) {
                hashes[j]     = h;
                severities[j] = threats[h].maxSeverity;
                j++;
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Stats
    // ─────────────────────────────────────────────────────────────────────────

    function totalThreats() external view returns (uint256) {
        return _threatIndex.length;
    }

    function categoryCount(ThreatCategory cat) external view returns (uint256) {
        return _categoryIndex[uint8(cat)].length;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Admin
    // ─────────────────────────────────────────────────────────────────────────

    function setPaused(bool _paused) external {
        require(msg.sender == owner, "Not owner");
        paused = _paused;
    }

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
