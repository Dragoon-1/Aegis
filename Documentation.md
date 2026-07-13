# AEGIS — Complete Project Documentation

**Version:** 1.0.0 (MVP)
**Last Updated:** June 2025
**Type:** Android Security Application + Backend + Blockchain

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Problem Statement](#2-problem-statement)
3. [Solution Architecture](#3-solution-architecture)
4. [Security Modules (Detailed)](#4-security-modules-detailed)
5. [Blockchain Threat Network](#5-blockchain-threat-network)
6. [Backend API Reference](#6-backend-api-reference)
7. [Database Schema](#7-database-schema)
8. [Smart Contract Reference](#8-smart-contract-reference)
9. [Installation & Setup](#9-installation--setup)
10. [Configuration Guide](#10-configuration-guide)
11. [User Guide](#11-user-guide)
12. [Developer Guide](#12-developer-guide)
13. [Testing Guide](#13-testing-guide)
14. [Glossary](#14-glossary)

---

## 1. Project Overview

Aegis is a next-generation, 100% root-free Android security application that redefines mobile defense through proactive deception, collective blockchain intelligence, and local-first execution.

### Core Philosophy

Traditional mobile antivirus is **reactive** — it can only detect threats it has already seen. Aegis is **proactive** — it lays traps for attackers, catches them in the act, and instantly shares threat intelligence with every other Aegis user on the planet, without compromising anyone's privacy.

### Key Facts

| Property | Value |
|---|---|
| Platform | Android 8.0+ (API 26+) |
| Root required | No |
| Cloud scanning | No — 100% on-device |
| Languages | 15 in UI, 40+ via AI assistant |
| Backend | Python FastAPI + PostgreSQL |
| Blockchain | Polygon PoS (Solidity 0.8.19) |
| AI Engine | Claude claude-sonnet-4-6 (Anthropic) |
| Min Android SDK | 26 (Android 8.0 Oreo) |
| Target SDK | 34 (Android 14) |

### What Makes Aegis Different

| Feature | Aegis | Bitdefender | Norton | Malwarebytes | RethinkDNS |
|---|:---:|:---:|:---:|:---:|:---:|
| Honey-Token Canary | ✓ | ✗ | ✗ | ✗ | ✗ |
| VPN + DNS Sinkhole | ✓ | ✓ | ✓ | ✗ | ✓ |
| SMS Phishing Filter | ✓ | ✓ | ✓ | ✓ | ✗ |
| Anti-Clickjack Shield | ✓ | ✗ | ✗ | ✗ | ✗ |
| Permission Auditor | ✓ | ✓ | ✓ | ✓ | ✓ |
| Blockchain CTI | ✓ | ✗ | ✗ | ✗ | ✗ |
| Police Auto-Report | ✓ | ✗ | ✗ | ✗ | ✗ |
| AI Security Assistant | ✓ | ✗ | ✗ | ✗ | ✗ |
| Root-Free | ✓ | ✓ | ✓ | ✓ | ✓ |
| 100% Local Processing | ✓ | ✗ | ✗ | ✗ | ✓ |

---

## 2. Problem Statement

### 2.1 The Reactive Defense Problem

Every major Android security application relies on signature-based scanning — maintaining a database of known malware hashes and comparing files against it. This approach has a fundamental flaw: **it cannot detect any threat it has not already seen.**

Zero-day ransomware — malware that has never been encountered before — passes through signature scanners completely undetected. The attacker wins on first strike.

### 2.2 The Cloud Dependency Problem

Cloud-based scanning sends files and metadata to remote servers for analysis. This creates three problems:
- **Privacy:** User files leave the device
- **Battery:** Continuous background radio usage
- **Reliability:** Fails in low-connectivity areas

### 2.3 The Isolation Problem
r
When a user in Mumbai is attacked by a new smishing campaign, users in Delhi, Chennai, and Hyderabad remain completely unaware. There is no mechanism for mobile users to share threat intelligence privately and in real time.

### 2.4 The Reporting Gap

The vast majority of mobile cybercrime victims never file reports. Cyber police and CERT-In have little real-time visibility into active attack campaigns. Reports arrive days or weeks after attacks, when intervention is no longer possible.

### 2.5 Market Statistics

- Kaspersky reported 14 million Android attacks in 2025
- Banking Trojans rose 56% year-over-year (Kaspersky Mobile Report 2025)
- India reported ₹1,750 crore in cyber fraud losses in 2024
- 900 million+ Android users in India alone
- Less than 12% of cybercrime victims formally report incidents

---

## 3. Solution Architecture

### 3.1 Three-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    ANDROID APPLICATION                           │
│                                                                  │
│  ┌──────────────┐  ┌───────────┐  ┌───────────┐  ┌──────────┐  │
│  │ HoneyToken   │  │ MicroVPN  │  │SMS Filter │  │Permission│  │
│  │ Engine       │  │ DNS Sink  │  │           │  │ Auditor  │  │
│  └──────┬───────┘  └─────┬─────┘  └─────┬─────┘  └─────┬────┘  │
│         │                │               │               │       │
│  ┌──────┴────────────────┴───────────────┴───────────────┴────┐  │
│  │              Anti-Clickjack Overlay Shield                  │  │
│  └──────────────────────────┬──────────────────────────────────┘  │
│                             │                                    │
│  ┌──────────────────────────┴──────────────────────────────────┐  │
│  │           Local Room DB + ThreatRepository                  │  │
│  └──────────────────────────┬──────────────────────────────────┘  │
└───────────────────────────  │  ───────────────────────────────────┘
                              │ (anonymised threat hashes only)
              ┌───────────────┴───────────────────┐
              │                                   │
     ┌────────▼────────┐               ┌──────────▼──────────┐
     │  AEGIS BACKEND  │               │  POLYGON BLOCKCHAIN  │
     │  FastAPI + PG   │◄─────────────►│  AegisThreatIntel   │
     │                 │  event sync   │  .sol               │
     └────────┬────────┘               └──────────┬──────────┘
              │                                   │
     ┌────────▼────────┐               ┌──────────▼──────────┐
     │  PDF Generator  │               │  Global Threat DB   │
     │  ReportLab      │               │  (hashes only)      │
     └────────┬────────┘               └─────────────────────┘
              │
     ┌────────▼────────┐
     │  CERT-In /      │
     │  Cyber Police   │
     └─────────────────┘
```

### 3.2 Data Flow

1. **Detection:** A security module on the Android device detects a threat
2. **Local storage:** Threat event saved to Room database (never leaves device in raw form)
3. **Hashing:** SHA-256 hash of the threat indicator computed on-device
4. **Backend report:** Hash + metadata sent to FastAPI backend (no raw data)
5. **Blockchain:** Same hash posted to Polygon smart contract (~$0.001 gas)
6. **Community warning:** All other Aegis devices check the hash before interacting with any URL/SMS
7. **Escalation:** At 100 reports → automatic PDF police report generated and submitted

### 3.3 Privacy Architecture

| Data | Stays on device | Backend receives | Blockchain receives |
|---|:---:|:---:|:---:|
| Raw URL / phone number | ✓ Yes | ✗ Never | ✗ Never |
| SHA-256 hash of indicator | — | ✓ Hash only | ✓ Hash only |
| Threat type + severity | — | ✓ Yes | ✓ Yes |
| Anonymous device ID (hashed) | — | ✓ Hash only | ✗ Never |
| User identity / name | ✓ Yes | ✗ Never | ✗ Never |
| Location | ✓ Yes | ✗ Never | ✗ Never |

SHA-256 is computationally infeasible to reverse. Raw threat indicators can never be recovered from published hashes.

---

## 4. Security Modules (Detailed)

### 4.1 Honey-Token Canary System

**File:** `honeytoken/HoneyTokenManager.kt`


#### How It Works

The honey-token system deploys decoy files designed to attract malicious processes. Ransomware, when it begins scanning a device, typically reads directories alphabetically before starting encryption. Aegis exploits this by naming trap files with characters that sort first alphabetically:

```
!AEGIS_CANARY_PRIVATE.txt      ← starts with "!" — sorts first
!IMPORTANT_DOCUMENTS.txt
000_account_passwords.csv      ← starts with "0" — sorts before letters
000_backup_keys.json
aaa_confidential_2024.txt
.aegis_hidden_canary           ← hidden file
```

Each file contains realistic-looking fake content — financial records, credentials, API keys — to make them attractive targets.

#### Detection Mechanism

```kotlin
// Watches for any file system event on trap files
val mask = FileObserver.OPEN or FileObserver.ACCESS or
           FileObserver.MODIFY or FileObserver.DELETE

object : FileObserver(trapFile, mask) {
    override fun onEvent(event: Int, path: String?) {
        onTrapTriggered(trapFile.name, eventType)
    }
}
```

#### Rapid-Scan Detection

If 3 or more trap files are accessed within a 5-second window, Aegis escalates from `RANSOMWARE_ATTEMPT` to `RANSOMWARE_CONFIRMED`. This matches the bulk directory scan behavior of ransomware.

A secondary `ContentObserver` on `MediaStore` catches ransomware that modifies files faster than individual file traps can respond — if 25+ file modifications occur within 10 seconds, a bulk encryption alert fires.

#### Detection Speed
- Single trap access → alert in < 100ms
- Bulk scan detection → alert after 25th file change
- No false positives from legitimate apps (legitimate apps rarely open files named `!IMPORTANT_DOCUMENTS.txt`)

---

### 4.2 Micro-VPN + DNS Sinkholing

**File:** `vpn/AegisVpnService.kt`
**Android API:** `android.net.VpnService`

#### How It Works

Aegis creates a local VPN tunnel using Android's built-in `VpnService` API. This requires only user consent — no root access. All network traffic from every app on the device is routed through this tunnel.

The tunnel intercepts DNS queries (UDP port 53) before they leave the device. Each queried domain is checked against an in-memory `HashSet` of blocked domains. If the domain is blocked, a NXDOMAIN response is returned immediately — the connection never reaches the network.

```
[App requests example.com] → [Aegis VPN] → [Check HashSet]
                                                     ↓
                                         domain in blocklist?
                                         YES → return 0.0.0.0 (NXDOMAIN)
                                         NO  → forward to Quad9 (9.9.9.9)
```

#### Blocklist Sources

| Source | Content | Update Frequency |
|---|---|---|
| abuse.ch URLhaus | Malware distribution URLs | Multiple times daily |
| PhishTank | Verified phishing sites | Multiple times daily |
| OISD Basic | Ads, trackers, malware | Weekly |
| Aegis Blockchain CTI | Community-reported threats | Every 6 hours |

#### Performance

- Lookup time: O(1) via `HashSet` — typically < 1ms per query
- Memory: ~15MB for 50,000 domain HashSet
- Battery impact: Minimal — local tunnel adds negligible overhead vs cloud VPN

#### Subdomain Inheritance

If `evil.com` is in the blocklist, `cdn.evil.com`, `login.evil.com`, and all other subdomains are also blocked automatically via parent-domain traversal.

---

### 4.3 SMS Phishing Filter

**File:** `sms/SmsPhishingDetector.kt`
**Android API:** `android.provider.Telephony.Sms.Intents`

#### Detection Pipeline

1. **Intercept:** `SmsReceiver` catches incoming SMS via broadcast
2. **Extract URLs:** Regex extracts all HTTP/HTTPS URLs from message body
3. **Hash check:** URLs hashed and checked against backend community database
4. **Keyword scoring:** Body text scored for urgency patterns
5. **Sender check:** Sender number hashed and checked against known smishing numbers
6. **Alert:** If score ≥ 40, user is warned with explanation before tapping

#### Scoring Matrix

| Signal | Score added |
|---|---|
| URL present | +20 per URL |
| Urgency keyword match | +10 per keyword |
| URL confirmed in blockchain | Score → HIGH immediately |

#### Urgency Keywords Detected

`urgent`, `click here`, `verify now`, `account suspended`, `blocked`, `winner`, `prize`, `claim`, `otp`, `kyc update`, `bank account`, `act now`, `immediately`, `expire`, `reward`, `free gift`, `congratulations`, `selected`, `lucky draw`

#### Why No READ_SMS Permission?

Aegis uses the `RECEIVE_SMS` broadcast permission instead of `READ_SMS`. This means:
- SMS content is analysed in real time as it arrives
- No access to the SMS inbox or message history
- Significantly less dangerous permission from user's perspective

---

### 4.4 Anti-Clickjacking Overlay Shield

**File:** `ui/overlay/AegisOverlayService.kt`
**Android API:** `android.accessibilityservice.AccessibilityService`

#### The Clickjacking Attack

Clickjacking (also called UI redressing) places a transparent malicious window over legitimate UI. When a user thinks they are tapping a legitimate button, they are actually interacting with a hidden malicious layer underneath — unknowingly granting permissions to a different app.

#### Detection

The `AccessibilityService` listens for `TYPE_WINDOW_STATE_CHANGED` and `TYPE_WINDOWS_CHANGED` events. On each change, it:

1. Identifies the currently active application window
2. Scans for `TYPE_APPLICATION_OVERLAY` or `TYPE_ACCESSIBILITY_OVERLAY` windows
3. Calculates the percentage of the active window covered by each overlay
4. If coverage > 30% from a suspicious source → fires alert with app name

#### Limitations

The `AccessibilityService` must be manually enabled by the user in Settings → Accessibility. This is an Android platform requirement for all accessibility services.

---

### 4.5 Permission Auditor

**File:** `permission/PermissionAuditor.kt`
**Android API:** `android.content.pm.PackageManager`

#### Risk Scoring

Each dangerous permission has an individual weight (1–30). The total score (capped at 100) is computed from:

```
score = min(sum(individual_weights), 70) + sum(combination_bonuses)
```

#### High-Risk Combinations

| Combination | Extra Score | Meaning |
|---|---|---|
| READ_SMS + SEND_SMS | +20 | Can intercept and forward OTPs |
| ACCESSIBILITY + SYSTEM_ALERT_WINDOW | +25 | Classic banking Trojan setup |
| REQUEST_INSTALL_PACKAGES + RECEIVE_SMS | +20 | Dropper malware pattern |
| ACCESS_FINE_LOCATION + ACCESS_BACKGROUND_LOCATION | +15 | Continuous location tracking |

#### Risk Levels

| Score | Level | Action |
|---|---|---|
| 0–24 | LOW | Informational |
| 25–49 | MEDIUM | Review recommended |
| 50–69 | HIGH | Investigation recommended |
| 70–100 | CRITICAL | Uninstall recommended |

---

## 5. Blockchain Threat Network

### 5.1 Smart Contract: AegisThreatIntel.sol

Deployed on Polygon PoS (Amoy testnet for development, mainnet for production).

**Address:** Set after deployment via `npx hardhat run scripts/deploy.js --network amoy`

### 5.2 Core Functions

```solidity
// Report a threat — costs ~$0.001 gas on Polygon
reportThreat(bytes32 hash, ThreatCategory category, uint8 severity, string region)

// Check if a hash is a confirmed community threat — free view call
checkThreat(bytes32 hash)
    returns (bool isThreat, uint32 reportCount, uint8 severity, uint8 category)

// Check many hashes in one call — used by VPN and SMS filter
batchCheckThreats(bytes32[] hashes)
    returns (bool[] flags, uint8[] severities)

// Get recent threats for device sync on startup
getRecentThreats(uint256 offset, uint256 limit)
```

### 5.3 Escalation Events

| Event | Trigger | Action |
|---|---|---|
| `NewThreatDiscovered` | First report of a hash | Logs to backend, starts count |
| `ThreatReported` | Every subsequent report | Increments counter |
| `ThreatEscalated` | 100 reports | Backend generates PDF police report |
| `MassAttackDetected` | 500 reports/hour | Emergency alert to authorities |

### 5.4 Threat Categories

| Value | Category | Example |
|---|---|---|
| 0 | URL | Phishing or malware URL |
| 1 | PHONE_NUMBER | Smishing sender number |
| 2 | FILE_HASH | Malware file SHA-256 |
| 3 | IP_ADDRESS | Malicious server IP |
| 4 | APP_PACKAGE | Malicious app package name hash |
| 5 | RANSOMWARE_PATH | File path pattern of ransomware |

### 5.5 Community Minimum Threshold

Threats are only surfaced to the community once they have been independently confirmed by at least **3 unique devices** (`MIN_REPORTS_PUBLIC = 3`). This prevents false positives from individual misclassifications.

---

## 6. Backend API Reference

Base URL: `http://localhost:8000` (development) or your deployed server URL.

Interactive documentation: `http://localhost:8000/docs`

### 6.1 Health Check

```
GET /health
```
**Response:**
```json
{ "status": "ok", "db": "ok", "ts": 1717123456, "version": "1.0.0" }
```

---

### 6.2 Report a Threat

```
POST /v1/threats/report
```
**Request body:**
```json
{
  "threat_hash": "sha256hexstring...",
  "threat_type": "URL",
  "severity": 4,
  "device_id": "sha256ofdevicefingerprint...",
  "region": "IN",
  "metadata": { "title": "Phishing URL detected" }
}
```
**Response:**
```json
{ "status": "ok", "hash": "abc123...", "report_count": 47 }
```

---

### 6.3 Batch Check Threats

```
POST /v1/threats/batch-check
```
**Request body:**
```json
{ "hashes": ["hash1", "hash2", "hash3"] }
```
**Response:**
```json
{
  "hash1": { "is_threat": true, "severity": 4, "report_count": 89, "type": "URL" },
  "hash2": { "is_threat": false },
  "hash3": { "is_threat": true, "severity": 3, "report_count": 12, "type": "PHONE" }
}
```

---

### 6.4 Get Recent Threats (Device Sync)

```
GET /v1/threats/recent?limit=500&threat_type=URL&min_severity=1
```
Returns the latest confirmed threats for device blocklist synchronisation.

---

### 6.5 Dashboard Statistics

```
GET /v1/dashboard/stats
```
**Response:**
```json
{
  "total_threats": 4821,
  "threats_24h": 142,
  "threats_7d": 893,
  "critical": 34,
  "total_reports": 128450,
  "police_reported": 7,
  "regions": 23,
  "by_type": { "URL": 2341, "PHONE": 1205, "FILE_HASH": 890 }
}
```

---

### 6.6 Threat Trend Data

```
GET /v1/dashboard/trend?days=7
```
Returns hourly threat counts for the last N days — used to power the in-app chart.

---

### 6.7 AI Security Assistant

```
POST /v1/assistant/ask
```
**Request body:**
```json
{
  "question": "Is this SMS safe to click?",
  "language": "hi",
  "threat_context": { "recent_threats": 3, "last_type": "SMS_PHISHING" }
}
```
**Response:**
```json
{ "answer": "नहीं, यह SMS संदिग्ध है...", "language": "hi" }
```

---

### 6.8 Generate Police Report

```
POST /v1/reports/generate-now
```
Manually triggers PDF generation for all unescalated threats above the police threshold.

```
GET /v1/reports/list
```
Lists all previously generated police reports with status.

---

## 7. Database Schema

### threats

| Column | Type | Description |
|---|---|---|
| id | UUID | Primary key |
| hash | CHAR(64) | SHA-256 hex — unique constraint |
| type | VARCHAR(20) | URL / PHONE / FILE_HASH / IP / APP |
| severity | SMALLINT | 1 (low) to 5 (emergency) |
| report_count | INTEGER | Total reports from community |
| first_seen | TIMESTAMPTZ | When first reported |
| last_seen | TIMESTAMPTZ | Most recent report |
| police_reported | BOOLEAN | Whether included in a police PDF |
| region | CHAR(2) | ISO 3166-1 country code |
| metadata | JSONB | Flexible additional data |

### threat_events

Tracks individual device reports for deduplication — ensures each device is counted only once per threat.

| Column | Type | Description |
|---|---|---|
| hash | CHAR(64) | Foreign key → threats.hash |
| device_id | CHAR(64) | SHA-256 of anonymous device fingerprint |
| timestamp | TIMESTAMPTZ | When this device reported it |

Unique constraint: `(hash, device_id)` — prevents double-counting.

### police_reports

| Column | Type | Description |
|---|---|---|
| id | UUID | Primary key |
| report_path | TEXT | Path to generated PDF file |
| threat_count | INTEGER | Threats included in report |
| generated_at | TIMESTAMPTZ | When generated |
| status | VARCHAR(20) | PENDING / SUBMITTED / ACKNOWLEDGED |

---

## 8. Smart Contract Reference

**Location:** `aegis-contracts/AegisThreatIntel.sol`
**Network:** Polygon Amoy testnet (development), Polygon mainnet (production)
**Language:** Solidity ^0.8.19

### Constants

```solidity
uint32 public constant POLICE_THRESHOLD   = 100;  // Reports before auto-escalation
uint32 public constant MIN_REPORTS_PUBLIC = 3;    // Minimum before visible to network
uint32 public constant EMERGENCY_THRESHOLD = 500; // Mass attack threshold
```

### Events

```solidity
event NewThreatDiscovered(bytes32 indexed hash, ThreatCategory category, string region);
event ThreatReported(bytes32 indexed hash, ThreatCategory indexed category, uint32 count, uint8 severity);
event ThreatEscalated(bytes32 indexed hash, uint32 reportCount, uint8 maxSeverity);
event MassAttackDetected(ThreatCategory indexed category, uint32 affectedDevices);
```

### Deployment

```bash
cd aegis-contracts
npm install
npx hardhat compile
npx hardhat test                              # run all tests first
npx hardhat run scripts/deploy.js --network amoy   # deploy to testnet
```

After deployment, copy the contract address from `deployed.json` into:
- `aegis-backend/.env` → `CONTRACT_ADDRESS=0x...`
- `aegis-android/app/src/main/java/com/aegis/security/blockchain/BlockchainReporter.kt` → `CONTRACT_ADDRESS` constant

---

## 9. Installation & Setup

### 9.1 Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Android Studio | Hedgehog (2023.1.1+) | Android development |
| JDK | 17 | Kotlin compilation |
| Docker Desktop | 24.0+ | Backend container |
| Node.js | 18+ | Hardhat (smart contracts) |
| Python | 3.11+ | Backend (if running without Docker) |

### 9.2 Quick Start

```bash
# 1. Download blocklists into APK assets
bash download_blocklists.sh

# 2. Start backend
cd aegis-backend
cp .env.example .env          # then add ANTHROPIC_API_KEY to .env
docker compose up -d
curl http://localhost:8000/health   # verify: {"status":"ok"}

# 3. Deploy smart contract
cd ../aegis-contracts
npm install
npx hardhat compile
npx hardhat test              # all tests should pass
# add POLYGON_PRIVATE_KEY to .env, get testnet MATIC from faucet.polygon.technology
npx hardhat run scripts/deploy.js --network amoy

# 4. Open Android project
# Open aegis-android/ in Android Studio
# In di/AppModule.kt, update baseUrl to your PC's LAN IP:
#   .baseUrl("http://YOUR_LAN_IP:8000/")
# Run on device (Android 8.0+)
```

### 9.3 Android Permissions Required

When you first run Aegis, it will request the following permissions:

| Permission | Module | Required |
|---|---|---|
| VPN | Micro-VPN Shield | Optional (module won't work without it) |
| Receive SMS | SMS Phishing Filter | Optional |
| Post Notifications | All threat alerts | Recommended |
| Accessibility | Anti-Clickjacking | Optional (must enable manually in Settings) |

### 9.4 Generating a Signed Release APK

```bash
# 1. Generate keystore (one time only)
keytool -genkeypair \
  -alias aegis_key \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -keystore aegis-release.jks \
  -storepass YOUR_STORE_PASS -keypass YOUR_KEY_PASS \
  -dname "CN=Aegis Security, O=YourOrg, C=IN"

# 2. Copy key.properties.template → key.properties and fill in values

# 3. In Android Studio: Build → Generate Signed Bundle / APK → APK → Release
```

---

## 10. Configuration Guide

### 10.1 Backend Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `ANTHROPIC_API_KEY` | Yes (for AI) | From console.anthropic.com |
| `POLYGON_PRIVATE_KEY` | Yes (for blockchain) | Wallet private key for gas |
| `CONTRACT_ADDRESS` | Yes (for blockchain) | Set after deploying smart contract |
| `POLICE_THRESHOLD` | No (default: 100) | Reports before auto police report |
| `REPORTS_DIR` | No (default: /app/reports) | Where PDF reports are saved |

### 10.2 Android Configuration

All runtime settings are stored in `DataStore` preferences and toggled from the Settings screen:

| Setting | Default | Description |
|---|---|---|
| VPN Shield | Off | Requires user VPN consent |
| Honey-Token Canary | On | Starts automatically |
| SMS Phishing Filter | On | Requires RECEIVE_SMS |
| Permission Auditor | On | Runs at startup |
| Blockchain Reporting | On | Posts hashes to Polygon |
| Language | en | Affects AI assistant responses |

### 10.3 Updating the Blocklist

Run `bash download_blocklists.sh` then rebuild the APK. The script fetches:
- `assets/blocklists/abuse_ch.txt` from URLhaus
- `assets/blocklists/oisd_basic.txt` from OISD
- `assets/blocklists/phishtank.txt` from PhishTank (API key required)

Schedule weekly automatic updates via cron:
```
0 3 * * 1 cd /path/to/aegis && bash download_blocklists.sh >> logs/blocklist.log 2>&1
```

---

## 11. User Guide

### 11.1 Dashboard

The dashboard is the first screen shown on launch. It displays:

- **Protection status** — a shield showing how many modules are active
- **Threat counts** — threats detected, DNS queries blocked, SMS messages scanned
- **Module toggles** — enable or disable each protection module with one tap
- **Recent threats** — the latest security events detected on your device

### 11.2 Enabling the VPN Shield

1. Tap the VPN Shield toggle on the dashboard
2. Android will show a VPN permission dialog — tap "OK"
3. The shield status will turn active (teal glow)
4. All DNS queries are now filtered

### 11.3 Enabling the Anti-Clickjack Shield

This module requires manual setup:
1. Open Settings → Accessibility on your phone
2. Find "Aegis Anti-Clickjack Shield" in the list
3. Tap it and toggle it on
4. Aegis will now monitor for overlay attacks

### 11.4 Using the AI Security Assistant

1. Tap the "AI Guard" icon in the bottom navigation
2. Type your question in any language
3. To change language, tap the language selector in the top-right
4. The assistant has context about recent threats on your device

**Example questions:**
- "Is this SMS from my bank safe?"
- "Why did Aegis block this app?"
- "I think my phone was hacked — what should I do?"
- "What is smishing and how do I avoid it?"

### 11.5 Reading the Permission Auditor

1. Tap Settings → then navigate to Permission Audit (or from dashboard)
2. Apps are sorted by risk score (0–100)
3. Tap any app card to expand and see the specific risky permissions and why they are dangerous
4. Red/critical apps should be carefully reviewed — consider uninstalling unknown apps

### 11.6 Threat History

1. Tap the "Threats" icon in the bottom navigation
2. Filter by severity using the chips at the top
3. Tap any threat card to see full details and the action taken
4. Tap "Mark Resolved" once you've addressed a threat

---

## 12. Developer Guide

### 12.1 Project Structure

```
aegis-android/
├── app/src/main/java/com/aegis/security/
│   ├── AegisApplication.kt          # App entry, Hilt, WorkManager, channels
│   ├── MainActivity.kt              # UI entry, initialises HoneyTokenManager
│   ├── BlocklistSyncWorker.kt       # 6-hour background sync + BootReceiver
│   ├── honeytoken/
│   │   └── HoneyTokenManager.kt     # Trap files, FileObserver, ContentObserver
│   ├── vpn/
│   │   └── AegisVpnService.kt       # VpnService, DNS filter, blocklist
│   ├── sms/
│   │   └── SmsPhishingDetector.kt   # SMS scoring + BroadcastReceiver
│   ├── permission/
│   │   └── PermissionAuditor.kt     # App risk scoring
│   ├── blockchain/
│   │   └── BlockchainReporter.kt    # Hash → Polygon RPC
│   ├── data/
│   │   ├── local/
│   │   │   └── AegisDatabase.kt     # Room DB, ThreatDao
│   │   ├── remote/
│   │   │   └── AegisApiService.kt   # Retrofit interface
│   │   └── repository/
│   │       └── ThreatRepository.kt  # Single source of truth
│   ├── domain/model/
│   │   └── AegisModels.kt           # ThreatEvent, Severity, ChatMessage, etc.
│   ├── di/
│   │   └── AppModule.kt             # Hilt module — wires all dependencies
│   └── ui/
│       ├── theme/AegisTheme.kt      # Compose dark theme, colours, typography
│       ├── navigation/AegisNavGraph.kt
│       ├── home/                    # HomeScreen + HomeViewModel
│       ├── threats/                 # ThreatListScreen + ThreatViewModel
│       ├── assistant/               # AssistantScreen + AssistantViewModel
│       ├── permissions/             # PermissionAuditScreen + PermissionViewModel
│       ├── settings/                # SettingsScreen
│       └── overlay/                 # AegisOverlayService (AccessibilityService)
```

### 12.2 Adding a New Security Module

1. Create a new package under `com.aegis.security/`
2. Inject `ThreatRepository` and `BlockchainReporter` via Hilt constructor injection
3. Use `ThreatRepository.save(threat)` to log detections
4. Use `ThreatRepository.reportToBackend(threat)` to report
5. Add a toggle to `HomeViewModel` and `SettingsScreen`
6. Register any Android services/receivers in `AndroidManifest.xml`

### 12.3 Dependency Injection

All classes use Hilt constructor injection. The `@ApplicationContext` qualifier provides the Android `Context`. The `AppModule.kt` provides:
- `AegisDatabase` (Room) — singleton
- `ThreatDao` — scoped to database lifecycle
- `OkHttpClient` — singleton with logging
- `Retrofit` — singleton
- `AegisApiService` — singleton

### 12.4 Background Work

All periodic background tasks use WorkManager with Hilt integration (`@HiltWorker`):
- `BlocklistSyncWorker` — runs every 6 hours, fetches new threat hashes
- Add new workers by extending `CoroutineWorker` and annotating with `@HiltWorker`

---

## 13. Testing Guide

### 13.1 Unit Tests

```bash
cd aegis-android
./gradlew test
```

Runs `PermissionAuditorTest` and `SmsPhishingDetectorTest` — 27 unit tests total covering all scoring logic, edge cases, and severity mapping.

### 13.2 Smart Contract Tests

```bash
cd aegis-contracts
npx hardhat test
```

Runs `AegisThreatIntel.test.js` — covers deployment, reportThreat, checkThreat, batchCheck, escalation events, admin functions, and gas estimates.

### 13.3 Manual Honey-Token Test

1. Install Aegis and enable Honey-Token Canary
2. On your device, open a file manager app
3. Navigate to `Android/data/com.aegis.security/files/`
4. Open any file starting with `!` or `000_`
5. Aegis should fire a HIGH severity notification within 1 second
6. Check Threat History — event should be logged

### 13.4 Manual VPN Test

1. Enable the Micro-VPN Shield
2. Open a browser and navigate to `http://malware.wicar.org/data/eicar.com` (a safe test URL that is in the abuse.ch blocklist)
3. The page should fail to load
4. Disable VPN and try again — it should load
5. Re-enable the VPN

### 13.5 Backend API Test

```bash
# Test health
curl http://localhost:8000/health

# Test threat reporting
curl -X POST http://localhost:8000/v1/threats/report \
  -H "Content-Type: application/json" \
  -d '{"threat_hash":"abc123def456","threat_type":"URL","severity":4,"device_id":"testdevice001","region":"IN"}'

# Test dashboard stats
curl http://localhost:8000/v1/dashboard/stats
```

---

## 14. Glossary

| Term | Definition |
|---|---|
| **Honey-Token** | A decoy resource (file, credential, token) designed to attract attackers. When accessed, its access is logged as an attack signal. |
| **Canary File** | A trap file whose access triggers a security alert, like a canary in a coal mine detecting danger. |
| **DNS Sinkhole** | A DNS response that redirects malicious domain requests to an invalid address (0.0.0.0), preventing connection. |
| **Smishing** | SMS phishing — fraudulent text messages designed to trick users into revealing credentials or clicking malicious links. |
| **Clickjacking** | A UI attack where a transparent layer is placed over legitimate UI to hijack user interaction. |
| **CTI** | Collective Threat Intelligence — shared knowledge about threats across multiple organisations or users. |
| **CERT-In** | Indian Computer Emergency Response Team — national cybersecurity authority. |
| **Polygon PoS** | Polygon Proof-of-Stake — a blockchain network offering low-cost (~$0.001/tx) Ethereum-compatible smart contract execution. |
| **SHA-256** | Secure Hash Algorithm 256-bit — produces a fixed-size hash from any input. Computationally infeasible to reverse. |
| **VpnService** | Android API that allows apps to create local VPN tunnels without root access. |
| **FileObserver** | Android API that monitors file system events (open, read, modify, delete) on specified paths. |
| **AccessibilityService** | Android API that provides apps with information about other apps' UI and system events. |
| **PackageManager** | Android API for querying information about installed applications including their permissions. |
| **Room** | Android SQLite abstraction library for local persistent storage. |
| **Hilt** | Android dependency injection framework built on top of Dagger. |
| **NXDOMAIN** | DNS response code meaning "Non-Existent Domain" — used by Aegis when sinkholing blocked domains. |

---

*Aegis — Because you should not have to choose between security and privacy.*

**Support contacts:**
- CERT-In: cert-in.org.in
- National Cyber Crime Helpline: 1930
- Cyber Crime Portal: cybercrime.gov.in
