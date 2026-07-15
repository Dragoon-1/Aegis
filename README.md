# 🛡️ AEGIS — Next-Generation Android Security

> A 100% root-free Android security app combining honey-token deception, blockchain collective threat intelligence, DNS sinkholing, SMS phishing detection, and an AI-powered multilingual security assistant.

---

## 📁 Project Structure

```
aegis/
├── aegis-android/          ← Android app (Kotlin + Jetpack Compose)
│   └── app/src/main/
│       ├── java/com/aegis/security/
│       │   ├── honeytoken/         HoneyTokenManager.kt
│       │   ├── vpn/                AegisVpnService.kt
│       │   ├── sms/                SmsPhishingDetector.kt
│       │   ├── permission/         PermissionAuditor.kt
│       │   ├── blockchain/         BlockchainReporter.kt
│       │   ├── data/
│       │   │   ├── local/          AegisDatabase.kt (Room)
│       │   │   ├── remote/         AegisApiService.kt (Retrofit)
│       │   │   └── repository/     ThreatRepository.kt
│       │   ├── domain/model/       AegisModels.kt
│       │   ├── ui/
│       │   │   ├── home/           HomeScreen.kt + HomeViewModel.kt
│       │   │   ├── threats/        ThreatListScreen.kt
│       │   │   ├── assistant/      AssistantScreen.kt
│       │   │   ├── permissions/    PermissionAuditScreen.kt
│       │   │   ├── settings/       SettingsScreen.kt
│       │   │   ├── navigation/     AegisNavGraph.kt
│       │   │   └── theme/          AegisTheme.kt
│       │   ├── di/                 AppModule.kt (Hilt)
│       │   ├── MainActivity.kt
│       │   ├── AegisApplication.kt
│       │   └── BlocklistSyncWorker.kt
│       ├── AndroidManifest.xml
│       └── res/
│
├── aegis-backend/          ← Python FastAPI backend
│   ├── main_complete.py    ← Full backend (use this as main.py)
│   ├── schema.sql          ← PostgreSQL schema
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── .env.example
│
└── aegis-contracts/        ← Solidity smart contract (Polygon)
    ├── AegisThreatIntel.sol
    ├── scripts/deploy.js
    ├── hardhat.config.js
    └── package.json
```

---

## 🚀 Quick Start — 3 Steps

### Step 1 — Backend (5 minutes)

```bash
# Clone / navigate to backend folder
cd aegis-backend

# Copy and configure environment
cp .env.example .env
# Edit .env — add your ANTHROPIC_API_KEY at minimum

# Start PostgreSQL + FastAPI with Docker
docker compose up -d

# Verify it's running
curl http://localhost:8000/health
# Expected: {"status":"ok","db":"ok",...}
```

The API is now live at **http://localhost:8000**  
Interactive docs: **http://localhost:8000/docs**

---

### Step 2 — Smart Contract (10 minutes)

```bash
cd aegis-contracts

# Install Hardhat
npm install

# Test locally first
npx hardhat compile
npx hardhat test

# Deploy to Polygon Amoy testnet
# 1. Add POLYGON_PRIVATE_KEY to .env
# 2. Get free MATIC: https://faucet.polygon.technology
npx hardhat run scripts/deploy.js --network amoy

# Copy the printed CONTRACT_ADDRESS into:
# • aegis-backend/.env  →  CONTRACT_ADDRESS=0x...
# • aegis-android BlockchainReporter.kt → CONTRACT_ADDRESS constant
```

---

### Step 3 — Android App (Android Studio)

```
1. Open Android Studio → File → Open → select aegis-android/
2. Let Gradle sync finish (downloads dependencies ~3 min)
3. Open AppModule.kt — change baseUrl to your backend IP:
      .baseUrl("http://YOUR_COMPUTER_IP:8000/")
      (Not localhost — use your actual LAN IP so the phone can reach it)
4. Run on device or emulator (API 26+)
5. Grant permissions when prompted:
      • VPN (for DNS shield)
      • SMS (for phishing filter)
      • Notifications
```

---

## 📱 App Screens

| Screen | Description |
|---|---|
| **Dashboard** | Protection status, module toggles, stats, recent threats |
| **Threat History** | Full log of detected threats with severity filters |
| **AI Guard** | Multilingual security assistant (Claude-powered) |
| **Settings** | Module toggles, language picker, police report generator |
| **Permission Audit** | All installed apps risk-scored by permission combinations |

---

## 🔑 Core Modules

### 1. Honey-Token Canary Engine
Files: `honeytoken/HoneyTokenManager.kt`  
- Deploys 6+ decoy trap files in device storage
- Named alphabetically-first to be found by ransomware before real files
- `FileObserver` fires alert < 100ms from first trap access
- `ContentObserver` on MediaStore catches bulk encryption events
- Automatically reports threat hash to blockchain

### 2. Micro-VPN + DNS Sinkhole
Files: `vpn/AegisVpnService.kt`  
- `VpnService` API — no root needed
- All DNS queries from all apps go through Aegis
- Malicious domains returned as `0.0.0.0`
- Blocklist: abuse.ch + PhishTank + OISD + community blockchain threats
- O(1) lookup via `HashSet` — < 1ms per query

### 3. SMS Phishing Filter
Files: `sms/SmsPhishingDetector.kt`  
- `SmsRetriever` API — no broad SMS permission needed
- Multi-layer scoring: URL blockchain check + keyword patterns + sender check
- Alert shown before user taps any link

### 4. Permission Auditor
Files: `permission/PermissionAuditor.kt`  
- Scans every installed app via `PackageManager`
- Weighted danger matrix — combinations score higher than individual permissions
- Flags spyware combos (Camera+Mic+Location) and banking trojan combos

### 5. Blockchain CTI Network
Files: `blockchain/BlockchainReporter.kt`, `aegis-contracts/AegisThreatIntel.sol`  
- SHA-256 hash of every threat posted to Polygon
- All Aegis devices worldwide check this before any URL/SMS interaction
- 100+ reports → auto police report
- Gas cost: ~$0.001 per report on Polygon

### 6. AI Security Assistant
Files: `ui/assistant/AssistantScreen.kt`  
- Claude API (claude-sonnet-4-6) with security expert system prompt
- Threat context injected from user's own device history
- 12 languages in UI, 40+ via LibreTranslate integration

---

## 🔧 Backend API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET  | `/health` | Service health check |
| POST | `/v1/threats/report` | Report an anonymized threat hash |
| POST | `/v1/threats/batch-check` | Check up to 200 hashes at once |
| GET  | `/v1/threats/recent` | Get latest confirmed threats for sync |
| GET  | `/v1/dashboard/stats` | Aggregate threat statistics |
| GET  | `/v1/dashboard/trend` | Hourly threat trend data |
| POST | `/v1/assistant/ask` | Ask the AI security assistant |
| GET  | `/v1/reports/list` | List generated police reports |
| POST | `/v1/reports/generate-now` | Manually trigger police report |

Full interactive docs: `http://localhost:8000/docs`

---

## ⛓️ Smart Contract Functions

```solidity
// Report a threat (costs ~$0.001 MATIC gas)
reportThreat(bytes32 hash, ThreatCategory category, uint8 severity, string region)

// Check one hash — free view call
checkThreat(bytes32 hash) → (bool isThreat, uint32 count, uint8 severity, uint8 category)

// Check many hashes in one call — used by VPN + SMS filter
batchCheckThreats(bytes32[] hashes) → (bool[] flags, uint8[] severities)

// Get recent threats for device sync
getRecentThreats(uint256 offset, uint256 limit)
```

Events emitted:
- `NewThreatDiscovered` — first report of a threat
- `ThreatReported` — every subsequent report
- `ThreatEscalated` — 100+ reports crossed → triggers police PDF
- `MassAttackDetected` — 500+ reports/hour → mass attack declaration

---

## 🔒 Privacy Guarantees

| Data | Stays on device | Posted to server | Posted to blockchain |
|---|:---:|:---:|:---:|
| Raw URL / phone number | ✓ | ✗ | ✗ |
| SHA-256 hash of threat | — | ✓ | ✓ |
| Threat type + severity | — | ✓ | ✓ |
| Anonymous device ID | ✓ (hashed) | ✓ (hash only) | ✗ |
| User identity | ✓ | ✗ | ✗ |

SHA-256 is computationally infeasible to reverse — raw indicators can never be recovered from hashes.

---

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Android | Kotlin 1.9 + Jetpack Compose + Hilt + Room + Retrofit |
| Backend | Python 3.11 + FastAPI + asyncpg + PostgreSQL 15 |
| Blockchain | Solidity 0.8.19 + Polygon PoS + Hardhat |
| AI | Claude API (claude-sonnet-4-6) |
| Translation | LibreTranslate (self-hosted) |
| PDF | ReportLab |
| DNS Feeds | abuse.ch + PhishTank + OISD |

---

## 📞 Support

- **Cyber Police India:** cybercrime.gov.in
- **CERT-In:** cert-in.org.in  
- **Helpline:** 1930 (National Cyber Crime Helpline)
