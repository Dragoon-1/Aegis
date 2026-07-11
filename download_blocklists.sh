#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# AEGIS — Blocklist Download Script
# Fetches the latest threat feeds and places them in the Android assets folder.
# Run this before building the APK to bundle an up-to-date blocklist.
# Usage: bash download_blocklists.sh
# ─────────────────────────────────────────────────────────────────────────────

set -e

ASSETS_DIR="aegis-android/app/src/main/assets/blocklists"
mkdir -p "$ASSETS_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "Downloading Aegis threat blocklists..."
echo ""

# ── 1. abuse.ch URLhaus — malware distribution URLs ──────────────────────────
echo -e "${YELLOW}[1/3] abuse.ch URLhaus...${NC}"
if curl -sf --max-time 30 \
    "https://urlhaus.abuse.ch/downloads/text/" \
    -o "$ASSETS_DIR/abuse_ch_raw.txt"; then
    # Extract just the domain names (strip URLs to bare domains)
    grep -v "^#" "$ASSETS_DIR/abuse_ch_raw.txt" | \
    sed 's|https\?://||g' | \
    sed 's|/.*||g' | \
    grep -E '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | \
    sort -u > "$ASSETS_DIR/abuse_ch.txt"
    rm -f "$ASSETS_DIR/abuse_ch_raw.txt"
    COUNT=$(wc -l < "$ASSETS_DIR/abuse_ch.txt")
    echo -e "${GREEN}  ✓ ${COUNT} domains${NC}"
else
    echo -e "${RED}  ✗ Failed — creating empty placeholder${NC}"
    echo "# abuse.ch URLhaus — download failed, update manually" > "$ASSETS_DIR/abuse_ch.txt"
fi

# ── 2. OISD basic — ads, trackers, malware ───────────────────────────────────
echo -e "${YELLOW}[2/3] OISD basic blocklist...${NC}"
if curl -sf --max-time 60 \
    "https://abp.oisd.nl/basic/" \
    -o "$ASSETS_DIR/oisd_raw.txt"; then
    grep -v "^[!#\[]" "$ASSETS_DIR/oisd_raw.txt" | \
    grep "^\|\|" | \
    sed 's/^\|\|//' | \
    sed 's/\^.*//' | \
    grep -E '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | \
    sort -u > "$ASSETS_DIR/oisd_basic.txt"
    rm -f "$ASSETS_DIR/oisd_raw.txt"
    COUNT=$(wc -l < "$ASSETS_DIR/oisd_basic.txt")
    echo -e "${GREEN}  ✓ ${COUNT} domains${NC}"
else
    echo -e "${RED}  ✗ Failed — creating empty placeholder${NC}"
    echo "# OISD basic — download failed, update manually" > "$ASSETS_DIR/oisd_basic.txt"
fi

# ── 3. PhishTank — verified phishing URLs ────────────────────────────────────
echo -e "${YELLOW}[3/3] PhishTank verified phishing domains...${NC}"
# PhishTank requires a free API key for bulk downloads
# Register at: https://www.phishtank.com/register.php
# Then set: export PHISHTANK_API_KEY=your_key_here
if [ -n "$PHISHTANK_API_KEY" ]; then
    if curl -sf --max-time 60 \
        "https://data.phishtank.com/data/${PHISHTANK_API_KEY}/online-valid.csv.gz" | \
        gunzip -c | \
        tail -n +2 | \
        cut -d',' -f2 | \
        sed 's/"//g' | \
        sed 's|https\?://||g' | \
        sed 's|/.*||g' | \
        grep -E '^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | \
        sort -u > "$ASSETS_DIR/phishtank.txt"; then
        COUNT=$(wc -l < "$ASSETS_DIR/phishtank.txt")
        echo -e "${GREEN}  ✓ ${COUNT} phishing domains${NC}"
    else
        echo -e "${RED}  ✗ Download failed${NC}"
        echo "# PhishTank — download failed" > "$ASSETS_DIR/phishtank.txt"
    fi
else
    echo -e "${YELLOW}  ⚠  No PHISHTANK_API_KEY set — using empty placeholder${NC}"
    echo "  Get a free key at https://www.phishtank.com/register.php"
    echo "  Then run: PHISHTANK_API_KEY=yourkey bash download_blocklists.sh"
    echo "# PhishTank — set PHISHTANK_API_KEY to populate this file" > "$ASSETS_DIR/phishtank.txt"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────────"
TOTAL=0
for f in "$ASSETS_DIR"/*.txt; do
    COUNT=$(grep -v "^#" "$f" | grep -c . || true)
    TOTAL=$((TOTAL + COUNT))
    printf "  %-22s %d domains\n" "$(basename $f)" "$COUNT"
done
echo "─────────────────────────────────────────"
echo -e "${GREEN}  Total: ${TOTAL} domains bundled${NC}"
echo ""
echo "Blocklists saved to: $ASSETS_DIR"
echo "Rebuild the APK to include the updated lists."
echo ""
echo "Schedule weekly updates with cron:"
echo "  0 3 * * 1 cd /path/to/aegis && bash download_blocklists.sh >> logs/blocklist.log 2>&1"
