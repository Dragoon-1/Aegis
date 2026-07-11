#!/bin/bash
# ============================================================
# AEGIS — One-command setup script
# Run this from the project root: bash setup.sh
# ============================================================

set -e  # Exit on any error

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${PURPLE}"
echo "  █████╗ ███████╗ ██████╗ ██╗███████╗"
echo " ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝"
echo " ███████║█████╗  ██║  ███╗██║███████╗"
echo " ██╔══██║██╔══╝  ██║   ██║██║╚════██║"
echo " ██║  ██║███████╗╚██████╔╝██║███████║"
echo " ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝"
echo -e "${NC}"
echo -e "${BLUE}Next-Generation Android Security — Setup Script${NC}"
echo "=================================================="
echo ""

# ── Check prerequisites ───────────────────────────────────────────────────────
echo -e "${YELLOW}[1/5] Checking prerequisites...${NC}"

check_command() {
    if command -v "$1" &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $1 found"
    else
        echo -e "  ${RED}✗${NC} $1 not found — please install it first"
        MISSING=true
    fi
}

MISSING=false
check_command docker
check_command "docker compose"
check_command node
check_command npm
check_command python3

if [ "$MISSING" = true ]; then
    echo ""
    echo -e "${RED}Please install missing tools and run this script again.${NC}"
    echo "  Docker:  https://docs.docker.com/get-docker/"
    echo "  Node.js: https://nodejs.org/"
    echo "  Python3: https://www.python.org/"
    exit 1
fi
echo ""

# ── Backend setup ─────────────────────────────────────────────────────────────
echo -e "${YELLOW}[2/5] Setting up backend...${NC}"
cd aegis-backend

if [ ! -f ".env" ]; then
    cp .env.example .env
    echo -e "  ${GREEN}✓${NC} Created .env from template"
    echo -e "  ${YELLOW}⚠${NC}  Edit aegis-backend/.env and add your ANTHROPIC_API_KEY"
else
    echo -e "  ${GREEN}✓${NC} .env already exists"
fi

# Use main_complete.py as main.py
if [ ! -f "main.py" ] && [ -f "main_complete.py" ]; then
    cp main_complete.py main.py
    echo -e "  ${GREEN}✓${NC} Copied main_complete.py → main.py"
fi

echo -e "  Starting Docker containers (PostgreSQL + FastAPI)..."
docker compose up -d --build

# Wait for health check
echo -e "  Waiting for backend to start..."
MAX_WAIT=30
COUNT=0
until curl -sf http://localhost:8000/health > /dev/null 2>&1; do
    sleep 2
    COUNT=$((COUNT + 2))
    if [ $COUNT -ge $MAX_WAIT ]; then
        echo -e "  ${RED}✗${NC} Backend didn't start in ${MAX_WAIT}s — check: docker compose logs api"
        break
    fi
done

if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Backend running at http://localhost:8000"
    echo -e "  ${GREEN}✓${NC} API docs at  http://localhost:8000/docs"
fi

cd ..
echo ""

# ── Smart contract setup ──────────────────────────────────────────────────────
echo -e "${YELLOW}[3/5] Setting up smart contracts...${NC}"
cd aegis-contracts

npm install --silent
echo -e "  ${GREEN}✓${NC} Hardhat dependencies installed"

npx hardhat compile --quiet
echo -e "  ${GREEN}✓${NC} Contracts compiled"

echo -e "  ${BLUE}ℹ${NC}  To deploy to Polygon Amoy testnet:"
echo "       1. Add POLYGON_PRIVATE_KEY to aegis-backend/.env"
echo "       2. Get free MATIC: https://faucet.polygon.technology"
echo "       3. Run: npm run deploy:testnet"

cd ..
echo ""

# ── Android setup info ────────────────────────────────────────────────────────
echo -e "${YELLOW}[4/5] Android app setup...${NC}"

# Get local IP address for Android connection
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || \
           ipconfig getifaddr en0 2>/dev/null || \
           echo "YOUR_PC_IP")

echo -e "  ${BLUE}ℹ${NC}  Open aegis-android/ in Android Studio"
echo -e "  ${BLUE}ℹ${NC}  In AppModule.kt, change baseUrl to:"
echo -e "       ${GREEN}.baseUrl(\"http://${LOCAL_IP}:8000/\")${NC}"
echo -e "  ${BLUE}ℹ${NC}  Your local IP: ${GREEN}${LOCAL_IP}${NC}"
echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[5/5] Setup complete!${NC}"
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  AEGIS is ready to run!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo -e "  Backend API:   ${BLUE}http://localhost:8000${NC}"
echo -e "  API Docs:      ${BLUE}http://localhost:8000/docs${NC}"
echo -e "  Database:      ${BLUE}localhost:5432 (aegisdb)${NC}"
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo "  1. Add ANTHROPIC_API_KEY to aegis-backend/.env"
echo "  2. Open aegis-android/ in Android Studio"
echo "  3. Update baseUrl in AppModule.kt to your IP"
echo "  4. Run on device (Android 8.0+)"
echo ""
echo -e "  Logs:    ${BLUE}docker compose -f aegis-backend/docker-compose.yml logs -f${NC}"
echo "  Stop:    docker compose -f aegis-backend/docker-compose.yml down"
echo ""
