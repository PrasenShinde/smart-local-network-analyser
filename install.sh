#!/bin/bash
# ============================================================
# Smart Local Network & Security Analyzer - Ubuntu Installer
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Smart Network & Security Analyzer - Installer     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Root check ──────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root: sudo bash install.sh${NC}"
  exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/venv"
LOG_FILE="$PROJECT_DIR/logs/install.log"
mkdir -p "$PROJECT_DIR/logs"

log() { echo -e "$1" | tee -a "$LOG_FILE"; }

log "${GREEN}[*] Updating apt packages...${NC}"
apt-get update -y >> "$LOG_FILE" 2>&1

log "${GREEN}[*] Installing system dependencies...${NC}"
apt-get install -y \
  nmap \
  masscan \
  nikto \
  whois \
  dnsutils \
  curl wget \
  git \
  python3 python3-pip python3-venv python3-dev \
  libssl-dev libffi-dev \
  sqlite3 \
  jq \
  theHarvester \
  dnsenum \
  subfinder \
  amass \
  >> "$LOG_FILE" 2>&1 || true

# ── Install subfinder if not via apt ────────────────────────
if ! command -v subfinder &>/dev/null; then
  log "${YELLOW}[*] Installing subfinder via Go...${NC}"
  apt-get install -y golang-go >> "$LOG_FILE" 2>&1 || true
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest >> "$LOG_FILE" 2>&1 || true
  cp ~/go/bin/subfinder /usr/local/bin/ 2>/dev/null || true
fi

# ── Install amass if not via apt ────────────────────────────
if ! command -v amass &>/dev/null; then
  log "${YELLOW}[*] Installing amass via snap...${NC}"
  snap install amass >> "$LOG_FILE" 2>&1 || true
fi

# ── Python virtual environment ──────────────────────────────
log "${GREEN}[*] Creating Python virtual environment...${NC}"
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

log "${GREEN}[*] Installing Python dependencies...${NC}"
pip install --upgrade pip >> "$LOG_FILE" 2>&1
pip install -r "$PROJECT_DIR/requirements.txt" >> "$LOG_FILE" 2>&1

# ── Database initialisation ─────────────────────────────────
log "${GREEN}[*] Initialising database...${NC}"
python3 "$PROJECT_DIR/db/init_db.py"

# ── Permissions ─────────────────────────────────────────────
log "${GREEN}[*] Setting up nmap capabilities (no-root scanning)...${NC}"
setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap) 2>/dev/null || true

chmod +x "$PROJECT_DIR/run.py"
chown -R "$SUDO_USER:$SUDO_USER" "$PROJECT_DIR" 2>/dev/null || true

# ── .env template ───────────────────────────────────────────
if [ ! -f "$PROJECT_DIR/.env" ]; then
  log "${YELLOW}[*] Creating .env template...${NC}"
  cat > "$PROJECT_DIR/.env" <<EOF
# ── Anthropic AI (required for remediation engine) ──────────
ANTHROPIC_API_KEY=your_anthropic_key_here

# ── Optional: Shodan (enhances Shadow IT discovery) ─────────
SHODAN_API_KEY=your_shodan_key_here

# ── Optional: SecurityTrails ────────────────────────────────
SECURITYTRAILS_API_KEY=your_securitytrails_key_here

# ── Optional: Hunter.io (email OSINT) ───────────────────────
HUNTER_API_KEY=your_hunter_key_here

# ── Optional: GitHub token (higher rate limits) ─────────────
GITHUB_TOKEN=your_github_token_here

# ── API server config ────────────────────────────────────────
API_HOST=0.0.0.0
API_PORT=8000
SECRET_KEY=change_me_to_a_random_string

# ── Database ─────────────────────────────────────────────────
DATABASE_URL=sqlite:///./smart_analyzer.db
EOF
fi

echo ""
log "${GREEN}╔══════════════════════════════════════════════════════╗"
log "║            ✅  Installation Complete!                ║"
log "╚══════════════════════════════════════════════════════╝${NC}"
echo ""
log "  1. Edit ${CYAN}.env${NC} and add your API keys"
log "  2. Activate venv:  ${CYAN}source venv/bin/activate${NC}"
log "  3. Start server:   ${CYAN}python run.py${NC}"
log "  4. API docs:       ${CYAN}http://localhost:8000/docs${NC}"
echo ""
