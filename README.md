# 🔐 Smart Network & Security Analyzer

> **Intelligent, AI-powered network and security analysis platform for Ubuntu.**
> Scans, discovers, correlates, and auto-generates tailored remediation scripts.

---

## Architecture Overview

```
smart-security-analyzer/
├── core/
│   ├── scanner.py          ← Nmap engine (5 scan types + masscan)
│   ├── osint.py            ← OSINT: subdomains, DNS, WHOIS, certs, Shodan
│   ├── shadow_it.py        ← Shadow IT: GitHub leaks, S3 buckets, Pastebin
│   └── remediation.py      ← AI Self-Healing Playbook Generator (Claude)
├── api/
│   ├── main.py             ← FastAPI app + CORS + health endpoints
│   └── routes/
│       ├── scan.py         ← /api/scan/*
│       ├── osint.py        ← /api/osint/* + /api/shadow-it/*
│       └── remediation.py  ← /api/remediation/*
├── db/
│   ├── models.py           ← SQLAlchemy ORM (SQLite / PostgreSQL)
│   └── database.py         ← Async session, CRUD helpers
├── utils/
│   ├── config.py           ← Pydantic Settings (loads .env)
│   └── helpers.py          ← Shared utilities, logging, network helpers
├── playbooks/              ← Generated remediation scripts (auto-created)
├── reports/                ← Exported scan reports
├── install.sh              ← One-shot Ubuntu installer
├── requirements.txt
└── run.py                  ← CLI entrypoint (server + CLI modes)
```

---

## Features

### 🛡️ Network Scanning (Nmap)
| Mode | Description |
|------|-------------|
| `discovery` | Fast ICMP/TCP ping sweep — find live hosts |
| `basic` | TCP SYN + service/version detection |
| `vulnerability` | Full NSE vuln scripts (Heartbleed, MS17-010, SQLi, etc.) |
| `web` | HTTP/HTTPS focused: headers, methods, SSL ciphers, XSS |
| `full` | All-port, all-UDP, all NSE scripts (thorough, slow) |
| `local` | Auto-detect and scan all local subnets |

### 🔍 OSINT Engine
- Subdomain enumeration: **crt.sh + DNS brute-force + subfinder + SecurityTrails**
- DNS records: A, AAAA, MX, NS, TXT, SOA, CAA, SPF, DMARC
- WHOIS & registration info
- TLS certificate analysis (SANs, expiry, weak ciphers)
- Email harvesting via Hunter.io
- Technology fingerprinting (headers + body patterns)
- Shodan host intelligence

### 🕵️ Shadow IT / Forgotten Attack Surface
- **GitHub dork scanner** — 12+ patterns for API keys, credentials, private keys
- **Secret pattern detection** — AWS keys, Stripe, GitHub tokens, DB strings, JWTs
- **Cloud bucket enumeration** — AWS S3, GCS, Azure Blob (37+ name variants)
- **Pastebin / grep.app hunting** — domain mentions in public pastes
- **Trello board discovery** — public boards referencing the org
- **AI correlation** — Claude synthesises raw findings into an attack-surface narrative

### 🤖 AI Self-Healing Playbook Generator
For **every vulnerability** found, Claude generates:
- Step-by-step runnable code (bash / Python / Nginx config / Terraform / SQL)
- Rollback script to undo changes if something breaks
- Verification command to confirm the fix worked
- Automation level (fully-automated / semi-automated / manual)
- Tailored to your exact OS, service version, and deployment context

---

## Installation (Ubuntu 20.04+)

```bash
# Clone
git clone https://github.com/your-org/smart-security-analyzer
cd smart-security-analyzer

# Install (requires sudo for nmap capabilities + system packages)
sudo bash install.sh

# Configure API keys
nano .env    # Add ANTHROPIC_API_KEY at minimum

# Activate venv
source venv/bin/activate
```

---

## Running

### API Server (for web UI integration)
```bash
python run.py server
# → http://localhost:8000
# → http://localhost:8000/docs  (Swagger UI)
```

### CLI Mode
```bash
# Network scans
python run.py scan run 192.168.1.1 --type basic
python run.py scan run 192.168.1.0/24 --type discovery
python run.py scan run example.com --type vuln --remediate
python run.py scan run 10.0.0.5 --type full --output results.json

# OSINT
python run.py osint run example.com
python run.py osint run example.com --output osint.json

# Shadow IT
python run.py shadow run example.com --output shadow.json
```

---

## API Reference

### Network Scanning

```http
POST /api/scan/discovery    {"target": "192.168.1.0/24"}
POST /api/scan/basic        {"target": "10.0.0.1", "ports": "1-10000"}
POST /api/scan/vulnerability {"target": "10.0.0.1", "auto_remediate": true,
                              "deployment_context": {"type": "docker", "extra": "Ubuntu 22.04"}}
POST /api/scan/web          {"target": "example.com"}
POST /api/scan/full         {"target": "192.168.1.1"}
POST /api/scan/local        (no body)
GET  /api/scan/{scan_id}
GET  /api/scans
```

### OSINT

```http
POST /api/osint/full        {"domain": "example.com"}
POST /api/osint/subdomains  {"domain": "example.com"}
POST /api/osint/dns         {"domain": "example.com"}
POST /api/osint/whois       {"domain": "example.com"}
POST /api/osint/cert        {"domain": "example.com"}
GET  /api/osint/{scan_id}
```

### Shadow IT

```http
POST /api/shadow-it/discover   {"domain": "example.com"}
GET  /api/shadow-it/{scan_id}
```

### Remediation Playbooks

```http
POST /api/remediation/generate        # single vuln → playbook
POST /api/remediation/generate-batch  # all vulns in a scan
GET  /api/remediation/scan/{scan_id}  # all playbooks for a scan
GET  /api/remediation/{playbook_id}   # single playbook
GET  /api/remediation/{id}/download   # download run.sh
GET  /api/remediation/{id}/rollback   # download rollback.sh
```

### System

```http
GET /           # service info
GET /health     # dependency checks (nmap, AI, Shodan)
GET /api/stats  # aggregate scan statistics
```

---

## Environment Variables (.env)

```env
# Required for AI remediation
ANTHROPIC_API_KEY=sk-ant-...

# Optional enrichment
SHODAN_API_KEY=...
SECURITYTRAILS_API_KEY=...
HUNTER_API_KEY=...
GITHUB_TOKEN=ghp_...        # higher rate limits for GitHub dorks

# Server
API_HOST=0.0.0.0
API_PORT=8000
```

---

## Frontend Integration

The API is designed for seamless frontend integration:

```javascript
// Example: start a vulnerability scan + auto-remediate
const resp = await fetch('http://localhost:8000/api/scan/vulnerability', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    target: '192.168.1.1',
    ports: '1-10000',
    auto_remediate: true,
    deployment_context: { type: 'bare-metal', extra: 'Ubuntu 22.04' }
  })
});
const { scan_id } = await resp.json();

// Poll for results
const poll = setInterval(async () => {
  const result = await fetch(`http://localhost:8000/api/scan/${scan_id}`);
  const data = await result.json();
  if (data.status === 'completed') {
    clearInterval(poll);
    console.log(data);
  }
}, 3000);
```

---

## Playbook Output Example

Each vulnerability gets a folder under `playbooks/PB-<id>/`:

```
playbooks/PB-a3f9c821/
├── manifest.json    ← Full playbook metadata + steps
├── run.sh           ← Executable remediation script
├── rollback.sh      ← Undo everything if it breaks
└── step_2.tf        ← Terraform snippet (if applicable)
```

Example `run.sh` for Heartbleed:
```bash
#!/usr/bin/env bash
# Playbook: PB-a3f9c821
# Vulnerability: OpenSSL Heartbleed (CVE-2014-0160)
# Severity: CRITICAL
set -euo pipefail

# Step 1: Check current OpenSSL version
openssl version -a

# Step 2: Upgrade OpenSSL to patched version
sudo apt-get update && sudo apt-get install -y openssl libssl-dev

# Step 3: Restart affected services
sudo systemctl restart nginx apache2 || true

# Verification
nmap -sV --script=ssl-heartbleed -p 443 localhost
```

---

## License

MIT — Use responsibly. Only scan systems you own or have explicit permission to test.
