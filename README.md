# 🔱 Pinakastra

**Penetration Testing Framework with Automated Reconnaissance and Deterministic Verification**

Pinakastra is a reconnaissance and exploitation tool that combines passive/active enumeration with deterministic vulnerability confirmation. Findings are verified by testing behavior, not by a model's opinion, so a reported vulnerability reflects a signal that actually held. Built for penetration testers and bug bounty hunters. Use only against targets you are authorized to test, and scope every run (`--scope`).

[![GitHub stars](https://img.shields.io/github/stars/who0xac/Pinakastra?style=flat-square&logo=github)](https://github.com/who0xac/Pinakastra/stargazers)
[![Version](https://img.shields.io/badge/version-v1.0-brightgreen.svg)](https://github.com/who0xac/Pinakastra/releases)
[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://go.dev)
[![Platform](https://img.shields.io/badge/platform-Linux-green.svg)](https://www.linux.org)

---

## ✨ What Does Pinakastra Do?

1. **Discovers subdomains** - subfinder, findomain, assetfinder, sublist3r, chaos, crtsh, shodan, puredns
2. **Probes live hosts** - httpx
3. **Resolves IPs** - dnsx with ASN and geolocation
4. **Discovers URLs** - Katana (crawler) + GAU (archive scraper)
5. **Scans ports** - Nmap with AI-powered CVE detection
6. **Analyzes security** - Headers, CORS, TLS, secrets, cloud assets, takeover
7. **Actively exploits** - XSS, SQLi, SSRF, Open Redirect, Path Traversal, IDOR, JWT
8. **Generates reports** - JSON, CSV, TXT formats

---

## 🚀 Features

### 🔍 Reconnaissance
- **Subdomain Discovery** - 8 passive sources + DNS bruteforce
- **HTTP Probing** - Live host detection with tech fingerprinting
- **IP Resolution** - ASN lookups and geolocation
- **URL Discovery** - Katana + GAU with smart filtering
- **Port Scanning** - Nmap with service detection

**Smart URL Filtering:**
- Removes static assets (images, CSS, fonts) while preserving sensitive files
- Keeps .env, .sql, .bak, .config, .js files for security testing
- Prioritizes API, admin, auth, and upload endpoints
- Limits to 150 URLs/subdomain, 5 URLs/pattern (70% reduction)
- Ensures no sensitive points are missed

### 🛡️ Security Analysis
- Security Headers, TLS/SSL, CORS
- Subdomain Takeover (50+ services)
- Cloud Asset Discovery (S3, Azure, GCP)
- Secret Detection (API keys, tokens)

### 🎯 Deterministic Active Verification

Each class is confirmed by a dedicated oracle that tests behavior and marks a finding `verified` only when a differential signal actually holds. No language model is involved in confirmation.

- **SQLi** - DBMS error signatures, boolean differential, and time-based blind
- **XSS** - reflection with context and encoding analysis, not bare reflection
- **Path Traversal / LFI** - file-signature content a baseline response lacks
- **Open Redirect** - Location header resolves to an injected sentinel host
- **SSRF** - cloud-metadata reflection, plus out-of-band blind detection (`--oob-url`)
- **IDOR** - cross-identity object access that anonymous access is denied (`--identities`)
- **JWT** - offline `alg:none` and weak-HMAC-secret analysis (`--jwt`)

Every oracle is built to refuse the common false positives: a page that merely echoes input, prints a vendor name, is uniformly slow, or is public rather than access-controlled.

### 🤖 AI (port scanning only)
- Port-scan CVE analysis via a local model (Ollama) with NVD verification. Active exploitation does **not** use a model.

---

## 📦 Installation

### 1. Check Required Tools

**Required:** subfinder, httpx, dnsx, katana, gau, puredns, findomain, assetfinder, chaos, nmap, sublist3r, crtsh, shodan

```bash
pinakastra check
```

### 2. Install Pinakastra

```bash
go install github.com/who0xac/pinakastra/cmd/pinakastra@main
```

### 3. Install AI

**Install Ollama:**
```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**Pull DeepSeek Model:**
```bash
ollama pull deepseek-r1:7b
```

**Start Ollama:**
```bash
ollama serve
```

**Verify:**
```bash
curl http://localhost:11434/api/tags
ollama list
```

---

## 📖 Usage

```bash
# Basic scan with AI
pinakastra -d target.com --enable-ai

# With options
pinakastra -d target.com --enable-ai -o ./results --no-bruteforce --use-tor
```

**Options:**
- `-o` - Custom output directory
- `--no-portscan` - Skip port scanning
- `--no-bruteforce` - Skip DNS bruteforce
- `--use-tor` - Use TOR proxy

---

## ⚙️ Configuration

**Pinakastra Config:** `~/.config/pinakastra/`

```
~/.config/pinakastra/
├── config.yaml              # API keys (Chaos, Shodan)
├── configs/
│   └── resolvers.txt        # DNS resolvers for puredns
└── wordlists/
    └── subdomains.txt       # Subdomain wordlist (auto-downloaded)
```

**Config File:** `~/.config/pinakastra/config.yaml`

```yaml
api_keys:
  chaos: "your-chaos-api-key"
  shodan: "your-shodan-api-key"
```

**Subfinder Config:** `~/.config/subfinder/provider-config.yaml`

---

## 📤 Output

Results saved in: `./output/<domain>-<timestamp>/`

```
subdomains.txt              # All discovered subdomains
live_hosts.txt              # Live HTTP/HTTPS hosts
resolved_ips.txt            # IPs with ASN and geolocation
urls.txt                    # All discovered URLs
open_ports.txt              # Open ports with services
vulnerabilities.json        # Exploitation results (JSON)
vulnerabilities.csv         # Exploitation results (CSV)
vulnerabilities.txt         # Exploitation results (TXT)
security_headers.txt        # Security header analysis
tls_analysis.txt            # TLS/SSL analysis
cors_issues.txt             # CORS misconfiguration
cloud_assets.txt            # Cloud storage buckets
secrets_found.txt           # API keys, tokens
subdomain_takeover.txt      # Takeover vulnerabilities
```

---

## 🎯 Active Exploitation

| Vulnerability | Hardcoded | AI | Total | Detection |
|--------------|-----------|----|----|-----------|
| XSS | 7 | 3 | 10 | Response reflection |
| SQL Injection | 7 | 3 | 10 | Error messages + time-based |
| SSRF | 7 | 3 | 10 | Cloud metadata detection |
| Open Redirect | 7 | 3 | 10 | Location header validation |
| Path Traversal | 7 | 3 | 10 | File signatures |
| IDOR | 7 | 3 | 10 | Response differential |
| JWT | - | Analysis | - | Token validation |

---

## 🤝 Contributing

Contributions welcome! Fork, create a feature branch, and submit a PR. Help us improve detection, add new modules, or optimize performance.

---

## ⚠️ Disclaimer

**For authorized security testing only.** Use only on systems you own or have explicit written permission to test. Owner is not responsible for misuse. Always follow responsible disclosure and comply with local laws.

---

**Built with ❤️ by who0xac**
