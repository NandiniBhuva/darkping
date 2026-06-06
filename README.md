# darkping 🔍

> Attacker's Eye View of Your Domain — OSINT + AI Correlation Engine

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Most OSINT tools give you a list of findings. **darkping** thinks like an attacker — it runs 6 scanners in parallel, then uses AI to connect individual findings into complete attack chains.

---

## What It Scans

| Scanner | What It Checks | Source |
|---|---|---|
| subdomains | Exposed subdomains including dev, staging, admin, API endpoints | crt.sh + HackerTarget |
| breaches | Domain emails in known data breach databases | HaveIBeenPwned |
| ports | Open ports, exposed services, known CVEs on the domain IP | Shodan InternetDB |
| dns | SPF/DMARC misconfigs, zone transfer, email spoofing risk | DNS resolver |
| urlscan | Recent attacker scanning activity against the domain | URLScan.io |
| github_leaks | Leaked secrets, credentials, config files in public repos | GitHub Code Search |

---

## Install

```bash
git clone https://github.com/NandiniBhuva/darkping.git
cd darkping
python3 -m venv venv && source venv/bin/activate
pip install -e .
```

Or directly via pip:

```bash
pip install git+https://github.com/NandiniBhuva/darkping.git
```

---

## Usage

### Basic scan (no API keys needed)
```bash
darkping scan yourdomain.com
```

### Full AI-powered scan with attack chain correlation
```bash
export GROQ_API_KEY="your-key"
export GITHUB_TOKEN="your-token"
darkping scan yourdomain.com --ai
```

Get a free Groq API key at console.groq.com and a free GitHub token at github.com/settings/tokens.

---

## What Makes darkping Different

Every existing OSINT tool gives you a list of findings. darkping does something none of them do — it chains findings into attack narratives.

A single finding like "port 3306 open" is noise. But "port 3306 open + leaked DB credentials in GitHub + recent URLScan probing" is a live attack path. That is what the AI correlation layer surfaces.

---

## API Keys

| Key | Required | Where to Get | Cost |
|---|---|---|---|
| GROQ_API_KEY | Only for --ai flag | console.groq.com | Free |
| GITHUB_TOKEN | Recommended | github.com/settings/tokens | Free |

All other scanners work with no API keys.

---

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | LOW or MEDIUM exposure |
| 1 | HIGH or CRITICAL exposure |

---

