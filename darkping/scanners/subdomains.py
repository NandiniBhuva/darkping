import requests
import time

def _fetch_crtsh(domain: str) -> set:
    """Fetch subdomains from crt.sh certificate transparency logs."""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            for entry in response.json():
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lower()
                    if name and "*" not in name and name != domain:
                        subdomains.add(name)
    except Exception:
        pass
    return subdomains


def _fetch_hackertarget(domain: str) -> set:
    """Fetch subdomains from HackerTarget API (free, no key needed)."""
    subdomains = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=15)
        if response.status_code == 200 and "error" not in response.text.lower():
            for line in response.text.strip().split("\n"):
                parts = line.split(",")
                if parts:
                    name = parts[0].strip().lower()
                    if name and name != domain:
                        subdomains.add(name)
    except Exception:
        pass
    return subdomains


def scan(domain: str) -> dict:
    """
    Finds subdomains using two sources:
    1. crt.sh — certificate transparency logs
    2. HackerTarget — subdomain search (fallback)
    Both are free and require no API key.
    """
    findings = []
    subdomains = set()

    # Try both sources
    crtsh_results = _fetch_crtsh(domain)
    hackertarget_results = _fetch_hackertarget(domain)

    # Combine results from both sources
    subdomains = crtsh_results | hackertarget_results
    subdomains = sorted(subdomains)

    if not subdomains:
        findings.append({
            "severity": "INFO",
            "title": "No subdomains found",
            "detail": "Both crt.sh and HackerTarget returned no results. Services may be temporarily unavailable.",
            "data": []
        })
        return {
            "scanner": "subdomains",
            "domain": domain,
            "total_subdomains": 0,
            "subdomains": [],
            "findings": findings
        }

    # Flag risky subdomains
    RISKY_KEYWORDS = [
        "dev", "staging", "test", "admin", "api",
        "internal", "vpn", "ssh", "backup", "old",
        "beta", "corp", "infra", "db", "database",
        "jenkins", "jira", "gitlab", "grafana", "kibana"
    ]

    risky = []
    for sub in subdomains:
        for keyword in RISKY_KEYWORDS:
            if keyword in sub:
                risky.append(sub)
                break

    if risky:
        findings.append({
            "severity": "HIGH",
            "title": "Sensitive subdomains exposed",
            "detail": f"Found {len(risky)} sensitive subdomains: {', '.join(risky[:5])}{'...' if len(risky) > 5 else ''}",
            "data": risky
        })

    if len(subdomains) > 20:
        findings.append({
            "severity": "MEDIUM",
            "title": "Large attack surface",
            "detail": f"Found {len(subdomains)} total subdomains — large attack surface increases exposure risk.",
            "data": list(subdomains)
        })

    return {
        "scanner": "subdomains",
        "domain": domain,
        "total_subdomains": len(subdomains),
        "subdomains": list(subdomains),
        "findings": findings
    }