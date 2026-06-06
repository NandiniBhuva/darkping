import requests

# HaveIBeenPwned API - free tier allows domain searches
HIBP_URL = "https://haveibeenpwned.com/api/v3/breachesfordomains/{domain}"

# No API key needed for domain-level breach lookup
HEADERS = {
    "User-Agent": "darkping-security-scanner"
}

def scan(domain: str) -> dict:
    """
    Checks HaveIBeenPwned for known data breaches affecting this domain.
    Returns breach count, severity, and breach details.
    """
    findings = []
    breaches = []

    try:
        # Query HIBP for all breaches associated with this domain
        url = f"https://haveibeenpwned.com/api/v3/breaches"
        response = requests.get(url, headers=HEADERS, timeout=15)
        response.raise_for_status()
        all_breaches = response.json()

        # Filter breaches that match our domain
        for breach in all_breaches:
            breach_domain = breach.get("Domain", "").lower()
            if breach_domain == domain.lower() or breach_domain.endswith(f".{domain.lower()}"):
                breaches.append({
                    "name": breach.get("Name"),
                    "date": breach.get("BreachDate"),
                    "count": breach.get("PwnCount"),
                    "data_classes": breach.get("DataClasses", []),
                    "description": breach.get("Description", "")
                })

        if breaches:
            # Check if passwords were leaked — that's the most critical
            password_breaches = [
                b for b in breaches
                if "Passwords" in b.get("data_classes", [])
            ]

            if password_breaches:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "Password breach detected",
                    "detail": f"{len(password_breaches)} breach(es) exposed plaintext or hashed passwords for this domain.",
                    "data": password_breaches
                })
            else:
                findings.append({
                    "severity": "HIGH",
                    "title": "Domain found in breach database",
                    "detail": f"Found in {len(breaches)} breach(es). No passwords leaked but sensitive data exposed.",
                    "data": breaches
                })

            # Extra flag if breach is recent (within last 2 years)
            recent = [b for b in breaches if b["date"] and b["date"] >= "2023-01-01"]
            if recent:
                findings.append({
                    "severity": "HIGH",
                    "title": "Recent breach detected",
                    "detail": f"{len(recent)} breach(es) occurred after 2023 — credentials may still be actively used by attackers.",
                    "data": recent
                })

    except requests.exceptions.Timeout:
        findings.append({
            "severity": "INFO",
            "title": "HIBP timeout",
            "detail": "Breach check timed out. Try again.",
            "data": []
        })
    except Exception as e:
        findings.append({
            "severity": "INFO",
            "title": "Breach scan error",
            "detail": str(e),
            "data": []
        })

    return {
        "scanner": "breaches",
        "domain": domain,
        "total_breaches": len(breaches),
        "breaches": breaches,
        "findings": findings
    }