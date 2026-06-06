import requests
from datetime import datetime, timezone

URLSCAN_API = "https://urlscan.io/api/v1/search/"

def scan(domain: str) -> dict:
    """
    Checks URLScan.io for recent scans of the domain.
    Frequent recent scans = someone is actively probing this domain.
    """
    findings = []
    scans = []

    try:
        # Query URLScan for recent scans of this domain
        params = {
            "q": f"domain:{domain}",
            "size": 20  # get last 20 scans
        }
        headers = {
            "User-Agent": "darkping-security-scanner"
        }

        response = requests.get(URLSCAN_API, params=params, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()

        results = data.get("results", [])

        for result in results:
            task = result.get("task", {})
            scans.append({
                "url": task.get("url"),
                "time": task.get("time"),
                "country": task.get("country"),
                "source": task.get("source"),
                "tags": result.get("verdicts", {}).get("overall", {}).get("tags", [])
            })

        if not scans:
            return {
                "scanner": "urlscan",
                "domain": domain,
                "total_scans": 0,
                "scans": [],
                "findings": findings
            }

        # --- Check for malicious verdicts ---
        malicious = [
            s for s in scans
            if "malicious" in s.get("tags", [])
            or "phishing" in s.get("tags", [])
        ]

        if malicious:
            findings.append({
                "severity": "CRITICAL",
                "title": "Domain flagged as malicious",
                "detail": f"{len(malicious)} scan(s) flagged this domain as malicious or phishing.",
                "data": malicious
            })

        # --- Check scan frequency (many scans = active probing) ---
        if len(scans) >= 10:
            findings.append({
                "severity": "HIGH",
                "title": "Domain heavily scanned",
                "detail": f"Found {len(scans)} recent scans on URLScan — domain is being actively probed.",
                "data": scans[:5]
            })
        elif len(scans) >= 3:
            findings.append({
                "severity": "MEDIUM",
                "title": "Domain recently scanned",
                "detail": f"Found {len(scans)} recent scans — someone is researching this domain.",
                "data": scans[:3]
            })

        # --- Check for very recent scans (last 7 days) ---
        recent = []
        now = datetime.now(timezone.utc)
        for s in scans:
            try:
                scan_time = datetime.fromisoformat(
                    s["time"].replace("Z", "+00:00")
                )
                days_ago = (now - scan_time).days
                if days_ago <= 7:
                    recent.append(s)
            except Exception:
                pass

        if recent:
            findings.append({
                "severity": "HIGH",
                "title": "Very recent scanning activity",
                "detail": f"{len(recent)} scan(s) in the last 7 days — active reconnaissance likely in progress.",
                "data": recent
            })

    except requests.exceptions.Timeout:
        findings.append({
            "severity": "INFO",
            "title": "URLScan timeout",
            "detail": "URLScan check timed out. Try again.",
            "data": []
        })
    except Exception as e:
        findings.append({
            "severity": "INFO",
            "title": "URLScan error",
            "detail": str(e),
            "data": []
        })

    return {
        "scanner": "urlscan",
        "domain": domain,
        "total_scans": len(scans),
        "scans": scans,
        "findings": findings
    }