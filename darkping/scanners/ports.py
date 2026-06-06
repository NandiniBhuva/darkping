import requests
import socket

# Risky ports and what they mean
RISKY_PORTS = {
    21:   "FTP — file transfer, often misconfigured with anonymous access",
    22:   "SSH — remote access, brute-force target",
    23:   "Telnet — unencrypted remote access, should never be public",
    25:   "SMTP — mail server, open relay risk",
    53:   "DNS — zone transfer or amplification attack risk",
    80:   "HTTP — unencrypted web traffic",
    443:  "HTTPS — web traffic (normal but worth noting)",
    445:  "SMB — Windows file sharing, ransomware target",
    1433: "MSSQL — Microsoft SQL Server exposed publicly",
    1521: "Oracle DB — database exposed publicly",
    2375: "Docker API — unauthenticated container access",
    3306: "MySQL — database exposed publicly",
    3389: "RDP — Windows remote desktop, ransomware target",
    4369: "RabbitMQ — message queue exposed",
    5432: "PostgreSQL — database exposed publicly",
    5900: "VNC — remote desktop, often unencrypted",
    6379: "Redis — cache/database, often no auth by default",
    8080: "HTTP alternate — dev server often exposed",
    8443: "HTTPS alternate — dev server often exposed",
    9200: "Elasticsearch — search engine, often no auth",
    27017: "MongoDB — database, often no auth by default",
}

# Ports that are CRITICAL if exposed
CRITICAL_PORTS = {2375, 6379, 9200, 27017, 3306, 5432, 1433, 23, 445, 3389}


def scan(domain: str) -> dict:
    """
    Uses Shodan InternetDB (free, no API key) to check
    what ports and services are exposed on the domain's IP.
    """
    findings = []
    exposed_ports = []
    ip_address = None
    cves = []
    tags = []

    try:
        # Step 1 — Resolve domain to IP
        ip_address = socket.gethostbyname(domain)

        # Step 2 — Query Shodan InternetDB (completely free, no key needed)
        url = f"https://internetdb.shodan.io/{ip_address}"
        response = requests.get(url, timeout=15)

        if response.status_code == 404:
            # IP not in Shodan database — not necessarily safe
            findings.append({
                "severity": "INFO",
                "title": "IP not in Shodan database",
                "detail": f"{ip_address} has no Shodan data. This could mean it's well-protected or recently changed.",
                "data": []
            })
            return {
                "scanner": "ports",
                "domain": domain,
                "ip": ip_address,
                "open_ports": [],
                "cves": [],
                "findings": findings
            }

        data = response.json()
        exposed_ports = data.get("ports", [])
        cves = data.get("vulns", [])
        tags = data.get("tags", [])

        # --- Check for risky open ports ---
        critical_found = []
        high_found = []

        for port in exposed_ports:
            if port in CRITICAL_PORTS:
                critical_found.append(port)
            elif port in RISKY_PORTS:
                high_found.append(port)

        if critical_found:
            descriptions = [f":{p} ({RISKY_PORTS[p]})" for p in critical_found]
            findings.append({
                "severity": "CRITICAL",
                "title": "Critical services exposed to internet",
                "detail": f"Dangerous ports open: {', '.join(descriptions)}",
                "data": critical_found
            })

        if high_found:
            descriptions = [f":{p} ({RISKY_PORTS.get(p, 'unknown service')})" for p in high_found]
            findings.append({
                "severity": "HIGH",
                "title": "Sensitive services exposed",
                "detail": f"Risky ports open: {', '.join(descriptions)}",
                "data": high_found
            })

        # --- Check for known CVEs ---
        if cves:
            findings.append({
                "severity": "CRITICAL",
                "title": "Known vulnerabilities detected",
                "detail": f"Shodan found {len(cves)} known CVE(s) on this IP: {', '.join(list(cves)[:5])}",
                "data": list(cves)
            })

        # --- Check for honeypot tag ---
        if "honeypot" in tags:
            findings.append({
                "severity": "INFO",
                "title": "Possible honeypot detected",
                "detail": "Shodan tagged this IP as a possible honeypot.",
                "data": tags
            })

    except socket.gaierror:
        findings.append({
            "severity": "INFO",
            "title": "DNS resolution failed",
            "detail": f"Could not resolve {domain} to an IP address.",
            "data": []
        })
    except requests.exceptions.Timeout:
        findings.append({
            "severity": "INFO",
            "title": "Shodan timeout",
            "detail": "Port scan timed out. Try again.",
            "data": []
        })
    except Exception as e:
        findings.append({
            "severity": "INFO",
            "title": "Port scan error",
            "detail": str(e),
            "data": []
        })

    return {
        "scanner": "ports",
        "domain": domain,
        "ip": ip_address,
        "open_ports": exposed_ports,
        "cves": list(cves),
        "findings": findings
    }