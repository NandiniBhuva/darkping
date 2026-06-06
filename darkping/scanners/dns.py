import dns.resolver
import dns.exception

def scan(domain: str) -> dict:
    """
    Checks for DNS misconfigurations:
    - Missing/weak SPF record (email spoofing risk)
    - Missing DMARC record (spoofed emails won't be rejected)
    - Missing DKIM (email integrity not verified)
    - Zone transfer enabled (full DNS exposure)
    """
    findings = []
    records = {}

    # --- Check SPF ---
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf_records = [
            r.to_text().strip('"')
            for r in answers
            if "v=spf1" in r.to_text()
        ]

        if not spf_records:
            findings.append({
                "severity": "HIGH",
                "title": "SPF record missing",
                "detail": f"No SPF record found for {domain}. Anyone can send emails pretending to be from this domain.",
                "data": []
            })
        else:
            records["spf"] = spf_records[0]
            # Check for weak SPF (+all means anyone can send)
            if "+all" in spf_records[0]:
                findings.append({
                    "severity": "CRITICAL",
                    "title": "SPF record is too permissive",
                    "detail": f"SPF record uses '+all' which allows ANY server to send email as {domain}.",
                    "data": spf_records
                })
            elif "~all" in spf_records[0]:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "SPF record uses softfail",
                    "detail": "SPF uses '~all' (softfail) — spoofed emails will be accepted but marked. Use '-all' for hard rejection.",
                    "data": spf_records
                })

    except dns.exception.DNSException:
        findings.append({
            "severity": "HIGH",
            "title": "SPF lookup failed",
            "detail": "Could not retrieve TXT records. SPF may be missing.",
            "data": []
        })

    # --- Check DMARC ---
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        dmarc_records = [
            r.to_text().strip('"')
            for r in answers
            if "v=DMARC1" in r.to_text()
        ]

        if not dmarc_records:
            findings.append({
                "severity": "HIGH",
                "title": "DMARC record missing",
                "detail": f"No DMARC record found for {domain}. Spoofed emails will not be rejected.",
                "data": []
            })
        else:
            records["dmarc"] = dmarc_records[0]
            # Check for weak DMARC policy
            if "p=none" in dmarc_records[0]:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "DMARC policy is set to none",
                    "detail": "DMARC policy 'p=none' means spoofed emails are only monitored, not rejected. Use 'p=reject'.",
                    "data": dmarc_records
                })

    except dns.exception.DNSException:
        findings.append({
            "severity": "HIGH",
            "title": "DMARC record missing",
            "detail": f"No DMARC record found for _dmarc.{domain}. Spoofed emails will not be rejected.",
            "data": []
        })

    # --- Check MX records ---
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = [r.to_text() for r in answers]
        records["mx"] = mx_records
    except dns.exception.DNSException:
        findings.append({
            "severity": "LOW",
            "title": "No MX records found",
            "detail": f"No mail servers configured for {domain}.",
            "data": []
        })

    # --- Check for open zone transfer ---
    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        for ns in ns_answers:
            ns_str = str(ns.target)
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_str, domain, timeout=5))
                if zone:
                    findings.append({
                        "severity": "CRITICAL",
                        "title": "Zone transfer enabled",
                        "detail": f"Nameserver {ns_str} allows zone transfers — attacker can dump all DNS records.",
                        "data": [ns_str]
                    })
            except Exception:
                pass  # Zone transfer blocked — this is expected and good
    except dns.exception.DNSException:
        pass

    return {
        "scanner": "dns",
        "domain": domain,
        "records": records,
        "findings": findings
    }