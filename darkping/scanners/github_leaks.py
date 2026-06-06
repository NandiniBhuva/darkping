import requests

GITHUB_SEARCH_API = "https://api.github.com/search/code"

# Patterns that suggest a real secret leak, not just a mention
SENSITIVE_PATTERNS = [
    "password", "passwd", "secret", "api_key", "apikey",
    "token", "credential", "private_key", "access_key",
    "auth", "connection_string", "database_url", "db_url",
    "smtp", "aws_secret", "private"
]


def scan(domain: str, github_token: str = None) -> dict:
    """
    Searches GitHub public code for leaked secrets containing the domain.
    Uses GitHub's code search API — works without token but rate limited.
    A token gives 30 requests/min vs 10/min unauthenticated.
    """
    findings = []
    leaks = []

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "darkping-security-scanner"
    }

    if github_token:
        headers["Authorization"] = f"token {github_token}"

    try:
        # Search for domain in public GitHub code
        params = {
            "q": f'"{domain}"',
            "per_page": 20
        }

        response = requests.get(
            GITHUB_SEARCH_API,
            headers=headers,
            params=params,
            timeout=15
        )

        # Handle rate limiting gracefully
        if response.status_code == 403:
            findings.append({
                "severity": "INFO",
                "title": "GitHub rate limit reached",
                "detail": "GitHub API rate limit hit. Set GITHUB_TOKEN env var for higher limits.",
                "data": []
            })
            return {
                "scanner": "github_leaks",
                "domain": domain,
                "total_results": 0,
                "leaks": [],
                "findings": findings
            }

        if response.status_code == 422:
            findings.append({
                "severity": "INFO",
                "title": "GitHub search unavailable",
                "detail": "GitHub code search returned an error. Try again later.",
                "data": []
            })
            return {
                "scanner": "github_leaks",
                "domain": domain,
                "total_results": 0,
                "leaks": [],
                "findings": findings
            }

        response.raise_for_status()
        data = response.json()
        total_count = data.get("total_count", 0)
        items = data.get("items", [])

        for item in items:
            repo = item.get("repository", {})
            leaks.append({
                "file": item.get("name"),
                "path": item.get("path"),
                "repo": repo.get("full_name"),
                "url": item.get("html_url"),
                "repo_private": repo.get("private", False)
            })

        # --- Flag based on total count ---
        if total_count > 50:
            findings.append({
                "severity": "HIGH",
                "title": "Domain widely referenced in public code",
                "detail": f"Found {total_count} public GitHub files containing '{domain}' — high chance of credential exposure.",
                "data": leaks[:5]
            })
        elif total_count > 10:
            findings.append({
                "severity": "MEDIUM",
                "title": "Domain referenced in public code",
                "detail": f"Found {total_count} public GitHub files containing '{domain}'.",
                "data": leaks[:5]
            })
        elif total_count > 0:
            findings.append({
                "severity": "LOW",
                "title": "Domain found in public repos",
                "detail": f"Found {total_count} public GitHub files containing '{domain}'. Review for accidental exposure.",
                "data": leaks
            })

        # --- Flag sensitive file types ---
        sensitive_files = [
            l for l in leaks
            if any(
                l["file"].endswith(ext)
                for ext in [".env", ".config", ".yml", ".yaml", ".json", ".xml", ".properties"]
            )
        ]

        if sensitive_files:
            findings.append({
                "severity": "CRITICAL",
                "title": "Domain in sensitive config files",
                "detail": f"Found in {len(sensitive_files)} config/env file(s) — likely contains credentials: {', '.join([l['file'] for l in sensitive_files[:3]])}",
                "data": sensitive_files
            })

    except requests.exceptions.Timeout:
        findings.append({
            "severity": "INFO",
            "title": "GitHub scan timeout",
            "detail": "GitHub search timed out. Try again.",
            "data": []
        })
    except Exception as e:
        findings.append({
            "severity": "INFO",
            "title": "GitHub scan error",
            "detail": str(e),
            "data": []
        })

    return {
        "scanner": "github_leaks",
        "domain": domain,
        "total_results": total_count if "total_count" in dir() else 0,
        "leaks": leaks,
        "findings": findings
    }