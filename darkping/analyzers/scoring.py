# How much each severity contributes to the exposure score
SEVERITY_WEIGHTS = {
    "CRITICAL": 35,
    "HIGH":     20,
    "MEDIUM":   10,
    "LOW":       3,
    "INFO":      0,
}

# Score thresholds that map to a risk level
RISK_LEVELS = [
    (80, "CRITICAL"),
    (50, "HIGH"),
    (20, "MEDIUM"),
    (0,  "LOW"),
]

RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold green",
}


def calculate_score(all_findings: list) -> dict:
    """
    Takes combined findings from all scanners and returns
    an exposure score summary.
    """

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for finding in all_findings:
        severity = finding.get("severity", "INFO")
        if severity in counts:
            counts[severity] += 1

    # Calculate raw score
    raw_score = sum(counts[sev] * SEVERITY_WEIGHTS[sev] for sev in counts)

    # Cap at 100
    score = min(raw_score, 100)

    # Determine risk level
    level = "LOW"
    for threshold, label in RISK_LEVELS:
        if score >= threshold:
            level = label
            break

    return {
        "raw_score": raw_score,
        "score": score,
        "level": level,
        "color": RISK_COLORS[level],
        "counts": counts,
        "total": len(all_findings)
    }