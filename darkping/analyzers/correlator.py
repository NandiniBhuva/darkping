import os
from groq import Groq

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))


def correlate(domain: str, scan_results: dict, all_findings: list, score_result: dict) -> dict:
    """
    Uses LLaMA 3.3 to analyze all findings together and produce:
    - Attack chains (how findings combine into real threats)
    - Executive summary
    - Prioritized fix list
    - Overall attacker narrative
    """

    if not all_findings:
        return {
            "success": True,
            "attack_chains": "No significant findings to correlate.",
            "executive_summary": f"No major exposure found for {domain}.",
            "fixes": "No immediate action required.",
            "attacker_narrative": "An attacker would find limited opportunity with this domain.",
        }

    # Format findings for the prompt
    findings_text = ""
    for finding in all_findings:
        if finding.get("severity") not in ["INFO"]:
            findings_text += f"[{finding['severity']}] {finding['title']}: {finding['detail']}\n"

    # Add scan metadata
    metadata = f"""
Domain: {domain}
Exposure Score: {score_result['score']}/100
Risk Level: {score_result['level']}
Total Findings: {score_result['total']}
Subdomains found: {scan_results.get('subdomains', {}).get('total_subdomains', 0)}
Breaches found: {scan_results.get('breaches', {}).get('total_breaches', 0)}
Open ports: {scan_results.get('ports', {}).get('open_ports', [])}
Known CVEs: {scan_results.get('ports', {}).get('cves', [])}
URLScan hits: {scan_results.get('urlscan', {}).get('total_scans', 0)}
GitHub results: {scan_results.get('github_leaks', {}).get('total_results', 0)}
"""

    prompt = f"""You are an elite offensive security researcher performing a threat assessment.

You have just completed automated reconnaissance on a target domain. Your job is NOT to 
just list findings — your job is to think like an attacker and identify how these findings 
COMBINE into real attack paths.

--- TARGET METADATA ---
{metadata}

--- FINDINGS FROM ALL SCANNERS ---
{findings_text}

Respond in EXACTLY this format:

EXECUTIVE SUMMARY:
[2-3 sentences. What is the overall exposure level and what's the single biggest risk?]

ATTACK CHAINS:
[Identify 2-3 specific attack chains where multiple findings combine. Format each as:
CHAIN 1: [Finding A] + [Finding B] → [What attacker can do] → [Business impact]
Be specific and realistic. If findings don't combine into chains, explain the top standalone risks.]

ATTACKER NARRATIVE:
[Write 3-4 sentences in first person as the attacker: "I would start by... then I would use... this gives me access to...". Make it realistic and specific to these findings.]

PRIORITIZED FIXES:
[List the top 3 most important fixes, numbered, most critical first. Be specific — not "fix DNS" but "Add DMARC record with p=reject policy to prevent email spoofing"]

VERDICT:
[One sentence — would a real attacker find this domain an easy target, medium effort, or hardened?]"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1500,
            temperature=0.3
        )

        response_text = response.choices[0].message.content
        sections = _parse_response(response_text)

        return {
            "success": True,
            "executive_summary": sections.get("EXECUTIVE SUMMARY", "").strip(),
            "attack_chains": sections.get("ATTACK CHAINS", "").strip(),
            "attacker_narrative": sections.get("ATTACKER NARRATIVE", "").strip(),
            "fixes": sections.get("PRIORITIZED FIXES", "").strip(),
            "verdict": sections.get("VERDICT", "").strip(),
            "raw_response": response_text
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "executive_summary": "",
            "attack_chains": "",
            "attacker_narrative": "",
            "fixes": "",
            "verdict": ""
        }


def _parse_response(text: str) -> dict:
    """Splits AI response into labeled sections."""
    sections = {}
    current_section = None
    current_lines = []

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.endswith(":") and stripped.upper() == stripped:
            if current_section:
                sections[current_section] = "\n".join(current_lines).strip()
            current_section = stripped[:-1]
            current_lines = []
        else:
            if current_section:
                current_lines.append(line)

    if current_section:
        sections[current_section] = "\n".join(current_lines).strip()

    return sections