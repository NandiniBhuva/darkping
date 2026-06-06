import argparse
import sys
import os
import concurrent.futures
from rich.console import Console

from darkping.scanners import subdomains, breaches, ports, dns, urlscan, github_leaks
from darkping.analyzers.scoring import calculate_score
from darkping.analyzers.correlator import correlate
from darkping.report import (
    print_header, print_findings_table,
    print_scan_summary, print_score, print_ai_correlation
)

console = Console()


def run_all_scanners(domain: str, github_token: str = None) -> dict:
    """
    Runs all 5 scanners in parallel using ThreadPoolExecutor.
    Each scanner is independent so they can all run at the same time.
    Returns a dict of scanner_name -> result.
    """

    console.print("[dim]Running scanners in parallel...[/dim]\n")

    # Define all scanner tasks
    scanner_tasks = {
        "subdomains":   lambda: subdomains.scan(domain),
        "breaches":     lambda: breaches.scan(domain),
        "ports":        lambda: ports.scan(domain),
        "dns":          lambda: dns.scan(domain),
        "urlscan":      lambda: urlscan.scan(domain),
        "github_leaks": lambda: github_leaks.scan(domain, github_token),
    }

    results = {}

    # Run all scanners concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        future_to_name = {
            executor.submit(task): name
            for name, task in scanner_tasks.items()
        }

        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results[name] = future.result()
                console.print(f"  [green]✓[/green] [dim]{name}[/dim]")
            except Exception as e:
                console.print(f"  [red]✗[/red] [dim]{name}: {e}[/dim]")
                results[name] = {"scanner": name, "findings": []}

    console.print()
    return results


def collect_all_findings(scan_results: dict) -> list:
    """
    Collects all findings from all scanners into one flat list.
    Adds the scanner name to each finding for the report.
    """
    all_findings = []
    for scanner_name, result in scan_results.items():
        for finding in result.get("findings", []):
            finding["scanner"] = scanner_name
            all_findings.append(finding)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "INFO"), 4))

    return all_findings


def cmd_scan(args):
    """Runs the full darkping scan pipeline."""

    domain = args.domain.lower().strip()
    use_ai = args.ai
    github_token = os.environ.get("GITHUB_TOKEN")

    # Remove http/https if user included it
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]

    # Remove trailing slashes
    domain = domain.rstrip("/")

    # Print header
    print_header(domain)

    # Step 1 — Run all scanners in parallel
    scan_results = run_all_scanners(domain, github_token)

    # Step 2 — Collect and sort all findings
    all_findings = collect_all_findings(scan_results)

    # Step 3 — Print findings table
    print_findings_table(all_findings)

    # Step 4 — Print scan summary
    print_scan_summary(scan_results)

    # Step 5 — Calculate and print exposure score
    score_result = calculate_score(all_findings)
    print_score(score_result, domain)

    # Step 6 — AI correlation (optional)
    if use_ai:
        console.print("\n[dim]Running AI threat correlation...[/dim]")
        ai_result = correlate(domain, scan_results, all_findings, score_result)
        print_ai_correlation(ai_result)

    # Exit with code 1 if HIGH or CRITICAL
    if score_result["level"] in ["HIGH", "CRITICAL"]:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="darkping",
        description="Attacker's eye view of your domain — OSINT + AI correlation engine"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- scan subcommand ---
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a domain for exposure and vulnerabilities"
    )
    scan_parser.add_argument(
        "domain",
        help="Target domain to scan (e.g. example.com)"
    )
    scan_parser.add_argument(
        "--ai",
        action="store_true",
        help="Run AI-powered attack chain correlation (requires GROQ_API_KEY)"
    )
    scan_parser.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()