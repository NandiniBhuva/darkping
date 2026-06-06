from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich import box

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold white on red",
    "HIGH":     "bold white on orange1",
    "MEDIUM":   "bold black on yellow",
    "LOW":      "bold white on green",
    "INFO":     "bold white on blue",
}


def _severity_badge(severity: str) -> Text:
    style = SEVERITY_COLORS.get(severity, "white")
    return Text(f" {severity} ", style=style)


def print_header(domain: str):
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]darkping[/bold cyan] [dim]— Attacker's Eye View[/dim]\n"
        f"[dim]Target:[/dim] [bold white]{domain}[/bold white]",
        border_style="cyan"
    ))
    console.print()


def print_findings_table(all_findings: list):
    """Prints all findings from all scanners in one table."""

    if not all_findings:
        console.print(Panel(
            "[bold green]✓ No significant findings.[/bold green] This domain looks clean.",
            border_style="green"
        ))
        return

    # Filter out INFO findings for cleaner output
    real_findings = [f for f in all_findings if f.get("severity") != "INFO"]

    if not real_findings:
        console.print(Panel(
            "[bold green]✓ No significant findings.[/bold green] This domain looks clean.",
            border_style="green"
        ))
        return

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold dim",
        border_style="dim",
        expand=True
    )

    table.add_column("Severity", width=12, justify="center")
    table.add_column("Scanner", width=16)
    table.add_column("Finding", ratio=1)

    for finding in real_findings:
        severity = finding.get("severity", "INFO")
        scanner  = finding.get("scanner", "unknown")
        title    = finding.get("title", "")
        detail   = finding.get("detail", "")

        table.add_row(
            _severity_badge(severity),
            f"[dim]{scanner}[/dim]",
            f"[bold]{title}[/bold]\n[dim]{detail}[/dim]"
        )

    console.print(table)


def print_scan_summary(scan_results: dict):
    """Prints a quick summary of what each scanner found."""
    console.print()
    console.rule("[dim]Scan Summary[/dim]")
    console.print()

    summary_table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold dim",
        expand=False
    )

    summary_table.add_column("Scanner", width=18)
    summary_table.add_column("Result", width=40)

    # Subdomains
    sub = scan_results.get("subdomains", {})
    summary_table.add_row(
        "subdomains",
        f"{sub.get('total_subdomains', 0)} subdomains found"
    )

    # Breaches
    breach = scan_results.get("breaches", {})
    summary_table.add_row(
        "breaches",
        f"{breach.get('total_breaches', 0)} breach(es) found"
    )

    # Ports
    ports = scan_results.get("ports", {})
    port_list = ports.get("open_ports", [])
    cve_list = ports.get("cves", [])
    summary_table.add_row(
        "ports",
        f"{len(port_list)} open port(s), {len(cve_list)} CVE(s)"
    )

    # DNS
    dns = scan_results.get("dns", {})
    dns_findings = [f for f in dns.get("findings", []) if f.get("severity") != "INFO"]
    summary_table.add_row(
        "dns",
        f"{len(dns_findings)} misconfiguration(s) found"
    )

    # URLScan
    urlscan = scan_results.get("urlscan", {})
    summary_table.add_row(
        "urlscan",
        f"{urlscan.get('total_scans', 0)} recent scan(s) detected"
    )

    # GitHub
    github = scan_results.get("github_leaks", {})
    summary_table.add_row(
        "github_leaks",
        f"{github.get('total_results', 0)} public repo reference(s)"
    )

    console.print(summary_table)


def print_score(score_result: dict, domain: str):
    """Prints the exposure score panel."""

    level  = score_result["level"]
    score  = score_result["score"]
    color  = score_result["color"]
    counts = score_result["counts"]
    total  = score_result["total"]

    summary = Text()
    summary.append(f"  Exposure Score : ", style="dim")
    summary.append(f"{score}/100\n", style=color)
    summary.append(f"  Risk Level     : ", style="dim")
    summary.append(f"{level}\n", style=color)
    summary.append(f"  Findings       : ", style="dim")
    summary.append(f"{total} total", style="white")

    if total > 0:
        parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if counts[sev] > 0:
                parts.append(f"{counts[sev]} {sev}")
        summary.append(f"  ({', '.join(parts)})", style="dim")

    summary.append(f"\n  Target         : ", style="dim")
    summary.append(domain, style="dim")

    border_color = {
        "CRITICAL": "red",
        "HIGH":     "orange1",
        "MEDIUM":   "yellow",
        "LOW":      "green"
    }.get(level, "white")

    console.print()
    console.print(Panel(
        summary,
        title=f"[{color}] Exposure Result [/{color}]",
        border_style=border_color,
        expand=False
    ))


def print_ai_correlation(ai_result: dict):
    """Prints the AI attack chain correlation."""

    console.print()
    console.rule("[bold cyan]AI Threat Correlation[/bold cyan]")

    if not ai_result.get("success"):
        console.print(f"[red]AI correlation failed:[/red] {ai_result.get('error')}")
        return

    if ai_result.get("executive_summary"):
        console.print(Panel(
            ai_result["executive_summary"],
            title="[bold cyan]Executive Summary[/bold cyan]",
            border_style="cyan"
        ))

    if ai_result.get("attack_chains"):
        console.print(Panel(
            ai_result["attack_chains"],
            title="[bold red]Attack Chains[/bold red]",
            border_style="red"
        ))

    if ai_result.get("attacker_narrative"):
        console.print(Panel(
            ai_result["attacker_narrative"],
            title="[bold orange1]Attacker's Perspective[/bold orange1]",
            border_style="orange1"
        ))

    if ai_result.get("fixes"):
        console.print(Panel(
            ai_result["fixes"],
            title="[bold green]Prioritized Fixes[/bold green]",
            border_style="green"
        ))

    if ai_result.get("verdict"):
        console.print(Panel(
            f"[bold]→[/bold] {ai_result['verdict']}",
            title="[bold yellow]Verdict[/bold yellow]",
            border_style="yellow"
        ))