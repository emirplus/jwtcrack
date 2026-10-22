import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

SEVERITY_STYLES = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


def display_decoded(decoded):
    console.print()
    console.print("[bold cyan]Token Breakdown[/bold cyan]")
    console.print()

    header_table = Table(title="Header", show_header=True, header_style="bold magenta")
    header_table.add_column("Claim", style="cyan")
    header_table.add_column("Value", style="white")
    for k, v in decoded["header"].items():
        header_table.add_row(str(k), json.dumps(v) if isinstance(v, (dict, list)) else str(v))
    console.print(header_table)
    console.print()

    payload_table = Table(title="Payload", show_header=True, header_style="bold magenta")
    payload_table.add_column("Claim", style="cyan")
    payload_table.add_column("Value", style="white")
    for k, v in decoded["payload"].items():
        payload_table.add_row(str(k), json.dumps(v) if isinstance(v, (dict, list)) else str(v))
    console.print(payload_table)
    console.print()

    sig_preview = decoded["signature_b64"][:32] + "..." if len(decoded["signature_b64"]) > 32 else (decoded["signature_b64"] or "[dim]None[/dim]")
    sig_panel = Panel(
        f"[dim]Algorithm:[/] [bold]{decoded['header'].get('alg', 'Unknown')}[/]\n"
        f"[dim]Signature (b64):[/] {sig_preview}",
        title="[bold]Signature Details[/bold]",
        border_style="cyan"
    )
    console.print(sig_panel)
    console.print()


def display_analysis(decoded, findings):
    display_decoded(decoded)

    if not findings:
        console.print("[bold green][+] No vulnerabilities or misconfigurations detected in token![/bold green]")
        console.print()
        return

    table = Table(title=f"Security Findings ({len(findings)} issues)", show_header=True, header_style="bold magenta")
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Issue", style="bold")
    table.add_column("Description")

    for f in findings:
        sev = f["severity"]
        style = SEVERITY_STYLES.get(sev, "white")
        table.add_row(f"[{style}] {sev} [/]", f["title"], f["description"])

    console.print(table)
    console.print()


def display_crack_result(result):
    console.print()
    if not result.get("success"):
        error_msg = result.get("error", "Secret not found in wordlist.")
        console.print(f"[bold red][-] Cracking failed:[/] {error_msg}")
        if result.get("elapsed"):
            console.print(f"[dim]Tried {result.get('attempts', 0)} words in {result['elapsed']:.2f}s ({result.get('speed', 0):.0f} words/sec)[/dim]")
        console.print()
        return

    secret = result["secret"]
    elapsed = result["elapsed"]
    speed = result["speed"]
    attempts = result["attempts"]

    content = Text()
    content.append("Found Secret: ", style="bold")
    content.append(f"{secret}\n\n", style="bold green on black")
    content.append(f"Tested: {attempts} passwords\n", style="dim")
    content.append(f"Elapsed: {elapsed:.3f} seconds\n", style="dim")
    content.append(f"Speed: {speed:,.0f} attempts/sec", style="cyan")

    panel = Panel(content, title="[bold green]CRACK SUCCESSFUL[/bold green]", border_style="green")
    console.print(panel)
    console.print()


def display_forged(forged):
    console.print()
    token = forged["token"]
    content = Text()
    content.append(f"{token}\n\n", style="bold cyan")
    content.append("Algorithm: ", style="bold")
    content.append(f"{forged['algorithm']}\n", style="yellow")
    content.append("Payload:\n", style="bold")
    content.append(json.dumps(forged["payload"], indent=2), style="dim")

    panel = Panel(content, title="[bold green]Forged JWT Token[/bold green]", border_style="green")
    console.print(panel)
    console.print()
