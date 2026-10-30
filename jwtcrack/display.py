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

    from jwtcrack.aspnet import is_aspnet_token, ASPNET_TO_STANDARD
    if is_aspnet_token(decoded["payload"]):
        aspnet_table = Table(title="ASP.NET Core Claims (Normalized)", show_header=True, header_style="bold green")
        aspnet_table.add_column("Standard Claim", style="bold green")
        aspnet_table.add_column("Value", style="white")
        aspnet_table.add_column("Original ASP.NET XML Schema URI", style="dim")
        for k, v in decoded["payload"].items():
            if k in ASPNET_TO_STANDARD:
                aspnet_table.add_row(ASPNET_TO_STANDARD[k], json.dumps(v) if isinstance(v, (dict, list)) else str(v), k)
        if aspnet_table.row_count > 0:
            console.print(aspnet_table)
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

    table = Table(title=f"Security Findings & Remediation ({len(findings)} issues)", show_header=True, header_style="bold magenta")
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Issue", style="bold", width=22)
    table.add_column("Description", width=34)
    table.add_column("How to Fix (Remediation)", style="green")

    for f in findings:
        sev = f["severity"]
        style = SEVERITY_STYLES.get(sev, "white")
        remediation = f.get("remediation", "Follow RFC 7519 guidelines.")
        table.add_row(f"[{style}] {sev} [/]", f["title"], f["description"], remediation)

    console.print(table)
    console.print()


def display_explanation(decoded, explanation):
    console.print()
    h_b64 = decoded["header_b64"]
    p_b64 = decoded["payload_b64"]
    s_b64 = decoded["signature_b64"]

    colored_token = Text()
    colored_token.append(h_b64, style="bold red")
    colored_token.append(".", style="white")
    colored_token.append(p_b64, style="bold green")
    colored_token.append(".", style="white")
    colored_token.append(s_b64 or "", style="bold cyan")

    token_panel = Panel(
        colored_token,
        title="[bold]Anatomy of a JWT[/bold]",
        subtitle="[red]Red: Header[/red] | [green]Green: Payload[/green] | [cyan]Cyan: Signature[/cyan]",
        border_style="magenta",
    )
    console.print(token_panel)
    console.print()

    alg_table = Table(title="1. Header & Cryptographic Algorithm", show_header=True, header_style="bold red")
    alg_table.add_column("Property", style="bold", width=20)
    alg_table.add_column("Value / Explanation", style="white")
    alg_table.add_row("Algorithm (alg)", explanation["algorithm"])
    alg_table.add_row("Key Type", explanation["algorithm_type"])
    alg_table.add_row("How It Works", explanation["algorithm_detail"])
    console.print(alg_table)
    console.print()

    claims_table = Table(title="2. Payload Claims (Decoded Data)", show_header=True, header_style="bold green")
    claims_table.add_column("Claim", style="bold green", width=14)
    claims_table.add_column("Standard Name", style="bold white", width=18)
    claims_table.add_column("Value", style="cyan", width=22)
    claims_table.add_column("Human Meaning / Purpose", style="dim")

    for c in explanation["claims"]:
        val_str = str(c["value"])
        if c.get("human_readable"):
            val_str += f"\n({c['human_readable']})"
        claims_table.add_row(c["key"], c["title"], val_str, c["description"])

    console.print(claims_table)
    console.print()

    tips_text = Text()
    tips_text.append("1. JWTs are NOT encrypted by default — anyone who sees the token can read all claims.\n", style="yellow")
    tips_text.append("2. The signature ONLY guarantees integrity (nobody changed the claims in transit).\n", style="white")
    tips_text.append("3. Never store passwords, API keys, or sensitive PII inside JWT claims.\n", style="red")
    tips_text.append("4. Always verify the signature server-side before trusting any claim value.\n", style="green")

    tips_panel = Panel(
        tips_text,
        title="[bold yellow]Beginner Security Rules[/bold yellow]",
        border_style="yellow",
    )
    console.print(tips_panel)
    console.print()


def display_labs(labs, active_lab=None):
    console.print()
    if active_lab:
        content = Text()
        content.append(f"Title: {active_lab['title']}\n", style="bold cyan")
        content.append(f"Difficulty: {active_lab['difficulty']}  |  Category: {active_lab['category']}\n\n", style="bold yellow")
        content.append("Objective:\n", style="bold white")
        content.append(f"{active_lab['objective']}\n\n", style="white")
        content.append("Challenge Token:\n", style="bold magenta")
        content.append(f"{active_lab['token']}\n\n", style="dim cyan")
        content.append("Hint:\n", style="bold green")
        content.append(f"{active_lab['hint']}\n", style="green")

        panel = Panel(
            content,
            title=f"[bold green]Practice Lab #{active_lab['id']}[/bold green]",
            border_style="green",
        )
        console.print(panel)
        console.print()
        return

    table = Table(title="Interactive Beginner Practice Labs (CTF)", show_header=True, header_style="bold cyan")
    table.add_column("ID", justify="center", width=6)
    table.add_column("Challenge Name", style="bold")
    table.add_column("Difficulty", justify="center", width=14)
    table.add_column("Category", width=20)
    table.add_column("Learning Objective")

    for lab in labs:
        diff_style = "green" if lab["difficulty"] == "Beginner" else "yellow"
        table.add_row(
            str(lab["id"]),
            lab["title"],
            f"[{diff_style}]{lab['difficulty']}[/{diff_style}]",
            lab["category"],
            lab["objective"],
        )

    console.print(table)
    console.print("[dim]Run 'jwtcrack lab <id>' (e.g. 'jwtcrack lab 1') to start a challenge.[/dim]\n")


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
