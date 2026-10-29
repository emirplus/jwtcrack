import argparse
import sys


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="jwtcrack",
        description="JWT Token Analyzer & Secret Brute-Forcer",
    )
    subparsers = parser.add_subparsers(dest="command")

    decode_parser = subparsers.add_parser("decode", help="Decode a JWT token")
    decode_parser.add_argument("token")
    decode_parser.add_argument("--aspnet", action="store_true", help="Normalize ASP.NET XML schema claims")

    subparsers.add_parser("analyze", help="Analyze token for vulnerabilities").add_argument("token")

    subparsers.add_parser("aspnet", help="Inspect and normalize ASP.NET Core XML schema claims").add_argument("token")

    crack_parser = subparsers.add_parser("crack", help="Brute-force the signing secret")
    crack_parser.add_argument("token")
    crack_parser.add_argument("--wordlist", "-w", required=True)
    crack_parser.add_argument("--threads", "-t", type=int, default=8)

    forge_parser = subparsers.add_parser("forge", help="Forge a modified token")
    forge_parser.add_argument("token")
    forge_parser.add_argument("--secret", "-s", required=True)
    forge_parser.add_argument("--claims", "-c", required=True)
    forge_parser.add_argument("--extend-exp", default=None)
    forge_parser.add_argument("--aspnet", action="store_true", help="Convert claims to ASP.NET XML schemas")

    gen_parser = subparsers.add_parser("generate", help="Generate a new JWT token")
    gen_parser.add_argument("--secret", "-s", required=True)
    gen_parser.add_argument("--claims", "-c", required=True)
    gen_parser.add_argument("--aspnet", action="store_true", help="Convert claims to ASP.NET XML schemas")

    gui_parser = subparsers.add_parser("gui", help="Launch interactive web dashboard")
    gui_parser.add_argument("--port", "-p", type=int, default=8765, help="Port to serve dashboard on")
    parser.add_argument("--gui", action="store_true", help="Launch interactive web dashboard")

    args = parser.parse_args()

    if args.gui or args.command == "gui":
        from jwtcrack.gui import launch_gui
        port = getattr(args, "port", 8765)
        launch_gui(port=port)
        return

    if args.command is None:
        _interactive_mode()
        return

    if args.command == "decode":
        from jwtcrack.decoder import decode_token
        from jwtcrack.display import display_decoded
        result = decode_token(args.token)
        if args.aspnet:
            from jwtcrack.aspnet import normalize_aspnet_claims
            result["payload"] = normalize_aspnet_claims(result["payload"])
        display_decoded(result)

    elif args.command == "analyze":
        from jwtcrack.decoder import decode_token
        from jwtcrack.analyzer import analyze_token
        from jwtcrack.display import display_analysis
        decoded = decode_token(args.token)
        findings = analyze_token(decoded)
        display_analysis(decoded, findings)

    elif args.command == "aspnet":
        from jwtcrack.decoder import decode_token
        from jwtcrack.aspnet import check_aspnet_issues
        from jwtcrack.display import display_analysis
        decoded = decode_token(args.token)
        findings = check_aspnet_issues(decoded["payload"])
        display_analysis(decoded, findings)

    elif args.command == "crack":
        from jwtcrack.cracker import crack_token
        from jwtcrack.display import display_crack_result
        result = crack_token(args.token, args.wordlist, args.threads)
        display_crack_result(result)

    elif args.command == "forge":
        import json
        from jwtcrack.forger import forge_token
        from jwtcrack.display import display_forged
        claims = json.loads(args.claims)
        forged = forge_token(args.token, args.secret, claims, args.extend_exp, as_aspnet=args.aspnet)
        display_forged(forged)

    elif args.command == "generate":
        import json
        from jwtcrack.forger import generate_token
        from jwtcrack.display import display_forged
        claims = json.loads(args.claims)
        token = generate_token(args.secret, claims, as_aspnet=args.aspnet)
        display_forged(token)


def _interactive_mode():
    try:
        from rich.prompt import Prompt
        from rich.console import Console

        console = Console()
        console.print("\n[bold cyan]jwtcrack[/bold cyan] — JWT Token Analyzer & Secret Brute-Forcer\n")

        token = Prompt.ask("[bold yellow]Paste your JWT token[/bold yellow]")
        if not token.strip():
            console.print("[red]No token provided.[/red]")
            sys.exit(1)

        action = Prompt.ask(
            "[bold yellow]What do you want to do?[/bold yellow]",
            choices=["decode", "analyze", "aspnet", "crack", "forge", "gui"],
            default="gui",
        )

        if action == "gui":
            from jwtcrack.gui import launch_gui
            launch_gui()
            return

        from jwtcrack.decoder import decode_token
        from jwtcrack.display import display_decoded, display_analysis, display_crack_result, display_forged

        if action == "decode":
            result = decode_token(token)
            display_decoded(result)

        elif action == "analyze":
            from jwtcrack.analyzer import analyze_token
            decoded = decode_token(token)
            findings = analyze_token(decoded)
            display_analysis(decoded, findings)

        elif action == "aspnet":
            from jwtcrack.aspnet import check_aspnet_issues
            decoded = decode_token(token)
            findings = check_aspnet_issues(decoded["payload"])
            display_analysis(decoded, findings)

        elif action == "crack":
            wordlist = Prompt.ask("[bold yellow]Path to wordlist[/bold yellow]", default="wordlists/common.txt")
            threads = int(Prompt.ask("[bold yellow]Threads[/bold yellow]", default="8"))
            from jwtcrack.cracker import crack_token
            result = crack_token(token, wordlist, threads)
            display_crack_result(result)

        elif action == "forge":
            secret = Prompt.ask("[bold yellow]Signing secret[/bold yellow]")
            claims_raw = Prompt.ask("[bold yellow]Claims JSON[/bold yellow]")
            import json
            from jwtcrack.forger import forge_token
            claims = json.loads(claims_raw)
            forged = forge_token(token, secret, claims)
            display_forged(forged)

    except KeyboardInterrupt:
        print("\nBye.")
        sys.exit(0)
