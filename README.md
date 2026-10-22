# jwtcrack

jwt token analyzer & secret brute-forcer.

inspects json web tokens, detects insecure configurations (alg:none, weak hmac algorithms, expired/missing claims), performs multi-threaded dictionary attacks against hs256/hs384/hs512 signatures to find weak secrets, and forges modified tokens for testing.

zero external dependencies beyond `rich` for terminal formatting. built using standard python crypto primitives.

## features

- **interactive web dashboard**: launch a local cyberpunk-styled dark mode gui in your browser (`jwtcrack gui`)
- **decode**: parse and inspect token header, payload, and signature without needing the signing key
- **analyze**: audit token security posture (`alg:none` bypasses, weak symmetric hmac, expired timestamps, missing standard claims)
- **crack**: multi-threaded wordlist attack against hs256, hs384, and hs512 tokens with live throughput stats
- **forge**: generate new tokens or alter existing claims (e.g. modify role or extend expiration) once the secret is known or with `alg:none`
- **zero dependencies**: pure python stdlib implementation (`hmac`, `hashlib`, `base64`, `concurrent.futures`)

## installation

```bash
git clone https://github.com/emirplus/jwtcrack.git
cd jwtcrack
pip install -e .
```

or run directly:

```bash
python -m jwtcrack gui
```

## usage

### launch web dashboard (recommended)
```bash
jwtcrack gui
```
opens an interactive dark-mode dashboard at `http://127.0.0.1:8765` in your default browser. Paste any token to view decoded claims, audit security warnings, crack the secret in real-time, and forge elevated admin tokens with one click.

### 1. decode a token
```bash
jwtcrack decode <token>
```

### 2. analyze for vulnerabilities
```bash
jwtcrack analyze <token>
```

### 3. brute-force weak secrets
```bash
jwtcrack crack <token> --wordlist wordlists/common.txt --threads 8
```

### 4. forge modified claims
```bash
jwtcrack forge <token> --secret "password123" --claims '{"role":"admin"}' --extend-exp 24h
```

### 5. generate a token from scratch
```bash
jwtcrack generate --secret "mysecret" --claims '{"sub":"user123","role":"admin"}'
```

### 6. interactive mode
run without arguments to launch the interactive prompt:
```bash
jwtcrack
```

## example output

### crack successful
```text
╭────────────────────────────── CRACK SUCCESSFUL ──────────────────────────────╮
│ Found Secret: password123                                                    │
│                                                                              │
│ Tested: 250 passwords                                                        │
│ Elapsed: 0.008 seconds                                                       │
│ Speed: 31,250 attempts/sec                                                   │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### analysis report
```text
                          Security Findings (2 issues)                          
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity     ┃ Issue                   ┃ Description                         ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│  CRITICAL    │ Algorithm None Attack   │ Token uses 'none' algorithm —       │
│              │                         │ signature verification is disabled. │
├──────────────┼─────────────────────────┼─────────────────────────────────────┤
│     LOW      │ Missing Claims          │ Token is missing: exp, iss.         │
└──────────────┴─────────────────────────┴─────────────────────────────────────┘
```

## license

MIT
