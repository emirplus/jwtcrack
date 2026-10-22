import http.server
import json
import os
import sys
import threading
import urllib.parse
import webbrowser
from typing import Dict, Any

from jwtcrack import __version__
from jwtcrack.decoder import decode_token
from jwtcrack.analyzer import analyze_token
from jwtcrack.cracker import crack_token
from jwtcrack.forger import forge_token, generate_token, forge_none_token

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORDLIST_PATH = os.path.join(BASE_DIR, "wordlists", "common.txt")

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>jwtcrack - GUI Dashboard</title>
<style>
  :root {
    --bg: #0b0f19;
    --card: #131b2e;
    --card-border: #1e293b;
    --accent: #06b6d4;
    --accent-hover: #0891b2;
    --green: #10b981;
    --red: #ef4444;
    --yellow: #f59e0b;
    --text: #f1f5f9;
    --text-muted: #94a3b8;
    --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    padding: 24px;
    max-width: 1200px;
    margin: 0 auto;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--card-border);
    margin-bottom: 24px;
  }
  .logo { font-size: 24px; font-weight: 800; color: var(--accent); font-family: var(--font-mono); }
  .badge { background: #1e293b; color: var(--accent); padding: 4px 8px; border-radius: 4px; font-size: 12px; }
  .card {
    background: var(--card);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    padding: 18px;
    margin-bottom: 20px;
  }
  h2 { font-size: 16px; margin-bottom: 12px; color: var(--text); display: flex; align-items: center; justify-content: space-between; }
  textarea, input {
    width: 100%;
    background: #070b14;
    border: 1px solid var(--card-border);
    color: var(--text);
    padding: 12px;
    border-radius: 6px;
    font-family: var(--font-mono);
    font-size: 13px;
    resize: vertical;
  }
  textarea:focus, input:focus { outline: none; border-color: var(--accent); }
  .btn-group { display: flex; gap: 10px; margin-top: 12px; }
  button {
    background: var(--accent);
    color: #041019;
    border: none;
    font-weight: 700;
    padding: 10px 18px;
    border-radius: 6px;
    cursor: pointer;
    transition: background 0.2s;
  }
  button:hover { background: var(--accent-hover); }
  button.secondary { background: #1e293b; color: var(--text); }
  button.secondary:hover { background: #334155; }
  button.success { background: var(--green); color: #041019; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 800px) { .grid { grid-template-columns: 1fr; } }
  pre {
    background: #070b14;
    padding: 14px;
    border-radius: 6px;
    overflow-x: auto;
    font-family: var(--font-mono);
    font-size: 12px;
    line-height: 1.5;
  }
  .finding {
    padding: 12px;
    border-radius: 6px;
    margin-bottom: 10px;
    background: #182238;
    border-left: 4px solid var(--text-muted);
  }
  .finding.CRITICAL { border-left-color: var(--red); background: rgba(239,68,68,0.1); }
  .finding.HIGH { border-left-color: var(--red); }
  .finding.MEDIUM { border-left-color: var(--yellow); }
  .finding.LOW { border-left-color: var(--accent); }
  .finding-title { font-weight: 700; font-size: 14px; margin-bottom: 4px; }
  .finding-desc { font-size: 12px; color: var(--text-muted); }
  .crack-box {
    background: rgba(16,185,129,0.1);
    border: 1px solid var(--green);
    padding: 16px;
    border-radius: 6px;
    margin-top: 14px;
    display: none;
  }
</style>
</head>
<body>
  <header>
    <div class="logo">jwtcrack <span class="badge">v0.1.0 GUI</span></div>
    <div style="font-size: 13px; color: var(--text-muted);">JWT Security Analyzer & Secret Cracker</div>
  </header>

  <div class="card">
    <h2>
      <span>Target Token</span>
      <button class="secondary" style="font-size: 11px; padding: 4px 8px;" onclick="loadSample()">Load Sample Token</button>
    </h2>
    <textarea id="tokenInput" rows="3" placeholder="Paste your JWT token here (eyJhbGciOi...)"></textarea>
    <div class="btn-group">
      <button onclick="runAudit()">Inspect & Analyze</button>
      <button class="secondary" onclick="runCrack()">Crack Secret</button>
      <button class="success" onclick="toggleForge()">Forge Admin Token</button>
    </div>
  </div>

  <div id="crackResult" class="crack-box"></div>

  <div class="grid">
    <div class="card">
      <h2>Header & Claims</h2>
      <div style="margin-bottom: 10px;">
        <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 4px;">HEADER:</div>
        <pre id="headerOutput">Waiting for token...</pre>
      </div>
      <div>
        <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 4px;">PAYLOAD:</div>
        <pre id="payloadOutput">Waiting for token...</pre>
      </div>
    </div>

    <div class="card">
      <h2>Security Findings</h2>
      <div id="findingsOutput" style="color: var(--text-muted); font-size: 13px;">No token analyzed yet.</div>
    </div>
  </div>

  <div id="forgeCard" class="card" style="display: none;">
    <h2>Forge Token with Custom Claims</h2>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 12px;">
      <div>
        <label style="font-size: 12px; color: var(--text-muted); display: block; margin-bottom: 4px;">Secret (or leave blank for alg:none):</label>
        <input id="forgeSecret" type="text" placeholder="e.g. password123">
      </div>
      <div>
        <label style="font-size: 12px; color: var(--text-muted); display: block; margin-bottom: 4px;">Claims to overwrite (JSON):</label>
        <input id="forgeClaims" type="text" value='{"role": "admin", "admin": true}'>
      </div>
    </div>
    <button class="success" onclick="executeForge()">Generate Forged Token</button>
    <div id="forgeResult" style="margin-top: 14px; display: none;">
      <div style="font-size: 12px; color: var(--green); margin-bottom: 6px; font-weight: 700;">FORGED TOKEN GENERATED:</div>
      <textarea id="forgedTokenOutput" rows="2" readonly></textarea>
      <button class="secondary" style="margin-top: 6px; font-size: 12px; padding: 6px 12px;" onclick="copyForged()">Copy to Clipboard</button>
    </div>
  </div>

<script>
const sampleToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkVtaXIiLCJyb2xlIjoidXNlciIsImlhdCI6MTY3MDAwMDAwMCwiZXhwIjoxNjcwMDAzNjAwfQ.jG53_1P1g5_c3s003w0d8vL7d19c118";

function loadSample() {
  document.getElementById('tokenInput').value = sampleToken;
  runAudit();
}

async function runAudit() {
  const token = document.getElementById('tokenInput').value.trim();
  if (!token) return alert('Please paste a JWT token.');

  try {
    const res = await fetch('/api/audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });
    const data = await res.json();
    if (data.error) return alert(data.error);

    document.getElementById('headerOutput').textContent = JSON.stringify(data.decoded.header, null, 2);
    document.getElementById('payloadOutput').textContent = JSON.stringify(data.decoded.payload, null, 2);

    const findingsDiv = document.getElementById('findingsOutput');
    findingsDiv.innerHTML = '';
    if (data.findings.length === 0) {
      findingsDiv.innerHTML = '<div style="color: var(--green);">[+] No vulnerabilities or misconfigurations detected.</div>';
    } else {
      data.findings.forEach(f => {
        const item = document.createElement('div');
        item.className = 'finding ' + f.severity;
        item.innerHTML = `<div class="finding-title">[${f.severity}] ${f.title}</div><div class="finding-desc">${f.description}</div>`;
        findingsDiv.appendChild(item);
      });
    }
  } catch (err) {
    alert('Failed to connect to local server: ' + err);
  }
}

async function runCrack() {
  const token = document.getElementById('tokenInput').value.trim();
  if (!token) return alert('Please paste a JWT token.');

  const crackBox = document.getElementById('crackResult');
  crackBox.style.display = 'block';
  crackBox.innerHTML = '<span style="color: var(--accent);">Cracking signature with multi-threaded dictionary attack...</span>';

  try {
    const res = await fetch('/api/crack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });
    const data = await res.json();
    if (data.success) {
      crackBox.innerHTML = `
        <div style="font-weight: 800; color: var(--green); font-size: 16px; margin-bottom: 4px;">CRACK SUCCESSFUL</div>
        <div>Found Secret: <strong style="color: #fff; background: #000; padding: 2px 6px; border-radius: 4px;">${data.secret}</strong></div>
        <div style="font-size: 12px; color: var(--text-muted); margin-top: 6px;">Tested ${data.attempts} passwords in ${data.elapsed.toFixed(3)}s (${Math.round(data.speed).toLocaleString()} attempts/sec)</div>
      `;
      document.getElementById('forgeSecret').value = data.secret;
    } else {
      crackBox.innerHTML = `<div style="color: var(--red); font-weight: 700;">Secret not found in default wordlist.</div>`;
    }
  } catch (err) {
    crackBox.innerHTML = `<div style="color: var(--red);">Error: ${err}</div>`;
  }
}

function toggleForge() {
  const card = document.getElementById('forgeCard');
  card.style.display = card.style.display === 'none' ? 'block' : 'none';
  if (card.style.display === 'block') card.scrollIntoView({ behavior: 'smooth' });
}

async function executeForge() {
  const token = document.getElementById('tokenInput').value.trim();
  const secret = document.getElementById('forgeSecret').value.trim();
  const claimsRaw = document.getElementById('forgeClaims').value.trim();

  let claims = {};
  try { claims = JSON.parse(claimsRaw); } catch(e) { return alert('Invalid JSON in claims field.'); }

  try {
    const res = await fetch('/api/forge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, secret, claims })
    });
    const data = await res.json();
    if (data.error) return alert(data.error);

    document.getElementById('forgeResult').style.display = 'block';
    document.getElementById('forgedTokenOutput').value = data.forged.token;
  } catch (err) {
    alert('Forge failed: ' + err);
  }
}

function copyForged() {
  const copyText = document.getElementById('forgedTokenOutput');
  copyText.select();
  navigator.clipboard.writeText(copyText.value);
  alert('Copied forged admin token to clipboard!');
}
</script>
</body>
</html>
"""

class JwtRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        try:
            payload = json.loads(body)
        except Exception:
            payload = {}

        if self.path == "/api/audit":
            token = payload.get("token", "")
            try:
                decoded = decode_token(token)
                findings = analyze_token(decoded)
                safe_decoded = {
                    "header": decoded["header"],
                    "payload": decoded["payload"],
                    "signature_b64": decoded["signature_b64"],
                }
                self._send_json({"decoded": safe_decoded, "findings": findings})
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)

        elif self.path == "/api/crack":
            token = payload.get("token", "")
            try:
                res = crack_token(token, WORDLIST_PATH, num_threads=8)
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)

        elif self.path == "/api/forge":
            token = payload.get("token", "")
            secret = payload.get("secret", "")
            claims = payload.get("claims", {})
            try:
                if not secret:
                    forged = forge_none_token(token, claims)
                else:
                    forged = forge_token(token, secret, claims)
                self._send_json({"forged": forged})
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)
        else:
            self.send_response(404)
            self.end_headers()

    def _send_json(self, data: Dict[str, Any], status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def log_message(self, format, *args):
        pass

def launch_gui(host: str = "127.0.0.1", port: int = 8765):
    server = http.server.ThreadingHTTPServer((host, port), JwtRequestHandler)
    url = f"http://{host}:{port}"
    print(f"[*] jwtcrack GUI dashboard running at {url}")
    print("[*] Press Ctrl+C in terminal to stop.")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down GUI server.")
        server.server_close()
