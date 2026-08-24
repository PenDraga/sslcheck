#!/usr/bin/env python3
"""
TLS- & Zertifikatskette-Web-Check (abgespecktes SSL-Labs) im LAN.

Nur Python-Standardbibliothek. Start:
    python3 tlscheck_web.py                # Port 8765, 0.0.0.0
    python3 tlscheck_web.py --port 9000 --bind 127.0.0.1

Passwort-Schutz (optional):
    TLS_CHECK_PASSWORD="meinpasswort" python3 tlscheck_web.py
    (alternativ gehasht: TLS_CHECK_PASSWORD="hash:ITER$salt$dk" – Hash erzeugen
     mit: python3 tlscheck_web.py --make-hash)

Die eigentliche Prüfung läuft serverseitig als Subprozess:
    python3 tlscheck.py <host> --json
Damit bleibt jede Anfrage isoliert (keine Global-State-Probleme bei
mehreren parallelen Checks) und der Truststore-Build pro Check ist klein.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

HERE = Path(__file__).resolve().parent
CHECKER = HERE / "tlscheck.py"
PY = sys.executable or "python3"

# Max. parallele Checks (Subprocess-Budget) – davor: 503.
MAX_CONCURRENT_CHECKS = 5
_check_slots = threading.Semaphore(MAX_CONCURRENT_CHECKS)

# --- Passwort-Auth (optional, via ENV) -------------------------------------
# TLS_CHECK_PASSWORD gesetzt  → Login erforderlich (HTTP Basic / Cookie-Session).
# TLS_CHECK_SECRET optional → Session-Cookie-Signatur (Default: zufällig pro
#   Start; Sessions enden beim Neustart).
AUTH_ENABLED = bool(os.environ.get("TLS_CHECK_PASSWORD"))
_SESSION_SECRET = os.environ.get("TLS_CHECK_SECRET") or secrets.token_hex(32)
_SESSION_TTL = 12 * 3600          # 12 h gültig
_LOGIN_MAX_ATTEMPTS = 10         # dann 5 min Sperre
_login_failures = 0
_login_locked_until = 0.0
_login_lock = threading.Lock()

PBKDF2_ITER = 200_000


def _password_hash(password):
    """PBKDF2-HMAC-SHA256 (iter, salt hex, hash hex)."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                             PBKDF2_ITER)
    return f"{PBKDF2_ITER}${salt.hex()}${dk.hex()}"


def _password_ok(password):
    """Prüft Passwort gegen ENV-TLS_CHECK_PASSWORD (plain oder hash-Format)."""
    ref = os.environ["TLS_CHECK_PASSWORD"]
    if ref.startswith(("plain:", "hash:")):
        kind, ref = ref.split(":", 1)
    else:
        kind = "plain"
    pw = password.encode("utf-8")
    if kind == "plain":
        return hmac.compare_digest(ref.encode("utf-8"), pw)
    try:
        iters_s, salt_s, dk_s = ref.split("$", 2)
        iters, salt, dk = int(iters_s), bytes.fromhex(salt_s), bytes.fromhex(dk_s)
    except (ValueError, TypeError):
        return False
    calc = hashlib.pbkdf2_hmac("sha256", pw, salt, iters)
    return hmac.compare_digest(calc, dk)


def _issue_session_cookie():
    """Erstellt Signed+HMAC Session-Cookie-Wert (token|ttl|hmac)."""
    token = secrets.token_hex(32)
    exp = int(time.time()) + _SESSION_TTL
    sig = hmac.new(_SESSION_SECRET.encode("utf-8"),
                   f"{token}|{exp}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{token}|{exp}|{sig}"


def _session_cookie_ok(cookie_value):
    try:
        token, exp_s, sig = cookie_value.split("|", 2)
        exp = int(exp_s)
    except (ValueError, TypeError):
        return False
    expect = hmac.new(_SESSION_SECRET.encode("utf-8"),
                      f"{token}|{exp}".encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expect) or exp < time.time():
        return False
    return True


def _login_allowed():
    """Rate-Limit: nach N Fehlversuchen 5 min Sperre."""
    global _login_failures, _login_locked_until
    with _login_lock:
        if _login_locked_until and time.time() < _login_locked_until:
            return False
        if _login_failures >= _LOGIN_MAX_ATTEMPTS:
            _login_locked_until = time.time() + 300
            _login_failures = 0
            return False
        return True


def _login_note_success():
    global _login_failures, _login_locked_until
    with _login_lock:
        _login_failures = 0
        _login_locked_until = 0.0


def _login_note_failure():
    global _login_failures
    with _login_lock:
        _login_failures += 1


def _cookie_named(name, raw):
    """Sucht einen Cookie-Wert im raw-Cookie-Header (None falls nicht da)."""
    for part in (raw or "").split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            return part[len(name) + 1:]
    return None

# Host muss wie ein Hostname / IP (optional mit :Port) aussehen.
HOST_RE = re.compile(
    r"^(?:"
    r"[\d.]{7,15}"                                  # IPv4
    r"|[0-9A-Fa-f:]{2,39}"                          # IPv6 (kurz)
    r"|[A-Za-z0-9]([A-Za-z0-9.\-]{0,253})?"         # Hostname
    r")?(?::\d{1,5})?$"
)


def run_check(hostport, timeout=120, ocsp=False, no_aia=False, fast=False):
    """tlscheck.py als Subprozess ausführen -> (json-obj|dict, exitcode)."""
    cmd = [PY, str(CHECKER), hostport, "--json"]
    if timeout:
        cmd += ["--timeout", str(timeout)]
    if ocsp:
        cmd += ["--ocsp"]
    if no_aia:
        cmd += ["--no-aia"]
    if fast:
        cmd += ["--fast"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return {"host": hostport, "error": "Prüfung dauerte zu lange (Timeout)."}, 2
    out = (p.stdout or "").strip() or (p.stderr or "").strip()
    try:
        return json.loads(out), p.returncode
    except json.JSONDecodeError:
        return {"host": hostport, "error": out or "keine Ausgabe"}, 2


INDEX_HTML = r"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TLS- &amp; Zertifikats-Check</title>
<style>
:root{
  color-scheme:dark;
  --bg:#0b0f17; --panel:#101624; --panel2:#171f31; --line:#243047;
  --txt:#e9eef7; --dim:#8f9db3;
  --ok:#34d399; --warn:#fbbf24; --bad:#f87171;
  --ok-soft:rgba(52,211,153,.10); --warn-soft:rgba(251,191,36,.12); --bad-soft:rgba(248,113,113,.12);
  --accent:#4f8cff; --accent2:#7c5cff;
  --radius:14px; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --shadow:0 1px 2px rgba(0,0,0,.35),0 10px 30px rgba(0,0,0,.22);
  --grad1:rgba(79,140,255,.10);
}
html[data-theme="light"]{
  color-scheme:light;
  --bg:#f3f5fa; --panel:#ffffff; --panel2:#eef2f8; --line:#dce3ef;
  --txt:#1b2436; --dim:#5c6a82;
  --ok:#0f9d58; --warn:#b45309; --bad:#dc2626;
  --ok-soft:rgba(15,157,88,.10); --warn-soft:rgba(180,83,9,.12); --bad-soft:rgba(220,38,38,.10);
  --accent:#2563eb; --accent2:#7c3aed;
  --shadow:0 1px 2px rgba(16,24,40,.05),0 10px 30px rgba(16,24,40,.07);
  --grad1:rgba(37,99,235,.08);
}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;color:var(--txt);
  background:radial-gradient(1100px 480px at 85% -8%,var(--grad1),transparent 60%),var(--bg);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  padding:0 16px 70px;transition:background-color .25s ease,color .25s ease}
.topbar{position:sticky;top:0;z-index:20;margin:0 -16px 22px;
  background:var(--bg);background:color-mix(in srgb,var(--bg) 82%,transparent);
  -webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px);
  border-bottom:1px solid var(--line);transition:background-color .25s ease,border-color .25s}
.topbar-in{max-width:960px;margin:0 auto;padding:12px 2px;display:flex;
  align-items:center;justify-content:space-between;gap:12px}
.brand{display:flex;align-items:center;gap:12px;min-width:0}
.brand svg{flex:0 0 auto}
h1{font-size:17px;font-weight:700;margin:0;letter-spacing:-.01em}
.sub{color:var(--dim);font-size:12px;margin-top:1px}
#themebtn{width:38px;height:38px;flex:0 0 auto;border-radius:10px;border:1px solid var(--line);
  background:var(--panel2);color:var(--dim);cursor:pointer;display:flex;align-items:center;
  justify-content:center;transition:color .15s,border-color .15s,background-color .25s}
#themebtn:hover{color:var(--txt);border-color:var(--accent)}
#themebtn svg{width:19px;height:19px}
.icon-moon{display:none}
html[data-theme="dark"] .icon-sun{display:block}
html[data-theme="light"] .icon-moon{display:block}
.wrap{max-width:960px;margin:0 auto}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  padding:20px;margin-bottom:16px;box-shadow:var(--shadow);
  transition:background-color .25s ease,border-color .25s}
label{color:var(--dim);font-size:11.5px;font-weight:600;display:block;margin-bottom:7px;
  letter-spacing:.05em;text-transform:uppercase}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.field{flex:1;min-width:230px}
input[type=text]{width:100%;background:var(--panel2);border:1px solid var(--line);
  color:var(--txt);border-radius:10px;padding:12px 14px;font-size:14.5px;font-family:var(--mono);
  transition:border-color .15s,box-shadow .15s,background-color .25s}
input[type=text]::placeholder{color:var(--dim);opacity:.7}
input[type=text]:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(79,140,255,.22)}
.chk{display:flex;align-items:center;gap:8px;background:var(--panel2);
  border:1px solid var(--line);border-radius:10px;padding:10px 13px;cursor:pointer;white-space:nowrap;
  transition:background-color .25s,border-color .25s}
.chk:hover{border-color:var(--accent)}
.chk input{width:16px;height:16px;accent-color:var(--accent)}
.chk span{font-size:13px;color:var(--txt)}
#go{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:none;
  border-radius:10px;padding:12px 26px;font-size:14.5px;font-weight:650;cursor:pointer;letter-spacing:.01em;
  box-shadow:0 3px 12px rgba(79,140,255,.30);transition:transform .12s,filter .12s,box-shadow .12s}
#go:hover:not(:disabled){transform:translateY(-1px);filter:brightness(1.07);box-shadow:0 5px 16px rgba(79,140,255,.40)}
#go:active:not(:disabled){transform:translateY(0)}
#go:disabled{opacity:.55;cursor:not-allowed}
.gradebar{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.badge{font-size:32px;font-weight:800;width:68px;height:68px;border-radius:18px;letter-spacing:-.02em;
  display:flex;align-items:center;justify-content:center;flex:0 0 auto;box-shadow:0 5px 16px rgba(0,0,0,.22)}
.grade-F{background:linear-gradient(135deg,#f87171,#ef4444);color:#fff}
.grade-C{background:linear-gradient(135deg,#fbbf24,#f59e0b);color:#2b1d00}
.grade-B,.grade-A-,.grade-A{background:linear-gradient(135deg,#34d399,#10b981);color:#04261b}
.grade-note{font-size:14.5px;font-weight:500;max-width:560px}
.proto{color:var(--dim);font-size:12.5px;margin-top:6px}
.list{list-style:none;padding:0;margin:10px 0 0}
.list li{padding:9px 0;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:flex-start}
.list li:last-child{border-bottom:none}
.tag{font-size:10.5px;font-weight:700;padding:3px 9px;border-radius:999px;flex:0 0 auto;
  text-transform:uppercase;letter-spacing:.06em;margin-top:2px}
.tag.p{background:var(--bad-soft);color:var(--bad)}
.tag.w{background:var(--warn-soft);color:var(--warn)}
.tag.i{background:var(--panel2);color:var(--dim);border:1px solid var(--line)}
.tag.ok{background:var(--ok-soft);color:var(--ok)}
.okbox{color:var(--ok);font-weight:600}
h2{font-size:11.5px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:var(--dim);
  margin:0 0 14px}
.kv{display:grid;grid-template-columns:200px 1fr;gap:10px 16px;font-size:14px}
.kv dt{color:var(--dim);font-size:12.5px;padding-top:2px}
.kv dd{margin:0;word-break:break-word;font-family:var(--mono);font-size:13px}
.chainbox{background:var(--panel2);border:1px solid var(--line);border-radius:10px;
  padding:12px 14px;margin-bottom:8px;transition:background-color .25s,border-color .25s}
.chainbox.srv{border-left:3px solid var(--ok)}
.chainbox.ts{border-left:3px solid var(--accent)}
.chainbox.miss{border-left:3px solid var(--bad)}
.chainbox .c-head{font-weight:600;margin-bottom:2px;font-size:13.5px}
.chainbox .c-sub{color:var(--dim);font-size:12px;font-family:var(--mono)}
.chip{display:inline-flex;align-items:center;gap:6px;padding:5px 13px;border-radius:999px;
  font-size:12.5px;font-family:var(--mono);margin:0 8px 8px 0;border:1px solid var(--line);
  background:var(--panel2);color:var(--dim);transition:background-color .25s,border-color .25s}
.chip.on{border-color:transparent;color:var(--ok);background:var(--ok-soft);font-weight:600}
.chip.off{opacity:.55}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:9px 8px;vertical-align:top}
th{color:var(--dim);font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;
  border-bottom:1px solid var(--line)}
tr+tr td{border-top:1px solid var(--line)}
td.name{font-family:var(--mono);word-break:break-all}

/* CRL-Liste (mobiltauglich: Karten statt Tabellenspalten) */
.crls{margin-top:10px;display:flex;flex-direction:column;gap:8px}
.crlrow{display:grid;grid-template-columns:auto 1fr;gap:4px 10px;align-items:baseline;
  padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--panel2)}
.crlrow .dot{grid-row:1/4;width:10px;height:10px;border-radius:50%;align-self:center}
.crlrow .dot.ok{background:var(--ok);box-shadow:0 0 8px var(--ok)}
.crlrow .dot.bad{background:var(--bad);box-shadow:0 0 8px var(--bad)}
.crlrow .dot.na{background:var(--dim)}
.crlrow .crl-url{font-family:var(--mono);font-size:12.5px;word-break:break-all}
.crlrow .crl-meta{color:var(--dim);font-size:12px;word-break:break-word}
.cat-S{color:var(--ok);font-weight:600}
.cat-W{color:var(--warn);font-weight:600}
.cat-X{color:var(--bad);font-weight:600}
.dim{color:var(--dim)}
.errbox{background:var(--bad-soft);border:1px solid var(--bad);color:var(--txt);
  border-radius:10px;padding:12px;font-family:var(--mono);font-size:13px;white-space:pre-wrap}
.mono{font-family:var(--mono);font-size:12px}
#raw{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:14px;
  max-height:420px;overflow:auto}
.spin{display:inline-block;width:14px;height:14px;border:2px solid rgba(140,150,170,.3);
  border-top-color:var(--accent);border-radius:50%;animation:sp .7s linear infinite;
  vertical-align:-2px;margin-right:6px}
@keyframes sp{to{transform:rotate(360deg)}}
.foot{color:var(--dim);font-size:12px;text-align:center;margin-top:8px;opacity:.85}
.hide{display:none}
@media(max-width:600px){
  .kv{grid-template-columns:1fr}.kv dt{margin-top:4px}
  .wrap{padding:0 12px}
  table{font-size:12px}
  th,td{padding:7px 6px}
  th{white-space:nowrap}
  td{word-break:break-word}
  .gradebar{gap:12px}.badge{font-size:26px;width:56px;height:56px;border-radius:14px}
  .row{align-items:stretch}.chk{justify-content:center}
}
</style>
</head>
<body>
<div class="topbar">
  <div class="topbar-in">
    <div class="brand">
      <svg width="34" height="34" viewBox="0 0 34 34" fill="none" aria-hidden="true">
        <path d="M17 3 L28.5 7.5 v8.2 c0 6.9-4.9 12.4-11.5 14.8 C10.4 28.1 5.5 22.6 5.5 15.7 V7.5 Z"
              fill="url(#tg)" stroke="var(--line)" stroke-width="1"/>
        <path d="M12.5 17.2 l3.2 3.2 L22 14" stroke="#fff" stroke-width="2.4"
              stroke-linecap="round" stroke-linejoin="round"/>
        <defs>
          <linearGradient id="tg" x1="5.5" y1="3" x2="28.5" y2="30.5"
                          gradientUnits="userSpaceOnUse">
            <stop stop-color="var(--accent)"/><stop offset="1" stop-color="var(--accent2)"/>
          </linearGradient>
        </defs>
      </svg>
      <div>
        <h1>TLS- &amp; Zertifikats-Check</h1>
        <div class="sub">Kette, Protokolle, Webserver, Revocation – im LAN</div>
      </div>
    </div>
    <button id="themebtn" title="Thema umschalten" aria-label="Dunkel-/Hellmodus umschalten">
      <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round">
        <circle cx="12" cy="12" r="4.2"/>
        <path d="M12 2.5v2.4M12 19.1v2.4M2.5 12h2.4M19.1 12h2.4M5.2 5.2l1.7 1.7M17.1 17.1l1.7 1.7M18.8 5.2l-1.7 1.7M6.9 17.1l-1.7 1.7"/>
      </svg>
      <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M20.5 14.5A8.5 8.5 0 0 1 9.5 3.5a8.5 8.5 0 1 0 11 11Z"/>
      </svg>
    </button>
  </div>
</div>
<div class="wrap">
  <div class="card">
    <div class="row">
      <div class="field">
        <label for="host">Hostname / IP (optional mit :Port)</label>
        <input type="text" id="host" placeholder="example.com  oder  10.0.0.5:8443" autocomplete="off" spellcheck="false">
      </div>
      <label class="chk"><input type="checkbox" id="ocsp"><span>OCSP prüfen</span></label>
      <label class="chk"><input type="checkbox" id="noaia"><span>AIA überspringen</span></label>
      <label class="chk" title="Überspringt CRL, OCSP-Stapling, Session-Resume & HTTP/3 (Schnellcheck)"><input type="checkbox" id="fast"><span>Schnellcheck</span></label>
      <button id="go">Prüfen</button>
    </div>
  </div>

  <div id="status"></div>
  <div id="result"></div>
  <div id="rawwrap" class="card hide">
    <h2>Roh-JSON</h2>
    <pre id="raw" class="mono" style="white-space:pre-wrap;margin:0"></pre>
  </div>
  <div class="foot">Läuft lokal im LAN · Datenquelle: <span class="mono">tlscheck.py --json</span></div>
</div>

<script>
// --- Thema (Dunkel/Hell), persistiert in localStorage ----------------------
const rootEl=document.documentElement;
function applyTheme(t){rootEl.setAttribute("data-theme",t);try{localStorage.setItem("tlscheck-theme",t)}catch(e){}}
(function initTheme(){
  let t=null;try{t=localStorage.getItem("tlscheck-theme")}catch(e){}
  if(!t)t=window.matchMedia&&matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";
  applyTheme(t);
})();
document.getElementById("themebtn").addEventListener("click",()=>{
  applyTheme(rootEl.getAttribute("data-theme")==="light"?"dark":"light");
});
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const gradeClass=g=>["F","C","B","A-","A"].includes(g)?`grade-${g}`:"grade-B";
function badge(g){return `<div class="badge ${gradeClass(g)}">${esc(g)}</div>`}

function chip(avail,txt){return `<span class="chip ${avail?"on":"off"}">${esc(txt)} ${avail?"✓":"—"}</span>`}

function render(r){
  if(r.error){return `<div class="card"><div class="errbox">${esc(r.error)}</div></div>`}
  const s=r.summary, c=r.certificate, ch=r.chain;
  const sanIp=c.san_ip?(Array.isArray(c.san_ip)?c.san_ip.join(", "):String(c.san_ip)):null;
  let h="";

  // Fehler-Banner
  h+=`<div class="card"><div class="gradebar">
    ${badge(s.grade)}
    <div>
      <div class="grade-note">${esc(s.note)}</div>
      <div class="proto">Prüfzeit: ${esc(r.checked_at_utc)} UTC &nbsp;·&nbsp; Verhandelte Version: <b>${esc(r.negotiated_protocol||"unbekannt")}</b></div>
    </div>
  </div>`;
  const probs=s.problems||[], warn=s.warnings||[];
  if(probs.length||warn.length){
    h+=`<ul class="list">`;
    probs.forEach(p=>h+=`<li><span class="tag p">Problem</span><span>${esc(p)}</span></li>`);
    warn.forEach(p=>h+=`<li><span class="tag w">Warnung</span><span>${esc(p)}</span></li>`);
    h+=`</ul>`;
  } else {
    h+=`<div class="okbox" style="margin-top:10px">✓ Keine Probleme, keine Warnungen.</div>`;
  }
  h+=`</div>`;

  // Zertifikat
  h+=`<div class="card"><h2>Endzertifikat</h2>
  <dl class="kv">
    <dt>Hostname-Match</dt><dd>${c.hostname_match?"✓ ":"✗ "} <b>${esc(c.hostname_matched_name||"(kein Match)")}</b></dd>
    <dt>SAN (DNS)</dt><dd>${c.san_dns&&c.san_dns.length?esc(c.san_dns.join(", ")):"–"}${sanIp?` <span class="dim">IP: ${esc(sanIp)}</span>`:""}</dd>
    <dt>Subject</dt><dd>${esc(c.subject)}</dd>
    <dt>Issuer</dt><dd>${esc(c.issuer)}</dd>
    <dt>Serial</dt><dd>${esc(c.serial)}</dd>
    <dt>Gültig</dt><dd>${esc(c.not_before)} → ${esc(c.not_after)} <span class="${c.days_left>0?"":"dim"}">(${c.days_left} Tage)</span></dd>
    <dt>Signatur / Schlüssel</dt><dd>${esc(c.signature_algorithm)} · ${esc(c.public_key)}</dd>
    <dt>AIA (CA Issuers)</dt><dd class="dim">${esc(c.aia_ca||"–")}</dd>
    <dt>OCSP-URL</dt><dd class="dim">${esc(c.ocsp_url||"–")}</dd>
  </dl></div>`;

  // Kette (geordnet leaf → root, Karten mit Pro-Zertifikat-Quellen-Badge)
  h+=`<div class="card"><h2>Zertifikatskette (Endzertifikat → Root)</h2>`;
  const fc=ch.full_chain||[];
  const srcBadge=s=>s==="server"
      ?`<span class="tag ok">Vom Server gesendet</span>`
      :s==="truststore"
        ?`<span class="tag i">Aus Truststore (nicht vom Server)</span>`
        :`<span class="tag p">Fehlt (weder Server noch lokal)</span>`;
  if(fc.length){
    fc.forEach((p,i)=>{
      const cls=p.source==="server"?"srv":p.source==="truststore"?"ts":"miss";
      const role=i===0?"Endzertifikat":(p.self_signed?"Root":"Zwischenzertifikat");
      h+=`<div class="chainbox ${cls}">
        <div class="c-head">${role} ${srcBadge(p.source)}${p.self_signed?" <span class='dim'>(self-signed)</span>":""}</div>
        <div class="c-sub">${esc(p.subject)}</div>
        <div class="c-sub">${p.issuer?`Issuer: ${esc(p.issuer)} · `:""}${p.serial?`Serial ${esc(p.serial)} · `:""}${p.valid_to?`gültig bis ${esc(p.valid_to)}`:""}</div>
      </div>`;
    });
  } else {
    (ch.presented||[]).forEach((p,i)=>{
      const tag=i===0?"Endzertifikat":i===1?"Zwischenzertifikat":(i===2?"Root":"Glied "+i);
      h+=`<div class="chainbox srv">
        <div class="c-head">${tag} ${srcBadge("server")}${p.self_signed?" <span class='dim'>(self-signed)</span>":""}</div>
        <div class="c-sub">${esc(p.subject)}</div>
        <div class="c-sub">Issuer: ${esc(p.issuer)} · Serial ${esc(p.serial)} · gültig bis ${esc(p.valid_to)}</div>
      </div>`;
    });
  }
  const vsp=ch.verify_with_server_chain, vst=ch.verify_with_truststore;
  h+=`<table><tr><th>Verifikation</th><th>Ergebnis</th><th>Detail</th></tr>
    <tr><td>Nur Server-Kette</td>
       <td class="${vsp.ok?"cat-S":"cat-X"}">${vsp.ok?"erfolgreich":"FEHLGESCHLAGEN"}</td>
       <td class="dim mono">${esc(vsp.detail||"")}</td></tr>
    <tr><td>mit lokalem Truststore</td>
       <td class="${vst.ok?"cat-S":"cat-X"}">${vst.ok?"erfolgreich":"FEHLGESCHLAGEN"}</td>
       <td class="dim mono">${esc(vst.detail||"")}</td></tr></table>`;

  const missing=ch.missing_from_server||[];
  h+=`<div style="margin-top:12px">${
    missing.length
      ? `<span class="tag w">Fehlt am Server</span> <span class="dim">– Client muss sie beschaffen (Truststore/AIA):</span>
         <ul class="list">${missing.map(m=>`<li class="mono">${m.in_truststore?"<span class='tag i'>im Truststore</span>":"<span class='tag p'>nicht lokal</span>"} ${esc(m.subject)} <span class="dim">(Serial ${esc(m.serial)})</span></li>`).join("")}</ul>`
      : `<span class="okbox">✓ Kette komplett vom Server${ch.root_presented_by_server?" (inkl. Root)":""}.</span>`
  }</div>`;

  const aia=ch.aia||[];
  if(aia.length){
    h+=`<table style="margin-top:8px"><tr><th>AIA</th><th>Erreichbar</th><th>Note</th></tr>`+
      aia.map(a=>`<tr><td class="mono">${esc(a.url||"(kein Eintrag)")}</td>
        <td class="${a.reachable===true?"cat-S":a.reachable===false?"cat-X":"dim"}">${a.reachable===true?"✓":a.reachable===false?"✗":"n/a"}</td>
        <td class="dim">${esc(a.note||"")}</td></tr>`).join("")+`</table>`;
  }
  (ch.notes||[]).forEach(n=>h+=`<div class="dim" style="margin-top:6px">(i) ${esc(n)}</div>`);
  h+=`</div>`;

  // TLS-Versionen
  h+=`<div class="card"><h2>TLS-Versionen</h2><div>`;
  for(const k in (r.tls_versions||{})){h+=chip(r.tls_versions[k].available,k)}
  h+=`</div></div>`;

  // Cipher-Suiten
  h+=`<div class="card"><h2>Cipher-Suiten</h2><table>
    <tr><th>Suite</th><th>Kategorie</th><th>Verfügbar</th></tr>`;
  (r.ciphers||[]).forEach(c=>{
    const cat=(c.category||"").includes("STARK")?"S":(c.category||"").includes("S")?"W":"X";
    h+=`<tr><td class="name">${esc(c.cipher)}</td>
        <td class="cat-${c.available?(cat==="S"?"S":cat==="W"?"W":"X"):""}">${esc(c.category||"")}</td>
        <td>${c.available?"<span class='cat-S'>✓ aktiv</span>":"<span class='dim'>—</span>"}</td></tr>`;
  });
  h+=`</table></div>`;

  // DNS / Auflösung
  if(r.dns){
    const d=r.dns;
    const ips=(d.ipv4||[]).concat(d.ipv6||[]);
    h+=`<div class="card"><h2>DNS / Auflösung</h2>`;
    if(!d.ok){
      h+=`<div class="errbox">Auflösung fehlgeschlagen: ${esc(d.error||"")}</div>`;
    } else {
      h+=`<dl class="kv">
        <dt>Adressen</dt><dd>${ips.length?ips.map(x=>esc(x)).join(" · "):"–"}${ips.length>1?` <span class="dim">(${ips.length} Adressen – Round-Robin/CDN?)</span>`:""}</dd>
      </dl>`;
    }
    h+=`</div>`;
  }

  // Web-Server
  if(r.webserver){
    const w=r.webserver;
    const srv=w.server, hsts=w.hsts, proto=w.protocol, h80=w.http80;
    h+=`<div class="card"><h2>Web-Server (Hintergrund)</h2>
      <dl class="kv">
        <dt>Server (Header)</dt><dd>${srv?esc(srv):'<span class="dim">nicht gesetzt</span>'}</dd>
        <dt>Protokoll (ALPN)</dt><dd>${proto?esc(proto):"–"}</dd>
        <dt>HSTS</dt><dd>${hsts?`<span class="cat-S">✓ ${esc(hsts)}${w.hsts_preload?" [preload]":""}</span>`:'<span class="cat-W">nicht gesetzt</span>'}</dd>
        ${w.alt_svc?`<dt>Alt-Svc (HTTP/3)</dt><dd>${esc(w.alt_svc)}</dd>`:""}
        ${w.final_status!=null?`<dt>Finaler Status</dt><dd>${esc(w.final_status)}</dd>`:""}
        <dt>HTTP (Port 80)</dt><dd>${h80?esc(h80):"–"}</dd>
      </dl>`;
    const reds=(w.redirects||[]).filter(x=>String(x.status||"").startsWith("3"));
    if(reds.length){
      h+=`<div class="dim" style="margin-top:8px">Redirect-Kette: `+
        reds.map(x=>`${esc(x.status)} → ${esc(x.location||"-")}`).join(" · ") + `</div>`;
    }
    if(w.error){h+=`<div class="dim" style="margin-top:8px">Webserver-Check: ${esc(w.error)}</div>`}
    h+=`</div>`;
  }

  // OCSP
  if(r.ocsp){
    const o=r.ocsp;
    h+=`<div class="card"><h2>OCSP</h2>
      <dl class="kv">
      <dt>Erreichbar</dt><dd>${o.available?'<span class="cat-S">✓</span>':'<span class="cat-W">✗</span>'} ${o.url?`<span class="dim mono">${esc(o.url)}</span>`:""}</dd>
      <dt>Status</dt><dd class="${o.ok?"cat-S":"cat-W"}">${esc(o.certificate_status||o.response_status||"unbekannt")}</dd>
      ${o.available?`<dt>This Update</dt><dd>${esc(o.this_update||"")}</dd>
      <dt>Next Update</dt><dd>${esc(o.next_update||"")}</dd>`:""}
      </dl></div>`;
  }

  // Revocation (CRL + Stapling + direkter Status)
  if(r.revocation){
    const rv=r.revocation;
    const cls=rv.level==="ok"?"cat-S":rv.level==="revoked"?"cat-X":"cat-W";
    const label=rv.level==="ok"?"OK":rv.level==="revoked"?"REVOKIERT":"unbekannt";
    const st=r.ocsp_stapling||{};
    h+=`<div class="card"><h2>Revocation (CRL + OCSP)</h2>
      <dl class="kv">
      <dt>Status</dt><dd class="${cls}"><b>${label}</b> – ${esc(rv.detail||"")}</dd>
      <dt>OCSP-Stapling</dt><dd>${st.stapled?`<span class="cat-S">✓ ${esc(st.status||"")}</span>`:'<span class="dim">nicht vorhanden</span>'}</dd>
      </dl>`;
    if(r.crl&&r.crl.crls&&r.crl.crls.length){
      h+=`<div class="crls">`+r.crl.crls.map(c=>{
        const cls=c.ok===true?"ok":c.ok===false?"bad":"na";
        return `<div class="crlrow">
          <span class="dot ${cls}" title="${c.ok===true?"Abrufbar":c.ok===false?"Nicht abrufbar":"unbekannt"}"></span>
          <div class="crl-url">${esc(c.url||"")}</div>
          <div class="crl-meta">${esc(c.issuer||"")}${c.last_update?` · Last Update ${esc(c.last_update)}`:""}${c.note?` · ${esc(c.note)}`:""}</div>
        </div>`;}).join("")+`</div>`;
    }
    h+=`</div>`;
  }

  // SSL-Session
  if(r.session){
    const se=r.session;
    h+=`<div class="card"><h2>SSL-Session (Resume)</h2>
      <dl class="kv">
      <dt>Session-Resume</dt><dd class="${se.resumed?"cat-S":"dim"}">${se.resumed?`✓ erfolgreich (${esc(se.version||"")})`:"nicht möglich"}</dd>
      <dt>Notiz</dt><dd class="dim">${esc(se.note||"")}</dd>
      </dl></div>`;
  }

  // HTTP/3
  if(r.http3){
    const h3=r.http3;
    const cls=h3.active?"cat-S":h3.unknown?"cat-W":"dim";
    const label=h3.active?"aktiv":h3.unknown?"unbekannt":"nicht aktiv";
    h+=`<div class="card"><h2>HTTP/3 (QUIC)</h2>
      <dl class="kv">
      <dt>Status</dt><dd class="${cls}"><b>${label}</b></dd>
      <dt>Notiz</dt><dd class="dim">${esc(h3.note||"")}</dd>
      </dl></div>`;
  }
  return h;
}

let busy=false;
async function doCheck(){
  if(busy) return;
  const host=$("host").value.trim();
  if(!host){$("host").focus();return}
  busy=true;
  const ocsp=$("ocsp").checked, noaia=$("noaia").checked, fast=$("fast").checked;
  $("go").disabled=true;
  $("go").innerHTML='<span class="spin"></span> Prüfe …';
  $("result").innerHTML="";
  $("rawwrap").classList.add("hide");
  try{
    const q=new URLSearchParams({host});
    if(ocsp)q.set("ocsp","1");
    if(noaia)q.set("no_aia","1");
    if(fast)q.set("fast","1");
    const res=await fetch("/api/check?"+q.toString());
    const data=await res.json();
    $("result").innerHTML=render(data);
    $("raw").textContent=JSON.stringify(data,null,2);
    $("rawwrap").classList.remove("hide");
  }catch(e){
    $("result").innerHTML=`<div class="card"><div class="errbox">Abfrage fehlgeschlagen: ${esc(e.message||e)}</div></div>`;
  }finally{
    busy=false;$("go").disabled=false;$("go").textContent="Prüfen";
  }
}
$("go").addEventListener("click",doCheck);
$("host").addEventListener("keydown",e=>{if(e.key==="Enter")doCheck()});
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "TLSWebCheck/1.0"

    def _send(self, code, body, ctype="application/json; charset=utf-8",
              extra_headers=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self._maybe_attach_session_cookie()
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self):
        """Cookie-Session oder HTTP Basic (Basic gibt Session-Cookie zurück)."""
        if not AUTH_ENABLED:
            return True
        raw = self.headers.get("Cookie", "")
        val = _cookie_named("tlscheck", raw)
        if val and _session_cookie_ok(val):
            return True
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("basic ") and AUTH_ENABLED:
            import base64
            try:
                user, _, pw = base64.b64decode(auth[6:]).decode("utf-8").partition(":")
            except Exception:
                user, pw = "", ""
            if _login_allowed() and _password_ok(pw):
                _login_note_success()
                self._auth_pending_cookie = _issue_session_cookie()
                return True
            _login_note_failure()
        return False

    def _require_auth(self):
        """401 + WWW-Authenticate, falls Auth aktiv und nicht authorisiert."""
        if self._authorized():
            return True
        self._send(401, json.dumps({"error": "Login erforderlich."}),
                   extra_headers={
                       "WWW-Authenticate": 'Basic realm="TLS-Check", charset="UTF-8"'})
        return False

    def _maybe_attach_session_cookie(self):
        """Cookie setzen, wenn gerade per Basic authifiziert wurde."""
        ck = getattr(self, "_auth_pending_cookie", None)
        if ck:
            self.send_header("Set-Cookie",
                             f"tlscheck={ck}; Path=/; HttpOnly; "
                             "SameSite=Lax; Max-Age=43200")
            self._auth_pending_cookie = None

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/healthz":
            self._send(200, json.dumps({"ok": True}))
            return
        if not self._require_auth():
            return
        if u.path in ("/", "/index.html"):
            self._send(200, INDEX_HTML, "text/html; charset=utf-8")
        elif u.path == "/api/check":
            q = parse_qs(u.query)
            host = (q.get("host", [""])[0]).strip()
            ocsp = q.get("ocsp", ["0"])[0] in ("1", "true")
            no_aia = q.get("no_aia", ["0"])[0] in ("1", "true")
            fast = q.get("fast", ["0"])[0] in ("1", "true")
            if not host:
                self._send(400, json.dumps({"error": "Kein Host angegeben."}))
                return
            # leicht sanitized: Whitespace raus, Länge begrenzt
            host = re.sub(r"\s+", "", host)[:256]
            if not HOST_RE.match(host):
                self._send(400, json.dumps({"error": f"'{host}' sieht nicht wie "
                                                 "Hostname/IP(:Port) aus."}))
                return
            # DoS-Schutz: max. MAX_CONCURRENT_CHECKS parallele Checks
            if not _check_slots.acquire(blocking=False):
                self._send(503, json.dumps(
                    {"error": "Alle Prüf-Slots belegt – bitte in "
                              "wenigen Sekunden erneut versuchen."}),
                    extra_headers={"Retry-After": "5"})
                return
            try:
                data, code = run_check(host, ocsp=ocsp, no_aia=no_aia,
                                       fast=fast)
            finally:
                _check_slots.release()
            self._send(200 if code in (0, 1) else 502,
                       json.dumps(data, ensure_ascii=False))
        else:
            self._send(404, json.dumps({"error": "nicht gefunden"}))

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" %
                         (self.log_date_time_string(), fmt % args))


def main():
    ap = argparse.ArgumentParser(description="TLS-Web-Check (LAN)")
    ap.add_argument("--bind", default="0.0.0.0", help="Bind-Adresse (Default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=8765, help="Port (Default 8765)")
    ap.add_argument("--make-hash", action="store_true",
                    help="Passwort (interaktiv) zu hash:ITER$salt$dk hashen und beenden")
    args = ap.parse_args()
    if args.make_hash:
        import getpass
        pw = getpass.getpass("Passwort für TLS_CHECK_PASSWORD (Eingabe unsichtbar): ")
        print("hash:" + _password_hash(pw))
        print("(Als TLS_CHECK_PASSWORD setzen, z. B. in docker-compose.yml)")
        return
    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"TLS-Web-Check läuft: http://{args.bind}:{args.port} "
          f"(Checker: {CHECKER})")
    if AUTH_ENABLED:
        print("⚠ Passwort-Schutz AKTIV (TLS_CHECK_PASSWORD gesetzt) – "
              "Browser wird per HTTP-Basic/Session-Cookie abfragen.")
    print("Strg+C zum Beenden.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nBeendet.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
