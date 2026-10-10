#!/usr/bin/env python3
"""
TLS- & Zertifikatskette-Web-Check (abgespecktes SSL-Labs) – Web + API.

Nur Python-Standardbibliothek. Start:
    python3 tlscheck_web.py                # Port 8765, 0.0.0.0
    python3 tlscheck_web.py --port 9000 --bind 127.0.0.1

Umgebungsvariablen:
    TLS_CHECK_PASSWORD        Login erforderlich (Klartext oder hash:ITER$salt$dk,
                              Hash erzeugen mit: python3 tlscheck_web.py --make-hash)
    TLS_CHECK_TRUST_PROXY=1   Client-IP/Schema aus X-Real-IP/X-Forwarded-Proto
                              (nur hinter einem Reverse Proxy setzen)
    TLS_CHECK_BLOCK_PRIVATE   interne Ziele sperren (Default 1, 0 = erlauben)
    TLS_CHECK_LANG            Fallback-Sprache für die API (de/en, Default de)

Die eigentliche Prüfung läuft serverseitig als Subprozess:
    python3 tlscheck.py <host> --json --lang <de|en>
Damit bleibt jede Anfrage isoliert (keine Global-State-Probleme bei
mehreren parallelen Checks) und der Truststore-Build pro Check ist klein.
"""

import argparse
import base64
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
from urllib.parse import urlparse, parse_qs

HERE = Path(__file__).resolve().parent
CHECKER = HERE / "tlscheck.py"
STATIC = HERE / "static"
PY = sys.executable or "python3"

# Max. parallele Checks (Subprocess-Budget) – davor: 503.
MAX_CONCURRENT_CHECKS = 5
_check_slots = threading.Semaphore(MAX_CONCURRENT_CHECKS)

BLOCK_PRIVATE = os.environ.get("TLS_CHECK_BLOCK_PRIVATE", "1").lower() \
    not in ("0", "false", "no", "off")
DEFAULT_LANG = os.environ.get("TLS_CHECK_LANG", "de").lower()
if DEFAULT_LANG not in ("de", "en"):
    DEFAULT_LANG = "de"

# --- Passwort-Auth (optional, via ENV) -------------------------------------
# TLS_CHECK_PASSWORD gesetzt → Login erforderlich: Formular unter /login
# (Browser) bzw. HTTP Basic für /api/* (Skripte, curl -u). Sessions liegen
# serverseitig im Speicher: Logout widerruft sofort; nach einem Neustart
# ist eine neue Anmeldung nötig.
AUTH_ENABLED = bool(os.environ.get("TLS_CHECK_PASSWORD"))
SESSION_COOKIE = "tlscheck_session"
_SESSION_TTL = 12 * 3600          # 12 h gültig (absolut)
_SESSION_MAX = 1000
_sessions = {}                    # token -> ablauf
_session_lock = threading.Lock()

_LOGIN_MAX_ATTEMPTS = 10         # pro Client-IP, dann 5 min Sperre
_LOGIN_LOCK_SECONDS = 300
_LOGIN_MAX_TRACKED = 10_000      # Speicher-Deckel für die IP-Tabelle
_login_state = {}                # ip -> [fehlversuche, gesperrt_bis]
_login_lock = threading.Lock()
# TLS_CHECK_TRUST_PROXY=1 → Client-IP aus X-Real-IP (nur hinter einem Reverse
#   Proxy setzen, der den Header selbst überschreibt – sonst fälschbar).
TRUST_PROXY = os.environ.get("TLS_CHECK_TRUST_PROXY", "") in ("1", "true")

PBKDF2_ITER = 600_000            # OWASP-Empfehlung (PBKDF2-HMAC-SHA256)


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


def _session_new():
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _session_lock:
        for k in [k for k, exp in _sessions.items() if exp <= now]:
            del _sessions[k]
        while len(_sessions) >= _SESSION_MAX:
            del _sessions[next(iter(_sessions))]
        _sessions[token] = now + _SESSION_TTL
    return token


def _session_valid(token):
    if not token:
        return False
    with _session_lock:
        exp = _sessions.get(token)
        if exp is None:
            return False
        if exp <= time.time():
            del _sessions[token]
            return False
        return True


def _session_drop(token):
    with _session_lock:
        _sessions.pop(token, None)


def _login_prune(now):
    """Abgelaufene Sperren entfernen; bei Überlauf älteste Einträge verwerfen."""
    for ip in [ip for ip, (_, until) in _login_state.items()
               if until and until <= now]:
        del _login_state[ip]
    while len(_login_state) >= _LOGIN_MAX_TRACKED:
        del _login_state[next(iter(_login_state))]


def _login_allowed(ip):
    """Rate-Limit pro IP: nach N Fehlversuchen 5 min Sperre."""
    with _login_lock:
        st = _login_state.get(ip)
        return not (st and st[1] and time.time() < st[1])


def _login_note_success(ip):
    with _login_lock:
        _login_state.pop(ip, None)


def _login_note_failure(ip):
    with _login_lock:
        now = time.time()
        st = _login_state.get(ip)
        if st is None:
            _login_prune(now)
            st = _login_state[ip] = [0, 0.0]
        elif st[1] and st[1] <= now:     # Sperre abgelaufen → neu zählen
            st[:] = [0, 0.0]
        st[0] += 1
        if st[0] >= _LOGIN_MAX_ATTEMPTS:
            st[1] = now + _LOGIN_LOCK_SECONDS


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
    r"|\[?[0-9A-Fa-f:]{2,39}\]?"                    # IPv6 (kurz, optional [..])
    r"|[A-Za-z0-9]([A-Za-z0-9.\-]{0,253})?"         # Hostname
    r")?(?::\d{1,5})?$"
)


def run_check(hostport, lang, timeout=120, ocsp=False, no_aia=False, fast=False):
    """tlscheck.py als Subprozess ausführen -> (json-obj|dict, exitcode)."""
    cmd = [PY, str(CHECKER), hostport, "--json", "--lang", lang]
    if timeout:
        cmd += ["--timeout", str(timeout)]
    if ocsp:
        cmd += ["--ocsp"]
    if no_aia:
        cmd += ["--no-aia"]
    if fast:
        cmd += ["--fast"]
    cmd += ["--block-private" if BLOCK_PRIVATE else "--allow-private"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return {"host": hostport, "error": _msg(lang, "timeout")}, 2
    out = (p.stdout or "").strip() or (p.stderr or "").strip()
    try:
        return json.loads(out), p.returncode
    except json.JSONDecodeError:
        return {"host": hostport, "error": out or _msg(lang, "noout")}, 2


MESSAGES = {
    "timeout": ("Prüfung dauerte zu lange (Timeout).", "Check took too long (timeout)."),
    "noout": ("keine Ausgabe", "no output"),
    "nohost": ("Kein Host angegeben.", "No host given."),
    "badhost": ("'{h}' sieht nicht wie Hostname/IP(:Port) aus.",
                "'{h}' does not look like a hostname/IP(:port)."),
    "busy": ("Alle Prüf-Slots belegt – bitte in wenigen Sekunden erneut versuchen.",
             "All check slots busy – please retry in a few seconds."),
    "login": ("Login erforderlich.", "Login required."),
    "notfound": ("nicht gefunden", "not found"),
}


def _msg(lang, key, **kw):
    de, en = MESSAGES[key]
    return (en if lang == "en" else de).format(**kw)

# --- Statische Dateien (beim Start geladen, ohne Verzeichnis-Zugriff) --------

ASSET_TYPES = {".css": "text/css; charset=utf-8",
               ".js": "text/javascript; charset=utf-8",
               ".svg": "image/svg+xml"}
ASSETS = {}
PAGES = {}

LOGOUT_HTML = (
    '<form method="post" action="/logout" class="logout">'
    '<button type="submit" class="iconbtn" data-i18n-title="logout">'
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round"><path d="M15 4h3a2 2 0 0 1 2 2v12'
    'a2 2 0 0 1-2 2h-3M10 17l5-5-5-5M15 12H3"/></svg>'
    '<span class="lbl" data-i18n="logout"></span></button></form>')


def load_static():
    for p in STATIC.iterdir():
        if p.suffix in ASSET_TYPES and not p.name.startswith("_"):
            ASSETS[p.name] = (p.read_bytes(), ASSET_TYPES[p.suffix])
    header = (STATIC / "_header.html").read_text("utf-8")
    for name in ("index", "login"):
        html = (STATIC / f"{name}.html").read_text("utf-8")
        hdr = header.replace("{{LOGOUT}}",
                             LOGOUT_HTML if (AUTH_ENABLED and name == "index") else "")
        PAGES[name] = (html.replace("{{HEADER}}", hdr)
                       .replace("{{BLOCK}}", "1" if BLOCK_PRIVATE else "0")
                       .encode("utf-8"))


CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
       "style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
       "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = "TLSWebCheck/2.0"
    sys_version = ""

    # ---------------------------------------------------------- Antworten
    def _send(self, code, body, ctype="application/json; charset=utf-8",
              extra_headers=None, cache="no-store"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Referrer-Policy", "same-origin")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _json(self, code, obj, extra_headers=None):
        self._send(code, json.dumps(obj, ensure_ascii=False),
                   extra_headers=extra_headers)

    def _redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    # ---------------------------------------------------------- Client-Infos
    def _client_ip(self):
        if TRUST_PROXY:
            real = self.headers.get("X-Real-IP", "").strip()
            if real:
                return real
        return self.client_address[0]

    def _is_https(self):
        return TRUST_PROXY and \
            self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def _cookie(self, value, max_age):
        # Secure nur, wenn der Browser wirklich per HTTPS kommt – sonst würde
        # er das Cookie bei reinem HTTP im LAN gar nicht speichern.
        return (f"{SESSION_COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; "
                f"Max-Age={max_age}" + ("; Secure" if self._is_https() else ""))

    def _same_origin(self):
        """CSRF-Schutz für POST: Origin (bzw. Referer) muss zum Host passen."""
        host = self.headers.get("Host", "")
        src = self.headers.get("Origin") or self.headers.get("Referer") or ""
        if not src or src == "null":
            return False
        return urlparse(src).netloc == host

    def _lang(self, q=None):
        lang = ((q or {}).get("lang", [""])[0] or "").lower()
        if lang in ("de", "en"):
            return lang
        al = self.headers.get("Accept-Language", "").lower()
        if al.startswith("en"):
            return "en"
        if al.startswith("de"):
            return "de"
        return DEFAULT_LANG

    # ---------------------------------------------------------- Auth
    def _session_token(self):
        return _cookie_named(SESSION_COOKIE, self.headers.get("Cookie", ""))

    def _authorized(self, allow_basic=False):
        """Session-Cookie (Browser) oder HTTP Basic (nur API, z. B. curl -u)."""
        if not AUTH_ENABLED:
            return True
        if _session_valid(self._session_token()):
            return True
        auth = self.headers.get("Authorization", "")
        if allow_basic and auth.lower().startswith("basic "):
            try:
                _, _, pw = base64.b64decode(auth[6:]).decode("utf-8").partition(":")
            except Exception:
                pw = ""
            return self._check_password(pw) == "ok"
        return False

    def _check_password(self, pw):
        ip = self._client_ip()
        if not _login_allowed(ip):
            return "locked"
        if pw and _password_ok(pw):
            _login_note_success(ip)
            return "ok"
        _login_note_failure(ip)
        return "bad"

    # ---------------------------------------------------------- Routen
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        if path == "/healthz":
            self._json(200, {"ok": True})
            return
        if path.startswith("/assets/"):
            a = ASSETS.get(path[len("/assets/"):])
            if a is None:
                self._json(404, {"error": "not found"})
            else:
                self._send(200, a[0], a[1], cache="no-cache")
            return
        if path == "/login":
            if not AUTH_ENABLED or self._authorized():
                self._redirect("/")
            else:
                self._send(200, PAGES["login"], "text/html; charset=utf-8")
            return
        if path in ("/", "/index.html"):
            if not self._authorized():
                self._redirect("/login")
            else:
                self._send(200, PAGES["index"], "text/html; charset=utf-8")
            return
        if path == "/api/check":
            self._api_check(parse_qs(u.query))
            return
        self._json(404, {"error": _msg(self._lang(), "notfound")})

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/login", "/logout"):
            self._json(404, {"error": "not found"})
            return
        if not self._same_origin():
            self._redirect("/login?e=origin")
            return
        if path == "/logout":
            _session_drop(self._session_token())
            self._redirect("/login?e=out", cookie=self._cookie("", 0))
            return
        if not AUTH_ENABLED:
            self._redirect("/")
            return
        try:
            n = min(int(self.headers.get("Content-Length") or 0), 4096)
        except ValueError:
            n = 0
        form = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        result = self._check_password(form.get("password", [""])[0])
        if result == "ok":
            self._redirect("/", cookie=self._cookie(_session_new(), _SESSION_TTL))
        else:
            self._redirect(f"/login?e={result}")

    def _api_check(self, q):
        lang = self._lang(q)
        if not self._authorized(allow_basic=True):
            # Bewusst ohne WWW-Authenticate: kein Browser-Popup mehr.
            self._json(401, {"error": _msg(lang, "login")})
            return
        host = (q.get("host", [""])[0]).strip()
        ocsp = q.get("ocsp", ["0"])[0] in ("1", "true")
        no_aia = q.get("no_aia", ["0"])[0] in ("1", "true")
        fast = q.get("fast", ["0"])[0] in ("1", "true")
        if not host:
            self._json(400, {"error": _msg(lang, "nohost")})
            return
        # leicht sanitized: Whitespace raus, Länge begrenzt
        host = re.sub(r"\s+", "", host)[:256]
        if not HOST_RE.match(host):
            self._json(400, {"error": _msg(lang, "badhost", h=host)})
            return
        # DoS-Schutz: max. MAX_CONCURRENT_CHECKS parallele Checks
        if not _check_slots.acquire(blocking=False):
            self._json(503, {"error": _msg(lang, "busy")},
                       extra_headers={"Retry-After": "5"})
            return
        try:
            data, code = run_check(host, lang, ocsp=ocsp, no_aia=no_aia,
                                   fast=fast)
        finally:
            _check_slots.release()
        self._json(200 if code in (0, 1) else
                   (403 if data.get("blocked") else 502), data)

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s %s\n" %
                         (self.log_date_time_string(), self._client_ip(),
                          fmt % args))


def main():
    ap = argparse.ArgumentParser(description="TLS-Web-Check")
    ap.add_argument("--bind", default="0.0.0.0", help="Bind-Adresse (Default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=8765, help="Port (Default 8765)")
    ap.add_argument("--make-hash", action="store_true",
                    help="Passwort (interaktiv) zu hash:ITER$salt$dk hashen und beenden")
    args = ap.parse_args()
    if args.make_hash:
        import getpass
        pw = getpass.getpass("Passwort / password (TLS_CHECK_PASSWORD): ")
        print("hash:" + _password_hash(pw))
        print("(Als TLS_CHECK_PASSWORD setzen / set as TLS_CHECK_PASSWORD)")
        return
    load_static()
    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"TLS-Web-Check: http://{args.bind}:{args.port} (Checker: {CHECKER})")
    print(f"  Login: {'an/on' if AUTH_ENABLED else 'aus/off'} · "
          f"interne Ziele / internal targets: "
          f"{'gesperrt/blocked' if BLOCK_PRIVATE else 'erlaubt/allowed'} · "
          f"Proxy-Header: {'vertraut/trusted' if TRUST_PROXY else 'ignoriert/ignored'}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nBeendet / stopped.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
