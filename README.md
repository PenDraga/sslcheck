# TLS & Certificate Check (CLI + Web)

A lightweight, self-hosted **SSL Labs–style** checker: certificate validity,
chain completeness (server presentation vs. truststore/AIA), TLS versions,
cipher suites, key exchange groups, revocation and web server hardening –
rated with an SSL Labs–like grade (**F … A+**) and four sub-scores.
Python standard library + `openssl` only.

*Deutsche Fassung: siehe [Anhang: Deutsch](#anhang-deutsch).*

## Features

| Area | What is checked |
|---|---|
| **Certificate** | Validity period, SAN/hostname (incl. IP SAN), self-signed, signature algorithm, key size, AIA/OCSP URLs |
| **Chain** | What the server presents, `openssl verify`, missing intermediates, AIA retrieval |
| **Protocols** | TLS 1.0 – 1.3 |
| **Cipher suites** | TLS 1.2 + 1.3 suites with category (strong / legacy / weak) and key length |
| **Key exchange** | Accepted groups: X25519, P-256/384/521, X448, FFDHE, **X25519MLKEM768 (post-quantum hybrid)**, DHE parameter size, static RSA |
| **Scores** | Certificate / Protocol support / Key exchange / Cipher strength (0–100) + overall, following the SSL Labs rating guide |
| **Grade** | F, E, D, C, B, A-, A, **A+** (A+ requires HSTS ≥ 6 months and no findings) |
| **Revocation** | OCSP (direct, optional `--ocsp`) + **stapling**, CRL download and serial check |
| **Session / HTTP/3** | Session resumption (TLS 1.2 & 1.3), QUIC probe on UDP/443 + Alt-Svc hint |
| **DNS / web server** | All A/AAAA addresses, tested IP, Server header, ALPN (h2/http1.1), HSTS, HTTP:80 behaviour, redirect chain |

The scores are an approximation of SSL Labs: the tool tests a fixed list of
common cipher suites and groups, not every possible one.

## CLI

```bash
python3 tlscheck.py example.com                     # text report
python3 tlscheck.py example.com --lang en           # English messages
python3 tlscheck.py 10.0.0.5:8443 --json --allow-private
python3 tlscheck.py example.com --ocsp --no-aia     # direct OCSP / skip AIA
python3 tlscheck.py host --cafile /path/ca-bundle.pem
python3 tlscheck.py host --fast                     # quick check (skips CRL/stapling/session/HTTP3)
python3 tlscheck.py example.com --crl-max-mb 60     # raise CRL size limit
```

Exit codes: `0` clean · `1` problems/warnings · `2` error (no connection, blocked target …).

## Web UI

```bash
python3 tlscheck_web.py                  # http://0.0.0.0:8765
python3 tlscheck_web.py --port 9000 --bind 127.0.0.1
```

- **Frontend:** dark/light theme, **German/English** (browser language,
  switchable), grade ring with overall score, four score bars, highlight
  badges (TLS 1.3, HSTS, HTTP/2, post-quantum, stapling, HTTP/3, revocation),
  findings, collapsible sections (certificate, chain, protocols & key
  exchange, ciphers, DNS & web server, revocation, session & HTTP/3, raw
  JSON) and live progress while checking.
- **API:** `GET /api/check?host=example.com[&lang=en&ocsp=1&no_aia=1&fast=1]`
  → JSON (same as `tlscheck.py --json`). `GET /healthz` → `{"ok":true}`.
- Every check runs isolated as a `tlscheck.py --json` subprocess; at most 5
  checks run in parallel (then HTTP 503 + `Retry-After`).

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `TLS_CHECK_PASSWORD` | – | Enables login. Plain text or `hash:ITER$salt$hash` (create with `python3 tlscheck_web.py --make-hash`) |
| `TLS_CHECK_BLOCK_PRIVATE` | `1` | Block internal targets (see below). `0` = allow, e.g. for LAN use |
| `TLS_CHECK_TRUST_PROXY` | `0` | `1` = take client IP / scheme from `X-Real-IP` / `X-Forwarded-Proto`. **Only** behind a reverse proxy that overwrites these headers |
| `TLS_CHECK_LANG` | `de` | Fallback language for CLI/API (`de`/`en`) |

In `.env` files put hashes in **single quotes** (`'hash:600000$…'`), otherwise
Docker Compose interprets the `$` signs.

## Docker

```bash
docker build -t tlscheck .
docker run -d --name tlscheck --restart unless-stopped \
  -e TLS_CHECK_PASSWORD='hash:600000$…' -p 127.0.0.1:8765:8765 tlscheck
```

`docker-compose.yml` contains a Traefik example (no port mapping, router via
labels). Every push to `main` builds and publishes
`ghcr.io/pendraga/sslcheck:latest` via GitHub Actions
(`.github/workflows/publish.yml`; needs *Settings → Actions → Workflow
permissions → Read and write*).

## Security

- **Login form instead of a browser popup**; sessions are stored server-side
  (random 256-bit token, 12 h), so **sign-out revokes immediately**. A restart
  ends all sessions.
- Session cookie `HttpOnly`, `SameSite=Strict`, `Secure` when served via
  HTTPS (detected through the trusted proxy).
- **CSRF protection:** login/logout `POST`s must carry a matching `Origin`.
- **Lockout per client IP:** 10 failed attempts → 5 minutes, only for that IP.
- **Password hash:** PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP);
  older hashes with fewer iterations keep working.
- HTTP Basic is still accepted for `/api/*` (scripts, `curl -u`) – without
  `WWW-Authenticate`, so browsers show no popup.
- **Content Security Policy** without inline scripts (`script-src 'self'`),
  `frame-ancestors 'none'`, `Referrer-Policy: same-origin`, `nosniff`.
- **Internal targets blocked** (`TLS_CHECK_BLOCK_PRIVATE=1`): private
  networks (RFC 1918), loopback, link-local / cloud metadata
  (169.254.169.254), CGNAT, ULA, multicast, also via IPv4-mapped/NAT64/6to4
  addresses. Applies to the target **and** to AIA, CRL and OCSP downloads
  and redirects.
- **DNS rebinding protection:** every hostname is resolved exactly once per
  check; all connections – including the `openssl` subprocesses
  (`-connect <IP>` with separate SNI) – use that pinned address.
- No shell calls (argument lists only), host validation (regex, 256 chars),
  only `http(s)://` for AIA/CRL/OCSP URLs, size limits (CRL 20 MB, AIA/OCSP
  1 MB), no redirect downgrade HTTPS → HTTP.
- Docker: non-root user (UID 10001), no secrets in the image, healthcheck.

## Notes

- The local truststore (default `/etc/ssl/certs/ca-certificates.crt`) is
  loaded once per check; `--cafile` replaces it.
- "Root not sent by the server" is **normal** (Let's Encrypt & co.); only
  missing *intermediates* are reported.
- TLS 1.3 suites and key exchange groups are tested via `openssl s_client`
  (`-ciphersuites`, `-groups`); post-quantum groups need OpenSSL ≥ 3.5
  (included in the Docker image).

---

## Anhang: Deutsch

### Überblick

Schlanker, selbst gehosteter Prüfer im Stil von **SSL Labs**: Zertifikat,
Vollständigkeit der Kette (Server-Präsentation vs. Truststore/AIA),
TLS-Versionen, Cipher-Suiten, Key-Exchange-Gruppen, Revocation und
Webserver-Härtung – bewertet mit Note (**F … A+**) und vier Teilpunkten.
Nur Python-Standardbibliothek + `openssl`.

### Funktionen

| Bereich | Inhalt |
|---|---|
| **Zertifikat** | Gültigkeit, SAN/Hostname (inkl. IP-SAN), selbstsigniert, Signatur, Schlüssellänge, AIA-/OCSP-URLs |
| **Kette** | Server-Präsentation, `openssl verify`, fehlende Zwischenzertifikate, AIA-Abruf |
| **Protokolle** | TLS 1.0 – 1.3 |
| **Cipher-Suiten** | TLS 1.2 + 1.3 mit Kategorie (stark / veraltet / schwach) und Schlüssellänge |
| **Key Exchange** | Akzeptierte Gruppen: X25519, P-256/384/521, X448, FFDHE, **X25519MLKEM768 (Post-Quanten-Hybrid)**, DHE-Parametergröße, statisches RSA |
| **Punkte** | Zertifikat / Protokolle / Key Exchange / Cipher-Stärke (0–100) + Gesamt nach dem SSL-Labs-Rating-Guide |
| **Note** | F, E, D, C, B, A-, A, **A+** (A+ nur mit HSTS ≥ 6 Monate und ohne Befund) |
| **Revocation** | OCSP (direkt, optional `--ocsp`) + **Stapling**, CRL-Abruf mit Serial-Abgleich |
| **Session / HTTP/3** | Session-Resume (TLS 1.2 & 1.3), QUIC-Test auf UDP/443 + Alt-Svc-Indiz |
| **DNS / Webserver** | Alle A/AAAA-Adressen, geprüfte IP, Server-Header, ALPN, HSTS, Verhalten auf HTTP:80, Redirects |

Die Punkte sind eine Annäherung an SSL Labs: Getestet wird eine feste Liste
gängiger Cipher-Suiten und Gruppen, nicht jede denkbare.

### Kommandozeile

```bash
python3 tlscheck.py example.com                     # Text-Bericht
python3 tlscheck.py example.com --lang en           # Meldungen auf Englisch
python3 tlscheck.py 10.0.0.5:8443 --json --allow-private
python3 tlscheck.py example.com --ocsp --no-aia
python3 tlscheck.py host --fast                     # Schnellcheck
```

Exit-Codes: `0` sauber · `1` Probleme/Warnungen · `2` Fehler (keine Verbindung, gesperrtes Ziel …).

### Weboberfläche

`python3 tlscheck_web.py` startet auf Port 8765. Hell/Dunkel,
**Deutsch/Englisch** (Browsersprache, umschaltbar), Noten-Ring,
vier Punkte-Balken, Kennzeichen, Befunde, aufklappbare Abschnitte und
Fortschrittsanzeige. API: `GET /api/check?host=…[&lang=en&ocsp=1&no_aia=1&fast=1]`.

### Konfiguration (Umgebungsvariablen)

| Variable | Default | Bedeutung |
|---|---|---|
| `TLS_CHECK_PASSWORD` | – | Aktiviert den Login. Klartext oder `hash:ITER$salt$hash` (`python3 tlscheck_web.py --make-hash`) |
| `TLS_CHECK_BLOCK_PRIVATE` | `1` | Interne Ziele sperren. `0` = erlauben, z. B. im LAN |
| `TLS_CHECK_TRUST_PROXY` | `0` | `1` = Client-IP/Schema aus `X-Real-IP`/`X-Forwarded-Proto` – **nur** hinter einem Reverse Proxy, der diese Header überschreibt |
| `TLS_CHECK_LANG` | `de` | Fallback-Sprache für CLI/API |

Hashes in `.env`-Dateien in **einfache Anführungszeichen** setzen
(`'hash:600000$…'`), sonst interpretiert Docker Compose die `$`-Zeichen.

### Sicherheit

- **Login-Formular statt Browser-Popup**, Sessions serverseitig (zufälliges
  256-Bit-Token, 12 h) → **Abmelden widerruft sofort**; ein Neustart beendet
  alle Sessions.
- Cookie `HttpOnly`, `SameSite=Strict`, `Secure` bei HTTPS.
- **CSRF-Schutz:** Login/Logout-`POST` nur mit passendem `Origin`.
- **Sperre pro Client-IP:** 10 Fehlversuche → 5 Minuten, nur für diese IP.
- **Passwort-Hash:** PBKDF2-HMAC-SHA256 mit 600 000 Runden; ältere Hashes
  funktionieren weiter.
- HTTP Basic weiterhin für `/api/*` (Skripte, `curl -u`), ohne Popup.
- **Content-Security-Policy** ohne Inline-Skripte, `frame-ancestors 'none'`.
- **Interne Ziele gesperrt** (`TLS_CHECK_BLOCK_PRIVATE=1`): RFC 1918,
  Loopback, Link-Local/Cloud-Metadata, CGNAT, ULA, Multicast – auch über
  IPv4-mapped/NAT64/6to4. Gilt für das Ziel **und** für AIA-, CRL-,
  OCSP-Abrufe und Redirects.
- **Schutz vor DNS-Rebinding:** Jeder Hostname wird pro Check genau einmal
  aufgelöst; alle Verbindungen – auch die `openssl`-Subprozesse – nutzen
  diese festgehaltene Adresse.
- Keine Shell-Aufrufe, Host-Validierung, nur `http(s)://` für
  AIA/CRL/OCSP, Größen-Deckel, kein Redirect-Downgrade HTTPS → HTTP.
- Docker: ohne Root (UID 10001), keine Secrets im Image, Healthcheck.
