# TLS- & Zertifikats-Check (CLI + Web)

Abgespecktes SSL-Labs: prüft Gültigkeit eines Zertifikats,
Zertifikatsketten-Vollständigkeit (Server-Präsentation vs. Truststore/AIA)
und verfügbare TLS-Versionen/Cipher-Suiten. Nur Python-Stdlib + `openssl`.

## CLI

```bash
python3 tlscheck.py example.com                     # Text-Report (inkl. CRL/Session/HTTP3)
python3 tlscheck.py 10.0.0.5:8443 --json            # JSON
python3 tlscheck.py example.com --ocsp --no-aia     # OCSP mitprüfen / AIA überspringen
python3 tlscheck.py host --cafile /pfad/ca-bundle.pem
python3 tlscheck.py host --fast                     # Schnellcheck (~1 s)
python3 tlscheck.py host --crl-max-mb 60            # CRL-Deckel anheben
```

Exit-Codes: `0` sauber · `1` Probleme/Warnungen · `2` Fehler (keine Verbindung …).

## Checks im Überblick

| Bereich | Inhalt |
|---|---|
| **Zertifikat** | Zeitraum, SAN/Hostname (inkl. IP-SAN), Signatur, AIA/OCSP-URLs |
| **Kette** | Server-Präsentation, openssl-verify, fehlende Zwischenglieder, AIA-Abholung |
| **TLS** | Versionen 1.0–1.3, Cipher-Suiten (stark/veraltet/schwach) |
| **OCSP** | Direkt (optional `--ocsp`) + **Stapling** (im Handshake via `s_client -status`) |
| **CRL** | CRL-DPs der Kette abrufen (20 MB-Deckel, `--crl-max-mb`), Last/Next Update, Endzert-Serial gegenprüfen |
| **Revocation** | SSL-Labs-artiger Gesamtstatus: ok / unbekannt / **revokiert** (Problem) |
| **SSL-Session** | Session-Resume via `-sess_out`/`-sess_in` (TLS 1.2 & 1.3) |
| **HTTP/3** | QUIC-Initial an UDP:443; Long-Header-Antwort → aktiv; sonst unbekannt (UDP-Freigabe beachten) + Alt-Svc-Indiz |
| **DNS/Webserver** | Alle A/AAAA-IPs, Server-Header, ALPN (h2/h1.1), HSTS, HTTP:80-Verhalten, Redirects |

## Web (LAN)

```bash
python3 tlscheck_web.py                  # http://0.0.0.0:8765
python3 tlscheck_web.py --port 9000      # anderer Port
python3 tlscheck_web.py --bind 127.0.0.1 # nur lokal
```

- **Frontend:** Dark-Theme, Eingabe `Host[:Port]`, Checkboxen *OCSP prüfen* /
  *AIA überspringen* / *schnell* (überspringt CRL/Stapling/Session/HTTP3);
  Grade-Badge (F–A), Problem-/Warnungsliste, Zertifikat, Kette
  (Präsentation + openssl-verify + AIA-Reachability), TLS-Version-Chips,
  Cipher-Tabelle, DNS-Auflösung (alle A/AAAA-IPs), Webserver (Server-Header,
  ALPN-Protokoll, HSTS, HTTP:80-Verhalten, Redirect-Kette), Revocation
  (Status + Stapling + CRL-Tabelle), SSL-Session (Resume), HTTP/3,
  optional OCSP, expandierbares Roh-JSON.
- **API:** `GET /api/check?host=example.com[&ocsp=1&no_aia=1&fast=1]` → JSON
  (identisch zu `tlscheck.py --json`). Host wird serverseitig validiert
  (Hostname/IP-Regex), keine SSRF-Overrun. `GET /healthz` → `{"ok":true}`.
- Prüfungen laufen serverseitig isoliert als `tlscheck.py --json`-Subprozess;
  parallele Anfragen sind möglich (ThreadingHTTPServer).

### Dauerbetrieb (LAN)

```bash
python3 tlscheck_web.py --port 8765 &
# oder mit systemd-User-Service / pm2 / docker …
```

### Via GitHub (Build & Pull)
1. Repo auf GitHub (z.B. `PenDraga/sslcheck`); Workflow liegt in
   `.github/workflows/publish.yml` und pusht bei jedem Push an `main`/Tag.
2. Repo-Settings → **Actions → Workflow permissions** → **Read and write**
   (erforderlich, um das Image nach GHCR zu pushen).
3. Danach liegt das Image auf **GHCR**: `ghcr.io/pendraga/sslcheck:latest`
   (plus `:vX.Y.Z` aus Tags).
4. Auf dem Ziel-Host:
   ```bash
   docker login ghcr.io            # mit GitHub-PAT (Scope: read:packages)
   docker compose up -d            # docker-compose.yml: Port 8765 + Restart
   ```

## Sicherheit / Audit

Stand: 2026-08-23 (Security-Audit, alle Fixes drin):

- **Keine Shell-Aufrufe**: alle `openssl`-Aufrufe per Argument-Liste
  (`subprocess.run([...])`, nie `shell=True`) – kein Injection-Pfad.
- **Host-Validierung (Web)**: `HOST_RE` (Hostname/IP `:Port`),
  Whitespace-Raum + 256-Char-Limit; ungültig → HTTP 400.
- **SSRF-Schutz (feindliche Server)**: Redirect-Following folgt
  **nicht** auf Loopback/Link-Local (127.x, ::1, 169.254.x – inkl.
  Cloud-Metadata) und **nicht** auf Downgrades HTTPS → HTTP.
- **URL-Schema-Check (feindliche Zertifikate)**: AIA- und
  CRL-URLs aus Zertifikaten werden nur abgerufen, wenn
  `http://`/`https://` – `file://`, `gopher://`, `ldap://` etc.
  werden abgelehnt (blockt lokale Dateileaks).
- **Größen-Deckel**: CRL-Downloads max. 20 MB
  (`--crl-max-mb`), AIA-Antworten max. 1 MB – Memory-Exhaustion
  durch feindliche Endpunkte begrenzt.
- **DoS-Schutz (Web)**: max. 5 parallele Checks
  (`threading.Semaphore`), darüber → HTTP 503 + `Retry-After`.
- **Temp-Dateien**: `NamedTemporaryFile(delete=False)` +
  `finally: os.unlink()` – nichts bleibt in `/tmp`.
- **Keine Secrets**: keine API-Keys/Passwörter im Code oder im
  Docker-Image; Subprozesse bekommen `input=""` (keine stdin).
- **XSS (Frontend)**: alle Zertifikat-/Server-Daten werden via
  `esc()` HTML-escapet bevor sie in `innerHTML` wandern;
  Raw-JSON via `textContent` (kein HTML-Parse).
- **Docker**: non-root-User (`tlscheck`, UID 10001),
  `python:3.11-slim` + `openssl` + `ca-certificates`,
  keine Secrets im Image, HEALTHCHECK.
- **CI (GitHub Actions)**: `actions/checkout@v4` (pinned),
  `permissions: contents:read, packages:write` (minimal),
  `GITHUB_TOKEN` nur für GHCR-Login.

**Inhärente Einschränkung (Design)**: Das Tool prüft *auf Wunsch*
beliebige Hosts – wer den Web-Port (8765) im LAN erreicht, kann
auch interne Hosts:Ports checken lassen (Port-Scan-Ersatz).
Gegenmassnahme: Port 8765 nur im vertrauenswürdigen
LAN binden (Docker-Compose bindet standardmäßig an alle
Schnittstellen – für multi-NIC-Hosts `127.0.0.1:8765:8765`
verwenden).

## Hinweise

- Der lokale Truststore (Default: `/etc/ssl/certs/ca-certificates.crt`, 121 CAs)
  wird pro Check einmalig per `openssl crl2pkcs7 | pkcs7 -print_certs`
  geladen (~40 ms). `--cafile` ersetzt ihn.
- „Root wird nicht vom Server gesendet“ ist der **Normalfall** (Let's Encrypt
  & Co.) und kein Defizit; nur fehlende *Zwischen*zertifikate werden alarmiert.
  AIA-URLs fehlender Glieder werden zusätzlich auf Abrufbarkeit geprüft.
- TLS 1.3-Suiten werden per `openssl s_client -ciphersuites` geprüft,
  da dieser Python-Build kein `ssl.set_ciphersuites` hat.
