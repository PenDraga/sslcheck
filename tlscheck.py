#!/usr/bin/env python3
"""
tlscheck — TLS/Zertifikats-Prüfung, abgespecktes SSL-Labs-Equivalent.

Prüft für eine HTTPS-Endpunkt:
  1. Zertifikat gültig? (Gültigkeitszeitraum, Hostname/SAN, selbstsigniert,
     Signaturalgorithmus, Schlüsselstärke)
  2. Zertifikatskette: Liefert der Server die Kette komplett mit,
     oder müssen Zwischenzertifikate vom Client aus Truststore/AIA
     beschafft werden? (inkl. AIA-Reachability-Check)
  3. Verfügbare TLS-Versionen + Cipher-Suites (stark / veraltet / schwach)
  4. Schlüsselaustausch (ECDHE-Gruppen, DHE, statisches RSA)
  5. SSL-Labs-artige Punkte (Zertifikat / Protokoll / Key Exchange / Cipher)
  6. Optional: OCSP-Status des Endzertifikats (--ocsp)

Abhängigkeiten: Python-Standardbibliothek + openssl CLI.

Beispiele:
  tlscheck.py example.com
  tlscheck.py example.com:8443 --json
  tlscheck.py example.com --ocsp --lang en
  tlscheck.py 10.0.0.5 --allow-private      # internes Ziel erlauben

Umgebungsvariablen (Default, per Option überschreibbar):
  TLS_CHECK_LANG=de|en              Sprache der Meldungen (Default: de)
  TLS_CHECK_BLOCK_PRIVATE=1|0       interne Adressen sperren (Default: 1)

Exit-Codes: 0 = sauber, 1 = Probleme/Warnings (Bericht siehe Ausgabe),
            2 = Fehler (keine Verbindung, gesperrtes Ziel o.ä.)
"""

import argparse
import datetime
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import urllib.request
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning,
                        message=r"ssl\.TLSVersion")
from urllib.parse import urlparse
from pathlib import Path

# ---------------------------------------------------------------- Sprache

LANG = os.environ.get("TLS_CHECK_LANG", "de").lower()


def L(de, en):
    """Meldung in der gewählten Sprache (de/en)."""
    return en if LANG == "en" else de

# ---------------------------------------------------------------- util

def run_cmd(args, input_text="", timeout=15):
    """Subprocess mit Timeout. Return (rc, stdout, stderr)."""
    try:
        p = subprocess.run(args, input=input_text, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"

def parse_pem(text):
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                        text, re.S)
    return [b + "\n" for b in blocks]

def norm_name(s):
    """Zertifikatsnamen normalisieren für Vergleich (keine Leerzeichen, case-insensitiv)."""
    return re.sub(r"\s+", "", s.upper().strip())

def load_openssl():
    path = shutil.which("openssl")
    if not path:
        sys.exit(L("Fehler: openssl CLI nicht gefunden (Systempfad fehlt).",
                   "Error: openssl CLI not found (not in PATH)."))
    return path

CA_BUNDLE_CANDIDATES = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
    "/usr/lib/ssl/cert.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
]

def find_ca_bundle():
    for c in CA_BUNDLE_CANDIDATES:
        if os.path.exists(c):
            return c
    return None

# ---------------------------------------------------------------- Netzwerk-Policy
#
# Alle Namensauflösungen dieses Prozesses laufen über _guarded_getaddrinfo:
#  - Jeder Hostname wird genau EINMAL aufgelöst und das Ergebnis für den
#    ganzen Check festgehalten (DNS-Rebinding: ein feindlicher DNS-Server
#    kann nicht erst eine öffentliche und danach eine interne IP liefern).
#  - Mit BLOCK_PRIVATE werden interne Ziele (RFC1918, Loopback, Link-Local/
#    Cloud-Metadata, CGNAT, ULA, Multicast …) abgelehnt – auch für AIA-,
#    CRL-, OCSP-Abrufe und Redirects.
#  - openssl-Subprozesse bekommen die festgehaltene IP (-connect IP:Port,
#    SNI separat), lösen also nicht selbst auf.

BLOCK_PRIVATE = os.environ.get("TLS_CHECK_BLOCK_PRIVATE", "1").lower() \
    not in ("0", "false", "no", "off")

_real_getaddrinfo = socket.getaddrinfo
_dns_cache = {}
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class BlockedAddress(OSError):
    """Ziel liegt in einem gesperrten (internen) Netz."""


def ip_blocked(ip_str):
    """True für alles, was nicht öffentlich routbar ist."""
    ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    if ip.version == 6:
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip in _NAT64:
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        elif ip.sixtofour:
            ip = ip.sixtofour
        elif ip.teredo:
            ip = ip.teredo[1]
    return (not ip.is_global) or ip.is_multicast


def _port_number(port):
    if port in (None, "", b""):
        return 0
    if isinstance(port, int):
        return port
    p = port.decode() if isinstance(port, bytes) else str(port)
    return int(p) if p.isdigit() else socket.getservbyname(p)


def _guarded_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if host is None:
        return _real_getaddrinfo(host, port, family, type, proto, flags)
    key = (host.decode() if isinstance(host, bytes) else str(host)) \
        .lower().strip("[]").rstrip(".")
    infos = _dns_cache.get(key)
    if infos is None:
        infos = _real_getaddrinfo(key, None, 0, socket.SOCK_STREAM)
        _dns_cache[key] = infos
    if BLOCK_PRIVATE:
        for info in infos:
            if ip_blocked(info[4][0]):
                raise BlockedAddress(L(
                    f"Ziel '{key}' ({info[4][0]}) ist eine interne Adresse – "
                    f"gesperrt (TLS_CHECK_BLOCK_PRIVATE).",
                    f"Target '{key}' ({info[4][0]}) is an internal address – "
                    f"blocked (TLS_CHECK_BLOCK_PRIVATE)."))
    pnum = _port_number(port)
    out = []
    for fam, _t, _p, canon, sa in infos:
        if family not in (0, socket.AF_UNSPEC) and fam != family:
            continue
        out.append((fam, type or socket.SOCK_STREAM, proto, canon,
                    (sa[0], pnum) + tuple(sa[2:])))
    if not out:
        raise socket.gaierror(socket.EAI_FAMILY, "address family mismatch")
    return out


socket.getaddrinfo = _guarded_getaddrinfo


def pinned_ip(host):
    """Festgehaltene (erste) IP eines Hosts – Policy-geprüft."""
    try:
        return socket.getaddrinfo(host, 443)[0][4][0]
    except BlockedAddress:
        raise
    except socket.gaierror as e:
        raise ConnectionError(L(f"Hostname nicht auflösbar: {host} ({e})",
                                f"Cannot resolve hostname: {host} ({e})"))


def ossl_target(host, port):
    """-connect-Argument für openssl: feste IP statt Hostname."""
    ip = pinned_ip(host)
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"

# ---------------------------------------------------------------- Zertifikat

class Cert:
    """Ein X.509-Zertifikat (PEM) mit lazy-gemachter openssl-Parzierung."""

    def __init__(self, pem, label):
        self.pem = pem
        self.label = label
        self._meta = None
        self._text = ""

    def _openssl_text(self):
        """subject/issuer/serial/validity + -text in einem Durchgang.
        Hinweis: openssl x509 -in - (stdin) funktioniert in manchen
        OpenSSL-3.x-Builds nicht → PEM in eine Temp-Datei schreiben."""
        if self._text:
            return self._text
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem",
                                         delete=False) as tf:
            tf.write(self.pem)
            tf_path = tf.name
        try:
            rc, out, err = run_cmd(
                [OSSL, "x509", "-in", tf_path, "-noout", "-subject",
                 "-issuer", "-serial", "-startdate", "-enddate", "-text"])
        finally:
            os.unlink(tf_path)
        if rc != 0:
            raise RuntimeError(L("openssl x509 fehlerhaft: ",
                                 "openssl x509 failed: ") + err.strip()[:200])
        self._text = out
        return out

    def meta(self):
        if self._meta:
            return self._meta
        out = self._openssl_text()
        m = {}
        for line in out.splitlines():
            line = line.rstrip()
            if line.startswith("subject="):
                m["subject"] = line.split("=", 1)[1]
            elif line.startswith("issuer="):
                m["issuer"] = line.split("=", 1)[1]
            elif line.startswith("serial="):
                m["serial"] = line.split("=", 1)[1].upper()
            elif line.startswith("notBefore="):
                m["notBefore"] = line.split("=", 1)[1]
            elif line.startswith("notAfter="):
                m["notAfter"] = line.split("=", 1)[1]
            elif line.strip().startswith("Public Key Algorithm:"):
                m["pubkey_alg"] = line.split(":", 1)[1].strip()
            elif "Public-Key:" in line:
                bm = re.search(r"\((\d+)\s*bit\)", line)
                if bm:
                    m["pubkey_bits"] = int(bm.group(1))
            elif line.strip().startswith("Signature Algorithm:"):
                m["sig_alg"] = line.split(":", 1)[1].strip()
        # SAN: Zeile nach 'X509v3 Subject Alternative Name'
        sm = re.search(r"X509v3 Subject Alternative Name:(?: critical)?\s*\n\s*(.+)", out)
        san = sm.group(1) if sm else ""
        m["san_dns"] = re.findall(r"DNS:([^,\n]+)", san)
        m["san_ip"] = re.findall(r"IP Address:([^,\n]+)", san)
        # AIA-URIs
        ca = re.search(r"CA Issuers\s*-\s*URI:(\S+)", out)
        ocsp = re.search(r"OCSP\s*-\s*URI:(\S+)", out)
        m["aia_ca"] = ca.group(1) if ca else None
        m["aia_ocsp"] = ocsp.group(1) if ocsp else None
        m["subject_norm"] = norm_name(m.get("subject", ""))
        m["issuer_norm"] = norm_name(m.get("issuer", ""))
        m["self_signed"] = (m["subject_norm"] == m["issuer_norm"]
                            and m["subject_norm"] != "")
        self._meta = m
        return m

    @property
    def days_left(self):
        m = self.meta()
        end = datetime.datetime.strptime(m["notAfter"], "%b %d %H:%M:%S %Y %Z")
        return (end - datetime.datetime.utcnow()).days

    @property
    def short(self):
        cm = re.search(r"CN\s*=\s*([^,/]+)", self.meta().get("subject", ""))
        return cm.group(1) if cm else self.meta().get("subject", "?")

# ---------------------------------------------------------------- Chain-Analyse

def build_store(bundle):
    """Lädt den Truststore in zwei openssl-Aufrufen:
    crl2pkcs7 → pkcs7 -print_certs (liefert subject + PEM-Block pro Zertifikat).
    Return: subject_norm → pem."""
    rc, out, err = run_cmd(
        ["openssl", "crl2pkcs7", "-nocrl", "-certfile", bundle], timeout=30)
    if rc != 0:
        raise RuntimeError(L("CA-Bundle nicht lesbar: ",
                             "CA bundle not readable: ") + err.strip()[:200])
    rc2, out2, err2 = run_cmd(
        ["openssl", "pkcs7", "-print_certs"], input_text=out, timeout=30)
    if rc2 != 0:
        raise RuntimeError(L("CA-Bundle-Auswertung fehlgeschlagen: ",
                             "CA bundle parsing failed: ") + err2.strip()[:200])
    pem_by_subject = {}
    cur_norm = None
    cur_pem = []
    for line in out2.splitlines():
        if line.startswith("subject="):
            if cur_norm and cur_pem:
                pem_by_subject.setdefault(cur_norm, "\n".join(cur_pem))
            cur_norm = norm_name(line.split("=", 1)[1])
            cur_pem = []
        elif cur_norm is not None:
            cur_pem.append(line)
    if cur_norm and cur_pem:
        pem_by_subject.setdefault(cur_norm, "\n".join(cur_pem))
    return pem_by_subject

def fetch_presented_chain(host, port, timeout):
    """openssl s_client -showcerts: alle Zertifikate, die der Server beim
    TLS-Handshake vorlegt, plus verhandelte Protokollversion."""
    cmd = [OSSL, "s_client", "-connect", ossl_target(host, port),
           "-servername", host, "-showcerts"]
    try:
        p = subprocess.run(cmd, input="", capture_output=True, text=True,
                           timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        raise ConnectionError(L(f"Timeout bei Verbindung zu {host}:{port}",
                                f"Timeout connecting to {host}:{port}"))
    pems = parse_pem(p.stdout)
    m = re.search(r"SSL-Session:.*?\n\s*Protocol\s*:\s*(\S+)", p.stdout, re.S)
    proto = m.group(1) if m else None
    if proto is None:
        m2 = re.search(r"New,\s*(\S+),\s*Cipher is", p.stdout)
        proto = m2.group(1) if m2 else None
    if not pems:
        errhint = " | ".join(
            l.strip() for l in p.stdout.splitlines()
            if "verify error" in l or "alert" in l.lower())[:300]
        raise ConnectionError(
            L(f"Keine Zertifikate erhalten von {host}:{port}",
              f"No certificates received from {host}:{port}")
            + (f" ({errhint})" if errhint else
               L(" (Server hat nicht geantwortet)", " (server did not respond)")))
    return pems, proto

def _fetch_limited(url, limit, timeout, data=None, headers=None):
    """HTTP(S)-Abruf mit Größendeckel (Policy-geprüft über den Resolver)."""
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": "tlscheck/1.0", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        buf = b""
        while True:
            chunk = r.read(128 * 1024)
            if not chunk:
                break
            buf += chunk
            if len(buf) > limit:
                raise RuntimeError(L(f"Antwort zu groß (> {limit // 1024} KB)",
                                     f"Response too large (> {limit // 1024} KB)"))
        return buf, (r.headers.get("Content-Type") or "").lower()

def check_chain(pem_list, store, host, do_aia=True):
    """
    Analyse der vom Server gelieferten Kette:
    - Werden alle Zwischenzertifikate mitgeliefert?
    - Was muss der Client selbst beschaffen (Truststore/AIA)?
    - Verifiziert openssl die Kette (a) nur mit Server-Zertifikaten,
      (b) mit zusätzlichem lokalem Truststore?
    """
    res = {"presented": [], "complete": False, "root_presented": False,
           "missing": [], "notes": [],
           "verify_with_presentation": None,
           "verify_store_only": None, "aia": []}
    chain = [Cert(p, f"server[{i}]") for i, p in enumerate(pem_list)]
    res["presented"] = chain

    # Adjazenz-Check (Warnung, falls Kette durcheinander)
    for i, (a, b) in enumerate(zip(chain, chain[1:])):
        if norm_name(a.meta()["issuer"]) != norm_name(b.meta()["subject"]):
            res["notes"].append(L(
                f"Glied [{i}]: Issuer wird nicht direkt vom nächsten Glied "
                f"abgedeckt (Kettenglied fehlt oder durcheinander).",
                f"Link [{i}]: issuer is not covered by the next link "
                f"(link missing or chain out of order)."))

    presented = {}
    for c in chain:
        presented.setdefault(c.meta()["subject_norm"], c)

    # Kette aufwärts traversieren. Lücken (nicht von Server, nicht im
    # Truststore) werden als Gap-Objekte in res["missing"] erfasst; die
    # caIssuers-AIA-URL des jeweiligen Kindes steht in res["aia_urls"].
    res["aia_urls"] = []
    res["full_chain"] = []
    cur = chain[0]
    cur_source = "server"
    seen = set()
    while len(seen) < 12:
        m = cur.meta()
        seen.add(m["subject_norm"])
        res["full_chain"].append({
            "subject": m.get("subject"), "issuer": m.get("issuer"),
            "serial": m.get("serial"), "valid_to": m.get("notAfter"),
            "self_signed": m.get("self_signed"), "source": cur_source,
        })
        # 1) Anker: aktuelles Glied ist eine vertraute Root (selbstsignierte
        #    Version im Truststore) → Kette abgeschlossen. Deckt auch
        #    Cross-Signaturen ab.
        if m["subject_norm"] in store:
            sc = Cert(store[m["subject_norm"]], "truststore")
            fm = sc.meta()
            if fm["self_signed"]:
                res["complete"] = True
                res["root_presented"] = cur in chain
                if res["missing"]:
                    res["notes"].append(L(
                        "Kette wird über lokale Truststore-Zertifikate bis "
                        "zum Root ergänzt; die fehlenden Glieder sind oben "
                        "aufgeführt.",
                        "Chain is completed up to the root from the local "
                        "truststore; the missing links are listed above."))
                else:
                    res["notes"].append(L(
                        f"Kette reicht bis zum Root im Truststore "
                        f"'{fm.get('subject')}' – alle Zwischenglieder "
                        f"werden vom Server geliefert.",
                        f"Chain reaches the truststore root "
                        f"'{fm.get('subject')}' – all intermediates are "
                        f"sent by the server."))
                break
        # 2) Selbstsigniert, aber keine vertraute Root
        if m["self_signed"]:
            res["notes"].append(L(
                "Oberstes selbstsigniertes Zertifikat ist nicht im lokalen "
                "Truststore (private oder unbekannte CA).",
                "Topmost self-signed certificate is not in the local "
                "truststore (private or unknown CA)."))
            break
        # 3) Issuer weiterverfolgen: liegt er bei den Server-Zertifikaten?
        issuer_norm = m["issuer_norm"]
        nxt = presented.get(issuer_norm)
        if nxt is not None and id(nxt) != id(cur) and \
           issuer_norm not in seen:
            cur = nxt
            cur_source = "server"
            continue
        # 4) Issuer nicht vom Server → aus dem Truststore?
        found_pem = store.get(issuer_norm)
        if found_pem is None:
            # Gap: Zertifikat nirgends lokal → AIA-URL des Kindes nutzen
            res["missing"].append({"_gap": True,
                                   "subject": m.get("issuer"),
                                   "serial": None})
            res["aia_urls"].append(m.get("aia_ca"))
            res["notes"].append(L(
                f"Issuer '{m.get('issuer')}' weder vom Server geliefert noch "
                f"im lokalen Truststore gefunden – Kettenglied fehlt.",
                f"Issuer '{m.get('issuer')}' neither sent by the server nor "
                f"found in the local truststore – chain link missing."))
            res["full_chain"].append({
                "subject": m.get("issuer"), "issuer": None,
                "serial": None, "valid_to": None,
                "self_signed": None, "source": "missing",
            })
            break
        found = Cert(found_pem, "truststore")
        fm = found.meta()
        if fm["self_signed"]:
            # Vertrauenswürdige Root, die der Server nicht mitliefert
            res["complete"] = True
            res["root_presented"] = False
            res["notes"].append(L(
                "Kette endet bei einem Zertifikat, dessen Root im lokalen "
                "Truststore liegt; die Root wird nicht vom Server geliefert "
                "– der Client ergänzt sie aus seinem Truststore (üblich).",
                "Chain ends at a certificate whose root is in the local "
                "truststore; the root is not sent by the server – the "
                "client adds it from its truststore (normal)."))
            res["full_chain"].append({
                "subject": fm.get("subject"), "issuer": fm.get("issuer"),
                "serial": fm.get("serial"), "valid_to": fm.get("notAfter"),
                "self_signed": True, "source": "truststore",
            })
            break
        # Echtes Zwischenglied fehlt am Server
        res["missing"].append(found)
        res["aia_urls"].append(m.get("aia_ca"))
        res["notes"].append(L(
            f"Fehlt am Server: '{found.short}' (Serial {fm['serial']}) – "
            f"Client muss es aus dem Truststore oder per AIA laden.",
            f"Missing on server: '{found.short}' (serial {fm['serial']}) – "
            f"client must load it from its truststore or via AIA."))
        cur = found
        cur_source = "truststore"

    # Verifikation per openssl: (a) nur mit Server-Kette
    with tempfile.TemporaryDirectory() as td:
        leaf_path = os.path.join(td, "leaf.pem")
        untr_path = os.path.join(td, "untrusted.pem")
        Path(leaf_path).write_text(pem_list[0])
        extra = "".join(pem_list[1:]) if len(pem_list) > 1 else ""
        Path(untr_path).write_text(extra)
        rc, out, err = run_cmd([OSSL, "verify", "-CAfile", CA_BUNDLE,
                                *([] if not extra else ["-untrusted", untr_path]),
                                leaf_path])
        detail = ((out or err).strip().splitlines() or [""])[-1]
        if "Could not read any untrusted certificates" in detail:
            detail = L("Verifikation fehlgeschlagen", "verification failed")
        res["verify_with_presentation"] = {"ok": rc == 0, "detail": detail}
        rc2, out2, err2 = run_cmd([OSSL, "verify", "-CAfile", CA_BUNDLE,
                                   leaf_path])
        detail2 = ((out2 or err2).strip().splitlines() or [""])[-1]
        res["verify_store_only"] = {"ok": rc2 == 0, "detail": detail2}

    # AIA-Check für fehlende Glieder
    if res["missing"] and do_aia:
        for c, url in zip(res["missing"], res["aia_urls"]):
            if isinstance(c, dict) and c.get("_gap"):
                label, serial, subject = c["subject"], c["serial"], c["subject"]
            else:
                cm = c.meta()
                label, serial, subject = c.short, cm.get("serial"), \
                    cm.get("subject")
            info = {"cert": label, "url": url, "reachable": False,
                    "note": None}
            if not url:
                info["note"] = L(
                    "Keine AIA 'CA Issuers'-URL im Kind-Zertifikat – "
                    "automatischer Abruf nicht möglich.",
                    "No AIA 'CA Issuers' URL in the child certificate – "
                    "automatic retrieval impossible.")
                res["aia"].append(info)
                continue
            if not _url_is_http(url):
                info["note"] = L(f"AIA-URL-Schema nicht erlaubt "
                                 f"(nur http/https): {url}",
                                 f"AIA URL scheme not allowed "
                                 f"(http/https only): {url}")
                res["aia"].append(info)
                continue
            try:
                data, _ = _fetch_limited(url, AIA_MAX_BYTES, 10)
                pems = parse_pem(data.decode("utf-8", "replace"))
                if pems:
                    fetched = Cert(pems[0], "aia")
                    fm = fetched.meta()
                    # Erwartung: das geholte Zertifikat deckt die Lücke –
                    # bei Gap: dessen Subject muss dem erwarteten Issuernamen
                    # entsprechen; bei Store-Hit: Serial-Abgleich.
                    if isinstance(c, dict) and c.get("_gap"):
                        if norm_name(subject) in fm["subject_norm"] or \
                           fm["subject_norm"] in norm_name(subject):
                            info["reachable"] = True
                            info["note"] = L("Zertifikat abrufbar (Subject "
                                             "stimmt überein).",
                                             "Certificate retrievable "
                                             "(subject matches).")
                        else:
                            info["note"] = L("Liefert anderes Zertifikat.",
                                             "Returns a different certificate.")
                    else:
                        cm = c.meta()
                        if fm["subject_norm"] == cm["subject_norm"]:
                            info["reachable"] = True
                            if fm.get("serial") and cm.get("serial") and \
                               fm["serial"] == cm["serial"]:
                                info["note"] = L("Passend (Serial stimmt überein).",
                                                 "Matching (serial matches).")
                            else:
                                info["note"] = L("Abrufbar (Serial weicht ab "
                                                 "– erneut ausgestellte CA?).",
                                                 "Retrievable (serial differs "
                                                 "– re-issued CA?).")
                        else:
                            info["note"] = L("Liefert anderes Zertifikat.",
                                             "Returns a different certificate.")
                else:
                    info["note"] = L("Kein PEM-Zertifikat in der Antwort.",
                                     "No PEM certificate in the response.")
            except Exception as e:
                info["note"] = L("Abruf fehlgeschlagen: ", "Retrieval failed: ") + str(e)
            res["aia"].append(info)
    return res

# ---------------------------------------------------------------- Hostname

def hostname_matches(host, cert):
    m = cert.meta()
    names = list(m["san_dns"]) + list(m["san_ip"])
    if not names:
        cm = re.search(r"CN\s*=\s*([^,/]+)", m.get("subject", ""))
        names = [cm.group(1)] if cm else []
    host_l = host.lower().lstrip(".")
    for n in names:
        n = n.lower().lstrip(".")
        if n == host_l:
            return True, n
        if n.startswith("*.") and host_l.endswith(n[1:]) and \
           host_l.count(".") == n.count("."):
            return True, n
    return False, None

# ---------------------------------------------------------------- TLS-Versionen/Cipher

# (Name, Klasse, Schlüssellänge in Bit)
TLS13_SUITES = [
    ("TLS_AES_128_GCM_SHA256", "tls13", 128),
    ("TLS_AES_256_GCM_SHA384", "tls13", 256),
    ("TLS_CHACHA20_POLY1305_SHA256", "tls13", 256),
    ("TLS_AES_128_CCM_SHA256", "tls13iot", 128),
]

CIPHERS_12 = [
    ("ECDHE-ECDSA-AES128-GCM-SHA256", "aead", 128),
    ("ECDHE-RSA-AES128-GCM-SHA256", "aead", 128),
    ("ECDHE-ECDSA-AES256-GCM-SHA384", "aead", 256),
    ("ECDHE-RSA-AES256-GCM-SHA384", "aead", 256),
    ("ECDHE-ECDSA-CHACHA20-POLY1305", "chacha", 256),
    ("ECDHE-RSA-CHACHA20-POLY1305", "chacha", 256),
    ("ECDHE-ECDSA-AES128-SHA256", "cbc", 128),
    ("ECDHE-RSA-AES128-SHA256", "cbc", 128),
    ("ECDHE-ECDSA-AES256-SHA384", "cbc", 256),
    ("ECDHE-RSA-AES256-SHA384", "cbc", 256),
    ("DHE-RSA-AES256-GCM-SHA384", "dhe", 256),
    ("AES128-SHA256", "nopfs", 128),
    ("DES-CBC3-SHA", "3des", 112),
    ("RC4-SHA", "rc4", 128),
]

# Klasse → Stufe (maschinenlesbar, steuert Bewertung + Frontend-Farbe)
CIPHER_LEVEL = {"tls13": "strong", "tls13iot": "strong", "aead": "strong",
                "chacha": "strong", "cbc": "legacy", "dhe": "ok",
                "nopfs": "weak", "3des": "weak", "rc4": "weak"}


def cipher_category(cls):
    return {
        "tls13": L("stark (TLS 1.3)", "strong (TLS 1.3)"),
        "tls13iot": L("stark (IoT) (TLS 1.3)", "strong (IoT) (TLS 1.3)"),
        "aead": L("stark (AEAD, PFS)", "strong (AEAD, PFS)"),
        "chacha": L("stark (ChaCha20, PFS)", "strong (ChaCha20, PFS)"),
        "cbc": L("veraltet (CBC, PFS)", "legacy (CBC, PFS)"),
        "dhe": L("DHE (AEAD, PFS, langsam)", "DHE (AEAD, PFS, slow)"),
        "nopfs": L("statisches RSA-KE (kein PFS)",
                   "static RSA key exchange (no PFS)"),
        "3des": L("SCHWACH (3DES)", "WEAK (3DES)"),
        "rc4": L("SCHWACH (RC4)", "WEAK (RC4)"),
    }[cls]


def try_handshake(host, port, timeout, min_ver, max_ver, ciphers=None,
                  ciphersuites=None, seclevel0=False):
    """Einzelner TLS-Handshake mit eingeengten Optionen. Return (ok, detail)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = min_ver
    ctx.maximum_version = max_ver
    if ciphers:
        try:
            ctx.set_ciphers(ciphers + (":@SECLEVEL=0" if seclevel0 else ""))
        except ssl.SSLError:
            return False, L("lokal: Cipher in OpenSSL nicht verfügbar",
                            "local: cipher not available in OpenSSL")
    if ciphersuites:
        try:
            ctx.set_ciphersuites(ciphersuites)
        except ssl.SSLError:
            return False, L("lokal: Cipher-Suite in OpenSSL nicht verfügbar",
                            "local: cipher suite not available in OpenSSL")
    raw = None
    try:
        try:
            raw = socket.create_connection((host, port), timeout=timeout)
        except OSError as e:
            return False, L("keine TCP-Verbindung: ", "no TCP connection: ") + str(e)
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            cipher, version, _ = s.cipher()
            return True, version
    except ssl.SSLError as e:
        return False, L("TLS-Handshake abgelehnt", "TLS handshake rejected") + \
            f" ({e.reason if hasattr(e, 'reason') else e})"
    except OSError as e:
        return False, L("OS-Fehler: ", "OS error: ") + str(e)
    finally:
        if raw is not None:
            try:
                raw.close()
            except Exception:
                pass

def tls13_suite_available(host, port, timeout, suite):
    """TLS-1.3-Verfügbarkeit per openssl s_client -ciphersuites prüfen
    (suite=None: einfach TLS 1.3). Python-ssl hat je nach Build kein
    set_ciphersuites."""
    cmd = [OSSL, "s_client", "-connect", ossl_target(host, port),
           "-servername", host, "-tls1_3"]
    if suite:
        cmd += ["-ciphersuites", suite]
    rc, out, err = run_cmd(cmd, input_text="", timeout=timeout + 5)
    # s_client zeigt den SSL-Session-Block erst nach EOF auf stdin;
    # zuverlässiger Erfolgs-Marker: rc=0 + "DONE" in stderr.
    ok = (rc == 0) and ("DONE" in err)
    if ok:
        return True, ""
    text = (out + "\n" + err).strip()
    line = text.splitlines()[-1] if text else ""
    if "alert" in text.lower() or "error" in text.lower():
        line = " " + line
    return False, line[:160] or L("Handshake nicht möglich", "handshake not possible")

def check_tls(host, port, timeout):
    res = {"versions": {}, "ciphers": []}
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        tlsv1_0 = getattr(ssl.TLSVersion, "TLSv1_0", None) or ssl.TLSVersion.TLSv1
        tls1_1 = ssl.TLSVersion.TLSv1_1
        tls1_2 = ssl.TLSVersion.TLSv1_2
        tls1_3 = ssl.TLSVersion.TLSv1_3
    for label, ver in (("TLS 1.0", tlsv1_0),
                       ("TLS 1.1", tls1_1),
                       ("TLS 1.2", tls1_2),
                       ("TLS 1.3", tls1_3)):
        if ver == tls1_3:
            ok, d = tls13_suite_available(host, port, timeout, None)
        else:
            ok, d = try_handshake(host, port, timeout, ver, ver,
                                  ciphers="ALL", seclevel0=True)
        res["versions"][label] = {"available": ok, "detail": d}
    for name, cls, bits in CIPHERS_12:
        ok, d = try_handshake(host, port, timeout,
                              tlsv1_0, tls1_2,
                              ciphers=name, seclevel0=True)
        res["ciphers"].append({"cipher": name, "category": cipher_category(cls),
                               "class": cls, "level": CIPHER_LEVEL[cls],
                               "bits": bits, "available": ok, "detail": d})
    for name, cls, bits in TLS13_SUITES:
        ok, d = tls13_suite_available(host, port, timeout, name)
        res["ciphers"].append({"cipher": name, "category": cipher_category(cls),
                               "class": cls, "level": CIPHER_LEVEL[cls],
                               "bits": bits, "available": ok, "detail": d})
    return res

# ---------------------------------------------------------------- Key Exchange

# (Gruppe, Art, Schlüsselbits, RSA-Äquivalent für die Bewertung)
KX_GROUPS = [
    ("X25519MLKEM768", "hybrid", 253, 3072),
    ("X25519", "ecdh", 253, 3072),
    ("P-256", "ecdh", 256, 3072),
    ("P-384", "ecdh", 384, 7680),
    ("P-521", "ecdh", 521, 15360),
    ("X448", "ecdh", 448, 15360),
    ("ffdhe2048", "dh", 2048, 2048),
    ("ffdhe3072", "dh", 3072, 3072),
    ("ffdhe4096", "dh", 4096, 4096),
]


def _s_client_ok(out):
    m = re.search(r"Cipher is (\S+)", out)
    return bool(m) and m.group(1) != "(NONE)"


def check_kx(host, port, timeout, tls, cert_meta):
    """Welche Schlüsselaustausch-Gruppen akzeptiert der Server?
    Plus DHE-Parametergröße und statisches RSA (kein PFS)."""
    res = {"groups": [], "dhe_bits": None, "static_rsa_bits": None}
    for name, kind, bits, rsa_eq in KX_GROUPS:
        rc, out, err = run_cmd([OSSL, "s_client", "-connect",
                                ossl_target(host, port), "-servername", host,
                                "-groups", name], input_text="",
                               timeout=timeout + 5)
        unsupported = "Call to SSL_CONF_cmd" in err or "unknown group" in err.lower()
        res["groups"].append({"group": name, "kind": kind, "bits": bits,
                              "rsa_equivalent": rsa_eq,
                              "post_quantum": kind == "hybrid",
                              "available": (not unsupported) and _s_client_ok(out),
                              "tested": not unsupported})
    avail = {c["class"] for c in tls["ciphers"] if c["available"]}
    if "dhe" in avail:
        rc, out, err = run_cmd([OSSL, "s_client", "-connect",
                                ossl_target(host, port), "-servername", host,
                                "-tls1_2", "-cipher", "DHE:@SECLEVEL=0"],
                               input_text="", timeout=timeout + 5)
        m = re.search(r"Temp Key:\s*DH,\s*(\d+)\s*bits", out)
        res["dhe_bits"] = int(m.group(1)) if m else None
    if "nopfs" in avail and "RSA" in (cert_meta.get("pubkey_alg") or "").upper():
        res["static_rsa_bits"] = cert_meta.get("pubkey_bits")
    return res

# ---------------------------------------------------------------- Bewertung (SSL-Labs-artig)

PROTO_SCORE = {"TLS 1.0": 90, "TLS 1.1": 95, "TLS 1.2": 100, "TLS 1.3": 100}


def _kx_points(rsa_eq):
    if not rsa_eq:
        return 0
    if rsa_eq < 512:
        return 20
    if rsa_eq < 1024:
        return 40
    if rsa_eq < 2048:
        return 80
    if rsa_eq < 4096:
        return 90
    return 100


def _cipher_points(bits):
    if bits <= 0:
        return 0
    if bits < 128:
        return 20
    if bits < 256:
        return 80
    return 100


def compute_scores(cert_valid, tls, kx):
    """Vier Teilwerte wie SSL Labs (Rating Guide):
    Protokoll und Cipher = Mittel aus bestem und schwächstem Wert,
    Key Exchange = schwächster angebotener Austausch.
    Gesamt = 30 % Protokoll + 30 % Key Exchange + 40 % Cipher."""
    protos = [PROTO_SCORE[v] for v, d in tls["versions"].items()
              if d.get("available") and v in PROTO_SCORE]
    proto = (max(protos) + min(protos)) // 2 if protos else 0
    kx_eq = [g["rsa_equivalent"] for g in kx["groups"] if g["available"]]
    if kx.get("dhe_bits"):
        kx_eq.append(kx["dhe_bits"])
    if kx.get("static_rsa_bits"):
        kx_eq.append(kx["static_rsa_bits"])
    kxs = _kx_points(min(kx_eq)) if kx_eq else 0
    bits = [c["bits"] for c in tls["ciphers"] if c["available"]]
    ciph = (_cipher_points(max(bits)) + _cipher_points(min(bits))) // 2 \
        if bits else 0
    overall = round(0.3 * proto + 0.3 * kxs + 0.4 * ciph)
    return {"certificate": 100 if cert_valid else 0, "protocol": proto,
            "key_exchange": kxs, "cipher": ciph,
            "overall": overall if cert_valid else 0}


GRADE_ORDER = ["F", "E", "D", "C", "B", "A-", "A", "A+"]


def _score_grade(overall):
    for limit, g in ((80, "A"), (65, "B"), (50, "C"), (35, "D"), (20, "E")):
        if overall >= limit:
            return g
    return "F"


def _hsts_max_age(hsts):
    m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts or "", re.I)
    return int(m.group(1)) if m else 0

# ---------------------------------------------------------------- OCSP

def check_ocsp(host, port, pem_list, timeout):
    """OCSP direkt beim Responder abfragen. Die Anfrage baut openssl offline,
    der HTTP-POST läuft über Python (Resolver-Policy, Größendeckel)."""
    leaf = Cert(pem_list[0], "leaf")
    url = leaf.meta().get("aia_ocsp")
    if not url:
        return {"available": False,
                "detail": L("Kein OCSP-URI im Endzertifikat hinterlegt.",
                            "No OCSP URI in the leaf certificate.")}
    if not _url_is_http(url):
        return {"available": False,
                "detail": L(f"OCSP-URL-Schema nicht erlaubt: {url}",
                            f"OCSP URL scheme not allowed: {url}")}
    issuer_pem = None
    if len(pem_list) > 1:
        issuer_pem = pem_list[1]
    else:
        # Kette unvollständig → Issuer-PEM aus dem Truststore holen
        store = STORE or build_store(CA_BUNDLE)
        issuer_pem = store.get(leaf.meta()["issuer_norm"])
        if issuer_pem is None:
            return {"available": False,
                    "detail": L("OCSP-URI vorhanden, aber Issuer-Zertifikat "
                                "nicht verfügbar (Kette unvollständig und "
                                "kein Pass im Truststore).",
                                "OCSP URI present, but issuer certificate "
                                "unavailable (chain incomplete and no match "
                                "in the truststore).")}
    with tempfile.TemporaryDirectory() as td:
        leafp = os.path.join(td, "leaf.pem")
        issp = os.path.join(td, "issuer.pem")
        reqp = os.path.join(td, "req.der")
        respp = os.path.join(td, "resp.der")
        Path(leafp).write_text(pem_list[0])
        Path(issp).write_text(issuer_pem)
        rc, out, err = run_cmd([OSSL, "ocsp", "-issuer", issp, "-cert", leafp,
                                "-no_nonce", "-reqout", reqp], timeout=10)
        if rc != 0:
            return {"available": False, "url": url,
                    "detail": L("OCSP-Anfrage nicht erstellbar: ",
                                "Cannot build OCSP request: ") + err.strip()[:160]}
        try:
            data, _ = _fetch_limited(
                url, AIA_MAX_BYTES, timeout + 8, data=Path(reqp).read_bytes(),
                headers={"Content-Type": "application/ocsp-request"})
        except Exception as e:
            return {"available": False, "url": url,
                    "detail": L("OCSP-Responder nicht erreichbar: ",
                                "OCSP responder unreachable: ") + str(e)}
        Path(respp).write_bytes(data)
        rc, out, err = run_cmd([OSSL, "ocsp", "-respin", respp, "-issuer",
                                issp, "-cert", leafp, "-CAfile", CA_BUNDLE,
                                "-no_nonce", "-text"], timeout=10)
        resp_status = None
        cs = re.search(r"OCSP Response Status:\s*(\S+)", out)
        if cs:
            resp_status = cs.group(1)
        cert_status = None
        cs2 = re.search(r"(?:Certificate|Cert)\s+status:\s*(\S+)", out, re.I)
        if cs2:
            cert_status = cs2.group(1)
        this_upd = re.search(r"This Update:\s*(.+)", out)
        next_upd = re.search(r"Next Update:\s*(.+)", out)
        detail = ((out or err).strip().splitlines() or [""])[-1]
        return {"available": True, "url": url,
                "response_status": resp_status,
                "certificate_status": cert_status,
                "this_update": this_upd.group(1).strip() if this_upd else None,
                "next_update": next_upd.group(1).strip() if next_upd else None,
                "ok": cert_status == "good",
                "detail": detail}

# ---------------------------------------------------------------- Revocation

def check_ocsp_stapling(host, port, timeout=15):
    """OCSP-Stapling: fragt per s_client -status die stapelte OCSP-Antwort
    direkt im TLS-Handshake ab."""
    p = run_cmd([OSSL, "s_client", "-connect", ossl_target(host, port),
                 "-servername", host, "-status"], input_text="",
                timeout=timeout)
    out = p[1] or ""
    if "OCSP Response Status" not in out:
        return {"stapled": False, "status": "unknown",
                "note": L("Server liefert keine stapelte OCSP-Antwort.",
                          "Server does not staple an OCSP response.")}
    st = re.search(r"OCSP Response Status:\s*(\S+)", out)
    cs = re.search(r"(?:Certificate|Cert)\s+status:\s*(\S+)", out, re.I)
    status = (cs.group(1) if cs else (st.group(1) if st else "unknown"))
    return {"stapled": True, "status": status,
            "response_status": st.group(1) if st else None,
            "note": L("Stapelte OCSP-Antwort im Handshake erhalten.",
                      "Stapled OCSP response received in the handshake.")}


CRL_MAX_BYTES = 20 * 1024 * 1024  # Default 20 MB; via --crl-max-mb änderbar
CRL_MAX_MB = 20


AIA_MAX_BYTES = 1 * 1024 * 1024  # 1 MB Deckel für AIA-/OCSP-Abrufe


def _url_is_http(url):
    """Nur http/https-URLs sind erlaubt (blockt file://, gopher://, ldap://
    etc. aus feindlichen Zertifikaten)."""
    return urlparse(url).scheme in ("http", "https")


def _fetch_crl(url, timeout):
    """CRL-Download -> bytes (max. CRL_MAX_BYTES); wirft CrlFetchError
    mit menschenlesbarem Grund (404, HTML, zu groß, …)."""
    if not _url_is_http(url):
        raise CrlFetchError(L(f"URL-Schema nicht erlaubt (nur http/https): {url}",
                              f"URL scheme not allowed (http/https only): {url}"))
    try:
        data, ctype = _fetch_limited(url, CRL_MAX_BYTES, timeout)
    except RuntimeError:
        raise CrlFetchError(L(f"CRL zu groß (> {CRL_MAX_MB} MB) – Inhalt nicht "
                              "geprüft (Deckel via --crl-max-mb anheben).",
                              f"CRL too large (> {CRL_MAX_MB} MB) – content not "
                              "checked (raise limit via --crl-max-mb)."))
    if data[:1] in (b"<",) or "text/html" in ctype:
        raise CrlFetchError(L("Server antwortete mit HTML statt CRL-Daten "
                              "(CRL vermutlich rotiert oder 404).",
                              "Server answered with HTML instead of CRL data "
                              "(CRL probably rotated or 404)."))
    if "text/plain" in ctype and not (b"BEGIN X509 CRL" in data[:300]
                                      or b"\x30" in data[:16]):
        raise CrlFetchError(L("Antwort sieht nicht wie CRL aus.",
                              "Response does not look like a CRL."))
    return data


class CrlFetchError(Exception):
    pass


def check_crl(pem_list, timeout=15):
    """CRL-DP der präsentierten Zertifikate abrufen und prüfen, ob das
    Endzertifikat als revoked gelistet ist."""
    leaf_serial = (Cert(pem_list[0], "leaf").meta().get("serial") or
                   "").upper()
    results = []
    checked_any = False
    for i, pem in enumerate(pem_list[:3]):
        p = run_cmd([OSSL, "x509", "-noout", "-text"], input_text=pem,
                    timeout=8)
        xout = p[1] or ""
        dp = re.findall(r"CRL Distribution Point.*?URI:(\S+)",
                        xout, re.S)
        dp_uri = dp[-1].strip() if dp else None
        if not dp_uri:
            continue
        checked_any = True
        iss = re.search(r"^\s*Issuer: (.+)$", xout, re.M)
        entry = {"issuer": iss.group(1).strip() if iss else
                 L(f"Glied {i}", f"link {i}"),
                 "url": dp_uri, "ok": None, "revoked": False, "note": ""}
        try:
            data = _fetch_crl(dp_uri, timeout)
        except CrlFetchError as e:
            entry["ok"] = False
            entry["note"] = str(e)
            results.append(entry)
            continue
        except Exception as e:
            entry["ok"] = False
            entry["note"] = L("CRL nicht abrufbar: ", "CRL not retrievable: ") + str(e)
            results.append(entry)
            continue
        # CRL ist abrufbar
        entry["ok"] = True
        entry["size_bytes"] = len(data)
        with tempfile.NamedTemporaryFile(suffix=".crl", delete=False,
                                         mode="wb") as tf:
            tf.write(data)
            crl_path = tf.name
        try:
            txt = run_cmd([OSSL, "crl", "-in", crl_path, "-noout",
                           "-text"], timeout=30)
            if txt[0] != 0:
                entry["note"] = L("CRL heruntergeladen, aber von OpenSSL "
                                  "nicht lesbar: ",
                                  "CRL downloaded, but not readable by "
                                  "OpenSSL: ") + \
                    " ".join((txt[2] or "").strip().splitlines()[-1:])
            else:
                lu = re.search(r"Last Update:\s*(.+)", txt[1])
                entry["last_update"] = lu.group(1).strip() if lu else None
                exp = re.search(r"Next Update:\s*(.+)", txt[1])
                if exp:
                    entry["next_update"] = exp.group(1).strip()
                if leaf_serial and i == 0:
                    found = False
                    for line in (txt[1] or "").splitlines():
                        ls = line.strip()
                        if ls.startswith("Serial Number:"):
                            val = ls.split(":", 1)[1].strip().upper() \
                                 .replace(":", "")
                            if val == leaf_serial:
                                found = True
                                break
                    entry["leaf_serial"] = leaf_serial
                    entry["ok"] = not found
                    entry["revoked"] = found
                    entry["note"] = (
                        L("Endzertifikat ist REVOKIERT (im CRL gelistet)!",
                          "Leaf certificate is REVOKED (listed in CRL)!")
                        if found else
                        L(f"Endzertifikat (Serial {leaf_serial[:16]}…) "
                          f"nicht im CRL.",
                          f"Leaf certificate (serial {leaf_serial[:16]}…) "
                          f"not in CRL."))
        finally:
            os.unlink(crl_path)
        results.append(entry)
    return {"checked": checked_any, "crls": results}


def check_session(host, port, timeout=15):
    """SSL-Session-Resume: 1) Session speichern (-sess_out), 2) erneut
    verbinden (-sess_in) und prüfen, ob 'Reused' gemeldet wird.
    Erst auf TLS 1.2 (klassisches Session-Ticket), dann TLS 1.3."""
    target = ossl_target(host, port)
    with tempfile.TemporaryDirectory() as td:
        sp = os.path.join(td, "sess.pem")
        def attempt(extra):
            p = run_cmd([OSSL, "s_client", "-connect", target,
                         "-servername", host, "-sess_out", sp, *extra],
                        input_text="", timeout=timeout)
            return p
        # TLS 1.2
        p12 = attempt(["-tls1_2"])
        # erneut laden + Resume
        p12b = run_cmd([OSSL, "s_client", "-connect", target,
                        "-servername", host, "-sess_in", sp, "-tls1_2"],
                       input_text="", timeout=timeout)
        reused12 = "Reused," in (p12b[1] or "")
        ok12 = p12[0] == 0 and p12b[0] == 0
        # TLS 1.3
        p13 = attempt([])
        p13b = run_cmd([OSSL, "s_client", "-connect", target,
                        "-servername", host, "-sess_in", sp],
                       input_text="", timeout=timeout)
        reused13 = "Reused," in (p13b[1] or "")
        ok13 = p13[0] == 0 and p13b[0] == 0
    if not ok12 and not ok13:
        return {"resumable": False, "resumed": False,
                "note": L("Keine Session-Tests möglich (Handshake fehlgeschlagen).",
                          "No session tests possible (handshake failed).")}
    if reused12:
        return {"resumable": True, "resumed": True, "version": "TLSv1.2",
                "note": L("Session-Resume (Session-Ticket) erfolgreich (TLS 1.2).",
                          "Session resumption (session ticket) successful (TLS 1.2).")}
    if reused13:
        return {"resumable": True, "resumed": True, "version": "TLSv1.3",
                "note": L("Session-Resume erfolgreich (TLS 1.3).",
                          "Session resumption successful (TLS 1.3).")}
    return {"resumable": ok12 or ok13, "resumed": False,
            "note": L("Kein Session-Resume (neuer Handshake).",
                      "No session resumption (new handshake).")}


def revocation_status(ocsp_stapled, crl, ocsp_direct):
    """SSL-Labs-artiger Revocation-Status (ok / unknown / revokiert)."""
    # 1) CRL: Endzertifikat gelistet -> REVOKIERT
    if crl and crl.get("crls"):
        for c in crl["crls"]:
            if c.get("revoked"):
                return {"level": "revoked", "source": "CRL",
                        "detail": L("Endzertifikat im CRL gelistet.",
                                    "Leaf certificate listed in CRL.")}
    # 2) OCSP-Stapling / Direkt-OCSP: 'good' -> ok
    good = None
    if ocsp_stapled and ocsp_stapled.get("stapled"):
        good = "good" in (ocsp_stapled.get("status") or "")
    if good is None and ocsp_direct:
        good = "good" in ((ocsp_direct.get("certificate_status") or
                           ocsp_direct.get("response_status")) or "")
    if good:
        return {"level": "ok", "source": "OCSP",
                "detail": L("Revocation-Status 'good' (OCSP).",
                            "Revocation status 'good' (OCSP).")}
    # 3) CRL erreichbar und Endzert nicht gelistet -> ok
    if crl and crl.get("crls"):
        leaf = [c for c in crl["crls"] if c.get("leaf_serial")]
        if leaf and all(c.get("ok") for c in leaf):
            return {"level": "ok", "source": "CRL",
                    "detail": L("Endzertifikat nicht in den CRLs gelistet.",
                                "Leaf certificate not listed in the CRLs.")}
    # 4) CRL abrufbar, aber Endserial nicht eindeutig geprüft -> unknown
    if crl and crl.get("checked"):
        return {"level": "unknown", "source": "CRL",
                "detail": L("CRL erreichbar; Revocation nicht eindeutig "
                            "bestätigt.",
                            "CRL reachable; revocation not clearly "
                            "confirmed.")}
    return {"level": "unknown", "source": L("keine", "none"),
            "detail": L("Kein CRL/OCSP für das Endzertifikat verfügbar.",
                        "No CRL/OCSP available for the leaf certificate.")}


def check_http3(host, port, timeout=6):
    """HTTP/3-Indiz: QUIC-Initial-Paket an host:443/UDP senden.
    Long-Header-Antwort (0x80-0xBF) → QUIC/HTTP3 aktiv.
    UDP-Ausgang gesperrt → 'unbekannt' (Alt-Svc-Header kombiniert)."""
    dcid = os.urandom(8)
    scid = os.urandom(8)
    ver = 0x00000001  # QUIC v1
    b = bytearray()
    b.append(0xC0)                    # form=1 (Long), fixed=1, reserved
    b += ver.to_bytes(4, "big")       # version
    b.append(len(dcid)); b += dcid
    b.append(len(scid)); b += scid
    b.append(0x00)                    # token-length = 0
    # Payload: VNO(4) + CRYPTO-Frame (type 0x00, len 0) = 6 Bytes
    b += (4 + 2).to_bytes(2, "big")
    b += (0).to_bytes(4, "big")       # VNO
    b += b"\x00" + (0).to_bytes(2, "big")  # CRYPTO: type, len=0
    # socket.connect löst selbst (in C) auf → feste IP verwenden
    ip = pinned_ip(host)
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(fam, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.send(bytes(b))
        try:
            data = sock.recv(1500)
            if data and data[0] & 0x80:
                return {"active": True,
                        "note": L("QUIC-Antwort (Long Header) erhalten → "
                                  "HTTP/3 aktiv.",
                                  "QUIC response (long header) received → "
                                  "HTTP/3 active.")}
            return {"active": False,
                    "note": L("UDP-Antwort erhalten, aber kein QUIC-Long-Header.",
                              "UDP response received, but no QUIC long header.")}
        except socket.timeout:
            return {"active": False, "unknown": True,
                    "note": L("Keine UDP-Antwort (UDP-Ausgang möglicherweise "
                              "gesperrt oder HTTP/3 nicht aktiv) – Alt-Svc-"
                              "Header beachten.",
                              "No UDP response (outbound UDP possibly blocked "
                              "or HTTP/3 not active) – see Alt-Svc header.")}
    except OSError as e:
        return {"active": False, "unknown": True,
                "note": L("UDP-Check nicht möglich: ", "UDP check not possible: ")
                + str(e)}
    finally:
        sock.close()

def resolve_host(host):
    """Alle A-/AAAA-Adressen eines Hostnamens (bzw. die IP selbst)."""
    h = host.strip("[]")
    try:
        infos = socket.getaddrinfo(h, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, BlockedAddress) as e:
        return {"ok": False, "error": str(e), "ipv4": [], "ipv6": []}
    v4, v6 = [], []
    for i in infos:
        ip = i[4][0]
        (v4 if i[0] == socket.AF_INET else v6).append(ip)
    return {"ok": True,
            "ipv4": list(dict.fromkeys(v4)),
            "ipv6": list(dict.fromkeys(v6)),
            "tested_ip": pinned_ip(h)}


def _alpn_negotiate(ctx, host, port, timeout=8):
    """Nur TLS-Handshake mit ALPN -> ausgehandeltes Protokoll (h2/http/1.1).
    Sendet keinen HTTP-Request, deshalb kein h2-Framing-Problem."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                return tls.selected_alpn_protocol()
    except Exception:
        return None


def _one_http_request(ctx, host, port, path, timeout, host_header):
    """Ein einzelner HTTP/1.1-GET (ALPN auf http/1.1 gezwungen)."""
    import http.client
    conn = (http.client.HTTPSConnection(host, port, timeout=timeout,
                                        context=ctx)
            if ctx is not None
            else http.client.HTTPConnection(host, port, timeout=timeout))
    try:
        conn.request("GET", path, headers={
            "Host": host_header, "User-Agent": "tlscheck/1.0",
            "Accept": "*/*"})
        r = conn.getresponse()
        hdrs = dict(r.getheaders())
        return {"status": r.status, "reason": r.reason,
                "headers": {k: v for k, v in hdrs.items()}}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _follow_redirects(ctx, host, port, timeout, max_hops=3):
    """HTTPS-Request mit Redirect-Following (https und http erlaubt).
    Sicherheit:
    - Redirects auf interne Ziele NICHT folgen (SSRF-Schutz; ohne
      BLOCK_PRIVATE mindestens Loopback/Link-Local).
    - Downgrade HTTPS → HTTP NICHT folgen (Verschlüsselung erhalten)."""
    started_secure = ctx is not None
    hops = []
    for _ in range(max_hops + 1):
        info = _one_http_request(ctx, host, port, "/", timeout,
                                 host_header=host if port == 443
                                 else f"{host}:{port}")
        hops.append({"status": info["status"],
                     "server": info["headers"].get("Server"),
                     "location": info["headers"].get("Location")})
        loc = info["headers"].get("Location")
        if info["status"] in (301, 302, 303, 307, 308) and loc:
            p = urlparse(loc)
            if p.scheme not in ("http", "https"):
                break
            new_host = p.hostname or host
            new_port = p.port or (443 if p.scheme == "https" else 80)
            if p.scheme == "http" and started_secure:
                hops.append({"status": "blocked",
                             "server": None,
                             "location": loc,
                             "note": L("Redirect auf unverschlüsseltes HTTP "
                                       "nicht gefolgt.",
                                       "Redirect to unencrypted HTTP not "
                                       "followed.")})
                break
            if _is_blocked_redirect_target(new_host):
                hops.append({"status": "blocked",
                             "server": None,
                             "location": loc,
                             "note": L("Redirect auf internes Ziel nicht "
                                       "gefolgt.",
                                       "Redirect to internal target not "
                                       "followed.")})
                break
            host = new_host
            port = new_port
            ctx = None if p.scheme == "http" else ctx
        else:
            break
    return hops, info, host, port


def _is_blocked_redirect_target(hostname):
    """True für Redirect-Ziele, die intern empfindlich sind.
    Mit BLOCK_PRIVATE: alle nicht-öffentlichen Adressen. Ohne: mindestens
    Loopback (127.x, ::1, localhost) und Link-Local/Cloud-Metadata
    (169.254.x, fe80::)."""
    if hostname is None:
        return False
    h = hostname.lower().strip(".")
    if h in ("localhost", "localhost.localdomain"):
        return True
    try:
        infos = socket.getaddrinfo(h, None, socket.AF_UNSPEC,
                                   socket.SOCK_STREAM)
    except BlockedAddress:
        return True
    except (socket.gaierror, OSError):
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        if ip.is_loopback or ip.is_link_local:
            return True
    return False


def check_http(host, port, timeout=8):
    """Webserver-Infos: ALPN/HTTP2, Server-Header, HSTS, Redirects.
    Liest keine Inhalte (nur GET /), daher unproblemabel."""
    res = {"alpn": None, "redirects": [], "https": None, "http80": None}
    try:
        alpn_ctx = ssl.create_default_context()
        alpn_ctx.set_alpn_protocols(["h2", "http/1.1"])
        res["alpn"] = _alpn_negotiate(alpn_ctx, host, port,
                                      min(timeout, 8))
    except Exception:
        pass
    if port == 443:
        try:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["http/1.1"])
            hops, final, _, _ = _follow_redirects(ctx, host, port, timeout)
            res["redirects"] = hops
            res["https"] = final
        except Exception as e:
            # Retry ohne Verifikation: Server-Header bleiben informativ
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols(["http/1.1"])
                hops, final, _, _ = _follow_redirects(ctx, host, port,
                                                      timeout)
                res["redirects"] = hops
                res["https"] = final
                res["https"]["unverified"] = True
            except Exception as e2:
                res["https"] = {"error": f"{e} / {e2}"}
    else:
        # nicht-443: trotzdem ALPN+Header vom TLS-Port holen
        try:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["http/1.1"])
            info = _one_http_request(ctx, host, port, "/", timeout,
                                     host_header=host if port == 443
                                     else f"{host}:{port}")
            res["https"] = info
        except Exception as e:
            res["https"] = {"error": str(e)}
    # HTTP-Port-80-Check nur beim Standardport & Hostname
    if port == 443:
        try:
            info = _one_http_request(None, host, 80, "/",
                                     min(timeout, 6), host_header=host)
            res["http80"] = info
        except Exception as e:
            res["http80"] = {"error": str(e)}
    return res


def webserver_summary(host, port, httpres):
    """check_http-Brutodaten -> compacte Report-Struktur + Warnungen."""
    warns = []
    out = {"server": None, "protocol": None, "hsts": None,
           "hsts_preload": False, "hsts_max_age": 0, "alt_svc": None,
           "final_status": None, "redirects": httpres.get("redirects", []),
           "http80": None, "http80_redirects_https": None}
    https = httpres.get("https") or {}
    if "error" in https:
        out["error"] = https["error"]
        return out, warns
    out["final_status"] = https.get("status")
    out["server"] = (https.get("headers") or {}).get("Server")
    out["alt_svc"] = (https.get("headers") or {}).get("Alt-Svc")
    alpn = httpres.get("alpn")
    out["protocol"] = {"h2": "HTTP/2", "http/1.1": "HTTP/1.1"}.get(
        alpn, alpn or L("unbekannt", "unknown"))
    hsts = (https.get("headers") or {}).get("Strict-Transport-Security")
    if hsts:
        out["hsts"] = hsts
        out["hsts_preload"] = "preload" in hsts.lower()
        out["hsts_max_age"] = _hsts_max_age(hsts)
    else:
        warns.append(L("Kein HSTS-Header (Strict-Transport-Security) gesetzt.",
                       "No HSTS header (Strict-Transport-Security) set."))
    h80 = httpres.get("http80") or {}
    if "error" not in h80:
        st = h80.get("status")
        loc = (h80.get("headers") or {}).get("Location") or ""
        if st in (301, 302, 303, 307, 308) and loc.startswith("https"):
            out["http80"] = "redirect → " + loc.split("/")[0]
            out["http80_redirects_https"] = True
        elif st in (301, 302, 303, 307, 308):
            out["http80"] = L(f"redirect (nicht auf HTTPS): {loc}",
                              f"redirect (not to HTTPS): {loc}")
            out["http80_redirects_https"] = False
            warns.append(L("HTTP (Port 80) redirectet nicht auf HTTPS.",
                           "HTTP (port 80) does not redirect to HTTPS."))
        elif st == 200:
            out["http80"] = L("antwortet 200 (kein Redirect auf HTTPS)",
                              "answers 200 (no redirect to HTTPS)")
            out["http80_redirects_https"] = False
            warns.append(L("HTTP (Port 80) liefert die Seite unverschlüsselt "
                           "ohne Redirect auf HTTPS.",
                           "HTTP (port 80) serves the page unencrypted "
                           "without redirecting to HTTPS."))
        else:
            out["http80"] = f"Status {st}"
    else:
        out["http80"] = h80["error"]
    return out, warns


# ---------------------------------------------------------------- Bericht

def rating(cert_ok, host_ok, chain, tls):
    if not cert_ok or not host_ok:
        return "F", L("Zertifikat ungültig bzw. Hostname passt nicht.",
                      "Certificate invalid or hostname mismatch.")
    weak = [x for x in tls["ciphers"] if x["available"] and x["level"] == "weak"]
    if weak:
        return "C", L("Schwache Cipher-Suite(s) aktiv: ",
                      "Weak cipher suite(s) enabled: ") + \
            ", ".join(x["cipher"] for x in weak)
    old_tls = [v for v in ("TLS 1.0", "TLS 1.1")
               if tls["versions"].get(v, {}).get("available")]
    if old_tls:
        return "C", L("Veraltete TLS-Version(en) verfügbar: ",
                      "Outdated TLS version(s) available: ") + \
            ", ".join(old_tls)
    if not chain["complete"] or chain["missing"]:
        return "B", L("Kette wird nicht komplett vom Server geliefert "
                      "(Client-Truststore/AIA nötig).",
                      "Chain is not completely sent by the server "
                      "(client truststore/AIA needed).")
    cbc = [x for x in tls["ciphers"] if x["available"] and x["class"] == "cbc"]
    if cbc:
        return "A-", L("CBC-Cipher-Suites aktiv (funktioniert, AEAD wäre "
                       "besser): ",
                       "CBC cipher suites enabled (works, AEAD would be "
                       "better): ") + ", ".join(x["cipher"] for x in cbc)
    return "A", L("Gültiges Zertifikat, vollständige Kette, moderne Cipher-Suites.",
                  "Valid certificate, complete chain, modern cipher suites.")

def build_report(host, port, args, pem_list, proto, cert, chain, tls, ocsp,
                 dns=None, webserver=None, session=None, stapling=None,
                 crl=None, http3=None, kx=None):
    m = cert.meta()
    host_ok, matched = hostname_matches(host, cert)
    now = datetime.datetime.utcnow()
    not_after = datetime.datetime.strptime(m["notAfter"],
                                           "%b %d %H:%M:%S %Y %Z")
    expired = now > not_after
    problems = []
    warnings = []
    if expired:
        problems.append(L("Zertifikat ist ABGELAUFEN.", "Certificate has EXPIRED."))
    elif cert.days_left < 14:
        warnings.append(L(f"Zertifikat läuft in {cert.days_left} Tagen ab.",
                          f"Certificate expires in {cert.days_left} days."))
    if not host_ok:
        problems.append(L(f"Hostname '{host}' nicht im Zertifikat (SAN/CN).",
                          f"Hostname '{host}' not in certificate (SAN/CN)."))
    if m["self_signed"]:
        problems.append(L("Endzertifikat ist selbst signiert.",
                          "Leaf certificate is self-signed."))
    if m.get("pubkey_bits") and m.get("pubkey_bits") < 2048 and \
       "RSA" in m.get("pubkey_alg", "").upper():
        warnings.append(L(f"RSA-Schlüssel nur {m['pubkey_bits']} Bit "
                          "(>=2048 empfohlen).",
                          f"RSA key only {m['pubkey_bits']} bits "
                          "(>=2048 recommended)."))
    if "SHA1" in m.get("sig_alg", "").upper():
        problems.append(L("Signatur mit SHA-1 (nicht mehr akzeptiert).",
                          "SHA-1 signature (no longer accepted)."))
    if chain["missing"]:
        warnings.append(L(f"{len(chain['missing'])} Zwischenzertifikat/-e "
                          f"werden nicht vom Server geliefert "
                          f"(Client-Truststore/AIA nötig).",
                          f"{len(chain['missing'])} intermediate certificate(s) "
                          f"not sent by the server "
                          f"(client truststore/AIA needed)."))
    if not chain["verify_with_presentation"]["ok"]:
        problems.append(L("Kette mit den Server-Zertifikaten nicht "
                          "verifizierbar: ",
                          "Chain not verifiable with the server "
                          "certificates: ") +
                        chain["verify_with_presentation"]["detail"])
    elif not chain["verify_store_only"]["ok"] and chain["missing"]:
        warnings.append(L("Kette verifiziert sich nur dank lokalem "
                          "Truststore (Zwischenglieder müssen lokal vorhanden "
                          "sein).",
                          "Chain only verifies thanks to the local truststore "
                          "(intermediates must be present locally)."))
    for x in tls["ciphers"]:
        if x["available"] and x["class"] in ("3des", "rc4"):
            warnings.append(L(f"Schwache Cipher-Suite aktiv: {x['cipher']}",
                              f"Weak cipher suite enabled: {x['cipher']}"))
    for v in ("TLS 1.0", "TLS 1.1"):
        if tls["versions"].get(v, {}).get("available"):
            warnings.append(L(f"Veraltete TLS-Version verfügbar: {v}",
                              f"Outdated TLS version available: {v}"))
    if ocsp and ocsp.get("available") and not ocsp.get("ok"):
        warnings.append("OCSP-Status: " +
                        (ocsp.get("certificate_status") or
                         ocsp.get("response_status") or
                         L("unbekannt", "unknown")))
    if webserver:
        warnings.extend(webserver.get("warnings", []))
        webserver = dict(webserver)
        webserver.pop("warnings", None)
        ws_problems = webserver.get("problems", [])
        problems.extend(ws_problems)
    # Revocation: revokiert = hartes Problem
    rev = revocation_status(stapling, crl, ocsp) if (crl or stapling or ocsp) else None
    if rev and rev.get("level") == "revoked":
        problems.append(L("Zertifikat ist REVOKIERT: ",
                          "Certificate is REVOKED: ") + rev.get("detail", ""))
    cert_ok = not expired and (m.get("sig_alg") != "") and not m["self_signed"]
    grade, grade_note = rating(cert_ok, host_ok, chain, tls)

    # Punkte wie SSL Labs; die Note ist das Schlechtere aus Regel-Note
    # und Punkte-Note, A+ zusätzlich nur mit langem HSTS und ohne Befund.
    cert_valid = cert_ok and host_ok and chain["verify_with_presentation"]["ok"] \
        and not (rev and rev.get("level") == "revoked")
    scores = compute_scores(cert_valid, tls, kx or {"groups": []})
    sg = _score_grade(scores["overall"])
    if GRADE_ORDER.index(sg) < GRADE_ORDER.index(grade):
        grade = sg
        grade_note = L(f"Gesamtpunktzahl {scores['overall']}/100 begrenzt die "
                       f"Note.",
                       f"Overall score {scores['overall']}/100 limits the "
                       f"grade.")
    if not cert_valid:
        grade = "F"
    hsts_age = (webserver or {}).get("hsts_max_age") or 0
    if grade == "A" and hsts_age >= 15552000 and not problems and not warnings:
        grade = "A+"
        grade_note = L("Ausgezeichnet: gültiges Zertifikat, vollständige "
                       "Kette, moderne Cipher-Suites und HSTS ≥ 6 Monate.",
                       "Excellent: valid certificate, complete chain, "
                       "modern cipher suites and HSTS ≥ 6 months.")
    elif grade == "A" and hsts_age < 15552000:
        grade_note += L(" (A+ erst mit HSTS ≥ 6 Monate.)",
                        " (A+ requires HSTS ≥ 6 months.)")
    return {
        "host": host, "port": port, "lang": LANG,
        "checked_at_utc": now.strftime("%Y-%m-%d %H:%M:%S"),
        "negotiated_protocol": proto,
        "certificate": {
            "subject": m["subject"], "issuer": m["issuer"],
            "serial": m.get("serial"),
            "not_before": m["notBefore"], "not_after": m["notAfter"],
            "days_left": cert.days_left,
            "signature_algorithm": m.get("sig_alg"),
            "public_key": f"{m.get('pubkey_alg', '?')} "
                         f"{m.get('pubkey_bits', '')} Bit",
            "san_dns": m["san_dns"],
            "san_ip": m.get("san_ip"),
            "hostname_match": host_ok,
            "hostname_matched_name": matched,
            "aia_ca": m.get("aia_ca"), "ocsp_url": m.get("aia_ocsp"),
        },
        "chain": {
            "presented_count": len(pem_list),
            "presented": [
                {"index": i, "subject": c.meta()["subject"],
                 "issuer": c.meta()["issuer"], "serial": c.meta().get("serial"),
                 "valid_to": c.meta()["notAfter"],
                 "self_signed": c.meta()["self_signed"]}
                for i, c in enumerate(chain["presented"])
            ],
            "full_chain": chain.get("full_chain", []),
            "complete_from_server": chain["complete"],
            "root_presented_by_server": chain["root_presented"],
            "missing_from_server": [
                ({"subject": c["subject"], "serial": c.get("serial"),
                  "in_truststore": False}
                 if isinstance(c, dict) and c.get("_gap")
                 else {"subject": c.meta()["subject"],
                       "serial": c.meta().get("serial"),
                       "in_truststore": True})
                for c in chain["missing"]],
            "verify_with_server_chain": chain["verify_with_presentation"],
            "verify_with_truststore": chain["verify_store_only"],
            "notes": chain["notes"],
            "aia": chain["aia"],
        },
        "tls_versions": tls["versions"],
        "ciphers": tls["ciphers"],
        "key_exchange": kx,
        "ocsp": ocsp,
        "dns": dns,
        "webserver": webserver,
        "session": session,
        "ocsp_stapling": stapling,
        "crl": crl,
        "http3": http3,
        "revocation": rev,
        "summary": {"grade": grade, "note": grade_note,
                    "scores": scores,
                    "problems": problems, "warnings": warnings,
                    "ok": not problems and not warnings},
    }

# ---------------------------------------------------------------- Ausgabe

GRADE_COLORS = {"F": "31", "E": "31", "D": "31", "C": "33", "B": "36",
                "A-": "32", "A": "32", "A+": "32"}

def paint(color, s):
    return f"\033[{color}m{s}\033[0m" if sys.stdout.isatty() else s

def mark(ok, good="[OK]", bad="[!!]"):
    return paint("32", good) if ok else paint("31", bad)

def _bar(score, width=20):
    n = round(score / 100 * width)
    return "█" * n + "░" * (width - n)

def print_report(r, args):
    s = r["summary"]
    sc = s["scores"]
    print(paint("1", "=" * 72))
    print(paint("1", f"  TLS-Check: {r['host']}:{r['port']}   "
                     f"{r['checked_at_utc']} UTC"))
    print(paint("1", "=" * 72))
    print(f"  {L('Bewertung', 'Grade')}: "
          f"{paint(GRADE_COLORS.get(s['grade'], '0'), s['grade'])}"
          f"  –  {s['note']}")
    print(f"  {L('Verhandelte Version', 'Negotiated version')}: "
          f"{r['negotiated_protocol'] or L('unbekannt', 'unknown')}")
    print()
    for label, key in ((L("Zertifikat", "Certificate"), "certificate"),
                       (L("Protokolle", "Protocol support"), "protocol"),
                       ("Key Exchange", "key_exchange"),
                       (L("Cipher-Stärke", "Cipher strength"), "cipher")):
        print(f"    {label:18s} {_bar(sc[key])} {sc[key]:3d}")
    print(f"    {L('Gesamt', 'Overall'):18s} {' ' * 20} {sc['overall']:3d}")
    print()

    cert = r["certificate"]
    print(paint("1", L("  ZERTIFIKAT", "  CERTIFICATE")))
    san = ", ".join(cert["san_dns"]) if cert["san_dns"] else "–"
    ips = cert.get("san_ip")
    ips = ips if isinstance(ips, list) else ([ips] if ips else [])
    if ips:
        san += (", " if cert["san_dns"] else "") + "IP " + ", ".join(ips)
    print(f"    {mark(cert['hostname_match'])} Hostname: "
          f"{cert['hostname_matched_name'] or L('(kein Match)', '(no match)')}"
          f"  (SAN: {san})")
    print(f"    {mark(True)} Subject: {cert['subject']}")
    print(f"    {mark(True)} Issuer:  {cert['issuer']}")
    print(f"    {mark(True)} Serial:  {cert['serial']}")
    print(f"    {mark(int(cert['days_left']) > 0)} {L('Gültig', 'Valid')}: "
          f"{cert['not_before']} → {cert['not_after']} ({cert['days_left']} "
          f"{L('Tage verbleibend', 'days left')})")
    print(f"    {mark(True)} {L('Signatur', 'Signature')}: "
          f"{cert['signature_algorithm']}  |  {L('Schlüssel', 'Key')}: "
          f"{cert['public_key']}")
    print(f"    {mark(True)} AIA (CA Issuers): {cert['aia_ca'] or '–'}")
    print(f"    {mark(True)} OCSP-URL:         {cert['ocsp_url'] or '–'}")
    print()

    ch = r["chain"]
    print(paint("1", L("  ZERTIFIKATSKETTE (vom Server geliefert)",
                       "  CERTIFICATE CHAIN (sent by server)")))
    for i, p in enumerate(ch["presented"]):
        tag = {0: L("Endzertifikat", "Leaf"),
               1: L("Zwischenzertifikat", "Intermediate"),
               2: L("Wurzel", "Root")}.get(i, L(f"Glied {i}", f"Link {i}"))
        extra = "  (self-signed)" if p["self_signed"] else ""
        print(f"    [{i}] {tag:20s} {p['subject']}{extra}  "
              f"({L('gültig bis', 'valid until')} {p['valid_to']})")
    vsp = ch["verify_with_server_chain"]
    print(f"    {mark(vsp['ok'])} "
          f"{L('openssl-verify nur mit Server-Kette', 'openssl verify with server chain only')}: "
          f"{L('erfolgreich', 'successful') if vsp['ok'] else L('FEHLGESCHLAGEN', 'FAILED')}"
          f"  ({vsp['detail']})")
    if ch["missing_from_server"]:
        print(f"    {mark(False)} "
              f"{L('Fehlt am Server (Client muss beschaffen)', 'Missing on server (client must obtain)')}:")
        for mcer in ch["missing_from_server"]:
            print(f"        - {mcer['subject']}  (Serial {mcer['serial']})")
        for a in ch["aia"]:
            st = {True: L("abrufbar ✓", "retrievable ✓"),
                  False: L("NICHT abrufbar", "NOT retrievable"),
                  None: "n/a"}[a["reachable"]]
            print(f"        AIA: {a['url'] or L('kein Eintrag', 'no entry')} → {st} "
                  f"{a['note'] or ''}")
    else:
        complete_txt = (L("komplett vom Server (inkl. Root)",
                          "complete from server (incl. root)")
                        if ch["root_presented_by_server"]
                        else L("bis zum Root im lokalen Truststore, alle "
                               "Zwischenglieder vom Server",
                               "up to the root in the local truststore, all "
                               "intermediates from the server"))
        print(f"    {mark(ch['complete_from_server'])} "
              f"{L('Kette', 'Chain')} {complete_txt}.")
    for n in ch["notes"]:
        print(f"    (i) {n}")
    print()

    print(paint("1", L("  TLS-VERSIONEN", "  TLS VERSIONS")))
    for label, v in r["tls_versions"].items():
        status = L("verfügbar", "available") if v["available"] \
            else L("nicht verfügbar", "not available")
        detail = "" if v["available"] else f"  ({v['detail']})"
        print(f"    {mark(v['available'])} {label:8s} {status}{detail}")
    print()

    print(paint("1", "  CIPHER-SUITES"))
    order = []
    groups = {}
    for cp in r["ciphers"]:
        if cp["category"] not in groups:
            groups[cp["category"]] = []
            order.append(cp["category"])
        groups[cp["category"]].append(cp)
    for cat in order:
        print(f"    {paint('1', cat + ':')}")
        for it in groups[cat]:
            if it["available"]:
                print(f"      {mark(True)}  {it['cipher']}")
            else:
                print(f"      {mark(False)} {it['cipher']}  "
                      f"{L('(nicht verfügbar)', '(not available)')}")
    print()

    kx = r.get("key_exchange") or {}
    if kx.get("groups"):
        print(paint("1", "  KEY EXCHANGE"))
        for g in kx["groups"]:
            if not g.get("tested"):
                continue
            pq = "  [PQ]" if g.get("post_quantum") else ""
            print(f"    {mark(g['available'], '[OK]', '[--]')} "
                  f"{g['group']:15s} {g['bits']} Bit{pq}")
        if kx.get("dhe_bits"):
            print(f"    (i) DHE: {kx['dhe_bits']} Bit")
        if kx.get("static_rsa_bits"):
            print(f"    (i) {L('Statisches RSA (kein PFS)', 'Static RSA (no PFS)')}: "
                  f"{kx['static_rsa_bits']} Bit")
        print()

    if r["ocsp"]:
        o = r["ocsp"]
        print(paint("1", L("  OCSP (direkt)", "  OCSP (direct)")))
        if o.get("available"):
            status = o.get("certificate_status") or o.get("response_status")
            print(f"    Status: {status or L('unbekannt', 'unknown')}  → "
                  f"{mark(o.get('ok'))}")
            if o.get("detail"):
                print(f"    {o['detail']}")
        else:
            print(f"    {o.get('detail')}")
        print()

    if r.get("revocation"):
        rv = r["revocation"]
        lvl = rv.get("level")
        tag = {"ok": mark(True, "OK"), "unknown": mark(False, "?"),
               "revoked": mark(False, L("REVOKIERT", "REVOKED"))}.get(lvl, "?")
        print(paint("1", L("  REVOCATION-STATUS (CRL + OCSP)",
                           "  REVOCATION STATUS (CRL + OCSP)")))
        print(f"    {tag} {rv.get('detail') or lvl}  "
              f"({L('Quelle', 'source')}: {rv.get('source') or '-'})")
        st = r.get("ocsp_stapling") or {}
        print(f"    {mark(st.get('stapled'), 'stapled', L('keine', 'none'))} "
              f"OCSP-Stapling: "
              f"{st.get('status') or L('nicht vorhanden', 'not present')}"
              f"{' (' + st.get('note', '') + ')' if not st.get('stapled') else ''}")
        cr = r.get("crl") or {}
        for c in (cr.get("crls") or []):
            ok = c.get("ok")
            m = {"true": L("abrufbar ✓", "retrievable ✓"),
                 "false": L("Nicht abrufbar", "not retrievable"),
                 "none": "?"}.get(str(ok).lower(), "?")
            extra = ""
            if c.get("last_update"):
                extra += f"  (Last Update {c['last_update']})"
            print(f"    - CRL: {c.get('url')} → {m}{extra}")
            if c.get("note"):
                print(f"        {c['note']}")
        print()

    if r.get("session"):
        se = r["session"]
        print(paint("1", "  SSL-SESSION"))
        print(f"    {mark(se.get('resumed'))} Resume: "
              f"{L('erfolgreich', 'successful') + ' (' + se.get('version', '') + ')' if se.get('resumed') else L('nicht möglich', 'not possible')}")
        print(f"    {se.get('note', '')}")
        print()

    if r.get("http3"):
        h3 = r["http3"]
        print(paint("1", "  HTTP/3 (QUIC)"))
        st3 = L("aktiv", "active") if h3.get("active") else (
            L("unbekannt", "unknown") if h3.get("unknown")
            else L("nicht aktiv", "not active"))
        print(f"    {mark(h3.get('active'))} {st3}: {h3.get('note')}")
        print()

    if r.get("dns"):
        d = r["dns"]
        print(paint("1", L("  DNS / AUFLÖSUNG", "  DNS / RESOLUTION")))
        if not d.get("ok"):
            print(f"    {mark(False)} "
                  f"{L('Auflösung fehlgeschlagen', 'Resolution failed')}: {d.get('error')}")
        else:
            ips = list(d.get("ipv4", [])) + list(d.get("ipv6", []))
            print(f"    {mark(True)} {r['host']} → "
                  f"{', '.join(ips) if ips else L('keine Adresse', 'no address')}")
            if len(ips) > 1:
                print(f"    (i) " + L(f"{len(ips)} Adressen aufgelöst "
                                      f"(Round-Robin/CDN?), geprüft: "
                                      f"{d.get('tested_ip')}",
                                      f"{len(ips)} addresses resolved "
                                      f"(round robin/CDN?), tested: "
                                      f"{d.get('tested_ip')}"))
        print()

    if r.get("webserver"):
        w = r["webserver"]
        print(paint("1", L("  WEB-SERVER", "  WEB SERVER")))
        if w.get("server"):
            print(f"    {mark(True)} Server-Header: {w['server']}")
        else:
            print(f"    {mark(False)} Server-Header: "
                  f"{L('(nicht gesetzt)', '(not set)')}")
        if w.get("protocol"):
            print(f"    {mark(True)} {L('Protokoll', 'Protocol')} (ALPN): "
                  f"{w['protocol']}")
        if w.get("hsts"):
            pl = " [preload]" if w.get("hsts_preload") else ""
            print(f"    {mark(True)} HSTS: {w['hsts']}{pl}")
        else:
            print(f"    {mark(False)} HSTS: {L('(nicht gesetzt)', '(not set)')}")
        if w.get("alt_svc"):
            print(f"    {mark(True)} Alt-Svc "
                  f"({L('HTTP/3-Indiz', 'HTTP/3 hint')}): {w['alt_svc']}")
        if w.get("final_status") is not None:
            print(f"    {mark(True)} {L('Finaler Status', 'Final status')}: "
                  f"{w['final_status']}")
        h80 = w.get("http80")
        if h80:
            print(f"    {mark(True)} HTTP (Port 80): {h80}")
        for red in w.get("redirects", []):
            if str(red.get("status", "")).startswith("3"):
                print(f"    (i) Redirect {red.get('status')} → "
                      f"{red.get('location') or '-'}")
        print()

    if s["problems"]:
        print(paint("31", L("  PROBLEME:", "  PROBLEMS:")))
        for p in s["problems"]:
            print(f"    ✗ {p}")
    if s["warnings"]:
        print(paint("33", L("  WARNUNGEN:", "  WARNINGS:")))
        for w in s["warnings"]:
            print(f"    ⚠ {w}")
    if not s["problems"] and not s["warnings"]:
        print(paint("32", L("  Keine Probleme festgestellt.",
                            "  No problems found.")))
    print(paint("1", "=" * 72))

# ---------------------------------------------------------------- Main

OSSL = None
CA_BUNDLE = None
STORE = None

def main():
    global OSSL, CA_BUNDLE, STORE, CRL_MAX_BYTES, CRL_MAX_MB, LANG, BLOCK_PRIVATE
    ap = argparse.ArgumentParser(
        description="TLS/Zertifikats-Check (abgespecktes SSL-Labs-Equivalent)")
    ap.add_argument("host", help="Hostname, optional mit Port: host[:port]")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--json", action="store_true", help="JSON-Ausgabe")
    ap.add_argument("--timeout", type=int, default=6,
                    help="Timeout pro Verbindung in Sekunden (Default: 6)")
    ap.add_argument("--ocsp", action="store_true",
                    help="OCSP-Status des Endzertifikats mitprüfen")
    ap.add_argument("--no-aia", action="store_true",
                    help="AIA-Reachability-Check für fehlende "
                         "Zwischenzertifikate überspringen")
    ap.add_argument("--cafile", default=None,
                    help="Alternativer CA-Bundle-Pfad (PEM)")
    ap.add_argument("--fast", action="store_true",
                    help="Schnellcheck: CRL/OCSP-Stapling/Session/HTTP3 "
                         "überspringen")
    ap.add_argument("--crl-max-mb", type=int, default=20,
                    help="Maximale CRL-Größe in MB (Default 20)")
    ap.add_argument("--lang", choices=("de", "en"), default=None,
                    help="Sprache der Meldungen (Default: TLS_CHECK_LANG "
                         "oder de)")
    pv = ap.add_mutually_exclusive_group()
    pv.add_argument("--allow-private", action="store_true",
                    help="Interne Adressen (RFC1918, Loopback …) erlauben")
    pv.add_argument("--block-private", action="store_true",
                    help="Interne Adressen sperren (Default: "
                         "TLS_CHECK_BLOCK_PRIVATE, sonst an)")
    args = ap.parse_args()

    if args.lang:
        LANG = args.lang
    if LANG not in ("de", "en"):
        LANG = "de"
    if args.allow_private:
        BLOCK_PRIVATE = False
    elif args.block_private:
        BLOCK_PRIVATE = True

    OSSL = load_openssl()
    CRL_MAX_MB = max(1, args.crl_max_mb)
    CRL_MAX_BYTES = CRL_MAX_MB * 1024 * 1024
    host = args.host.strip()
    port = args.port
    if ":" in host and host.count(":") == 1 and not host.startswith("["):
        try:
            port = int(host.rsplit(":", 1)[1])
            host = host.rsplit(":", 1)[0]
        except ValueError:
            pass
    elif host.startswith("[") and "]:" in host:
        try:
            port = int(host.rsplit("]:", 1)[1])
            host = host[1:].rsplit("]:", 1)[0]
        except ValueError:
            pass
    host = host.strip("[]")
    port = port or 443

    CA_BUNDLE = args.cafile or find_ca_bundle()
    if not CA_BUNDLE:
        sys.exit(L("Fehler: Kein CA-Bundle gefunden (mit --cafile angeben).",
                   "Error: no CA bundle found (specify with --cafile)."))

    err = None
    blocked = False
    try:
        pinned_ip(host)              # Policy zuerst: gesperrt → kein Kontakt
        STORE = build_store(CA_BUNDLE)
        pem_list, proto = fetch_presented_chain(host, port, args.timeout)
    except BlockedAddress as e:
        err, blocked = str(e), True
    except Exception as e:
        err = str(e)
    if err is None:
        try:
            cert = Cert(pem_list[0], "leaf")
            cert.meta()
            chain = check_chain(pem_list, STORE, host,
                                do_aia=not args.no_aia)
            tls = check_tls(host, port, args.timeout)
            kx = check_kx(host, port, args.timeout, tls, cert.meta())
            ocsp = check_ocsp(host, port, pem_list, args.timeout) \
                if args.ocsp else None
            dns = resolve_host(host)
            web_raw = check_http(host, port, args.timeout)
            web_data, web_warns = webserver_summary(host, port, web_raw)
            webserver = dict(web_data)
            webserver["warnings"] = web_warns
            session = None
            stapling = None
            crl = None
            http3 = None
            if not args.fast:
                session = check_session(host, port, args.timeout)
                stapling = check_ocsp_stapling(host, port, args.timeout + 8)
                crl = check_crl(pem_list, args.timeout + 8)
                http3 = check_http3(host, port, 6)
            report = build_report(host, port, args, pem_list, proto,
                                  cert, chain, tls, ocsp,
                                  dns=dns, webserver=webserver,
                                  session=session, stapling=stapling,
                                  crl=crl, http3=http3, kx=kx)
        except Exception as e:
            err = L("Auswertung fehlgeschlagen: ", "Evaluation failed: ") + str(e)

    if err is not None:
        if args.json:
            print(json.dumps({"host": host, "port": port, "error": err,
                              "blocked": blocked}, ensure_ascii=False))
        else:
            print(L("FEHLER: ", "ERROR: ") + err, file=sys.stderr)
        sys.exit(2)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_report(report, args)
    sys.exit(0 if report["summary"]["ok"] else 1)

if __name__ == "__main__":
    main()
