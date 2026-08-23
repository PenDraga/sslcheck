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
  4. Optional: OCSP-Status des Endzertifikats (--ocsp)

Abhängigkeiten: Python-Standardbibliothek + openssl CLI.

Beispiele:
  tlscheck.py example.com
  tlscheck.py example.com:8443 --json
  tlscheck.py example.com --ocsp
  tlscheck.py example.com --timeout 10 --no-aia

Exit-Codes: 0 = sauber, 1 = Probleme/Warnings (Bericht siehe Ausgabe),
            2 = Fehler (keine Verbindung o.ä.)
"""

import argparse
import datetime
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
from urllib.parse import urlparse
from pathlib import Path

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
        sys.exit("Fehler: openssl CLI nicht gefunden (Systempfad fehlt).")
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
            raise RuntimeError(f"openssl x509 fehlerhaft: {(err).strip()[:200]}")
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
        raise RuntimeError(f"CA-Bundle nicht lesbar: {err.strip()[:200]}")
    rc2, out2, err2 = run_cmd(
        ["openssl", "pkcs7", "-print_certs"], input_text=out, timeout=30)
    if rc2 != 0:
        raise RuntimeError(f"CA-Bundle-Auswertung fehlgeschlagen: "
                           f"{err2.strip()[:200]}")
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
    cmd = [OSSL, "s_client", "-connect", f"{host}:{port}",
           "-servername", host, "-showcerts"]
    try:
        p = subprocess.run(cmd, input="", capture_output=True, text=True,
                           timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        raise ConnectionError(f"Timeout bei Verbindung zu {host}:{port}")
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
            f"Keine Zertifikate erhalten von {host}:{port}"
            + (f" ({errhint})" if errhint else " (Server hat nicht geantwortet)"))
    return pems, proto

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
            res["notes"].append(
                f"Glied [{i}]: Issuer wird nicht direkt vom nächsten Glied "
                f"abgedeckt (Kettenglied fehlt oder durcheinander).")

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
                    res["notes"].append(
                        "Kette wird über lokale Truststore-Zertifikate bis "
                        "zum Root ergänzt; die fehlenden Glieder sind oben "
                        "aufgeführt.")
                else:
                    res["notes"].append(
                        f"Kette reicht bis zum Root im Truststore "
                        f"'{fm.get('subject')}' – alle Zwischenglieder "
                        f"werden vom Server geliefert.")
                break
        # 2) Selbstsigniert, aber keine vertraute Root
        if m["self_signed"]:
            res["notes"].append(
                "Oberstes selbstsigniertes Zertifikat ist nicht im lokalen "
                "Truststore (private oder unbekannte CA).")
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
            res["notes"].append(
                f"Issuer '{m.get('issuer')}' weder vom Server geliefert noch "
                f"im lokalen Truststore gefunden – Kettenglied fehlt.")
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
            res["notes"].append(
                "Kette endet bei einem Zertifikat, dessen Root im lokalen "
                "Truststore liegt; die Root wird nicht vom Server geliefert "
                "– der Client ergänzt sie aus seinem Truststore (üblich).")
            res["full_chain"].append({
                "subject": fm.get("subject"), "issuer": fm.get("issuer"),
                "serial": fm.get("serial"), "valid_to": fm.get("notAfter"),
                "self_signed": True, "source": "truststore",
            })
            break
        # Echtes Zwischenglied fehlt am Server
        res["missing"].append(found)
        res["aia_urls"].append(m.get("aia_ca"))
        res["notes"].append(
            f"Fehlt am Server: '{found.short}' (Serial {fm['serial']}) – "
            f"Client muss es aus dem Truststore oder per AIA laden.")
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
            detail = "verification fehlgeschlagen"
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
                info["note"] = ("Keine AIA 'CA Issuers'-URL im Kind-Zertifikat "
                                "– automatischer Abruf nicht möglich.")
                res["aia"].append(info)
                continue
            if not _url_is_http(url):
                info["note"] = (f"AIA-URL-Schema nicht erlaubt "
                                f"(nur http/https): {url}")
                res["aia"].append(info)
                continue
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "tlscheck/1.0"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    data = b""
                    while True:
                        chunk = r.read(128 * 1024)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) > AIA_MAX_BYTES:
                            raise RuntimeError(
                                f"AIA-Antwort zu groß (> "
                                f"{AIA_MAX_BYTES // 1024} KB)")
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
                            info["note"] = ("Zertifikat abrufbar (Subject "
                                            "stimmt überein).")
                        else:
                            info["note"] = "Liefert anderes Zertifikat."
                    else:
                        cm = c.meta()
                        if fm["subject_norm"] == cm["subject_norm"]:
                            info["reachable"] = True
                            if fm.get("serial") and cm.get("serial") and \
                               fm["serial"] == cm["serial"]:
                                info["note"] = "Passend (Serial stimmt überein)."
                            else:
                                info["note"] = ("Abrufbar (Serial weicht ab "
                                                "– erneut ausgestellte CA?).")
                        else:
                            info["note"] = "Liefert anderes Zertifikat."
                else:
                    info["note"] = "Kein PEM-Zertifikat in der Antwort."
            except Exception as e:
                info["note"] = f"Abruf fehlgeschlagen: {e}"
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

TLS13_SUITES = [
    ("TLS_AES_128_GCM_SHA256", "stark"),
    ("TLS_AES_256_GCM_SHA384", "stark"),
    ("TLS_CHACHA20_POLY1305_SHA256", "stark"),
    ("TLS_AES_128_CCM_SHA256", "stark (IoT)"),
]

CIPHERS_12 = [
    ("ECDHE-ECDSA-AES128-GCM-SHA256", "stark (AEAD, PFS)"),
    ("ECDHE-RSA-AES128-GCM-SHA256", "stark (AEAD, PFS)"),
    ("ECDHE-ECDSA-AES256-GCM-SHA384", "stark (AEAD, PFS)"),
    ("ECDHE-RSA-AES256-GCM-SHA384", "stark (AEAD, PFS)"),
    ("ECDHE-ECDSA-CHACHA20-POLY1305", "stark (ChaCha20, PFS)"),
    ("ECDHE-RSA-CHACHA20-POLY1305", "stark (ChaCha20, PFS)"),
    ("ECDHE-ECDSA-AES128-SHA256", "veraltet (CBC, PFS)"),
    ("ECDHE-RSA-AES128-SHA256", "veraltet (CBC, PFS)"),
    ("ECDHE-ECDSA-AES256-SHA384", "veraltet (CBC, PFS)"),
    ("ECDHE-RSA-AES256-SHA384", "veraltet (CBC, PFS)"),
    ("DHE-RSA-AES256-GCM-SHA384", "DHE (AEAD, PFS, langsam)"),
    ("AES128-SHA256", "statisches RSA-KE (kein PFS)"),
    ("DES-CBC3-SHA", "SCHWACH (3DES)"),
    ("RC4-SHA", "SCHWACH (RC4)"),
]

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
            return False, "lokal: Cipher in OpenSSL nicht verfügbar"
    if ciphersuites:
        try:
            ctx.set_ciphersuites(ciphersuites)
        except ssl.SSLError:
            return False, "lokal: Cipher-Suite in OpenSSL nicht verfügbar"
    raw = None
    try:
        try:
            raw = socket.create_connection((host, port), timeout=timeout)
        except OSError as e:
            return False, f"keine TCP-Verbindung: {e}"
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            cipher, version, _ = s.cipher()
            return True, version
    except ssl.SSLError as e:
        return False, f"TLS-Handshake abgelehnt ({e.reason if hasattr(e, 'reason') else e})"
    except OSError as e:
        return False, f"OS-Fehler: {e}"
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
    cmd = [OSSL, "s_client", "-connect", f"{host}:{port}",
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
    return False, line[:160] or "Handshake nicht möglich"

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
    for name, tag in CIPHERS_12:
        ok, d = try_handshake(host, port, timeout,
                              tlsv1_0, tls1_2,
                              ciphers=name, seclevel0=True)
        res["ciphers"].append({"cipher": name, "category": tag,
                               "available": ok, "detail": d})
    for name, tag in TLS13_SUITES:
        ok, d = tls13_suite_available(host, port, timeout, name)
        res["ciphers"].append({"cipher": name, "category": tag + " (TLS 1.3)",
                               "available": ok, "detail": d})
    return res

# ---------------------------------------------------------------- OCSP

def check_ocsp(host, port, pem_list, timeout):
    leaf = Cert(pem_list[0], "leaf")
    url = leaf.meta().get("aia_ocsp")
    if not url:
        return {"available": False,
                "detail": "Kein OCSP-URI im Endzertifikat hinterlegt."}
    issuer_pem = None
    if len(pem_list) > 1:
        issuer_pem = pem_list[1]
    else:
        # Kette unvollständig → Issuer-PEM aus dem Truststore holen
        store = build_store(CA_BUNDLE)
        issuer_pem = store.get(leaf.meta()["issuer_norm"])
        if issuer_pem is None:
            return {"available": False,
                    "detail": "OCSP-URI vorhanden, aber Issuer-Zertifikat "
                              "nicht verfügbar (Kette unvollständig und "
                              "kein Pass im Truststore)."}
    with tempfile.TemporaryDirectory() as td:
        leafp = os.path.join(td, "leaf.pem")
        issp = os.path.join(td, "issuer.pem")
        Path(leafp).write_text(pem_list[0])
        Path(issp).write_text(issuer_pem)
        rc, out, err = run_cmd([OSSL, "ocsp", "-CAfile", CA_BUNDLE,
                                "-issuer", issp, "-cert", leafp,
                                "-url", url, "-text"], timeout=timeout + 8)
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
    p = run_cmd([OSSL, "s_client", "-connect", f"{host}:{port}",
                 "-servername", host, "-status"], input_text="",
                timeout=timeout)
    out = p[1] or ""
    if "OCSP Response Status" not in out:
        return {"stapled": False, "status": "unknown",
                "note": "Server liefert keine stapelte OCSP-Antwort."}
    st = re.search(r"OCSP Response Status:\s*(\S+)", out)
    cs = re.search(r"(?:Certificate|Cert)\s+status:\s*(\S+)", out, re.I)
    status = (cs.group(1) if cs else (st.group(1) if st else "unknown"))
    return {"stapled": True, "status": status,
            "response_status": st.group(1) if st else None,
            "note": "Stapelte OCSP-Antwort im Handshake erhalten."}


CRL_MAX_BYTES = 20 * 1024 * 1024  # Default 20 MB; via --crl-max-mb änderbar
CRL_MAX_MB = 20


AIA_MAX_BYTES = 1 * 1024 * 1024  # 1 MB Deckel für AIA-Zertifikats-Abruf


def _url_is_http(url):
    """Nur http/https-URLs sind erlaubt (blockt file://, gopher://, ldap://
    etc. aus feindlichen Zertifikaten)."""
    return urlparse(url).scheme in ("http", "https")


def _fetch_crl(url, timeout):
    """CRL-Download -> bytes (max. CRL_MAX_BYTES); wirft CrlFetchError
    mit menschenlesbarem Grund (404, HTML, zu groß, …)."""
    if not _url_is_http(url):
        raise CrlFetchError(
            f"URL-Schema nicht erlaubt (nur http/https): {url}")
    req = urllib.request.Request(url,
                                 headers={"User-Agent": "tlscheck/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        ctype = (resp.headers.get("Content-Type") or "").lower()
        chunks = []
        total = 0
        while True:
            chunk = resp.read(256 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > CRL_MAX_BYTES:
                raise CrlFetchError(f"CRL zu groß (> {CRL_MAX_MB} MB) – "
                                     "Inhalt nicht geprüft "
                                     "(Deckel via --crl-max-mb anheben).")
            chunks.append(chunk)
    data = b"".join(chunks)
    if data[:1] in (b"<",) or "text/html" in ctype:
        raise CrlFetchError("Server antwortete mit HTML statt CRL-Daten "
                            "(CRL vermutlich rotiert oder 404).")
    if "text/plain" in ctype and not (b"BEGIN X509 CRL" in data[:300]
                                      or b"\x30" in data[:16]):
        raise CrlFetchError("Antwort sieht nicht wie CRL aus.")
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
        entry = {"issuer": iss.group(1).strip() if iss else f"Glied {i}",
                 "url": dp_uri, "ok": None, "note": ""}
        try:
            data = _fetch_crl(dp_uri, timeout)
        except CrlFetchError as e:
            entry["ok"] = False
            entry["note"] = str(e)
            results.append(entry)
            continue
        except Exception as e:
            entry["ok"] = False
            entry["note"] = f"CRL nicht abrufbar: {e}"
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
                entry["note"] = ("CRL heruntergeladen, aber von OpenSSL "
                                 "nicht lesbar: " +
                                 (txt[2] or "").strip().splitlines()
                                 [-1:])
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
                    entry["note"] = ("Endzertifikat ist REVOKIERT (im CRL "
                                     "gelistet)!" if found
                                     else f"Endzertifikat (Serial "
                                          f"{leaf_serial[:16]}…) nicht im "
                                          f"CRL.")
        finally:
            os.unlink(crl_path)
        results.append(entry)
    return {"checked": checked_any, "crls": results}


def check_session(host, port, timeout=15):
    """SSL-Session-Resume: 1) Session speichern (-sess_out), 2) erneut
    verbinden (-sess_in) und prüfen, ob 'Reused' gemeldet wird.
    Erst auf TLS 1.2 (klassisches Session-Ticket), dann TLS 1.3."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        sp = os.path.join(td, "sess.pem")
        def attempt(extra):
            p = run_cmd([OSSL, "s_client", "-connect", f"{host}:{port}",
                         "-servername", host, "-sess_out", sp, *extra],
                        input_text="", timeout=timeout)
            return p
        # TLS 1.2
        p12 = attempt(["-tls1_2"])
        reused12 = "Reused," in (p12[1] or "")
        # erneut laden + Resume
        p12b = run_cmd([OSSL, "s_client", "-connect", f"{host}:{port}",
                        "-servername", host, "-sess_in", sp, "-tls1_2"],
                       input_text="", timeout=timeout)
        reused12 = "Reused," in (p12b[1] or "")
        ok12 = p12[0] == 0 and p12b[0] == 0
        # TLS 1.3
        p13 = attempt([])
        p13b = run_cmd([OSSL, "s_client", "-connect", f"{host}:{port}",
                        "-servername", host, "-sess_in", sp],
                       input_text="", timeout=timeout)
        reused13 = "Reused," in (p13b[1] or "")
        ok13 = p13[0] == 0 and p13b[0] == 0
    if not ok12 and not ok13:
        return {"resumable": False, "resumed": False,
                "note": "Keine Session-Tests möglich (Handshake fehlgeschlagen)."}
    if reused12:
        return {"resumable": True, "resumed": True, "version": "TLSv1.2",
                "note": "Session-Resume (Session-Ticket) erfolgreich (TLS 1.2)."}
    if reused13:
        return {"resumable": True, "resumed": True, "version": "TLSv1.3",
                "note": "Session-Resume erfolgreich (TLS 1.3)."}
    return {"resumable": ok12 or ok13, "resumed": False,
            "note": "Kein Session-Resume (neuer Handshake)."}


def revocation_status(ocsp_stapled, crl, ocsp_direct):
    """SSL-Labs-artiger Revocation-Status (ok / unknown / revokiert)."""
    # 1) CRL: Endzertifikat gelistet -> REVOKIERT
    if crl and crl.get("crls"):
        for c in crl["crls"]:
            if c.get("leaf_serial") and c.get("ok") is False \
                    and "REVOKIERT" in c.get("note", ""):
                return {"level": "revoked", "source": "CRL",
                        "detail": "Endzertifikat im CRL gelistet."}
    # 2) OCSP-Stapling / Direkt-OCSP: 'good' -> ok
    good = None
    if ocsp_stapled and ocsp_stapled.get("stapled"):
        good = "good" in (ocsp_stapled.get("status") or "")
    if good is None and ocsp_direct:
        good = "good" in ((ocsp_direct.get("certificate_status") or
                           ocsp_direct.get("response_status")) or "")
    if good:
        return {"level": "ok", "source": "OCSP",
                "detail": "Revocation-Status 'good' (OCSP)."}
    # 3) CRL erreichbar und Endzert nicht gelistet -> ok
    if crl and crl.get("crls"):
        leaf = [c for c in crl["crls"] if c.get("leaf_serial")]
        if leaf and all(c.get("ok") for c in leaf):
            return {"level": "ok", "source": "CRL",
                    "detail": "Endzertifikat nicht in den CRLs gelistet."}
    # 4) CRL abrufbar, aber Endserial nicht eindeutig geprüft -> unknown
    if crl and crl.get("checked"):
        return {"level": "unknown", "source": "CRL",
                "detail": "CRL erreichbar; Revocation nicht eindeutig "
                          "bestätigt."}
    return {"level": "unknown", "source": "keine",
            "detail": "Kein CRL/OCSP für das Endzertifikat verfügbar."}


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
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.send(bytes(b))
        try:
            data = sock.recv(1500)
            if data and data[0] & 0x80:
                return {"active": True,
                        "note": "QUIC-Antwort (Long Header) erhalten → "
                                "HTTP/3 aktiv."}
            return {"active": False,
                    "note": "UDP-Antwort erhalten, aber kein QUIC-Long-Header."}
        except socket.timeout:
            return {"active": False, "unknown": True,
                    "note": "Keine UDP-Antwort (UDP-Ausgang möglicherweise "
                            "gesperrt oder HTTP/3 nicht aktiv) – Alt-Svc-"
                            "Header beachten."}
    except OSError as e:
        return {"active": False, "unknown": True,
                "note": f"UDP-Check nicht möglich: {e}"}
    finally:
        sock.close()

def resolve_host(host):
    """Alle A-/AAAA-Adressen eines Hostnamens (bzw. die IP selbst)."""
    h = host.strip("[]")
    try:
        infos = socket.getaddrinfo(h, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        return {"ok": False, "error": str(e), "ipv4": [], "ipv6": []}
    v4, v6 = [], []
    for i in infos:
        ip = i[4][0]
        (v4 if i[0] == socket.AF_INET else v6).append(ip)
    return {"ok": True,
            "ipv4": list(dict.fromkeys(v4)),
            "ipv6": list(dict.fromkeys(v6))}


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
    - Redirects auf Loopback/Link-Local (127.x, 169.254.x) NICHT folgen
      (SSRF-Schutz).
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
                             "note": "Redirect auf unverschlüsseltes HTTP "
                                     "nicht gefolgt."})
                break
            if _is_blocked_redirect_target(new_host):
                hops.append({"status": "blocked",
                             "server": None,
                             "location": loc,
                             "note": "Redirect auf internes Ziel "
                                     "(Loopback/Link-Local) nicht gefolgt."})
                break
            host = new_host
            port = new_port
            ctx = None if p.scheme == "http" else ctx
        else:
            break
    return hops, info, host, port


def _is_blocked_redirect_target(hostname):
    """True für Redirect-Ziele, die intern empfindlich sind:
    Loopback (127.x, ::1, localhost) und Link-Local/Cloud-Metadata
    (169.254.x, fe80::). Wird nur im Redirect-Following angewendet –
    der primär geprüfte Host bleibt unbeschränkt."""
    if hostname is None:
        return False
    h = hostname.lower().strip(".")
    if h in ("localhost", "localhost.localdomain"):
        return True
    try:
        import ipaddress
        ip = ipaddress.ip_address(h)
        return ip.is_loopback or ip.is_link_local
    except ValueError:
        # Hostname: per DNS auf IP prüfen (best effort, ohne Cache)
        try:
            import socket
            infos = socket.getaddrinfo(h, None, socket.AF_UNSPEC,
                                       socket.SOCK_STREAM)
            for info in infos:
                ip = ipaddress.ip_address(info[4][0])
                if ip.is_loopback or ip.is_link_local:
                    return True
        except (socket.gaierror, OSError):
            pass
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
           "hsts_preload": False, "alt_svc": None,
           "final_status": None, "redirects": httpres.get("redirects", []),
           "http80": None}
    https = httpres.get("https") or {}
    if "error" in https:
        out["error"] = https["error"]
        return out, warns
    out["final_status"] = https.get("status")
    out["server"] = (https.get("headers") or {}).get("Server")
    out["alt_svc"] = (https.get("headers") or {}).get("Alt-Svc")
    alpn = httpres.get("alpn")
    out["protocol"] = {"h2": "HTTP/2", "http/1.1": "HTTP/1.1"}.get(
        alpn, alpn or "unbekannt")
    hsts = (https.get("headers") or {}).get("Strict-Transport-Security")
    if hsts:
        out["hsts"] = hsts
        out["hsts_preload"] = "preload" in hsts.lower()
    else:
        warns.append("Kein HSTS-Header (Strict-Transport-Security) gesetzt.")
    h80 = httpres.get("http80") or {}
    if "error" not in h80:
        st = h80.get("status")
        loc = (h80.get("headers") or {}).get("Location") or ""
        if st in (301, 302, 303, 307, 308) and loc.startswith("https"):
            out["http80"] = "redirect → " + loc.split("/")[0]
        elif st in (301, 302, 303, 307, 308):
            out["http80"] = f"redirect (nicht auf HTTPS): {loc}"
            warns.append("HTTP (Port 80) redirectet nicht auf HTTPS.")
        elif st == 200:
            out["http80"] = "antwortet 200 (kein Redirect auf HTTPS)"
            warns.append("HTTP (Port 80) liefert die Seite unverschlüsselt "
                         "ohne Redirect auf HTTPS.")
        else:
            out["http80"] = f"Status {st}"
    else:
        out["http80"] = h80["error"]
    return out, warns


# ---------------------------------------------------------------- Bericht

def rating(cert_ok, host_ok, chain, tls):
    if not cert_ok or not host_ok:
        return "F", "Zertifikat ungültig bzw. Hostname passt nicht."
    weak = [x for x in tls["ciphers"] if x["available"] and
            ("SCHWACH" in x["category"] or "kein PFS" in x["category"])]
    if weak:
        return "C", "Schwache Cipher-Suite(s) aktiv: " + \
            ", ".join(x["cipher"] for x in weak)
    old_tls = [v for v in ("TLS 1.0", "TLS 1.1")
               if tls["versions"].get(v, {}).get("available")]
    if old_tls:
        return "C", "Veraltete TLS-Version(en) verfügbar: " + \
            ", ".join(old_tls)
    if not chain["complete"] or chain["missing"]:
        return "B", "Kette wird nicht komplett vom Server geliefert " \
                    "(Client-Truststore/AIA nötig)."
    cbc = [x for x in tls["ciphers"] if x["available"] and
           "veraltet" in x["category"]]
    if cbc:
        return "A-", "Nur CBC-Cipher-Suites aktiv (funktioniert, AEAD wäre besser): " + \
            ", ".join(x["cipher"] for x in cbc)
    return "A", "Gültiges Zertifikat, vollständige Kette, moderne Cipher-Suites."

def build_report(host, port, args, pem_list, proto, cert, chain, tls, ocsp,
                 dns=None, webserver=None, session=None, stapling=None,
                 crl=None, http3=None):
    m = cert.meta()
    host_ok, matched = hostname_matches(host, cert)
    now = datetime.datetime.utcnow()
    not_after = datetime.datetime.strptime(m["notAfter"],
                                           "%b %d %H:%M:%S %Y %Z")
    expired = now > not_after
    problems = []
    warnings = []
    if expired:
        problems.append("Zertifikat ist ABGELAUFEN.")
    elif cert.days_left < 14:
        warnings.append(f"Zertifikat läuft in {cert.days_left} Tagen ab.")
    if not host_ok:
        problems.append(f"Hostname '{host}' nicht im Zertifikat (SAN/CN).")
    if m["self_signed"]:
        problems.append("Endzertifikat ist selbst signiert.")
    if m.get("pubkey_bits") and m.get("pubkey_bits") < 2048 and \
       "RSA" in m.get("pubkey_alg", "").upper():
        warnings.append(f"RSA-Schlüssel nur {m['pubkey_bits']} Bit "
                        "(>=2048 empfohlen).")
    if "SHA1" in m.get("sig_alg", "").upper():
        problems.append("Signatur mit SHA-1 (nicht mehr akzeptiert).")
    if chain["missing"]:
        warnings.append(f"{len(chain['missing'])} Zwischenzertifikat/-e "
                        f"werden nicht vom Server geliefert "
                        f"(Client-Truststore/AIA nötig).")
    if not chain["verify_with_presentation"]["ok"]:
        problems.append("Kette mit den Server-Zertifikaten nicht "
                        "verificierbar: " +
                        chain["verify_with_presentation"]["detail"])
    elif not chain["verify_store_only"]["ok"] and chain["missing"]:
        warnings.append("Kette verifiziert sich nur dank lokalem "
                        "Truststore (Zwischenglieder müssen lokal vorhanden "
                        "sein).")
    for x in tls["ciphers"]:
        if x["available"] and "SCHWACH" in x["category"]:
            warnings.append(f"Schwache Cipher-Suite aktiv: {x['cipher']}")
    for v in ("TLS 1.0", "TLS 1.1"):
        if tls["versions"].get(v, {}).get("available"):
            warnings.append(f"Veraltete TLS-Version verfügbar: {v}")
    if ocsp and ocsp.get("available") and not ocsp.get("ok"):
        warnings.append("OCSP-Status: " +
                        (ocsp.get("certificate_status") or
                         ocsp.get("response_status") or "unbekannt"))
    if webserver:
        warnings.extend(webserver.get("warnings", []))
        webserver = dict(webserver)
        webserver.pop("warnings", None)
        ws_problems = webserver.get("problems", [])
        problems.extend(ws_problems)
    # Revocation: revokiert = hartes Problem
    rev = revocation_status(stapling, crl, ocsp) if (crl or stapling or ocsp) else None
    if rev and rev.get("level") == "revoked":
        problems.append("Zertifikat ist REVOKIERT: " + rev.get("detail", ""))
    cert_ok = not expired and (m.get("sig_alg") != "") and not m["self_signed"]
    grade, grade_note = rating(cert_ok, host_ok, chain, tls)
    return {
        "host": host, "port": port,
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
        "ocsp": ocsp,
        "dns": dns,
        "webserver": webserver,
        "session": session,
        "ocsp_stapling": stapling,
        "crl": crl,
        "http3": http3,
        "revocation": revocation_status(stapling, crl, ocsp) if (
            crl or stapling or ocsp) else None,
        "summary": {"grade": grade, "note": grade_note,
                    "problems": problems, "warnings": warnings,
                    "ok": not problems and not warnings},
    }

# ---------------------------------------------------------------- Ausgabe

GRADE_COLORS = {"F": "31", "C": "33", "B": "36", "A-": "32", "A": "32"}

def paint(color, s):
    return f"\033[{color}m{s}\033[0m" if sys.stdout.isatty() else s

def mark(ok, good="[OK]", bad="[!!]"):
    return paint("32", good) if ok else paint("31", bad)

def print_report(r, args):
    s = r["summary"]
    print(paint("1", "=" * 72))
    print(paint("1", f"  TLS-Check: {r['host']}:{r['port']}   "
                     f"{r['checked_at_utc']} UTC"))
    print(paint("1", "=" * 72))
    print(f"  Bewertung: {paint(GRADE_COLORS.get(s['grade'], '0'), s['grade'])}"
          f"  –  {s['note']}")
    print(f"  Verhandelte Version: {r['negotiated_protocol'] or 'unbekannt'}")
    print()

    cert = r["certificate"]
    print(paint("1", "  ZERTIFIKAT"))
    san = ", ".join(cert["san_dns"]) if cert["san_dns"] else "–"
    ips = cert.get("san_ip")
    ips = ips if isinstance(ips, list) else ([ips] if ips else [])
    if ips:
        san += (", " if cert["san_dns"] else "") + "IP " + ", ".join(ips)
    print(f"    {mark(cert['hostname_match'])} Hostname: "
          f"{cert['hostname_matched_name'] or '(kein Match)'}  (SAN: {san})")
    print(f"    {mark(True)} Subject: {cert['subject']}")
    print(f"    {mark(True)} Issuer:  {cert['issuer']}")
    print(f"    {mark(True)} Serial:  {cert['serial']}")
    print(f"    {mark(int(cert['days_left']) > 0)} Gültig: {cert['not_before']}"
          f" → {cert['not_after']} ({cert['days_left']} Tage verbleibend)")
    print(f"    {mark(True)} Signatur: {cert['signature_algorithm']}  |  "
          f"Schlüssel: {cert['public_key']}")
    print(f"    {mark(True)} AIA (CA Issuers): {cert['aia_ca'] or '–'}")
    print(f"    {mark(True)} OCSP-URL:         {cert['ocsp_url'] or '–'}")
    print()

    ch = r["chain"]
    print(paint("1", "  ZERTIFIKATSKETTE (vom Server geliefert)"))
    for i, p in enumerate(ch["presented"]):
        tag = {0: "Endzertifikat", 1: "Zwischenzertifikat",
               2: "Wurzel"}.get(i, f"Glied {i}")
        extra = "  (self-signed)" if p["self_signed"] else ""
        print(f"    [{i}] {tag:20s} {p['subject']}{extra}  "
              f"(gültig bis {p['valid_to']})")
    vsp = ch["verify_with_server_chain"]
    print(f"    {mark(vsp['ok'])} openssl-verify nur mit Server-Kette: "
          f"{'erfolgreich' if vsp['ok'] else 'FEHLGESCHLAGEN'}  ({vsp['detail']})")
    if ch["missing_from_server"]:
        print(f"    {mark(False)} Fehlt am Server (Client muss beschaffen):")
        for mcer in ch["missing_from_server"]:
            print(f"        - {mcer['subject']}  (Serial {mcer['serial']})")
        for a in ch["aia"]:
            st = {True: "abrufbar ✓", False: "NICHT abrufbar",
                  None: "n/a"}[a["reachable"]]
            print(f"        AIA: {a['url'] or 'kein Eintrag'} → {st} "
                  f"{a['note'] or ''}")
    else:
        complete_txt = ("komplett vom Server (inkl. Root)"
                        if ch["root_presented_by_server"]
                        else "bis zum Root im lokalen Truststore, alle "
                             "Zwischenglieder vom Server")
        print(f"    {mark(ch['complete_from_server'])} Kette {complete_txt}.")
    for n in ch["notes"]:
        print(f"    (i) {n}")
    print()

    print(paint("1", "  TLS-VERSIONEN"))
    for label, v in r["tls_versions"].items():
        status = "verfügbar" if v["available"] else "nicht verfügbar"
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
                print(f"      {mark(False)} {it['cipher']}  (nicht verfügbar)")
    print()

    if r["ocsp"]:
        o = r["ocsp"]
        print(paint("1", "  OCSP (direkt)"))
        if o.get("available"):
            status = o.get("certificate_status") or o.get("response_status")
            print(f"    Status: {status or 'unbekannt'}  → {mark(o.get('ok'))}")
            if o.get("detail"):
                print(f"    {o['detail']}")
        else:
            print(f"    {o.get('detail')}")
        print()

    if r.get("revocation"):
        rv = r["revocation"]
        lvl = rv.get("level")
        tag = {"ok": mark(True, "OK"), "unknown": mark(False, "?"),
               "revoked": mark(False, "REVOKIERT")}.get(lvl, "?")
        print(paint("1", "  REVOCATION-STATUS (CRL + OCSP)"))
        print(f"    {tag} {rv.get('detail') or lvl}  "
              f"(Quelle: {rv.get('source') or '-'})")
        st = r.get("ocsp_stapling") or {}
        print(f"    {mark(st.get('stapled'), 'stapled', 'keine')} "
              f"OCSP-Stapling: "
              f"{st.get('status') or 'nicht vorhanden'}"
              f"{' (' + st.get('note', '') + ')' if not st.get('stapled') else ''}")
        cr = r.get("crl") or {}
        for c in (cr.get("crls") or []):
            ok = c.get("ok")
            m = {"true": "abrufbar ✓", "false": "Nicht abrufbar",
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
              f"{'erfolgreich (' + se.get('version', '') + ')' if se.get('resumed') else 'nicht möglich'}")
        print(f"    {se.get('note', '')}")
        print()

    if r.get("http3"):
        h3 = r["http3"]
        print(paint("1", "  HTTP/3 (QUIC)"))
        st3 = "aktiv" if h3.get("active") else ("unbekannt"
              if h3.get("unknown") else "nicht aktiv")
        print(f"    {mark(h3.get('active'))} {st3}: {h3.get('note')}")
        print()

    if r.get("dns"):
        d = r["dns"]
        print(paint("1", "  DNS / AUFLÖSUNG"))
        if not d.get("ok"):
            print(f"    {mark(False)} Auflösung fehlgeschlagen: {d.get('error')}")
        else:
            ips = list(d.get("ipv4", [])) + list(d.get("ipv6", []))
            print(f"    {mark(True)} {r['host']} → "
                  f"{', '.join(ips) if ips else 'keine Adresse'}")
            if len(ips) > 1:
                print(f"    (i) {len(ips)} Adressen aufgelöst (Round-Robin/CDN?)")
        print()

    if r.get("webserver"):
        w = r["webserver"]
        print(paint("1", "  WEB-SERVER"))
        if w.get("server"):
            print(f"    {mark(True)} Server-Header: {w['server']}")
        else:
            print(f"    {mark(False)} Server-Header: (nicht gesetzt)")
        if w.get("protocol"):
            print(f"    {mark(True)} Protokoll (ALPN): {w['protocol']}")
        if w.get("hsts"):
            pl = " [preload]" if w.get("hsts_preload") else ""
            print(f"    {mark(True)} HSTS: {w['hsts']}{pl}")
        else:
            print(f"    {mark(False)} HSTS: (nicht gesetzt)")
        if w.get("alt_svc"):
            print(f"    {mark(True)} Alt-Svc (HTTP/3-Indiz): {w['alt_svc']}")
        if w.get("final_status") is not None:
            print(f"    {mark(True)} Finaler Status: {w['final_status']}")
        h80 = w.get("http80")
        if h80:
            print(f"    {mark(True)} HTTP (Port 80): {h80}")
        for red in w.get("redirects", []):
            if str(red.get("status", "")).startswith("3"):
                print(f"    (i) Redirect {red.get('status')} → "
                      f"{red.get('location') or '-'}")
        print()

    if s["problems"]:
        print(paint("31", "  PROBLEME:"))
        for p in s["problems"]:
            print(f"    ✗ {p}")
    if s["warnings"]:
        print(paint("33", "  WARNUNGEN:"))
        for w in s["warnings"]:
            print(f"    ⚠ {w}")
    if not s["problems"] and not s["warnings"]:
        print(paint("32", "  Keine Probleme festgestellt."))
    print(paint("1", "=" * 72))

# ---------------------------------------------------------------- Main

OSSL = None
CA_BUNDLE = None
STORE = None

def main():
    global OSSL, CA_BUNDLE, STORE, CRL_MAX_BYTES, CRL_MAX_MB
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
    args = ap.parse_args()

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
    port = port or 443

    CA_BUNDLE = args.cafile or find_ca_bundle()
    if not CA_BUNDLE:
        sys.exit("Fehler: Kein CA-Bundle gefunden (mit --cafile angeben).")

    err = None
    try:
        STORE = build_store(CA_BUNDLE)
        pem_list, proto = fetch_presented_chain(host, port, args.timeout)
    except Exception as e:
        err = str(e)
    if err is None:
        try:
            cert = Cert(pem_list[0], "leaf")
            cert.meta()
            chain = check_chain(pem_list, STORE, host,
                                do_aia=not args.no_aia)
            tls = check_tls(host, port, args.timeout)
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
                                  crl=crl, http3=http3)
        except Exception as e:
            err = f"Auswertung fehlgeschlagen: {e}"

    if err is not None:
        if args.json:
            print(json.dumps({"host": host, "port": port,
                              "error": err}, ensure_ascii=False))
        else:
            print(f"FEHLER: {err}", file=sys.stderr)
        sys.exit(2)

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_report(report, args)
    sys.exit(0 if report["summary"]["ok"] else 1)

if __name__ == "__main__":
    main()
