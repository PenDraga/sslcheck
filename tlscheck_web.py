#!/usr/bin/env python3
"""
TLS- & Zertifikatskette-Web-Check (abgespecktes SSL-Labs) im LAN.

Nur Python-Standardbibliothek. Start:
    python3 tlscheck_web.py                # Port 8765, 0.0.0.0
    python3 tlscheck_web.py --port 9000 --bind 127.0.0.1

Die eigentliche Prüfung läuft serverseitig als Subprozess:
    python3 tlscheck.py <host> --json
Damit bleibt jede Anfrage isoliert (keine Global-State-Probleme bei
mehreren parallelen Checks) und der Truststore-Build pro Check ist klein.
"""

import argparse
import json
import re
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

HERE = Path(__file__).resolve().parent
CHECKER = HERE / "tlscheck.py"
PY = sys.executable or "python3"

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
  --bg:#0d1117; --panel:#161b22; --panel2:#1c2330; --line:#2b3444;
  --txt:#e6edf3; --dim:#8b98a9; --ok:#3fb950; --warn:#d29922; --bad:#f85149;
  --accent:#4ea1ff; --radius:12px; --mono:ui-monospace,SFMono-Regular,Menlo,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);
  font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  padding:24px 16px 60px}
.wrap{max-width:960px;margin:0 auto}
h1{font-size:20px;margin:0 0 2px}
.sub{color:var(--dim);font-size:13px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
  padding:18px;margin-bottom:16px}
label{color:var(--dim);font-size:12px;display:block;margin-bottom:6px;letter-spacing:.04em;text-transform:uppercase}
.row{display:flex;gap:14px;flex-wrap:wrap;align-items:flex-end}
.field{flex:1;min-width:220px}
input[type=text]{width:100%;background:var(--panel2);border:1px solid var(--line);
  color:var(--txt);border-radius:8px;padding:11px 12px;font-size:15px;font-family:var(--mono)}
input[type=text]:focus{outline:none;border-color:var(--accent)}
.chk{display:flex;align-items:center;gap:8px;background:var(--panel2);
  border:1px solid var(--line);border-radius:8px;padding:10px 12px;cursor:pointer;white-space:nowrap}
.chk input{width:16px;height:16px;accent-color:var(--accent)}
.chk span{font-size:13px}
button{background:var(--accent);color:#fff;border:none;border-radius:8px;
  padding:11px 22px;font-size:15px;font-weight:600;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
button:hover:not(:disabled){filter:brightness(1.1)}
.gradebar{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.badge{font-size:40px;font-weight:800;width:74px;height:74px;border-radius:14px;
  display:flex;align-items:center;justify-content:center;flex:0 0 auto}
.grade-F{background:#f85149;color:#fff}
.grade-C{background:#d29922;color:#000}
.grade-B,.grade-A-,.grade-A{background:#3fb950;color:#000}
.grade-note{font-size:15px;color:var(--txt);max-width:560px}
.proto{color:var(--dim);font-size:13px;margin-top:6px}
.list{list-style:none;padding:0;margin:8px 0 0}
.list li{padding:7px 0;border-bottom:1px solid var(--line);display:flex;gap:10px}
.list li:last-child{border-bottom:none}
.tag{font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;flex:0 0 auto;
  text-transform:uppercase;letter-spacing:.04em;margin-top:2px}
.tag.p{background:#f85149;color:#fff}
.tag.w{background:#d29922;color:#000}
.tag.i{background:#2b3444;color:var(--dim)}
.okbox{color:var(--ok);font-weight:600}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--dim);
  margin:0 0 12px}
.kv{display:grid;grid-template-columns:190px 1fr;gap:4px 14px;font-size:14px}
.kv dt{color:var(--dim)}
.kv dd{margin:0;word-break:break-word;font-family:var(--mono);font-size:13px}
.chainbox{background:var(--panel2);border:1px solid var(--line);border-radius:8px;
  padding:12px;margin-bottom:8px}
.chainbox .c-head{font-weight:600;margin-bottom:2px}
.chainbox .c-sub{color:var(--dim);font-size:12px;font-family:var(--mono)}
.chip{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;
  font-family:var(--mono);margin:0 6px 6px 0;border:1px solid var(--line)}
.chip.on{border-color:var(--ok);color:var(--ok)}
.chip.off{color:var(--dim);opacity:.6}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.04em}
td.name{font-family:var(--mono);word-break:break-all}
.cat-S{color:var(--ok);font-weight:600}
.cat-W{color:var(--warn);font-weight:600}
.cat-X{color:var(--bad);font-weight:600}
.dim{color:var(--dim)}
.errbox{background:#3a1d1d;border:1px solid #f85149;color:#ff8a80;
  border-radius:8px;padding:12px;font-family:var(--mono);font-size:13px;white-space:pre-wrap}
.mono{font-family:var(--mono);font-size:12px}
.linkbtn{background:none;border:none;color:var(--accent);cursor:pointer;
  font-size:13px;padding:0;text-decoration:underline}
.spin{display:inline-block;width:14px;height:14px;border:2px solid #fff3;
  border-top-color:#fff;border-radius:50%;animation:sp .7s linear infinite;vertical-align:-2px}
@keyframes sp{to{transform:rotate(360deg)}}
.hide{display:none}
@media(max-width:600px){.kv{grid-template-columns:1fr}.kv dt{margin-top:6px}
  .gradebar{gap:12px}.badge{font-size:32px;width:58px;height:58px}}
</style>
</head>
<body>
<div class="wrap">
  <h1>TLS- &amp; Zertifikats-Check</h1>
  <div class="sub">Gültigkeit, Zertifikatskette (Server vs. Truststore/AIA), TLS-Versionen &amp; Cipher-Suiten</div>

  <div class="card">
    <div class="row">
      <div class="field">
        <label for="host">Hostname / IP (optional mit :Port)</label>
        <input type="text" id="host" placeholder="example.com  oder  10.0.0.5:8443" autocomplete="off" spellcheck="false">
      </div>
      <label class="chk"><input type="checkbox" id="ocsp"><span>OCSP prüfen</span></label>
      <label class="chk"><input type="checkbox" id="noaia"><span>AIA überspringen</span></label>
      <label class="chk" title="Überspringt CRL, OCSP-Stapling, Session-Resume & HTTP/3 (Schnellcheck)"><input type="checkbox" id="fast"><span>– schnell</span></label>
      <button id="go">Prüfen</button>
    </div>
  </div>

  <div id="status"></div>
  <div id="result"></div>
  <div id="rawwrap" class="card hide" style="margin-top:16px">
    <h2>Roh-JSON</h2>
    <pre id="raw" class="mono" style="white-space:pre-wrap;margin:0"></pre>
  </div>
</div>

<script>
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

  // Kette
  h+=`<div class="card"><h2>Zertifikatskette (vom Server geliefert)</h2>`;
  (ch.presented||[]).forEach((p,i)=>{
    const tag=i===0?"Endzertifikat":i===1?"Zwischenzertifikat":(i===2?"Wurzel":"Glied "+i);
    h+=`<div class="chainbox">
      <div class="c-head">${tag} ${p.self_signed?"<span class='dim'>(self-signed)</span>":""}</div>
      <div class="c-sub">${esc(p.subject)}</div>
      <div class="c-sub">Issuer: ${esc(p.issuer)} · Serial ${esc(p.serial)} · gültig bis ${esc(p.valid_to)}</div>
    </div>`;
  });
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
      h+=`<div class="errbox" style="background:#3a1d1d">Auflösung fehlgeschlagen: ${esc(d.error||"")}</div>`;
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
      <dt>Erreichbar</dt><dd>${o.available?"✓":"✗"}</dd>
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
      h+=`<table style="margin-top:8px"><tr><th>CRL (Issuer)</th><th>Abrufbar</th><th>Last Update</th><th>Notiz</th></tr>`+
        r.crl.crls.map(c=>`<tr>
          <td class="name">${esc(c.url||"")}<div class="dim">${esc(c.issuer||"")}</div></td>
          <td class="${c.ok===true?"cat-S":c.ok===false?"cat-X":"dim"}">${c.ok===true?"✓":c.ok===false?"✗":"?"}</td>
          <td class="dim">${esc(c.last_update||"")}</td>
          <td class="dim">${esc(c.note||"")}</td></tr>`).join("")+`</table>`;
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

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        u = urlparse(self.path)
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
            data, code = run_check(host, ocsp=ocsp, no_aia=no_aia, fast=fast)
            self._send(200 if code in (0, 1) else 502,
                       json.dumps(data, ensure_ascii=False))
        elif u.path == "/healthz":
            self._send(200, json.dumps({"ok": True}))
        else:
            self._send(404, json.dumps({"error": "nicht gefunden"}))

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" %
                         (self.log_date_time_string(), fmt % args))


def main():
    ap = argparse.ArgumentParser(description="TLS-Web-Check (LAN)")
    ap.add_argument("--bind", default="0.0.0.0", help="Bind-Adresse (Default 0.0.0.0)")
    ap.add_argument("--port", type=int, default=8765, help="Port (Default 8765)")
    args = ap.parse_args()
    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"TLS-Web-Check läuft: http://{args.bind}:{args.port} "
          f"(Checker: {CHECKER})")
    print("Strg+C zum Beenden.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nBeendet.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
