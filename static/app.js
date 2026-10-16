// TLS-Check – Hauptseite: Prüfung starten, Fortschritt, Ergebnis im SSL-Labs-Stil
"use strict";

const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const BLOCK_PRIVATE = document.body.dataset.blockPrivate === "1";
let lastResult = null, lastDuration = 0, busy = false;

// ---------------------------------------------------------------- Eingabe
document.querySelectorAll(".opt input").forEach(cb =>
  cb.addEventListener("change", () => cb.closest(".opt").classList.toggle("on", cb.checked)));

function renderPolicy() {
  $("policy").classList.toggle("off", !BLOCK_PRIVATE);
  $("policytxt").textContent = t(BLOCK_PRIVATE ? "policy.on" : "policy.off");
}
renderPolicy();

// ---------------------------------------------------------------- Fortschritt
const STEPS = [["s.connect", 1.2], ["s.cert", 1], ["s.chain", 1.5], ["s.proto", 2],
               ["s.cipher", 4], ["s.kx", 3], ["s.web", 2.5], ["s.rev", 4], ["s.sess", 3]];
let progTimer = null;

function startProgress(host, fast) {
  const steps = fast ? STEPS.slice(0, 7) : STEPS;
  const total = steps.reduce((a, s) => a + s[1], 0);
  $("phost").textContent = host;
  $("steps").innerHTML = steps.map(s =>
    `<li><span class="dot"></span><span>${esc(t(s[0]))}</span></li>`).join("");
  $("progress").classList.remove("hide");
  $("progress").classList.add("fade");
  const lis = [...$("steps").children];
  const t0 = performance.now();
  progTimer = setInterval(() => {
    const el = (performance.now() - t0) / 1000;
    $("ptime").textContent = el.toFixed(1) + " s";
    let acc = 0, cur = steps.length - 1;
    for (let i = 0; i < steps.length; i++) {
      acc += steps[i][1];
      if (el < acc) { cur = i; break; }
    }
    lis.forEach((li, i) => {
      li.classList.toggle("done", i < cur);
      li.classList.toggle("run", i === cur);
    });
    $("pfill").style.width = Math.min(94, el / total * 100) + "%";
  }, 100);
  return t0;
}

function stopProgress() {
  clearInterval(progTimer);
  $("pfill").style.width = "100%";
  [...$("steps").children].forEach(li => { li.classList.remove("run"); li.classList.add("done"); });
  setTimeout(() => $("progress").classList.add("hide"), 450);
}

// ---------------------------------------------------------------- Prüfung
async function doCheck(ev) {
  if (ev) ev.preventDefault();
  if (busy) return;
  const host = $("host").value.trim();
  if (!host) { $("host").focus(); return; }
  busy = true;
  const fast = $("fast").checked;
  $("go").disabled = true;
  $("go").innerHTML = `<span class="spin"></span><span>${esc(t("btn.checking"))}</span>`;
  $("result").innerHTML = "";
  const t0 = startProgress(host, fast);
  try {
    const q = new URLSearchParams({ host, lang: LANG });
    if ($("ocsp").checked) q.set("ocsp", "1");
    if ($("noaia").checked) q.set("no_aia", "1");
    if (fast) q.set("fast", "1");
    const res = await fetch("/api/check?" + q, { credentials: "same-origin",
                                                  headers: { "Accept": "application/json" } });
    if (res.status === 401) {
      lastResult = null;
      $("result").innerHTML = errorCard(t("err.title"), t("err.session"), false);
      setTimeout(() => { location.href = "/login?e=expired"; }, 1500);
      return;
    }
    const ct = res.headers.get("Content-Type") || "";
    if (!ct.includes("application/json")) {
      lastResult = null;
      $("result").innerHTML = errorCard(t("err.net"),
        res.status === 504 ? t("err.gateway") : `HTTP ${res.status}`, false);
      return;
    }
    lastResult = await res.json();
    lastDuration = (performance.now() - t0) / 1000;
    render();
  } catch (e) {
    lastResult = null;
    $("result").innerHTML = errorCard(t("err.net"), String(e.message || e), false);
  } finally {
    stopProgress();
    busy = false;
    $("go").disabled = false;
    $("go").innerHTML = ICON.bolt + `<span>${esc(t("btn.check"))}</span>`;
  }
}
$("form").addEventListener("submit", doCheck);

document.addEventListener("langchange", () => {
  renderPolicy();
  if (!busy) $("go").innerHTML = ICON.bolt + `<span>${esc(t("btn.check"))}</span>`;
  if (lastResult) render();
});

// ---------------------------------------------------------------- Bausteine
const tone = s => s >= 90 ? "good" : s >= 80 ? "mid" : s >= 50 ? "warn" : "bad";
const gradeTone = g => ({ "A+": "good", "A": "good", "A-": "mid", "B": "warn", "C": "warn" }[g] || "bad");

function errorCard(title, text, blocked) {
  return `<div class="card fade"><div class="errbox${blocked ? " blocked" : ""}">
    ${blocked ? ICON.ban : ICON.stop}<div><b>${esc(title)}</b>${esc(text)}</div></div></div>`;
}

function pill(cls, icon, txt) {
  return `<span class="pill ${cls}">${icon}${esc(txt)}</span>`;
}

function section(icon, titleKey, st, body, open) {
  const stTxt = { ok: t("st.ok"), warn: t("st.warn"), bad: t("st.bad"), info: t("st.info") }[st];
  return `<details class="card sec fade"${open ? " open" : ""}>
    <summary><span class="ic">${ICON[icon]}</span><h3>${esc(t(titleKey))}</h3>
      <span class="st ${st}">${esc(stTxt)}</span><span class="chev">${ICON.chev}</span></summary>
    <div class="body">${body}</div></details>`;
}

const kv = rows => `<dl class="kv">${rows.filter(Boolean).map(([k, v]) =>
  `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
const okTxt = (ok, a, b) => ok ? `<span class="ok-t">✓ ${esc(a)}</span>` : `<span class="bad-t">✗ ${esc(b)}</span>`;

// ---------------------------------------------------------------- Ergebnis
function render() {
  const r = lastResult;
  if (r.error) {
    $("result").innerHTML = errorCard(r.blocked ? t("err.blocked") : t("err.title"), r.error, r.blocked);
    return;
  }
  const s = r.summary, sc = s.scores || {}, c = r.certificate, ch = r.chain;
  const w = r.webserver || {}, kx = r.key_exchange || { groups: [] };
  const vers = r.tls_versions || {};
  let h = "";

  if (r.lang && r.lang !== LANG) {
    h += `<div class="note fade">${ICON.globe}<span>${esc(t("langhint"))}</span></div>`;
  }

  // --- Zusammenfassung: Note-Ring + vier Balken + Kennzeichen
  const gt = gradeTone(s.grade);
  const C = 2 * Math.PI * 74;
  h += `<div class="card fade"><div class="summary">
    <div class="ring pop">
      <svg viewBox="0 0 176 176">
        <circle class="trk" cx="88" cy="88" r="74" fill="none" stroke-width="13"/>
        <circle class="val g-${gt}" cx="88" cy="88" r="74" fill="none" stroke="currentColor" stroke-width="13"
          stroke-linecap="round" stroke-dasharray="${C.toFixed(1)}" stroke-dashoffset="${C.toFixed(1)}" data-target="${sc.overall || 0}"/>
      </svg>
      <div class="center"><div class="grade g-${gt}">${esc(s.grade)}</div><div class="score">${esc(sc.overall ?? "–")}/100</div></div>
    </div>
    <div>
      <div class="shead"><span class="host">${esc(r.host)}${r.port !== 443 ? ":" + esc(r.port) : ""}</span></div>
      <div class="snote">${esc(s.note)}</div>
      <div class="bars">${[["sc.cert", sc.certificate], ["sc.proto", sc.protocol],
                           ["sc.kx", sc.key_exchange], ["sc.cipher", sc.cipher]].map(([k, v]) =>
        `<div class="bar"><span class="lab">${esc(t(k))}</span><span class="trk"><span class="fill f-${tone(v || 0)}" data-w="${v || 0}"></span></span><span class="num">${esc(v ?? "–")}</span></div>`).join("")}
      </div>
      <div class="meta">
        <span>${esc(t("m.checked"))}: <b>${esc(r.checked_at_utc)} UTC</b></span>
        ${r.dns && r.dns.tested_ip ? `<span>${esc(t("m.ip"))}: <b class="mono">${esc(r.dns.tested_ip)}</b></span>` : ""}
        <span>${esc(t("m.proto"))}: <b>${esc(r.negotiated_protocol || "–")}</b></span>
        <span>${esc(t("m.dur"))}: <b>${lastDuration.toFixed(1)} s</b></span>
      </div>
    </div></div>`;

  const pills = [];
  pills.push(vers["TLS 1.3"] && vers["TLS 1.3"].available
    ? pill("ok", ICON.check, t("p.tls13")) : pill("warn", ICON.alert, t("p.notls13")));
  if ((vers["TLS 1.0"] || {}).available || (vers["TLS 1.1"] || {}).available)
    pills.push(pill("bad", ICON.x, t("p.oldtls")));
  if (w.hsts) pills.push(pill(w.hsts_max_age >= 15552000 ? "ok" : "warn",
                              w.hsts_max_age >= 15552000 ? ICON.check : ICON.alert, t("p.hsts")));
  else if (!w.error) pills.push(pill("bad", ICON.x, t("p.nohsts")));
  if (w.http80_redirects_https) pills.push(pill("ok", ICON.check, t("p.redirect")));
  if (w.protocol === "HTTP/2") pills.push(pill("info", ICON.bolt, t("p.h2")));
  if (kx.groups.some(g => g.post_quantum && g.available)) pills.push(pill("info", ICON.key, t("p.pq")));
  if (r.ocsp_stapling && r.ocsp_stapling.stapled) pills.push(pill("ok", ICON.check, t("p.staple")));
  if (r.http3 && r.http3.active) pills.push(pill("info", ICON.bolt, t("p.h3")));
  if (r.revocation && r.revocation.level === "ok") pills.push(pill("ok", ICON.shield, t("p.rev.ok")));
  if (r.revocation && r.revocation.level === "revoked") pills.push(pill("bad", ICON.shieldx, t("p.rev.bad")));
  h += `<div class="pills">${pills.join("")}</div></div>`;

  // --- Befunde
  const probs = s.problems || [], warns = s.warnings || [];
  h += `<div class="card fade"><h2 class="subh">${esc(t("find.title"))}</h2>`;
  if (probs.length || warns.length) {
    h += `<ul class="find">` +
      probs.map(p => `<li class="p">${ICON.stop}<span>${esc(p)}</span></li>`).join("") +
      warns.map(p => `<li class="w">${ICON.alert}<span>${esc(p)}</span></li>`).join("") + `</ul>`;
  } else {
    h += `<div class="allgood">${ICON.shield}<span>${esc(t("find.none"))}</span></div>`;
  }
  h += `</div>`;

  // --- Zertifikat
  const sanIp = c.san_ip && c.san_ip.length ? (Array.isArray(c.san_ip) ? c.san_ip.join(", ") : c.san_ip) : "";
  const certSt = !c.hostname_match || c.days_left <= 0 ? "bad" : c.days_left < 14 ? "warn" : "ok";
  h += section("cert", "sec.cert", certSt, kv([
    [t("f.match"), c.hostname_match ? `<span class="ok-t">✓ ${esc(c.hostname_matched_name)}</span>`
                                     : `<span class="bad-t">✗ ${esc(t("f.nomatch"))}</span>`],
    [t("f.san"), esc((c.san_dns || []).join(", ") || "–") + (sanIp ? ` <span class="dim">IP: ${esc(sanIp)}</span>` : "")],
    [t("f.subject"), esc(c.subject)],
    [t("f.issuer"), esc(c.issuer)],
    [t("f.serial"), esc(c.serial)],
    [t("f.valid"), `${esc(c.not_before)} → ${esc(c.not_after)} <span class="${c.days_left > 14 ? "ok-t" : c.days_left > 0 ? "warn-t" : "bad-t"}">(${esc(c.days_left)} ${esc(t("f.days"))})</span>`],
    [t("f.sigkey"), `${esc(c.signature_algorithm)} · ${esc(c.public_key)}`],
    [t("f.aia"), `<span class="dim">${esc(c.aia_ca || "–")}</span>`],
    [t("f.ocspurl"), `<span class="dim">${esc(c.ocsp_url || "–")}</span>`],
  ]), true);

  // --- Kette
  const vsp = ch.verify_with_server_chain || {}, vst = ch.verify_with_truststore || {};
  const missing = ch.missing_from_server || [];
  const vaia = ch.verify_with_aia;
  const chainSt = !vsp.ok && !(vaia && vaia.ok) ? "bad" : missing.length ? "warn" : "ok";
  const srcTag = src => src === "server" ? `<span class="tag ok">${esc(t("src.server"))}</span>`
    : src === "truststore" ? `<span class="tag i">${esc(t("src.ts"))}</span>`
    : src === "aia" ? `<span class="tag w">${esc(t("src.aia"))}</span>`
    : `<span class="tag p">${esc(t("src.miss"))}</span>`;
  let cb = `<div class="chain">`;
  const fc = ch.full_chain && ch.full_chain.length ? ch.full_chain
    : (ch.presented || []).map(p => ({ ...p, source: "server" }));
  fc.forEach((p, i) => {
    const role = i === 0 ? t("c.leaf") : (p.self_signed ? t("c.root") : t("c.inter"));
    const cls = p.source === "server" ? "" : p.source === "truststore" ? " ts" : p.source === "aia" ? " aia" : " miss";
    cb += `<div class="cnode${cls}"><div class="ch">${esc(role)} ${srcTag(p.source)}</div>
      <div class="cs">${esc(p.subject)}</div>
      ${p.valid_to ? `<div class="cs">${esc(t("c.until"))} ${esc(p.valid_to)}</div>` : ""}</div>`;
  });
  cb += `</div><table><tr><th>${esc(t("v.title"))}</th><th></th><th>Detail</th></tr>
    <tr><td>${esc(t("v.server"))}</td><td>${okTxt(vsp.ok, t("v.ok"), t("v.fail"))}</td><td class="dim mono">${esc(vsp.detail)}</td></tr>
    <tr><td>${esc(t("v.ts"))}</td><td>${okTxt(vst.ok, t("v.ok"), t("v.fail"))}</td><td class="dim mono">${esc(vst.detail)}</td></tr>${vaia ? `
    <tr><td>${esc(t("v.aia"))}</td><td>${okTxt(vaia.ok, t("v.ok"), t("v.fail"))}</td><td class="dim mono">${esc(vaia.detail)}</td></tr>` : ""}</table>`;
  if (missing.length) {
    cb += `<div class="note">${ICON.alert}<span>${esc(t("c.missing"))}</span></div><ul class="find">` +
      missing.map(m => `<li class="w">${ICON.alert}<span><span class="tag ${m.in_truststore ? "i" : "p"}">${esc(t(m.in_truststore ? "c.in_ts" : "c.not_local"))}</span> ${esc(m.subject)}</span></li>`).join("") + `</ul>`;
    if ((ch.aia || []).length) {
      cb += `<table><tr><th>AIA</th><th>${esc(t("aia.reach"))}</th><th></th></tr>` +
        ch.aia.map(a => `<tr><td class="name">${esc(a.url || "–")}</td><td>${a.reachable ? '<span class="ok-t">✓</span>' : '<span class="bad-t">✗</span>'}</td><td class="dim">${esc(a.note)}</td></tr>`).join("") + `</table>`;
    }
  } else if (vsp.ok) {
    cb += `<div class="note">${ICON.check}<span>${esc(t("c.complete"))}${ch.root_presented_by_server ? esc(t("c.inclroot")) : ""}.</span></div>`;
  }
  (ch.notes || []).forEach(n => cb += `<div class="note">${ICON.globe}<span>${esc(n)}</span></div>`);
  h += section("chain", "sec.chain", chainSt, cb, chainSt !== "ok");

  // --- Protokolle & Key Exchange
  const oldTls = (vers["TLS 1.0"] || {}).available || (vers["TLS 1.1"] || {}).available;
  const protoSt = oldTls ? "bad" : (sc.protocol < 100 || sc.key_exchange < 90) ? "warn" : "ok";
  let pb = `<div class="subh">${esc(t("pr.versions"))}</div><div class="chips">`;
  for (const k of Object.keys(vers)) {
    const av = vers[k].available, old = k === "TLS 1.0" || k === "TLS 1.1";
    pb += `<span class="chip ${av ? (old ? "bad" : "on") : "off"}">${av ? (old ? ICON.alert : ICON.check) : ""}${esc(k)}</span>`;
  }
  pb += `</div><div class="subh">${esc(t("pr.groups"))}</div><div class="chips">`;
  kx.groups.filter(g => g.tested !== false).forEach(g => {
    const weak = g.rsa_equivalent < 3072;
    pb += `<span class="chip ${g.available ? (weak ? "bad" : "on") : "off"}">${g.available ? ICON.check : ""}${esc(g.group)}
      <span class="dim">${esc(g.bits)}</span>${g.post_quantum ? '<span class="pq">PQ</span>' : ""}</span>`;
  });
  pb += `</div>`;
  if (kx.dhe_bits || kx.static_rsa_bits) {
    pb += kv([kx.dhe_bits && [t("pr.dhe"), esc(kx.dhe_bits) + " Bit"],
              kx.static_rsa_bits && [t("pr.rsa"), `<span class="warn-t">${esc(kx.static_rsa_bits)} Bit</span>`]]);
  }
  h += section("lock", "sec.proto", protoSt, pb, protoSt !== "ok");

  // --- Cipher-Suiten
  const ciphers = r.ciphers || [];
  const act = ciphers.filter(x => x.available);
  const cipherSt = act.some(x => x.level === "weak") ? "bad" : act.some(x => x.level === "legacy") ? "warn" : "ok";
  let ctab = `<table class="ciphers" id="ctab"><tr><th>${esc(t("ci.suite"))}</th><th>${esc(t("ci.cat"))}</th><th>${esc(t("ci.bits"))}</th><th>${esc(t("ci.status"))}</th></tr>` +
    ciphers.map(x => `<tr class="${x.available ? "" : "na"}"><td class="name"><span class="lv ${esc(x.level)}"></span>${esc(x.cipher)}</td>
      <td>${esc(x.category)}</td><td class="mono">${esc(x.bits)}</td>
      <td>${x.available ? `<span class="ok-t">✓ ${esc(t("ci.on"))}</span>` : '<span class="dim">—</span>'}</td></tr>`).join("") +
    `</table><button type="button" class="linkbtn" id="callbtn">${esc(t("ci.showall"))}</button>`;
  h += section("key", "sec.cipher", cipherSt, ctab, cipherSt !== "ok");

  // --- DNS & Webserver
  const d = r.dns || {};
  const ips = (d.ipv4 || []).concat(d.ipv6 || []);
  const webSt = w.error ? "warn" : (w.hsts && w.http80_redirects_https !== false) ? "ok" : "warn";
  const reds = (w.redirects || []).filter(x => String(x.status || "").startsWith("3"));
  h += section("server", "sec.web", webSt, kv([
    [t("w.addr"), ips.length ? ips.map(esc).join(" · ") : "–"],
    d.tested_ip && ips.length > 1 && [t("w.tested"), esc(d.tested_ip)],
    [t("w.server"), w.server ? esc(w.server) : `<span class="dim">${esc(t("w.notset"))}</span>`],
    [t("w.alpn"), esc(w.protocol || "–")],
    [t("w.hsts"), w.hsts ? `<span class="${w.hsts_max_age >= 15552000 ? "ok-t" : "warn-t"}">✓ ${esc(w.hsts)}${w.hsts_preload ? " [preload]" : ""}</span>`
                         : `<span class="bad-t">${esc(t("w.notset"))}</span>`],
    w.alt_svc && [t("w.altsvc"), esc(w.alt_svc)],
    w.final_status != null && [t("w.final"), esc(w.final_status)],
    [t("w.http80"), esc(w.http80 || "–")],
    reds.length && [t("w.redirects"), reds.map(x => `${esc(x.status)} → ${esc(x.location || "-")}`).join("<br>")],
    w.error && ["Error", `<span class="warn-t">${esc(w.error)}</span>`],
  ]), webSt !== "ok");

  // --- Revocation
  if (r.revocation || r.ocsp) {
    const rv = r.revocation || {};
    const revSt = rv.level === "ok" ? "ok" : rv.level === "revoked" ? "bad" : "info";
    const st = r.ocsp_stapling || {};
    let rb = kv([
      rv.level && [t("r.status"), `<span class="${rv.level === "ok" ? "ok-t" : rv.level === "revoked" ? "bad-t" : "warn-t"}">${esc(t(rv.level === "ok" ? "r.ok" : rv.level === "revoked" ? "r.revoked" : "r.unknown"))}</span> – ${esc(rv.detail)}`],
      r.ocsp_stapling && [t("r.staple"), st.stapled ? `<span class="ok-t">✓ ${esc(st.status)}</span>` : `<span class="dim">${esc(t("r.nostaple"))}</span>`],
      r.ocsp && [t("r.ocsp"), r.ocsp.available
        ? `${okTxt(r.ocsp.ok, r.ocsp.certificate_status || "good", r.ocsp.certificate_status || r.ocsp.response_status || t("r.unknown"))} <span class="dim">${esc(r.ocsp.url)}</span>`
        : `<span class="dim">${esc(r.ocsp.detail)}</span>`],
    ]);
    ((r.crl && r.crl.crls) || []).forEach(x => {
      const cls = x.ok === true ? "ok" : x.ok === false ? "bad" : "na";
      rb += `<div class="crow"><span class="d ${cls}"></span><div class="u">${esc(x.url)}</div>
        <div class="m">${esc(x.issuer)}${x.last_update ? " · Last Update " + esc(x.last_update) : ""}${x.note ? " · " + esc(x.note) : ""}</div></div>`;
    });
    h += section("shield", "sec.rev", revSt, rb, revSt === "bad");
  }

  // --- Session & HTTP/3
  if (r.session || r.http3) {
    const se = r.session || {}, h3 = r.http3 || {};
    h += section("bolt", "sec.extra", "info", kv([
      r.session && [t("x.resume"), se.resumed ? `<span class="ok-t">✓ ${esc(t("x.resumed"))} (${esc(se.version)})</span>` : `<span class="dim">${esc(t("x.noresume"))}</span>`],
      r.session && [t("x.note"), `<span class="dim">${esc(se.note)}</span>`],
      r.http3 && [t("x.h3"), h3.active ? `<span class="ok-t">✓ ${esc(t("x.active"))}</span>` : `<span class="dim">${esc(t(h3.unknown ? "x.unknown" : "x.inactive"))}</span>`],
      r.http3 && [t("x.note"), `<span class="dim">${esc(h3.note)}</span>`],
    ]), false);
  }

  // --- Roh-JSON
  h += section("code", "sec.raw", "info", `<pre class="raw" id="raw"></pre>`, false);

  $("result").innerHTML = h;
  $("raw").textContent = JSON.stringify(r, null, 2);
  const cbtn = $("callbtn");
  if (cbtn) cbtn.addEventListener("click", () => {
    $("ctab").classList.toggle("all");
    cbtn.classList.add("hide");
  });

  // Animationen: Karten gestaffelt einblenden, Ring + Balken füllen
  [...$("result").children].forEach((el, i) => { el.style.animationDelay = (i * 60) + "ms"; });
  requestAnimationFrame(() => requestAnimationFrame(() => {
    document.querySelectorAll(".ring .val").forEach(el => {
      const p = Number(el.dataset.target) / 100;
      el.style.strokeDashoffset = String(C * (1 - p));
    });
    document.querySelectorAll(".bar .fill").forEach(el => { el.style.width = el.dataset.w + "%"; });
  }));
}

$("host").focus();
