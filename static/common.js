// TLS-Check – gemeinsame Logik: Sprache (DE/EN), Thema (Hell/Dunkel), Icons
"use strict";

const I18N = {
  de: {
    "app.title": "TLS- & Zertifikats-Check",
    "app.sub": "Zertifikat · Kette · Protokolle · Key Exchange · Revocation",
    "theme": "Hell/Dunkel umschalten",
    "logout": "Abmelden",

    "login.title": "Anmelden",
    "login.lead": "Dieser TLS-Check ist passwortgeschützt.",
    "login.pw": "Passwort",
    "login.btn": "Anmelden",
    "login.err.bad": "Passwort falsch.",
    "login.err.locked": "Zu viele Fehlversuche – bitte in 5 Minuten erneut versuchen.",
    "login.err.origin": "Anfrage abgelehnt (ungültige Herkunft). Bitte Seite neu laden.",
    "login.out": "Du wurdest abgemeldet.",
    "login.expired": "Sitzung abgelaufen – bitte erneut anmelden.",
    "login.fine": "Sitzung 12 h gültig · Cookie HttpOnly, SameSite=Strict",

    "hero.t1": "Wie sicher ist ",
    "hero.t2": "deine TLS-Konfiguration?",
    "hero.lead": "Zertifikat, Kette, Protokolle, Cipher, Key Exchange, Revocation und Webserver – bewertet wie bei SSL Labs.",
    "host.ph": "example.com  oder  host:8443",
    "btn.check": "Prüfen",
    "btn.checking": "Prüfe …",
    "opt.ocsp": "OCSP prüfen",
    "opt.noaia": "AIA überspringen",
    "opt.fast": "Schnellcheck",
    "opt.fast.t": "Überspringt CRL, OCSP-Stapling, Session-Resume und HTTP/3",
    "policy.on": "Interne Adressen sind gesperrt – nur öffentliche Ziele werden geprüft.",
    "policy.off": "Interne Adressen sind erlaubt.",

    "prog.title": "Prüfung läuft",
    "s.connect": "Verbindung & DNS",
    "s.cert": "Zertifikat",
    "s.chain": "Zertifikatskette",
    "s.proto": "TLS-Versionen",
    "s.cipher": "Cipher-Suiten",
    "s.kx": "Key Exchange",
    "s.web": "Webserver & HSTS",
    "s.rev": "Revocation",
    "s.sess": "Session & HTTP/3",

    "sc.cert": "Zertifikat",
    "sc.proto": "Protokolle",
    "sc.kx": "Key Exchange",
    "sc.cipher": "Cipher-Stärke",
    "sc.overall": "Gesamt",
    "m.checked": "Geprüft",
    "m.ip": "IP",
    "m.proto": "Verhandelt",
    "m.dur": "Dauer",

    "p.tls13": "TLS 1.3",
    "p.notls13": "kein TLS 1.3",
    "p.hsts": "HSTS",
    "p.nohsts": "kein HSTS",
    "p.h2": "HTTP/2",
    "p.pq": "Post-Quantum",
    "p.staple": "OCSP-Stapling",
    "p.h3": "HTTP/3",
    "p.rev.ok": "nicht widerrufen",
    "p.rev.bad": "WIDERRUFEN",
    "p.oldtls": "veraltetes TLS",
    "p.redirect": "HTTP → HTTPS",

    "find.title": "Befunde",
    "find.none": "Keine Probleme, keine Warnungen – alles im grünen Bereich.",

    "sec.cert": "Endzertifikat",
    "f.match": "Hostname-Match",
    "f.nomatch": "(kein Match)",
    "f.san": "SAN",
    "f.subject": "Subject",
    "f.issuer": "Issuer",
    "f.serial": "Serial",
    "f.valid": "Gültig",
    "f.days": "Tage",
    "f.sigkey": "Signatur / Schlüssel",
    "f.aia": "AIA (CA Issuers)",
    "f.ocspurl": "OCSP-URL",

    "sec.chain": "Zertifikatskette",
    "c.leaf": "Endzertifikat",
    "c.inter": "Zwischenzertifikat",
    "c.root": "Root",
    "src.server": "vom Server",
    "src.ts": "aus Truststore",
    "src.miss": "fehlt",
    "src.aia": "per AIA geladen",
    "c.until": "gültig bis",
    "v.title": "Verifikation",
    "v.server": "Nur Server-Kette",
    "v.ts": "Mit lokalem Truststore",
    "v.aia": "Mit AIA-Nachladen (wie Browser)",
    "v.ok": "erfolgreich",
    "v.fail": "FEHLGESCHLAGEN",
    "c.complete": "Kette komplett vom Server",
    "c.inclroot": " (inkl. Root)",
    "c.missing": "Fehlt am Server – der Client muss es selbst beschaffen:",
    "c.in_ts": "im Truststore",
    "c.not_local": "nicht lokal",
    "aia.reach": "Erreichbar",

    "sec.proto": "Protokolle & Key Exchange",
    "pr.versions": "TLS-Versionen",
    "pr.groups": "Key-Exchange-Gruppen",
    "pr.dhe": "DHE-Parameter",
    "pr.rsa": "Statisches RSA (kein PFS)",

    "sec.cipher": "Cipher-Suiten",
    "ci.suite": "Suite",
    "ci.cat": "Kategorie",
    "ci.bits": "Bit",
    "ci.status": "Status",
    "ci.on": "aktiv",
    "ci.showall": "Alle getesteten anzeigen",

    "sec.web": "DNS & Webserver",
    "w.addr": "Adressen",
    "w.tested": "Geprüfte IP",
    "w.server": "Server-Header",
    "w.alpn": "Protokoll (ALPN)",
    "w.hsts": "HSTS",
    "w.altsvc": "Alt-Svc",
    "w.final": "Finaler Status",
    "w.http80": "HTTP (Port 80)",
    "w.redirects": "Redirect-Kette",
    "w.notset": "nicht gesetzt",

    "sec.rev": "Revocation (CRL & OCSP)",
    "r.status": "Status",
    "r.ok": "OK",
    "r.revoked": "WIDERRUFEN",
    "r.unknown": "unbekannt",
    "r.staple": "OCSP-Stapling",
    "r.nostaple": "nicht vorhanden",
    "r.ocsp": "OCSP direkt",
    "r.reach": "erreichbar",
    "r.unreach": "nicht erreichbar",

    "sec.extra": "Session & HTTP/3",
    "x.resume": "Session-Resume",
    "x.resumed": "erfolgreich",
    "x.noresume": "nicht möglich",
    "x.h3": "HTTP/3 (QUIC)",
    "x.active": "aktiv",
    "x.inactive": "nicht aktiv",
    "x.unknown": "unbekannt",
    "x.note": "Notiz",

    "sec.raw": "Roh-JSON",

    "st.ok": "OK",
    "st.warn": "Hinweis",
    "st.bad": "Problem",
    "st.info": "Info",

    "err.title": "Prüfung fehlgeschlagen",
    "err.blocked": "Ziel gesperrt",
    "err.net": "Abfrage fehlgeschlagen",
    "err.session": "Sitzung abgelaufen – du wirst zur Anmeldung weitergeleitet …",
    "foot": "Bewertung angelehnt an den SSL-Labs-Rating-Guide · Datenquelle: tlscheck.py --json",
    "langhint": "Sprache gewechselt – Prüf-Meldungen erscheinen ab der nächsten Prüfung in der neuen Sprache."
  },
  en: {
    "app.title": "TLS & Certificate Check",
    "app.sub": "Certificate · Chain · Protocols · Key Exchange · Revocation",
    "theme": "Toggle light/dark",
    "logout": "Sign out",

    "login.title": "Sign in",
    "login.lead": "This TLS check is password protected.",
    "login.pw": "Password",
    "login.btn": "Sign in",
    "login.err.bad": "Wrong password.",
    "login.err.locked": "Too many failed attempts – please try again in 5 minutes.",
    "login.err.origin": "Request rejected (invalid origin). Please reload the page.",
    "login.out": "You have been signed out.",
    "login.expired": "Session expired – please sign in again.",
    "login.fine": "Session valid for 12 h · cookie HttpOnly, SameSite=Strict",

    "hero.t1": "How secure is ",
    "hero.t2": "your TLS setup?",
    "hero.lead": "Certificate, chain, protocols, ciphers, key exchange, revocation and web server – rated SSL Labs style.",
    "host.ph": "example.com  or  host:8443",
    "btn.check": "Check",
    "btn.checking": "Checking …",
    "opt.ocsp": "Check OCSP",
    "opt.noaia": "Skip AIA",
    "opt.fast": "Quick check",
    "opt.fast.t": "Skips CRL, OCSP stapling, session resumption and HTTP/3",
    "policy.on": "Internal addresses are blocked – only public targets are checked.",
    "policy.off": "Internal addresses are allowed.",

    "prog.title": "Check running",
    "s.connect": "Connection & DNS",
    "s.cert": "Certificate",
    "s.chain": "Certificate chain",
    "s.proto": "TLS versions",
    "s.cipher": "Cipher suites",
    "s.kx": "Key exchange",
    "s.web": "Web server & HSTS",
    "s.rev": "Revocation",
    "s.sess": "Session & HTTP/3",

    "sc.cert": "Certificate",
    "sc.proto": "Protocol support",
    "sc.kx": "Key exchange",
    "sc.cipher": "Cipher strength",
    "sc.overall": "Overall",
    "m.checked": "Checked",
    "m.ip": "IP",
    "m.proto": "Negotiated",
    "m.dur": "Duration",

    "p.tls13": "TLS 1.3",
    "p.notls13": "no TLS 1.3",
    "p.hsts": "HSTS",
    "p.nohsts": "no HSTS",
    "p.h2": "HTTP/2",
    "p.pq": "Post-quantum",
    "p.staple": "OCSP stapling",
    "p.h3": "HTTP/3",
    "p.rev.ok": "not revoked",
    "p.rev.bad": "REVOKED",
    "p.oldtls": "outdated TLS",
    "p.redirect": "HTTP → HTTPS",

    "find.title": "Findings",
    "find.none": "No problems, no warnings – all green.",

    "sec.cert": "Leaf certificate",
    "f.match": "Hostname match",
    "f.nomatch": "(no match)",
    "f.san": "SAN",
    "f.subject": "Subject",
    "f.issuer": "Issuer",
    "f.serial": "Serial",
    "f.valid": "Valid",
    "f.days": "days",
    "f.sigkey": "Signature / key",
    "f.aia": "AIA (CA Issuers)",
    "f.ocspurl": "OCSP URL",

    "sec.chain": "Certificate chain",
    "c.leaf": "Leaf",
    "c.inter": "Intermediate",
    "c.root": "Root",
    "src.server": "sent by server",
    "src.ts": "from truststore",
    "src.miss": "missing",
    "src.aia": "fetched via AIA",
    "c.until": "valid until",
    "v.title": "Verification",
    "v.server": "Server chain only",
    "v.ts": "With local truststore",
    "v.aia": "With AIA fetching (like browsers)",
    "v.ok": "successful",
    "v.fail": "FAILED",
    "c.complete": "Chain complete from server",
    "c.inclroot": " (incl. root)",
    "c.missing": "Missing on server – the client has to obtain it:",
    "c.in_ts": "in truststore",
    "c.not_local": "not local",
    "aia.reach": "Reachable",

    "sec.proto": "Protocols & key exchange",
    "pr.versions": "TLS versions",
    "pr.groups": "Key exchange groups",
    "pr.dhe": "DHE parameters",
    "pr.rsa": "Static RSA (no PFS)",

    "sec.cipher": "Cipher suites",
    "ci.suite": "Suite",
    "ci.cat": "Category",
    "ci.bits": "Bits",
    "ci.status": "Status",
    "ci.on": "enabled",
    "ci.showall": "Show all tested",

    "sec.web": "DNS & web server",
    "w.addr": "Addresses",
    "w.tested": "Tested IP",
    "w.server": "Server header",
    "w.alpn": "Protocol (ALPN)",
    "w.hsts": "HSTS",
    "w.altsvc": "Alt-Svc",
    "w.final": "Final status",
    "w.http80": "HTTP (port 80)",
    "w.redirects": "Redirect chain",
    "w.notset": "not set",

    "sec.rev": "Revocation (CRL & OCSP)",
    "r.status": "Status",
    "r.ok": "OK",
    "r.revoked": "REVOKED",
    "r.unknown": "unknown",
    "r.staple": "OCSP stapling",
    "r.nostaple": "not present",
    "r.ocsp": "OCSP (direct)",
    "r.reach": "reachable",
    "r.unreach": "unreachable",

    "sec.extra": "Session & HTTP/3",
    "x.resume": "Session resumption",
    "x.resumed": "successful",
    "x.noresume": "not possible",
    "x.h3": "HTTP/3 (QUIC)",
    "x.active": "active",
    "x.inactive": "not active",
    "x.unknown": "unknown",
    "x.note": "Note",

    "sec.raw": "Raw JSON",

    "st.ok": "OK",
    "st.warn": "Notice",
    "st.bad": "Problem",
    "st.info": "Info",

    "err.title": "Check failed",
    "err.blocked": "Target blocked",
    "err.net": "Request failed",
    "err.session": "Session expired – redirecting to sign in …",
    "foot": "Rating based on the SSL Labs rating guide · data source: tlscheck.py --json",
    "langhint": "Language changed – check messages will appear in the new language from the next check on."
  }
};

function initialLang() {
  try {
    const l = localStorage.getItem("tlscheck-lang");
    if (l === "de" || l === "en") return l;
  } catch (e) {}
  return (navigator.language || "").toLowerCase().startsWith("de") ? "de" : "en";
}
let LANG = initialLang();

function t(key, vars) {
  let s = (I18N[LANG] && I18N[LANG][key]) ?? I18N.de[key] ?? key;
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.split("{" + k + "}").join(v);
  return s;
}

function applyI18n(root) {
  const r = root || document;
  r.querySelectorAll("[data-i18n]").forEach(el => { el.textContent = t(el.dataset.i18n); });
  r.querySelectorAll("[data-i18n-ph]").forEach(el => { el.placeholder = t(el.dataset.i18nPh); });
  r.querySelectorAll("[data-i18n-title]").forEach(el => {
    el.title = t(el.dataset.i18nTitle);
    el.setAttribute("aria-label", el.title);
  });
  document.documentElement.lang = LANG;
  document.title = t(document.body.dataset.titleKey || "app.title");
  document.querySelectorAll(".seg button[data-lang]").forEach(b =>
    b.classList.toggle("on", b.dataset.lang === LANG));
}

function setLang(l) {
  if (l === LANG) return;
  LANG = l;
  try { localStorage.setItem("tlscheck-lang", l); } catch (e) {}
  applyI18n();
  document.dispatchEvent(new CustomEvent("langchange"));
}

function applyTheme(th) {
  document.documentElement.setAttribute("data-theme", th);
  try { localStorage.setItem("tlscheck-theme", th); } catch (e) {}
}

(function initCommon() {
  let th = null;
  try { th = localStorage.getItem("tlscheck-theme"); } catch (e) {}
  if (!th) th = window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  applyTheme(th);
  const tb = document.getElementById("themebtn");
  if (tb) tb.addEventListener("click", () =>
    applyTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light"));
  document.querySelectorAll(".seg button[data-lang]").forEach(b =>
    b.addEventListener("click", () => setLang(b.dataset.lang)));
  applyI18n();
})();

const ICON = {
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.2 4.2L19 7"/></svg>',
  x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>',
  alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>',
  stop: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9.5"/><path d="M12 7.5v5.5M12 16.5h.01"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5l8 3.2v6c0 5-3.4 8.7-8 10.3-4.6-1.6-8-5.3-8-10.3v-6z"/><path d="M8.5 12.2l2.4 2.4 4.6-4.8"/></svg>',
  shieldx: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5l8 3.2v6c0 5-3.4 8.7-8 10.3-4.6-1.6-8-5.3-8-10.3v-6z"/><path d="M9.5 9.5l5 5M14.5 9.5l-5 5"/></svg>',
  cert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M7 9h10M7 12.5h6"/><circle cx="16.5" cy="17.5" r="2.5"/><path d="M15.3 19.7l-.8 2.3 2-1 2 1-.8-2.3"/></svg>',
  chain: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13.5a4.5 4.5 0 0 0 6.4.4l2.8-2.8a4.5 4.5 0 0 0-6.4-6.4l-1.2 1.2"/><path d="M14 10.5a4.5 4.5 0 0 0-6.4-.4l-2.8 2.8a4.5 4.5 0 0 0 6.4 6.4l1.2-1.2"/></svg>',
  lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10.5" width="16" height="11" rx="2.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/><circle cx="12" cy="16" r="1.4"/></svg>',
  key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3L20 3M16.5 6.5l3 3M14 9l2 2"/></svg>',
  server: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3.5" width="18" height="7" rx="2"/><rect x="3" y="13.5" width="18" height="7" rx="2"/><path d="M7 7h.01M7 17h.01"/></svg>',
  ban: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9.5"/><path d="M5.3 5.3l13.4 13.4"/></svg>',
  bolt: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2.5L4.5 13.5H12l-1 8 8.5-11H12z"/></svg>',
  code: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 7L3.5 12l5 5M15.5 7l5 5-5 5"/></svg>',
  chev: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>',
  globe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9.5"/><path d="M2.5 12h19M12 2.5c2.6 2.8 3.8 6 3.8 9.5s-1.2 6.7-3.8 9.5c-2.6-2.8-3.8-6-3.8-9.5S9.4 5.3 12 2.5z"/></svg>'
};
