// TLS-Check – Login-Seite: Fehlermeldung aus ?e=… anzeigen, Button-Zustand
"use strict";
(function () {
  const msg = document.getElementById("msg");
  const codes = { bad: "login.err.bad", locked: "login.err.locked", origin: "login.err.origin",
                  out: "login.out", expired: "login.expired" };
  const e = new URLSearchParams(location.search).get("e");
  function show() {
    if (!e || !codes[e]) return;
    const info = e === "out";
    msg.className = "msg" + (info ? " info" : "");
    msg.innerHTML = (info ? ICON.check : ICON.alert) + "<span></span>";
    msg.querySelector("span").textContent = t(codes[e]);
  }
  show();
  if (e === "bad" || e === "locked") document.getElementById("card").classList.add("shake");
  document.addEventListener("langchange", show);
  document.getElementById("f").addEventListener("submit", () => {
    const b = document.getElementById("go");
    b.disabled = true;
    b.innerHTML = '<span class="spin"></span>';
  });
  // Meldung nicht beim Neuladen wiederholen
  if (e) history.replaceState(null, "", "/login");
})();
