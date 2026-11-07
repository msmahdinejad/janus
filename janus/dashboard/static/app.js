// Janus dashboard — shell: routing, nav, theme, command palette, keyboard.
// Classic scripts, no build step. Load order: util, icons, ui, charts, store,
// drawer, views/*, then this file.
(function () {
  const { esc, icon, $, $$ } = J;
  const VIEWS = ["overview", "findings", "assets", "coverage", "timeline", "scans"];
  const NAV = [
    { id: "overview", label: "Overview", icon: "overview", key: "o" },
    { id: "findings", label: "Findings", icon: "findings", key: "f", href: J.href("findings", { st: J.ACTIVE }) },
    { id: "assets", label: "Assets", icon: "assets", key: "a" },
    { id: "coverage", label: "Coverage", icon: "coverage", key: "c" },
    { id: "timeline", label: "Timeline", icon: "timeline", key: "t" },
    { id: "scans", label: "Scans", icon: "clock", key: "s" },
  ];
  let current = { view: "overview", params: new URLSearchParams() };

  // ---- shell -------------------------------------------------------------
  function buildShell() {
    $("#brand").innerHTML = `${J.logo(28)}<div><div class="brand-name">Janus</div><div class="brand-sub">Findings console</div></div>`;
    $("#nav").innerHTML = `<div class="nav-label">Workspace</div>` + NAV.map((n) =>
      `<a href="${n.href || "#/" + n.id}" data-view="${n.id}" data-tip="Go to ${n.label}  (g ${n.key})"><span class="ico">${icon(n.icon)}</span><span class="t">${n.label}</span><span class="count" id="nc-${n.id}"></span></a>`).join("");
    $("#themeBtn").innerHTML = icon("monitor");
    $("#densityBtn").innerHTML = icon("rows");
    $("#helpBtn").innerHTML = icon("keyboard");
    $("#refreshBtn").innerHTML = `${icon("refresh", "sm")}<span class="lbl">Refresh</span>`;
    $("#menuBtn").innerHTML = icon("menu");
    $("#cmdkBtn").innerHTML = `${icon("search", "sm")}<span class="lbl">Search or jump to…</span><kbd>${/Mac|iPhone|iPad/.test(navigator.platform) ? "⌘" : "Ctrl"} K</kbd>`;
  }

  // ---- theme / density ---------------------------------------------------
  const THEMES = ["auto", "light", "dark"];
  function applyTheme(mode) {
    const root = document.documentElement;
    if (mode === "light" || mode === "dark") root.setAttribute("data-theme", mode); else root.removeAttribute("data-theme");
    const b = $("#themeBtn");
    b.innerHTML = icon(mode === "light" ? "sun" : mode === "dark" ? "moon" : "monitor");
    b.setAttribute("data-tip", `Theme: ${mode === "auto" ? "match system" : mode}  (t)`);
    b.setAttribute("aria-label", `Theme: ${mode}. Click to change.`);
  }
  J.cycleTheme = () => {
    const cur = THEMES.includes(J.pref.get("theme", "auto")) ? J.pref.get("theme", "auto") : "auto";
    const next = THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length];
    J.pref.set("theme", next); applyTheme(next);
    J.toast(`Theme: ${next === "auto" ? "match system" : next}`);
  };
  function applyDensity(d) {
    document.documentElement.setAttribute("data-density", d);
    const b = $("#densityBtn");
    b.setAttribute("data-tip", `Row density: ${d}`); b.setAttribute("aria-label", `Row density: ${d}. Click to change.`);
  }
  J.toggleDensity = () => {
    const next = J.pref.get("density", "comfortable") === "compact" ? "comfortable" : "compact";
    J.pref.set("density", next); applyDensity(next); J.toast(`Density: ${next}`);
  };

  // ---- routing -----------------------------------------------------------
  function parseHash() {
    const raw = location.hash.replace(/^#\/?/, "");
    const [path, qs] = raw.split("?");
    return { view: VIEWS.includes(path) ? path : "overview", params: new URLSearchParams(qs || "") };
  }
  function renderView({ keepScroll = false } = {}) {
    const y = window.scrollY;
    current = parseHash();
    const v = J.views[current.view];
    $$(".nav a").forEach((a) => (a.getAttribute("data-view") === current.view ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
    $("#crumb").innerHTML = `<span>${esc(v.title)}</span>`;
    document.title = `${v.title} · Janus`;
    try {
      v.render($("#page"), current.params);
    } catch (err) {
      // One broken view must never take the whole shell (and boot) down with it.
      console.error(err);
      $("#page").innerHTML = `<div class="banner error" role="alert">${icon("alert")}<div><b>This view failed to render.</b> ${esc(String(err && err.message || err))}</div></div>`;
    }
    if (keepScroll) window.scrollTo(0, y);
  }
  function onRoute() {
    J.closePopover();
    J.drawer.close();
    $("#sidebar").classList.remove("open"); $("#navScrim").classList.add("hidden");
    renderView();
    window.scrollTo(0, 0);
  }

  // ---- header status -----------------------------------------------------
  function updateChrome() {
    const s = J.store;
    const act = s.findings.filter(J.isActive).length;
    const ch = s.findings.filter((f) => J.isActive(f) && (f.severity === "critical" || f.severity === "high")).length;
    const nf = $("#nc-findings");
    if (nf) { nf.textContent = s.loaded ? J.n(act) : ""; nf.className = "count" + (ch ? " alert" : ""); nf.setAttribute("data-tip", ch ? `${act} active · ${ch} critical/high` : `${act} active`); }
    const na = $("#nc-assets");
    if (na) na.textContent = "";
    $("#regPath").innerHTML = s.meta ? `<b>Register</b>${esc(s.meta.register_path)}` : "";
    updateUpdated();
  }
  function updateUpdated() {
    const s = J.store;
    const el = $("#updated");
    if (J.saving()) el.textContent = "Saving…";
    else if (s.error && s.loaded) el.textContent = "Connection lost";
    else el.textContent = s.loadedAt ? `Updated ${J.rel(new Date(s.loadedAt).toISOString())}` : "Loading…";
    $("#refreshBtn").classList.toggle("spin", s.loading);
  }

  // ---- command palette ---------------------------------------------------
  function paletteItems(q) {
    const go = (hash) => () => { location.hash = hash; };
    const cmds = [
      ...NAV.map((n) => ({ g: "Go to", label: n.label, icon: n.icon, hint: `g ${n.key}`, run: go(n.href || "#/" + n.id) })),
      { g: "Findings", label: "Active findings", icon: "findings", run: go(J.href("findings", { st: J.ACTIVE })) },
      { g: "Findings", label: "Critical & high — active", icon: "alert", run: go(J.href("findings", { st: J.ACTIVE, sev: ["critical", "high"] })) },
      { g: "Findings", label: "Needs review", icon: "eye", run: go(J.href("findings", { st: "needs-review" })) },
      { g: "Findings", label: "Resolved", icon: "checkCircle", run: go(J.href("findings", { st: ["fixed", "ruled-out", "accepted-risk"] })) },
      { g: "Findings", label: "Only code findings", icon: "code", run: go(J.href("findings", { eng: "code", st: J.ACTIVE })) },
      { g: "Findings", label: "Only recon findings", icon: "radar", run: go(J.href("findings", { eng: "recon", st: J.ACTIVE })) },
      { g: "Scans", label: "Runs that need attention (partial / failed / unverified)", icon: "alert", run: go("#/scans?health=attention") },
      { g: "Scans", label: "Group runs by engagement", icon: "layers", run: go("#/scans") },
      { g: "Actions", label: "Refresh data", icon: "refresh", hint: "r", run: () => J.load() },
      { g: "Actions", label: "Cycle theme (auto / light / dark)", icon: "sun", hint: "t", run: J.cycleTheme },
      { g: "Actions", label: "Toggle compact rows", icon: "rows", run: J.toggleDensity },
      { g: "Actions", label: "Keyboard shortcuts", icon: "keyboard", hint: "?", run: () => setTimeout(openHelp, 0) },
    ];
    const ql = q.trim().toLowerCase();
    let out = ql ? cmds.filter((c) => (c.g + " " + c.label).toLowerCase().includes(ql)) : cmds;
    if (ql.length >= 2) {
      const f = J.sortRows(J.applyFilters(J.store.findings, { ...J.emptyFilters(), q }), J.emptyFilters()).slice(0, 8);
      out = out.concat(f.map((x) => ({ g: "Findings", label: x.title, icon: "findings", sub: J.locationOf(x), sev: x.severity, run: () => { if (current.view === "findings") { J.drawer.open(x.fingerprint, J.explorer.flat.includes(x.fingerprint) ? J.explorer.flat : [x.fingerprint]); } else J.drawer.open(x.fingerprint, [x.fingerprint]); } })));
    }
    return out;
  }
  function openPalette() {
    const el = J.openModal(`
      <div class="palette-input">${icon("search")}<input id="pq" type="text" placeholder="Jump to a view, run a command, or find a finding…" autocomplete="off" spellcheck="false" role="combobox" aria-controls="plist" aria-expanded="true"/><kbd>Esc</kbd></div>
      <div class="palette-list" id="plist" role="listbox"></div>
      <div class="palette-foot"><span><kbd>↑</kbd> <kbd>↓</kbd> navigate</span><span><kbd>↵</kbd> select</span><span class="ml-auto">${icon("command", "sm")} Janus</span></div>`, { label: "Command palette" });
    const input = $("#pq", el), list = $("#plist", el);
    let items = [], idx = 0;
    const draw = () => {
      items = paletteItems(input.value);
      idx = Math.min(idx, Math.max(items.length - 1, 0));
      let last = "";
      list.innerHTML = items.length ? items.map((it, i) => {
        const head = it.g !== last ? `<div class="menu-head">${esc(it.g)}</div>` : ""; last = it.g;
        return head + `<button class="menu-item ${i === idx ? "hl" : ""}" role="option" data-i="${i}" aria-selected="${i === idx}">
          ${it.sev ? `<span class="legend-dot s-${it.sev}"></span>` : icon(it.icon, "sm")}<span class="truncate">${esc(it.label)}</span>
          ${it.hint ? `<kbd class="kbd-hint">${esc(it.hint)}</kbd>` : it.sub ? `<span class="sub truncate mono">${esc(it.sub)}</span>` : ""}</button>`;
      }).join("") : `<div class="palette-empty">No results for “${esc(input.value)}”</div>`;
      const hl = $(".hl", list); if (hl) hl.scrollIntoView({ block: "nearest" });
    };
    const run = (i) => { const it = items[i]; if (!it) return; J.closeModal(); it.run(); };
    input.addEventListener("input", () => { idx = 0; draw(); });
    input.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") { e.preventDefault(); idx = (idx + 1) % Math.max(items.length, 1); draw(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); idx = (idx - 1 + items.length) % Math.max(items.length, 1); draw(); }
      else if (e.key === "Enter") { e.preventDefault(); run(idx); }
    });
    list.addEventListener("click", (e) => { const b = e.target.closest("[data-i]"); if (b) run(+b.dataset.i); });
    list.addEventListener("mousemove", (e) => { const b = e.target.closest("[data-i]"); if (b && +b.dataset.i !== idx) { idx = +b.dataset.i; $$(".menu-item", list).forEach((m) => m.classList.toggle("hl", m === b)); } });
    draw(); input.focus();
  }

  function openHelp() {
    const rows = (arr) => arr.map(([k, d]) => `<div class="r"><span>${d}</span><span>${k.split(" ").map((x) => `<kbd>${x}</kbd>`).join(" ")}</span></div>`).join("");
    J.openModal(`
      <div class="palette-input" style="height:50px">${icon("keyboard")}<b style="color:var(--text)">Keyboard shortcuts</b></div>
      <div class="help-grid">
        <h4>Triage — applies to selection, else the open/highlighted finding</h4>
        ${rows([["1", "Open"], ["2", "Needs review"], ["3", "Fixed"], ["4", "Ruled out"], ["5", "Accepted risk"]])}
        <h4>Move around</h4>
        ${rows([["j", "Next finding"], ["k", "Previous finding"], ["↵", "Open details"], ["x", "Select / deselect"], ["Esc", "Close · clear selection"], ["/", "Search findings"]])}
        <h4>Navigate</h4>
        ${rows([["g o", "Overview"], ["g f", "Findings"], ["g a", "Assets"], ["g c", "Coverage"], ["g t", "Timeline"], ["g s", "Scans"]])}
        <h4>Scans</h4>
        ${rows([["j k", "Next / previous run or finding"], ["↵ Space", "Open run · expand finding"], ["Esc", "Collapse the open finding"], ["/", "Filter runs / findings"]])}
        <h4>Global</h4>
        ${rows([["Ctrl K", "Command palette"], ["r", "Refresh data"], ["t", "Cycle theme"], ["?", "This help"], ["Ctrl ↵", "Save note (in note field)"]])}
      </div>`, { label: "Keyboard shortcuts" });
  }

  // ---- keyboard ----------------------------------------------------------
  let chord = null;
  function typing(e) {
    const t = e.target;
    return t && (t.tagName === "INPUT" && t.type !== "checkbox" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable);
  }
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); J.modalOpen() ? J.closeModal() : openPalette(); return; }
    if (J.modalOpen()) return;
    const vk = J.views[current.view];
    if (vk && vk.onKey && !typing(e) && vk.onKey(e)) return;
    if (e.key === "Escape") {
      if (typing(e)) return;
      if (J.drawer.fp) { J.drawer.close(); return; }
      if (J.explorer.selected.size) { J.explorer.clearSelection(); return; }
      return;
    }
    if (typing(e) || e.ctrlKey || e.metaKey || e.altKey) return;
    const k = e.key;
    if (chord) {
      const c = chord; chord = null; clearTimeout(c.t);
      const n = NAV.find((x) => x.key === k.toLowerCase());
      if (n) { e.preventDefault(); location.hash = n.href || "#/" + n.id; }
      return;
    }
    if (k === "g") { chord = { t: setTimeout(() => (chord = null), 1000) }; return; }
    if (k === "?") { e.preventDefault(); openHelp(); return; }
    if (k === "/") { e.preventDefault(); if (current.view !== "findings") { location.hash = J.href("findings", { st: J.ACTIVE }); setTimeout(() => $("#fsearch") && $("#fsearch").focus(), 30); } else { const s = $("#fsearch"); if (s) { s.focus(); s.select(); } } return; }
    if (k === "r") { J.load(); return; }
    if (k === "t") { J.cycleTheme(); return; }
    const inExplorer = current.view === "findings" && J.explorer.el;
    const st = J.STATUSES.find((s) => s.key === k);
    if (st) {
      const targets = inExplorer ? J.explorer.targets() : J.drawer.fp ? [J.drawer.fp] : [];
      if (!targets.length) return;
      e.preventDefault();
      if (J.drawer.fp && targets.length === 1 && targets[0] === J.drawer.fp) J.drawer.setStatus(st.id);
      else J.explorer.applyStatus(st.id, targets);
      return;
    }
    if (k === "j" || k === "ArrowDown" || k === "k" || k === "ArrowUp") {
      const dir = k === "j" || k === "ArrowDown" ? 1 : -1;
      if (inExplorer) { e.preventDefault(); J.explorer.moveCursor(dir); }
      else if (J.drawer.fp) { e.preventDefault(); J.drawer.step(dir); }
      return;
    }
    if (inExplorer) {
      if (k === "Enter" || k === "o") { if (J.explorer.cursor && !e.target.closest("button, a, input")) { e.preventDefault(); J.explorer.openCursor(); } return; }
      if (k === "x") { e.preventDefault(); J.explorer.toggleSelectCursor(); }
    }
  });

  // ---- global clicks (data-act hooks used by several views) ---------------
  document.addEventListener("click", (e) => {
    const a = e.target.closest("[data-act]");
    if (!a) return;
    if (a.dataset.act === "open" && a.dataset.fp) {
      const group = $$('[data-act="open"][data-fp]', a.parentElement).map((x) => x.dataset.fp);
      J.drawer.open(a.dataset.fp, group.length ? group : [a.dataset.fp]);
    } else if (a.dataset.act === "reload") J.load();
  });

  // ---- boot --------------------------------------------------------------
  document.addEventListener("DOMContentLoaded", () => {
    buildShell();
    const t = J.pref.get("theme", "auto"); applyTheme(THEMES.includes(t) ? t : "auto");
    applyDensity(J.pref.get("density", "comfortable"));
    $("#themeBtn").addEventListener("click", J.cycleTheme);
    $("#densityBtn").addEventListener("click", J.toggleDensity);
    $("#helpBtn").addEventListener("click", openHelp);
    $("#cmdkBtn").addEventListener("click", openPalette);
    $("#refreshBtn").addEventListener("click", () => J.load());
    $("#menuBtn").addEventListener("click", () => { $("#sidebar").classList.add("open"); $("#navScrim").classList.remove("hidden"); });
    $("#navScrim").addEventListener("click", () => { $("#sidebar").classList.remove("open"); $("#navScrim").classList.add("hidden"); });

    window.addEventListener("hashchange", onRoute);
    J.on("loading", updateChrome);
    J.on("saving", updateUpdated);
    J.on("tick", updateUpdated);
    J.on("data", (ev) => {
      updateChrome();
      if (current.view === "scans") { if (J.views.scans.revalidate) J.views.scans.revalidate(); return; }   // run records are immutable; never re-render under the reader
      if (ev && ev.patch) {
        // triage writes: views that don't repaint themselves catch up here
        if (current.view === "overview" || current.view === "coverage") renderView({ keepScroll: true });
        return;
      }
      renderView({ keepScroll: true });
    });
    setInterval(updateUpdated, 20000);
    setInterval(() => { if (!document.hidden) J.load({ silent: true }); }, 45000);
    document.addEventListener("visibilitychange", () => { if (!document.hidden && J.store.loaded) J.load({ silent: true }); });
    window.addEventListener("beforeunload", (e) => { if (J.saving()) { e.preventDefault(); e.returnValue = ""; } });

    current = parseHash();
    renderView();            // skeleton while loading
    J.load();
  });
})();
