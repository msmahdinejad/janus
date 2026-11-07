// Assets: the same findings, pivoted by *what is affected* — hosts on the
// outward face, files on the inward one — ranked by remaining risk.
(function () {
  const { esc, icon, n } = J;
  const A = { kind: "all", q: "", activeOnly: true, sort: "risk", expanded: new Set(), limit: 60 };
  let host = null;

  function build() {
    const m = new Map();
    J.store.findings.forEach((f) => {
      const a = J.assetOf(f);
      const id = a.kind + "|" + a.key;
      if (!m.has(id)) m.set(id, { id, kind: a.kind, key: a.key, list: [] });
      m.get(id).list.push(f);
    });
    return [...m.values()].map((g) => {
      const active = g.list.filter(J.isActive);
      return { ...g, active, risk: J.riskScore(g.list), sev: J.sevCounts(active), worst: active.length ? J.worstSeverity(active) : null,
        last: g.list.reduce((a, f) => (f.last_seen > a ? f.last_seen : a), "") };
    });
  }

  function row(g) {
    const open = A.expanded.has(g.id);
    const isFile = g.kind === "file";
    const { dir, base } = isFile ? J.splitPath(g.key) : { dir: "", base: g.key };
    const dirShort = dir.length > 46 ? "…" + dir.slice(-44) : dir;
    const shown = A.activeOnly ? g.active : g.list;
    return `<div class="asset ${open ? "open" : ""}" data-id="${esc(g.id)}">
      <button class="asset-row" data-act="toggle" aria-expanded="${open}">
        ${icon(open ? "chevD" : "chevR", "sm")}
        <span class="a-ico ${g.kind === "host" ? "recon" : "code"}">${icon(g.kind === "host" ? "globe" : "file", "sm")}</span>
        <span class="a-name-wrap"><span class="a-name mono"><span class="muted">${esc(dirShort)}</span><b>${esc(base)}</b></span></span>
        <span class="a-sev">${J.sevBar(g.sev, "thin")}</span>
        <span class="a-chips">${J.SEVERITIES.filter((s) => g.sev[s]).slice(0, 3).map((s) => `<span class="sev sev-${s}">${g.sev[s]}</span>`).join("")}</span>
        <span class="a-count tnum" data-tip="${g.active.length} active of ${g.list.length}"><b>${g.active.length}</b><span class="muted">/${g.list.length}</span></span>
      </button>
      ${open ? `<div class="asset-body">
        <div class="asset-tools"><a class="link-btn" href="${J.href("findings", { asset: g.key })}">Open in explorer →</a><span class="muted">last activity ${esc(J.rel(g.last))}</span></div>
        ${shown.length ? shown.slice().sort((a, b) => J.SEV_RANK[a.severity] - J.SEV_RANK[b.severity]).map((f) => `
          <button class="qrow compact" data-act="open" data-fp="${esc(f.fingerprint)}">
            ${J.sevBadge(f.severity)}
            <span class="qmain"><span class="qtitle truncate">${esc(f.title)}</span>
            <span class="qloc truncate mono">${isFile ? (f.line ? "line " + f.line : "") : esc(`${f.method ? f.method + " " : ""}${f.endpoint || "/"}`)} · ${esc(f.tool)}</span></span>
            ${J.statusPill(f.status)}
          </button>`).join("") : `<p class="muted" style="padding:6px 10px">No active findings on this asset.</p>`}
      </div>` : ""}
    </div>`;
  }

  function paint() {
    if (!host) return;
    let list = build();
    const counts = { all: list.length, host: list.filter((g) => g.kind === "host").length, file: list.filter((g) => g.kind === "file").length };
    if (A.kind !== "all") list = list.filter((g) => g.kind === A.kind);
    if (A.activeOnly) list = list.filter((g) => g.active.length);
    const q = A.q.trim().toLowerCase();
    if (q) list = list.filter((g) => g.key.toLowerCase().includes(q));
    list.sort(A.sort === "name" ? (a, b) => a.key.localeCompare(b.key)
      : A.sort === "count" ? (a, b) => b.active.length - a.active.length || b.risk - a.risk
      : (a, b) => b.risk - a.risk || b.active.length - a.active.length);
    J.$$(".seg button[data-kind]", host).forEach((b) => {
      b.setAttribute("aria-pressed", String(b.dataset.kind === A.kind));
      J.$(".n", b).textContent = n(counts[b.dataset.kind]);
    });
    const visible = list.slice(0, A.limit);
    J.$("#alist", host).innerHTML = visible.length
      ? visible.map(row).join("") + (list.length > visible.length ? `<div class="more"><button class="btn" data-act="more">Show ${Math.min(60, list.length - visible.length)} more</button></div>` : "")
      : J.emptyState({ icon: "assets", title: "No assets to show", body: A.activeOnly ? "No assets with active findings match. Turn off “Active only” to include fully-resolved assets." : "Nothing matches your search." });
    J.$("#ameta", host).innerHTML = `<b class="tnum">${n(list.length)}</b> assets · ranked by ${A.sort === "risk" ? "remaining risk" : A.sort === "count" ? "active findings" : "name"}`;
  }

  function render(el) {
    if (!J.gate(el, { skeleton: "list" })) { host = null; return; }
    host = el;
    el.innerHTML = `
      ${J.pageHead("Assets", "The same findings pivoted by what’s affected: <b>hosts</b> on the outward face, <b>files</b> on the inward one. Risk = severity-weighted, active findings only.")}
      <div class="toolbar">
        <div class="seg" role="group" aria-label="Asset kind">
          <button data-kind="all" aria-pressed="true">All <span class="n muted"></span></button>
          <button data-kind="host" aria-pressed="false">${icon("globe", "sm")}Hosts <span class="n muted"></span></button>
          <button data-kind="file" aria-pressed="false">${icon("file", "sm")}Files <span class="n muted"></span></button>
        </div>
        <div class="search"><span>${icon("search", "sm")}</span><input id="aq" class="input" type="search" placeholder="Filter assets…" aria-label="Filter assets" value="${esc(A.q)}"/></div>
        <label class="flex items-center gap-2 dim" style="cursor:pointer"><input type="checkbox" class="check" id="aact" ${A.activeOnly ? "checked" : ""}/> Active only</label>
        <div class="tool-right"><select id="asort" class="select" aria-label="Sort assets">
          <option value="risk">Sort: Risk</option><option value="count">Sort: Active findings</option><option value="name">Sort: Name</option></select></div>
      </div>
      <div class="results-meta"><span id="ameta"></span></div>
      <div class="card assets-card" id="alist"></div>`;
    J.$("#asort", el).value = A.sort;
    J.$(".seg", el).addEventListener("click", (e) => { const b = e.target.closest("[data-kind]"); if (b) { A.kind = b.dataset.kind; A.limit = 60; paint(); } });
    J.$("#aq", el).addEventListener("input", J.debounce((e) => { A.q = e.target.value; A.limit = 60; paint(); }, 100));
    J.$("#aact", el).addEventListener("change", (e) => { A.activeOnly = e.target.checked; paint(); });
    J.$("#asort", el).addEventListener("change", (e) => { A.sort = e.target.value; paint(); });
    J.$("#alist", el).addEventListener("click", (e) => {
      const a = e.target.closest("[data-act]"); if (!a) return;
      if (a.dataset.act === "toggle") { const id = a.closest(".asset").dataset.id; A.expanded.has(id) ? A.expanded.delete(id) : A.expanded.add(id); paint(); }
      else if (a.dataset.act === "more") { A.limit += 60; paint(); }
    });
    paint();
  }

  J.on("data", () => { if (host && document.body.contains(host) && location.hash.indexOf("#/assets") === 0) paint(); });
  J.views.assets = { title: "Assets", render };
})();
