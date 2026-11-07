// Overview: posture at a glance, with every number a link into the explorer.
(function () {
  const { esc, icon, n } = J;

  function kpi({ label, value, foot, href, accent, cls = "", iconName }) {
    return `<a class="card kpi ${cls}" href="${href}" style="--kpi-accent:${accent || "transparent"}">
      <div class="k-label">${iconName ? icon(iconName, "sm") : ""}${esc(label)}</div>
      <div class="k-value">${value}</div>
      <div class="k-foot">${foot || ""}</div>
    </a>`;
  }

  function facePanel(eng, list) {
    const info = J.ENGINES[eng];
    const active = list.filter(J.isActive);
    const tools = J.countBy(list, (f) => f.tool);
    const assets = new Set(list.map((f) => J.assetOf(f).key));
    const sc = J.sevCounts(active);
    const toolChips = Object.entries(tools).sort((a, b) => b[1] - a[1]).slice(0, 4)
      .map(([t, c]) => `<span class="tag">${esc(t)} <b class="tnum">${c}</b></span>`).join("");
    return `<a class="face ${eng}" href="${J.href("findings", { eng, st: J.ACTIVE })}">
      <div class="face-top">
        <span class="face-ico">${icon(info.icon)}</span>
        <div><div class="face-name">${esc(info.face)} · ${esc(info.label)}</div><div class="face-sub">${esc(info.blurb)}</div></div>
      </div>
      <div class="face-num"><span class="tnum">${n(active.length)}</span><span class="face-of">active of ${n(list.length)}</span></div>
      ${J.sevBar(sc, "tall")}
      <div class="face-meta"><span>${J.plural(assets.size, eng === "recon" ? "host" : "file")}</span>${toolChips || `<span class="muted">no tools reported</span>`}</div>
    </a>`;
  }

  function attentionRow(f) {
    return `<button class="qrow" data-act="open" data-fp="${esc(f.fingerprint)}">
      ${J.sevBadge(f.severity)}
      <span class="qmain"><span class="qtitle truncate">${esc(f.title)}</span><span class="qloc truncate">${J.locationHtml(f)}</span></span>
      ${J.engineTag(f)}
      ${J.statusPill(f.status)}
    </button>`;
  }

  function render(el) {
    if (!J.gate(el)) return;
    const all = J.store.findings;
    const active = all.filter(J.isActive);
    const resolved = all.filter((f) => !J.isActive(f));
    const sc = J.sevCounts(active);
    const critHigh = sc.critical + sc.high;
    const untriaged = all.filter((f) => f.status === "open").length;
    const needsReview = all.filter((f) => f.status === "needs-review").length;
    const pct = all.length ? Math.round((resolved.length / all.length) * 100) : 0;
    const stc = J.countBy(all, (f) => f.status);
    const lastTs = Math.max(0, ...all.map((f) => J.ts(f.last_seen) || 0));

    // Priority queue: worst severity, confirmed before guessed, newest first.
    const queue = active.slice().sort((a, b) =>
      (J.SEV_RANK[a.severity] - J.SEV_RANK[b.severity]) || (J.CONF_RANK[a.confidence] - J.CONF_RANK[b.confidence]) || (b.last_seen || "").localeCompare(a.last_seen || "")).slice(0, 7);

    // Assets by risk
    const groups = new Map();
    active.forEach((f) => { const a = J.assetOf(f); const k = a.key; if (!groups.has(k)) groups.set(k, { ...a, list: [] }); groups.get(k).list.push(f); });
    const topAssets = [...groups.values()].map((g) => ({ ...g, risk: J.riskScore(g.list) })).sort((a, b) => b.risk - a.risk).slice(0, 6);
    const maxRisk = Math.max(1, ...topAssets.map((a) => a.risk));

    // Categories stacked by severity
    const catMap = {};
    active.forEach((f) => { (catMap[f.category] = catMap[f.category] || []).push(f); });
    const cats = Object.entries(catMap).sort((a, b) => b[1].length - a[1].length).slice(0, 7);
    const maxCat = Math.max(1, ...cats.map((c) => c[1].length));

    const donutSegs = J.SEVERITIES.map((s) => ({ key: s, label: J.cap(s), value: sc[s], color: J.sevColor(s) }));

    el.innerHTML = `
      ${J.pageHead("Overview",
        `${J.plural(all.length, "finding")} across ${Object.keys(J.countBy(all, (f) => f.engine)).length > 1 ? "both engines" : "one engine"}${lastTs ? ` · last activity ${esc(J.rel(new Date(lastTs).toISOString()))}` : ""}.`,
        `<a class="btn" href="${J.href("findings", { st: J.ACTIVE })}">${icon("findings", "sm")}Open findings explorer</a>`)}

      <div class="stack">
        <div class="grid kpis">
          ${kpi({ label: "Active findings", value: n(active.length), foot: `${n(all.length)} total tracked`, href: J.href("findings", { st: J.ACTIVE }), iconName: "findings", accent: "var(--text-3)" })}
          ${kpi({ label: "Critical & high", value: n(critHigh), foot: `${sc.critical} critical · ${sc.high} high`, href: J.href("findings", { st: J.ACTIVE, sev: ["critical", "high"] }), iconName: "alert", cls: critHigh ? "sev-critical" : "", accent: critHigh ? "var(--sev-critical)" : "var(--st-fixed)" })}
          ${kpi({ label: "Untriaged", value: n(untriaged), foot: `${n(needsReview)} flagged needs-review`, href: J.href("findings", { st: "open" }), iconName: "inbox", accent: "var(--sev-medium)" })}
          <div class="card kpi" style="--kpi-accent:var(--st-fixed)">
            <div class="k-label">${icon("checkCircle", "sm")}Resolved</div>
            <div class="k-value">${pct}<span style="font-size:18px;color:var(--text-3)">%</span></div>
            <div class="sbar thin" style="margin:4px 0 2px"><i style="flex:${stc.fixed || 0};background:var(--st-fixed)"></i><i style="flex:${stc["ruled-out"] || 0};background:var(--st-ruled-out)"></i><i style="flex:${stc["accepted-risk"] || 0};background:var(--st-accepted-risk)"></i><i style="flex:${active.length};background:transparent"></i></div>
            <div class="k-foot">${stc.fixed || 0} fixed · ${stc["ruled-out"] || 0} ruled out · ${stc["accepted-risk"] || 0} accepted</div>
          </div>
        </div>

        <div class="grid split-2-1">
          <div class="card">
            <div class="card-head"><h2>Two faces, one register</h2><span class="hint">active findings by engine</span></div>
            <div class="card-body faces">
              ${facePanel("code", all.filter((f) => f.engine === "code"))}
              <div class="face-sep" aria-hidden="true"><span>${J.logo(22)}</span></div>
              ${facePanel("recon", all.filter((f) => f.engine === "recon"))}
            </div>
          </div>
          <div class="card">
            <div class="card-head"><h2>Active by severity</h2><span class="hint">click to filter</span></div>
            <div class="card-body donut-wrap">
              ${J.donut(donutSegs, { size: 150, thick: 22, center: { value: n(active.length), label: "active" } })}
              <div class="sev-legend">
                ${J.SEVERITIES.map((s) => `<a href="${J.href("findings", { st: J.ACTIVE, sev: s })}" class="sev-leg-row"><span class="legend-dot s-${s}"></span><span>${J.cap(s)}</span><b class="tnum">${sc[s]}</b></a>`).join("")}
              </div>
            </div>
          </div>
        </div>

        <div class="grid split-2-1">
          <div class="card flush">
            <div class="card-head"><h2>Needs attention first</h2><a class="link-btn" href="${J.href("findings", { st: J.ACTIVE })}">View all ${n(active.length)} →</a></div>
            <div class="card-body">
              ${queue.length ? `<div class="qlist">${queue.map(attentionRow).join("")}</div>` : J.emptyState({ icon: "checkCircle", title: "Nothing needs attention", body: "Every finding has been triaged. Nice." })}
            </div>
          </div>
          <div class="card">
            <div class="card-head"><h2>Riskiest assets</h2><a class="link-btn" href="#/assets">All assets →</a></div>
            <div class="card-body">
              ${topAssets.length ? `<div class="hbar-list">${topAssets.map((a) => `
                <a class="asset-mini" href="${J.href("findings", { asset: a.key, st: J.ACTIVE })}">
                  <span class="a-ico ${a.kind === "host" ? "recon" : "code"}">${icon(a.kind === "host" ? "globe" : "file", "sm")}</span>
                  <span class="a-main"><span class="truncate mono a-name" title="${esc(a.key)}">${esc(a.kind === "file" ? J.shortPath(a.key) : a.key)}</span>
                  <span class="sbar thin" style="width:${Math.max(18, (a.risk / maxRisk) * 100)}%">${J.SEVERITIES.map((s) => { const c = a.list.filter((f) => f.severity === s).length; return c ? `<i class="s-${s}" style="flex:${c}"></i>` : ""; }).join("")}</span></span>
                  <b class="tnum">${a.list.length}</b>
                </a>`).join("")}</div>` : `<p class="muted">No active findings.</p>`}
            </div>
          </div>
        </div>

        <div class="grid two">
          <div class="card">
            <div class="card-head"><h2>Top categories</h2><span class="hint">active, by severity</span></div>
            <div class="card-body">
              ${cats.length ? `<div class="hbar-list">${cats.map(([c, list]) => `
                <a class="hbar" href="${J.href("findings", { cat: c, st: J.ACTIVE })}">
                  <span class="name">${esc(J.catLabel(c))}</span>
                  <span style="width:${(list.length / maxCat) * 100}%">${J.sevBar(J.sevCounts(list))}</span>
                  <span class="n">${list.length}</span>
                </a>`).join("")}</div>` : `<p class="muted">No active findings.</p>`}
            </div>
          </div>
          <div class="card">
            <div class="card-head"><h2>Triage pipeline</h2><span class="hint">where findings stand</span></div>
            <div class="card-body">
              <div class="hbar-list">
                ${J.STATUSES.map((s) => `
                  <a class="hbar" href="${J.href("findings", { st: s.id })}">
                    <span class="name" style="display:flex;align-items:center;gap:7px">${J.statusPill(s.id)}</span>
                    <span style="width:${all.length ? Math.max(((stc[s.id] || 0) / all.length) * 100, stc[s.id] ? 2 : 0) : 0}%"><div class="sbar"><i style="flex:1;background:var(--st-${s.id})"></i></div></span>
                    <span class="n">${stc[s.id] || 0}</span>
                  </a>`).join("")}
              </div>
            </div>
          </div>
        </div>
      </div>`;
  }

  J.views.overview = { title: "Overview", render };
})();
