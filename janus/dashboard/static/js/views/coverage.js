// Coverage: what the register can prove about *how much was looked at*.
// Honest by construction — the API exposes findings, not run logs, so this view
// can say which tools produced findings, never which tools merely ran clean.
(function () {
  const { esc, icon, n } = J;

  const CATALOG = [
    { id: "builtin", engine: "code", name: "Built-in rules", desc: "Janus’s own Python / Docker / YAML / secret rules" },
    { id: "semgrep", engine: "code", name: "Semgrep", desc: "Multi-language SAST" },
    { id: "gitleaks", engine: "code", name: "Gitleaks", desc: "Secret scanning in source & history" },
    { id: "trivy", engine: "code", name: "Trivy", desc: "Dependencies, containers & IaC misconfig" },
    { id: "passive-recon", engine: "recon", name: "Passive recon", desc: "DNS, TLS, headers, exposure — no probing" },
    { id: "subfinder", engine: "recon", name: "Subfinder", desc: "Subdomain enumeration" },
    { id: "nuclei", engine: "recon", name: "Nuclei", desc: "Template-based probing (scope-gated)" },
    { id: "agent:strix", engine: "recon", name: "Strix agent", desc: "AI-assisted testing (scope-gated)" },
  ];
  const OWASP = {
    A01: "Broken access control", A02: "Cryptographic failures", A03: "Injection", A04: "Insecure design", A05: "Security misconfiguration",
    A06: "Vulnerable & outdated components", A07: "Identification & auth failures", A08: "Software & data integrity failures",
    A09: "Logging & monitoring failures", A10: "Server-side request forgery",
  };
  const CATS = ["injection", "xss", "deserialization", "auth", "access-control", "secrets", "crypto", "configuration", "container", "ci-cd", "supply-chain", "exposure", "network", "client", "other"];

  function toolRows(all) {
    const rows = CATALOG.map((c) => ({ ...c, known: true, list: all.filter((f) => f.tool === c.id || (f.sources || []).includes(c.id)) }));
    const known = new Set(CATALOG.map((c) => c.id));
    const extra = {};
    all.forEach((f) => { if (!known.has(f.tool)) (extra[f.tool] = extra[f.tool] || []).push(f); });
    Object.entries(extra).forEach(([id, list]) => rows.push({ id, engine: list[0].engine, name: id, desc: "Not in Janus’s built-in catalog", known: false, list }));
    return rows;
  }

  function enginePanel(eng, all) {
    const info = J.ENGINES[eng];
    const list = all.filter((f) => f.engine === eng);
    const assets = new Set(list.map((f) => J.assetOf(f).key));
    const tools = toolRows(all).filter((t) => t.engine === eng);
    const reported = tools.filter((t) => t.list.length).length;
    const cats = new Set(list.map((f) => f.category));
    const conf = J.countBy(list, (f) => f.confidence || "needs-review");
    return `<div class="card cov-engine ${eng}">
      <div class="card-body">
        <div class="face-top"><span class="face-ico">${icon(info.icon)}</span><div><div class="face-name">${esc(info.face)} · ${esc(info.label)} engine</div><div class="face-sub">${esc(info.blurb)}</div></div></div>
        <div class="cov-stats">
          <div><b class="tnum">${n(list.length)}</b><span>findings</span></div>
          <div><b class="tnum">${n(assets.size)}</b><span>${eng === "recon" ? "hosts" : "files"} touched</span></div>
          <div><b class="tnum">${reported}/${tools.length}</b><span>tools reporting</span></div>
          <div><b class="tnum">${cats.size}</b><span>categories hit</span></div>
        </div>
        ${list.length ? `<div class="mt-3"><div class="conf-bar">${confBar(conf)}</div></div>` : `<p class="muted mt-3">This engine has produced no findings in the register.</p>`}
      </div></div>`;
  }
  const CONF_COLOR = { confirmed: "var(--st-fixed)", likely: "var(--sev-low)", "needs-review": "var(--border-strong)" };
  function confBar(c) {
    const tot = (c.confirmed || 0) + (c.likely || 0) + (c["needs-review"] || 0);
    return `<div class="sbar tall">${J.CONFIDENCES.filter((k) => c[k]).map((k) => `<i style="flex:${c[k]};background:${CONF_COLOR[k]}" data-tip="${c[k]} ${k}"></i>`).join("")}</div>
      <div class="legend mt-2">${J.CONFIDENCES.map((k) => `<span class="legend-item"><span class="legend-dot" style="background:${CONF_COLOR[k]}"></span>${k} <b class="tnum">${c[k] || 0}</b></span>`).join("")}<span class="muted">· ${tot ? Math.round(((c.confirmed || 0) / tot) * 100) : 0}% confirmed</span></div>`;
  }

  function render(el) {
    if (!J.gate(el)) return;
    const all = J.store.findings;
    const tools = toolRows(all);

    // OWASP
    const ow = {};
    all.forEach((f) => (f.owasp || []).forEach((o) => { const k = String(o).slice(0, 3).toUpperCase(); (ow[k] = ow[k] || []).push(f); }));
    const owMax = Math.max(1, ...Object.values(ow).map((l) => l.length));

    // CWE
    const cw = J.countBy(all.flatMap((f) => (f.cwe || []).map((c) => ({ c }))), (x) => x.c);
    const cwList = Object.entries(cw).sort((a, b) => b[1] - a[1]).slice(0, 8);

    // heatmap
    const heat = {};
    all.forEach((f) => { const k = `${f.category}|${f.engine}`; heat[k] = (heat[k] || 0) + 1; });
    const heatMax = Math.max(1, ...Object.values(heat));
    const cell = (cat, eng) => {
      const v = heat[`${cat}|${eng}`] || 0;
      const pct = v ? 14 + (v / heatMax) * 38 : 0;   // capped so text stays readable in both themes
      return v
        ? `<a class="hcell ${eng}" style="--p:${pct}%" href="${J.href("findings", { cat, eng })}" data-tip="${v} ${J.catLabel(cat)} finding${v > 1 ? "s" : ""} from the ${eng} engine">${n(v)}</a>`
        : `<span class="hcell none" data-tip="No ${J.catLabel(cat)} findings from the ${eng} engine">–</span>`;
    };

    const conf = J.countBy(all, (f) => f.confidence || "needs-review");

    el.innerHTML = `
      ${J.pageHead("Coverage", "Which tools and standards the register has evidence from — and where it has none.")}
      <div class="stack">
        <div class="banner">${icon("info")}<div><b>What this view can and can’t tell you.</b> The dashboard sees findings, not scan logs, so a tool with no findings might have run clean, been skipped, or never been configured. Per-tool run status (ran / skipped / failed, duration, targets) needs a small backend addition — see <code>DESIGN_NOTES.md</code>. Absence of a finding is never proof of absence.</div></div>

        <div class="grid two">${enginePanel("code", all)}${enginePanel("recon", all)}</div>

        <div class="card flush">
          <div class="card-head"><h2>Tools</h2><span class="hint">${tools.filter((t) => t.list.length).length} of ${tools.length} reported findings</span></div>
          <div class="card-body">
            <div class="ttable" role="table">
              <div class="trow thead" role="row"><span>Tool</span><span>Engine</span><span>Findings</span><span>Active</span><span>Critical / high</span><span>Last reported</span><span>Evidence</span></div>
              ${tools.map((t) => {
                const act = t.list.filter(J.isActive);
                const ch = act.filter((f) => f.severity === "critical" || f.severity === "high").length;
                const last = t.list.reduce((a, f) => (f.last_seen > a ? f.last_seen : a), "");
                return `<div class="trow" role="row">
                  <span class="t-name"><b>${esc(t.name)}</b><span class="muted truncate">${esc(t.desc)}</span></span>
                  <span><span class="eng ${esc(t.engine)}"><i></i>${esc(J.ENGINES[t.engine] ? J.ENGINES[t.engine].label : t.engine)}</span></span>
                  <span class="tnum">${t.list.length ? `<a href="${J.href("findings", { tool: t.id })}">${n(t.list.length)}</a>` : `<span class="muted">0</span>`}</span>
                  <span class="tnum">${n(act.length)}</span>
                  <span class="tnum">${ch ? `<b style="color:var(--sev-critical-fg)">${ch}</b>` : `<span class="muted">0</span>`}</span>
                  <span class="muted">${t.list.length ? esc(J.rel(last)) : "—"}</span>
                  <span>${t.list.length
                    ? `<span class="pill fixed">${icon("check")}Reported</span>`
                    : `<span class="pill ruled-out" data-tip="No findings from this tool.\nJanus can’t yet tell “ran clean” from “not run”.">${icon("circle")}No findings</span>`}${t.known ? "" : ` <span class="tag">uncatalogued</span>`}</span>
                </div>`;
              }).join("")}
            </div>
          </div>
        </div>

        <div class="grid two">
          <div class="card">
            <div class="card-head"><h2>OWASP Top 10 (2021)</h2><span class="hint">all findings mapped by tag</span></div>
            <div class="card-body"><div class="hbar-list">
              ${Object.keys(OWASP).map((k) => { const l = ow[k] || []; return `
                <a class="hbar wide ${l.length ? "" : "zero"}" href="${l.length ? J.href("findings", { q: k }) : "#/coverage"}">
                  <span class="name"><b class="mono">${k}</b> ${esc(OWASP[k])}</span>
                  <span style="width:${(l.length / owMax) * 100}%">${J.sevBar(J.sevCounts(l))}</span>
                  <span class="n">${l.length}</span></a>`; }).join("")}
            </div></div>
          </div>
          <div class="stack">
            <div class="card">
              <div class="card-head"><h2>Evidence quality</h2><span class="hint">confidence across the register</span></div>
              <div class="card-body">${confBar(conf)}</div>
            </div>
            <div class="card">
              <div class="card-head"><h2>Most common weaknesses</h2><span class="hint">CWE</span></div>
              <div class="card-body">${cwList.length ? `<div class="hbar-list">${cwList.map(([c, v]) => `
                <a class="hbar" href="${J.href("findings", { q: c })}"><span class="name mono">${esc(c)}</span><span style="width:${(v / cwList[0][1]) * 100}%"><div class="sbar"><i style="flex:1;background:var(--accent)"></i></div></span><span class="n">${v}</span></a>`).join("")}</div>` : `<p class="muted">No CWE tags on any finding.</p>`}</div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-head"><h2>Category × engine</h2><span class="hint">empty cells are blind spots <i>or</i> clean — the register can’t say which</span></div>
          <div class="card-body">
            <div class="heat">
              <span></span><span class="hh code">${icon("code", "sm")}Inward · Code</span><span class="hh recon">${icon("radar", "sm")}Outward · Recon</span>
              ${CATS.map((c) => `<span class="hl">${esc(J.catLabel(c))}</span>${cell(c, "code")}${cell(c, "recon")}`).join("")}
            </div>
          </div>
        </div>
      </div>`;
  }

  J.views.coverage = { title: "Coverage", render };
})();
