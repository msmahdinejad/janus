// Scans: the history of runs, inside the same shell as everything else.
//
//   #/scans                    runs, headlined by "what changed since last time"
//   #/scans?id=<run_id>        one run: verdict, engines, gaps, delta, findings
//
// Data: /api/scans (list, each row carries kind / previous_run_id / baseline /
// delta) and /api/scans/<id> (record + this run's findings). Records are
// immutable, so a detail page never needs a live refresh; the list revalidates
// quietly. Pure logic + markup builders live in scans-core.js (unit-tested);
// this file owns state, fetching, events and focus.
(function () {
  const { esc, icon, n } = J;
  const C = J.scansCore;
  const PAGE_RUNS = 25, PAGE_GROUP = 8, PAGE_FINDINGS = 100;

  const S = {
    runs: null, error: "", loadedAt: 0, token: 0, io: null, raw: "",
    list: { q: "", kind: "", eng: "", health: "", sort: "newest", group: true, limit: {}, collapsed: new Set() },
    d: null,
  };

  // ---- data ---------------------------------------------------------------
  async function fetchRuns() {
    try {
      const r = await fetch("/api/scans", { cache: "no-store" });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const raw = await r.text();
      const changed = raw !== S.raw;
      S.raw = raw; S.runs = JSON.parse(raw); S.error = ""; S.loadedAt = Date.now();
      return changed;
    } catch (e) {
      S.error = String(e.message || e);
      if (!S.runs) S.runs = [];
      return true;
    }
  }
  async function fetchScan(id) {
    const r = await fetch(`/api/scans/${encodeURIComponent(id)}`, { cache: "no-store" });
    if (!r.ok) throw new Error(r.status === 404 ? "no such scan" : "HTTP " + r.status);
    return r.json();
  }
  const outDir = () => {
    const p = (J.store.meta && J.store.meta.register_path) || "";
    const i = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
    return i > 0 ? p.slice(0, i) : "out";
  };
  const setHash = (params) => {
    const qs = params.toString();
    const h = `#/scans${qs ? "?" + qs : ""}`;
    if (location.hash !== h) history.replaceState(null, "", h);
  };
  // The shell shares one #page between views, so "is my render still the current
  // route?" is the only safe guard for work that finishes after a fetch.
  const onRoute = (id) => {
    const h = location.hash;
    if (!/^#\/scans(\?|$)/.test(h)) return false;
    const got = new URLSearchParams(h.split("?")[1] || "").get("id");
    return id ? got === id : !got;
  };
  const stopObserver = () => { if (S.io) { S.io.disconnect(); S.io = null; } };

  // ==========================================================================
  // LIST
  // ==========================================================================
  function listParams() {
    const f = S.list, p = new URLSearchParams();
    if (f.q) p.set("q", f.q);
    if (f.kind) p.set("kind", f.kind);
    if (f.eng) p.set("eng", f.eng);
    if (f.health) p.set("health", f.health);
    if (f.sort !== "newest") p.set("sort", f.sort);
    if (!f.group) p.set("group", "0");
    return p;
  }

  function headline(runs) {
    const latest = C.latestPerKind(runs);
    if (!latest.length) return "";
    const shown = latest.slice(0, 6);
    const bad = latest.filter(C.attention);
    return `<section class="sc-headline" aria-labelledby="hlT">
      <div class="sc-sect-head"><h2 id="hlT">Since the previous run</h2>
        <span class="muted">Newest run per engagement and scan kind, compared with the run before it of the same kind.</span></div>
      ${bad.length ? `<div class="banner warn" role="status">${icon("alert")}<div><b>${n(bad.length)} of the latest ${bad.length === 1 ? "run" : "runs"} can’t be called complete</b>
        (${esc(Object.entries(C.countBy(bad, (r) => C.health(r).level)).map(([k, v]) => `${v} ${k}`).join(", "))}).
        Finding counts there may be understated — “0 findings” is not a clean result.
        <button class="link-btn" data-act="attn">Show only these runs</button></div></div>` : ""}
      <div class="hl-grid">${shown.map((r) => {
        const claim = C.resultClaim(r);
        return `<a class="hl-card" href="#/scans?id=${encodeURIComponent(r.run_id)}">
          <span class="hl-top"><span class="kchip k-${C.cls(C.kindOf(r).replace(/^scan\s+/, ""))}">${esc(C.kindLabel(C.kindOf(r)))}</span>
            <span class="truncate">${esc(C.engagementOf(r))}</span><span class="muted hl-when" data-tip="${esc(J.abs(r.finished_at))}">${esc(J.rel(r.finished_at))}</span></span>
          <span class="hl-delta">${C.deltaHtml(r, { big: true })}</span>
          <span class="hl-foot">${C.sevBar(r.by_severity || {})}<span class="r-claim tone-${claim.tone}">${esc(claim.text)}</span>${C.healthChip(r)}</span>
        </a>`;
      }).join("")}</div>
      ${latest.length > shown.length ? `<p class="muted small">${n(latest.length - shown.length)} more engagement / kind pairs — filter below.</p>` : ""}
    </section>`;
  }

  function emptyList() {
    const cmd = `janus scan all --scope scope.toml --out "${outDir()}"`;
    return `<div class="card"><div class="empty">
      <div class="art">${icon("clock")}</div><h2>No scans recorded yet</h2>
      <p>Every <code>janus scan</code> run keeps its own immutable record — findings, engine status, coverage gaps, report and SARIF — and shows up here with what changed since the run before it.</p>
      <pre class="mono" id="emptyCmd">${esc(cmd)}</pre>
      <button class="btn mt-2" data-act="copy-cmd">${icon("copy", "sm")}Copy command</button>
      <p class="small muted">Output goes to the folder this dashboard reads (<code>${esc(outDir())}</code>). Use <code>scan code</code> or <code>scan recon</code> to run one engine. Runs recorded by older Janus versions have no history entry.</p>
    </div></div>`;
  }

  function paintList(el) {
    const f = S.list;
    const runs = S.runs || [];
    const body = J.$("#scBody", el);
    const head = J.$("#scHead", el);
    if (!body) return;
    // facets
    const engs = [...new Set(runs.map(C.engagementOf))].sort();
    const kinds = [...new Set(runs.map(C.kindOf))].sort();
    const setOpts = (id, opts, cur) => { const s = J.$(id, el); s.innerHTML = opts.map(([v, l]) => `<option value="${esc(v)}"${v === cur ? " selected" : ""}>${esc(l)}</option>`).join(""); };
    setOpts("#scEng", [["", "All engagements"]].concat(engs.map((e) => [e, e])), f.eng);
    setOpts("#scKind", [["", "All kinds"]].concat(kinds.map((k) => [k, C.kindLabel(k)])), f.kind);
    J.$("#scGroup", el).setAttribute("aria-pressed", String(f.group));

    if (S.error && !runs.length) {
      head.innerHTML = "";
      body.innerHTML = `<div class="banner error" role="alert">${icon("alert")}<div><b>Couldn’t load scan history.</b><div>${esc(S.error)}</div>
        <button class="btn sm mt-2" data-act="retry">${icon("refresh", "sm")}Retry</button></div></div>`;
      return;
    }
    if (!runs.length) { head.innerHTML = ""; body.innerHTML = emptyList(); J.$("#scTools", el).classList.add("hidden"); return; }
    J.$("#scTools", el).classList.remove("hidden");
    head.innerHTML = headline(runs);

    const filtered = C.sortRuns(C.filterRuns(runs, f), f.sort);
    J.$("#scMeta", el).innerHTML = `<b class="tnum">${n(filtered.length)}</b> of <b class="tnum">${n(runs.length)}</b> runs`
      + (S.loadedAt ? ` <span class="muted">· updated ${esc(J.rel(new Date(S.loadedAt).toISOString()))}</span>` : "");
    if (!filtered.length) {
      body.innerHTML = `<div class="card"><div class="empty"><div class="art">${icon("search")}</div><h2>No runs match these filters</h2>
        <button class="btn mt-2" data-act="clear">Clear filters</button></div></div>`;
      return;
    }
    const grouped = f.group && new Set(filtered.map(C.engagementOf)).size > 1;
    let html = "", first = true;
    const rows = (rs, key, per) => {
      const lim = f.limit[key] || per;
      const shown = rs.slice(0, lim);
      const out = shown.map((r) => { const h = C.runRowHtml(r, { tabbable: first }); first = false; return h; }).join("");
      return out + (rs.length > shown.length ? `<button class="sc-more" data-act="more" data-key="${esc(key)}" data-per="${per}">Show ${n(Math.min(per, rs.length - shown.length))} more <span class="muted">(${n(rs.length - shown.length)} hidden)</span></button>` : "");
    };
    if (grouped) {
      html = C.groupRuns(filtered).map((g) => {
        const col = f.collapsed.has(g.key);
        const gs = C.sortRuns(g.runs, f.sort);
        return `<section class="sc-group" aria-label="${esc(g.key)}">
          <button class="sc-ghead" data-act="toggle" data-key="${esc(g.key)}" aria-expanded="${!col}">${icon(col ? "chevR" : "chevD", "sm")}
            <b class="truncate">${esc(g.key)}</b><span class="muted tnum">${n(g.runs.length)} run${g.runs.length === 1 ? "" : "s"}</span>
            ${g.attention ? `<span class="hchip h-partial" data-tip="Runs in this engagement that did not fully execute">${icon("alert", "sm")}${n(g.attention)} need attention</span>` : ""}
            <span class="muted ml-auto">latest ${esc(J.rel(g.latest.finished_at))}</span></button>
          ${col ? "" : `<div class="run-list">${rows(gs, g.key, PAGE_GROUP)}</div>`}
        </section>`;
      }).join("");
    } else {
      html = `<div class="run-list card">${rows(filtered, "__flat", PAGE_RUNS)}</div>`;
    }
    body.innerHTML = `<div class="run-cols" aria-hidden="true"><span>Finished</span><span>Kind</span><span>Change vs previous</span><span>Findings</span><span>Engines</span><span></span></div>${html}`;
  }

  function renderList(el, params, my) {
    const f = S.list;
    f.q = params.get("q") || ""; f.kind = params.get("kind") || ""; f.eng = params.get("eng") || "";
    f.health = params.get("health") || ""; f.sort = params.get("sort") || "newest"; f.group = params.get("group") !== "0";
    el.innerHTML = `<div class="sc-root">
      <div class="vhead"><div><h1 class="vtitle">Scans</h1>
        <p class="vsub">Every run keeps its own findings, engine status, report and SARIF. The merged <a href="#/findings?st=open,needs-review">current state</a> is a separate view on purpose.</p></div>
        <div class="vactions"><span class="muted small" id="scMeta" aria-live="polite"></span>
          <button class="btn" data-act="retry">${icon("refresh", "sm")}<span>Refresh</span></button></div></div>
      <div id="scHead"></div>
      <div class="toolbar sc-tools" id="scTools" role="search">
        <div class="search"><span>${icon("search", "sm")}</span><input id="scQ" class="input" type="search" placeholder="Run id, engagement, tool…" value="${esc(f.q)}" aria-label="Filter runs" autocomplete="off" spellcheck="false"/><kbd>/</kbd></div>
        <select id="scEng" class="select" aria-label="Engagement"></select>
        <select id="scKind" class="select" aria-label="Scan kind"></select>
        <select id="scHealth" class="select" aria-label="Engine status">
          <option value="">Any engine status</option><option value="attention"${f.health === "attention" ? " selected" : ""}>Needs attention (partial / failed / unverified)</option><option value="complete"${f.health === "complete" ? " selected" : ""}>Complete only</option></select>
        <select id="scSort" class="select" aria-label="Sort runs">
          <option value="newest">Sort: newest</option><option value="findings">Sort: most findings</option><option value="new">Sort: most new</option></select>
        <button class="btn" id="scGroup" aria-pressed="true" data-act="group" data-tip="Group runs by engagement">${icon("layers", "sm")}<span>Group</span></button>
      </div>
      <div id="scBody" aria-live="polite">${J.skeleton("list")}</div></div>`;
    const root = el.firstElementChild;
    J.$("#scSort", el).value = f.sort;

    const sync = () => { setHash(listParams()); paintList(el); };
    root.addEventListener("click", (e) => {
      const a = e.target.closest("[data-act]");
      if (!a) return;
      const act = a.dataset.act;
      if (act === "toggle") { f.collapsed.has(a.dataset.key) ? f.collapsed.delete(a.dataset.key) : f.collapsed.add(a.dataset.key); paintList(el); }
      else if (act === "more") { f.limit[a.dataset.key] = (f.limit[a.dataset.key] || Number(a.dataset.per)) + Number(a.dataset.per); paintList(el); }
      else if (act === "group") { f.group = !f.group; sync(); }
      else if (act === "attn") { f.health = "attention"; J.$("#scHealth", el).value = "attention"; sync(); }
      else if (act === "clear") { Object.assign(f, { q: "", kind: "", eng: "", health: "" }); J.$("#scQ", el).value = ""; J.$("#scHealth", el).value = ""; sync(); }
      else if (act === "copy-cmd") J.copy(J.$("#emptyCmd", el).textContent, "Command copied");
      else if (act === "retry") { fetchRuns().then(() => { if (my === S.token && onRoute(null)) { paintList(el); J.toast("Scan history refreshed"); } }); }
    });
    J.$("#scQ", el).addEventListener("input", J.debounce((e) => { f.q = e.target.value; f.limit = {}; sync(); }, 120));
    [["#scEng", "eng"], ["#scKind", "kind"], ["#scHealth", "health"], ["#scSort", "sort"]].forEach(([id, key]) =>
      J.$(id, el).addEventListener("change", (e) => { f[key] = e.target.value; f.limit = {}; sync(); }));

    if (S.runs) paintList(el);
    fetchRuns().then((changed) => { if (my === S.token && document.body.contains(el) && onRoute(null) && (changed || !S.runs.length)) paintList(el); });
  }

  // ==========================================================================
  // DETAIL
  // ==========================================================================
  const DEF = () => ({ q: "", sev: [], tool: "", conf: "", st: "", chg: "", sort: "severity", dir: "" });

  function detailParams(D) {
    const p = new URLSearchParams(); p.set("id", D.id);
    const f = D.f;
    if (f.q) p.set("q", f.q);
    if (f.sev.length) p.set("sev", f.sev.join(","));
    ["tool", "conf", "st", "chg"].forEach((k) => { if (f[k]) p.set(k, f[k]); });
    if (f.sort !== "severity") p.set("sort", f.sort);
    if (f.dir) p.set("dir", f.dir);
    return p;
  }

  const factsHtml = (m, d) => {
    const bits = [];
    if (m.files_scanned != null) bits.push(["Files scanned", n(m.files_scanned)]);
    if ((m.lenses || []).length) bits.push(["Lenses", m.lenses.join(", ")]);
    if (m.scope_sha256_16) bits.push(["Scope", m.scope_sha256_16]);
    if (m.authorization_reference) bits.push(["Reference", m.authorization_reference]);
    const rec = m.recon && typeof m.recon === "object" ? Object.entries(m.recon).filter(([, v]) => v != null && typeof v !== "object").slice(0, 6) : [];
    rec.forEach(([k, v]) => bits.push([k.replace(/_/g, " "), String(v)]));
    return bits.length ? `<dl class="facts">${bits.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd></div>`).join("")}</dl>` : "";
  };

  function enginesHtml(m, h) {
    const tools = C.allTools(m);
    const stChip = (s) => {
      const k = ({ ok: "ok", skipped: "skipped", failed: "failed" })[s] || "other";
      return `<span class="tchip t-${k}">${icon(k === "ok" ? "check" : k === "failed" ? "x" : "alert", "sm")}${esc(s || "unknown")}</span>`;
    };
    const byTool = Object.entries(m.by_tool || {});
    return `<div class="card" role="region" aria-labelledby="engT">
      <div class="card-head"><h2 id="engT">What actually ran</h2><span class="muted">${tools.length ? `${n(h.ok.length)} of ${n(tools.length)} engines ok` : "no engine status recorded"}</span></div>
      <div class="card-body">
        ${tools.length ? `<div class="etable" role="table"><div class="erow ehead" role="row"><span>Engine</span><span>Status</span><span class="num">Findings</span><span>Detail</span></div>
          ${tools.map((t) => `<div class="erow" role="row"><span class="mono" data-label="Engine">${esc(t.id)}</span><span data-label="Status">${stChip(t.status)}</span>
            <span class="num" data-label="Findings">${n(t.findings || 0)}</span><span class="edetail" data-label="Detail">${esc(t.detail || "")}</span></div>`).join("")}</div>`
        : `<div class="banner warn">${icon("info")}<div><b>This run didn’t record which engines executed.</b> Only tools that produced findings are known${byTool.length ? ": " + byTool.map(([k, v]) => `<code>${esc(k)}</code> (${n(v)})`).join(", ") : " — and none did"}.
          Whether anything else ran, was skipped, or failed can’t be determined from this record.</div></div>`}
        ${factsHtml(m)}
      </div></div>`;
  }

  function gapsHtml(m) {
    const gaps = m.gaps || [];
    return `<div class="card gaps-card ${gaps.length ? "has-gaps" : ""}" role="region" aria-labelledby="gapT">
      <div class="card-head"><h2 id="gapT">Not covered / degraded</h2><span class="muted">${gaps.length ? n(gaps.length) + " recorded" : "none recorded"}</span></div>
      <div class="card-body">${gaps.length
        ? `<ul class="gaps">${gaps.map((g) => `<li>${icon("alert", "sm")}<span>${esc(g)}</span></li>`).join("")}</ul>`
        : `<p class="muted">No coverage gaps were recorded for this run. That is a statement about what the run reported, not a guarantee about the target.</p>`}</div></div>`;
  }

  function renderDetail(el, id, params, my) {
    const alive = () => my === S.token && document.body.contains(el) && onRoute(id);
    el.innerHTML = `<div class="vhead"><div><a class="back" href="#/scans">${icon("chevL", "sm")} All scans</a>
      <h1 class="vtitle mono">${esc(id)}</h1><p class="vsub">Loading…</p></div></div>${J.skeleton("list")}`;
    // the run list is only needed to name the previous run; never block or fail the page on it
    Promise.all([fetchScan(id), S.runs ? null : fetchRuns().catch(() => {})]).then(([data]) => {
      if (!alive()) return;
      const D = S.d = { id, data, f: DEF(), limit: PAGE_FINDINGS, expanded: new Set(), cursor: 0, prev: null, view: [], cmp: null };
      const f = D.f;
      f.q = params.get("q") || ""; f.sev = (params.get("sev") || "").split(",").filter((x) => C.SEV.includes(x));
      f.tool = params.get("tool") || ""; f.conf = params.get("conf") || ""; f.st = params.get("st") || "";
      f.chg = params.get("chg") || ""; f.sort = params.get("sort") || "severity"; f.dir = params.get("dir") || "";
      D.base = data.findings || [];
      const m = data.meta || {};
      const h = C.health(m);
      const runLike = { ...m, delta: data.delta, baseline: data.baseline, previous_run_id: data.previous_run_id, kind: data.kind };
      const prevRow = data.previous_run_id ? (S.runs || []).find((r) => r.run_id === data.previous_run_id) : null;
      const claim = C.resultClaim(m);
      const d = C.runDelta(runLike);
      const kind = data.kind || C.kindOf(m);

      el.innerHTML = `<div class="sc-root">
        <div class="vhead"><div>
          <a class="back" href="#/scans">${icon("chevL", "sm")} All scans</a>
          <h1 class="vtitle"><span class="kchip k-${C.cls(String(kind).replace(/^scan\s+/, ""))}">${esc(C.kindLabel(kind))}</span> ${esc(m.command || "scan")}${m.mode ? ` <span class="muted">· ${esc(m.mode)}</span>` : ""}</h1>
          <p class="vsub mono">${esc(m.run_id || id)} · <span data-tip="${esc(J.abs(m.finished_at))}">${esc(J.rel(m.finished_at))}</span> · ${esc(m.engagement || "no engagement")}</p></div>
          <div class="vactions">
            <a class="btn" href="/api/scans/${encodeURIComponent(id)}/report" target="_blank" rel="noopener">${icon("file", "sm")}<span>report.md</span></a>
            <a class="btn" href="/api/scans/${encodeURIComponent(id)}/sarif" target="_blank" rel="noopener">${icon("code", "sm")}<span>SARIF</span></a>
          </div></div>

        <div class="verdict v-${h.level}" role="region" aria-label="Run verdict">
          <div class="v-health"><span class="v-ico">${icon(h.level === "complete" ? "checkCircle" : h.level === "unverified" ? "info" : "alert", "lg")}</span>
            <div><div class="v-title">${esc({ complete: "Complete", partial: "Partial coverage", degraded: "Degraded", unverified: "Unverified" }[h.level])}<span class="muted"> · ${esc(h.label)}</span></div>
              <div class="v-sub">${esc(h.summary)}</div>
              ${h.reasons.length ? `<ul class="v-reasons">${h.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>` : ""}
              ${!m.total && h.level !== "complete" ? `<div class="v-warn">${icon("alert", "sm")}0 findings here is <b>not</b> a clean result.</div>` : ""}</div></div>
          <div class="v-delta"><div class="v-dh">${d.baseline ? "Change since the previous run" : "Compared with "}${d.baseline ? "" : prevRow ? `<a href="#/scans?id=${encodeURIComponent(prevRow.run_id)}">previous ${esc(C.kindLabel(kind).toLowerCase())} run</a> <span class="muted">(${esc(J.rel(prevRow.finished_at))})</span>` : data.previous_run_id ? `<a href="#/scans?id=${encodeURIComponent(data.previous_run_id)}">previous run</a>` : "—"}</div>
            ${C.deltaHtml(runLike, { big: true })}
            ${d.baseline ? `<div class="muted small">First run of this kind${m.engagement ? " for " + esc(m.engagement) : ""} — nothing earlier to compare with.</div>` : ""}</div>
          <div class="v-sev">${C.sevBar(m.by_severity || {})}<span class="r-claim tone-${claim.tone}">${esc(claim.text)}</span>
            <div class="legend">${C.SEV.filter((s) => (m.by_severity || {})[s]).map((s) => `<span class="legend-item"><span class="legend-dot s-${s}"></span>${J.cap(s)} <b class="tnum">${n(m.by_severity[s])}</b></span>`).join("")}</div></div>
        </div>

        <div class="grid two sc-engines">${enginesHtml(m, h)}${gapsHtml(m)}</div>

        <section class="sc-findings" aria-labelledby="fT">
          <div class="sc-sect-head"><h2 id="fT">Findings <span class="muted tnum">${n(D.base.length)}</span></h2><span class="muted" id="sfMeta" aria-live="polite"></span></div>
          <div class="seg chg" role="group" aria-label="Compare with previous run" id="sfChg">
            <button data-chg="" aria-pressed="false">All <span class="n tnum">${n(D.base.length)}</span></button>
            <button data-chg="new" aria-pressed="false" ${d.baseline ? "disabled" : ""} data-tip="${d.baseline ? "No previous run of this kind to compare with" : "Findings not in the previous run"}">New <span class="n tnum">${d.baseline ? "–" : n(d.new)}</span></button>
            <button data-chg="fixed" aria-pressed="false" ${d.baseline ? "disabled" : ""} data-tip="${d.baseline ? "No previous run of this kind to compare with" : "In the previous run, gone in this one"}">Fixed <span class="n tnum">${d.baseline ? "–" : n(d.fixed)}</span></button>
            <button data-chg="same" aria-pressed="false" ${d.baseline ? "disabled" : ""}>Unchanged <span class="n tnum">${d.baseline ? "–" : n(d.same)}</span></button>
          </div>
          <div class="toolbar sc-tools">
            <div class="search"><span>${icon("search", "sm")}</span><input id="sfQ" class="input" type="search" placeholder="Search title, location, rule, CWE…" value="${esc(f.q)}" aria-label="Search findings" autocomplete="off" spellcheck="false"/><kbd>/</kbd></div>
            <div class="chips sev-chips" id="sfSev" role="group" aria-label="Severity">${C.SEV.map((s) => `<button class="sevchip sev-${s}" data-sev="${s}" aria-pressed="false">${s}<span class="n tnum"></span></button>`).join("")}</div>
            <select id="sfTool" class="select" aria-label="Tool"></select>
            <select id="sfConf" class="select" aria-label="Confidence"></select>
            <select id="sfSt" class="select" aria-label="Status"></select>
            <select id="sfSort" class="select sort-sel" aria-label="Sort findings">${[["severity", "Severity"], ["title", "Title"], ["location", "Location"], ["tool", "Tool"], ["confidence", "Confidence"], ["status", "Status"]].map(([v, l]) => `<option value="${v}">Sort: ${l}</option>`).join("")}</select>
          </div>
          <div class="sr-table card" role="table" aria-label="Findings in this run">
            <div class="sr-head" role="row">
              ${[["severity", "Severity"], ["title", "Finding"], ["location", "Location"], ["tool", "Tool"], ["confidence", "Confidence"], ["status", "Status"]].map(([k, l]) =>
                `<button type="button" class="sr-h h-${k}" data-sort="${k}">${l}<span class="sort-ind"></span></button>`).join("")}<span></span>
            </div>
            <div id="sfList" role="rowgroup"></div>
          </div>
          <div class="more" id="sfMore"></div>
        </section></div>`;
      wireDetail(el.firstElementChild, el, D, alive, d);
      paintFindings(el, D);
    }).catch((e) => {
      if (!alive()) return;
      el.innerHTML = `<div class="banner error" role="alert">${icon("alert")}<div><b>Couldn’t load scan <code>${esc(id)}</code>.</b> ${esc(String(e.message || e))}.
        <div class="mt-2"><a class="btn sm" href="#/scans">Back to all scans</a></div></div></div>`;
    });
  }

  function currentRows(D) {
    const f = D.f;
    let source = D.base;
    if (f.chg === "fixed") source = D.cmp ? D.cmp.fixed : [];
    return { source, rows: C.sortFindings(C.filterFindings(source, f, D.cmp), f.sort, f.dir) };
  }

  function paintFindings(el, D) {
    if (!onRoute(D.id)) return;            // a late repaint (observer, comparison fetch) must not touch another view
    const f = D.f;
    const { source, rows } = currentRows(D);
    D.view = rows;
    const list = J.$("#sfList", el);
    const badgeOf = (r) => (f.chg === "fixed" ? "gone" : D.cmp && D.cmp.newKeys.has(C.findingKey(r)) ? "new" : "");
    const shown = rows.slice(0, D.limit);
    if (D.cursor >= shown.length) D.cursor = 0;
    list.innerHTML = shown.map((r, i) => C.findingRowHtml(r, i, { expanded: D.expanded.has(C.findingKey(r)), badge: badgeOf(r), tabbable: i === D.cursor })).join("");

    // facets: counts reflect the *other* active filters, so a dead filter is visibly dead
    const w = (skip) => C.filterFindings(source, { ...f, [skip]: skip === "sev" ? [] : "" }, D.cmp);
    const sevC = C.countBy(w("sev"), (r) => r.severity);
    J.$$("#sfSev button", el).forEach((b) => { const s = b.dataset.sev; b.setAttribute("aria-pressed", String(f.sev.includes(s))); J.$(".n", b).textContent = n(sevC[s] || 0); b.classList.toggle("dead", !sevC[s] && !f.sev.includes(s)); });
    const facet = (id, key, label, fn, fmt = (x) => x) => {
      const counts = C.countBy(w(key), fn);
      const all = C.countBy(source, fn);
      const keys = [...new Set(Object.keys(all).concat(f[key] ? [f[key]] : []))].sort();
      J.$(id, el).innerHTML = `<option value="">${label}</option>` + keys.map((k) => `<option value="${esc(k)}"${f[key] === k ? " selected" : ""}>${esc(fmt(k))} (${n(counts[k] || 0)})</option>`).join("");
    };
    facet("#sfTool", "tool", "All tools", (r) => r.tool || "—");
    facet("#sfConf", "conf", "Any confidence", (r) => r.confidence || "needs-review");
    facet("#sfSt", "st", "Any status", (r) => r.status || "open");
    J.$("#sfSort", el).value = f.sort;
    J.$$("#sfChg button", el).forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.chg === f.chg)));
    J.$$(".sr-head [data-sort]", el).forEach((b) => {
      const on = f.sort === b.dataset.sort;
      b.setAttribute("aria-sort", on ? (f.dir ? "descending" : "ascending") : "none");
      J.$(".sort-ind", b).innerHTML = on ? J.icon(f.dir ? "arrowUp" : "arrowDown", "sm") : "";
    });
    J.$("#sfMeta", el).textContent = rows.length === source.length ? `${n(Math.min(D.limit, rows.length))} of ${n(rows.length)} shown` : `${n(Math.min(D.limit, rows.length))} of ${n(rows.length)} shown · filtered from ${n(source.length)}`;

    const more = J.$("#sfMore", el);
    stopObserver();
    const base = D.base.length;
    if (!rows.length) {
      const claim = !base ? C.resultClaim(D.data.meta || {}) : null;
      list.innerHTML = `<div class="empty">${f.chg === "fixed" && !D.cmp ? `<h2>Loading the previous run…</h2>` :
        !base ? `<div class="art">${icon(claim.clean ? "checkCircle" : "alert")}</div><h2>${claim.clean ? "No findings — and every engine ran" : "No findings recorded"}</h2><p>${claim.clean ? "This run completed cleanly." : "See “What actually ran” above: this run did not fully execute, so an empty list is <b>not</b> evidence the target is clean."}</p>`
        : `<div class="art">${icon("search")}</div><h2>No findings match these filters</h2><button class="btn mt-2" data-act="clear">Clear filters</button>`}</div>`;
      more.innerHTML = "";
    } else if (rows.length > shown.length) {
      more.innerHTML = `<button class="btn" data-act="more">Show ${n(Math.min(PAGE_FINDINGS, rows.length - shown.length))} more <span class="muted">(${n(rows.length - shown.length)} hidden)</span></button>`;
      if ("IntersectionObserver" in window) {
        S.io = new IntersectionObserver((es) => { if (es.some((e) => e.isIntersecting)) { D.limit += PAGE_FINDINGS; paintFindings(el, D); } }, { rootMargin: "400px" });
        S.io.observe(more);
      }
    } else more.innerHTML = "";
    setHash(detailParams(D));
  }

  async function ensureCompare(el, D) {
    if (D.cmp || D.prev === "loading") return;
    const pid = D.data.previous_run_id;
    if (!pid) return;
    D.prev = "loading";
    try {
      const prev = await fetchScan(pid);
      D.cmp = C.diff(D.base, prev.findings || []);
      D.prev = "done";
    } catch (e) {
      D.prev = "error";
      J.toast("Couldn’t load the previous run for comparison", { error: true });
    }
    if (S.d === D && document.body.contains(el) && onRoute(D.id)) paintFindings(el, D);
  }

  function wireDetail(root, el, D, alive, delta) {
    const f = D.f;
    const repaint = () => { D.limit = PAGE_FINDINGS; D.cursor = 0; paintFindings(el, D); };
    if (f.chg && !delta.baseline) ensureCompare(el, D); else if (delta.baseline) f.chg = "";
    root.addEventListener("click", (e) => {
      if (!alive()) return;
      const t = e.target;
      const chg = t.closest("#sfChg [data-chg]");
      if (chg && !chg.disabled) { f.chg = chg.dataset.chg; if (f.chg) ensureCompare(el, D); repaint(); return; }
      const sev = t.closest("#sfSev [data-sev]");
      if (sev) { const s = sev.dataset.sev; f.sev = f.sev.includes(s) ? f.sev.filter((x) => x !== s) : f.sev.concat(s); repaint(); return; }
      const sort = t.closest(".sr-head [data-sort]");
      if (sort) { const k = sort.dataset.sort; if (f.sort === k) f.dir = f.dir ? "" : "desc"; else { f.sort = k; f.dir = ""; } repaint(); return; }
      const act = t.closest("[data-act]");
      if (act && act.dataset.act === "more") { D.limit += PAGE_FINDINGS; paintFindings(el, D); return; }
      if (act && act.dataset.act === "clear") { Object.assign(f, { q: "", sev: [], tool: "", conf: "", st: "", chg: "" }); J.$("#sfQ", el).value = ""; repaint(); return; }
      const row = t.closest(".sr-row");
      if (row) toggleRow(el, D, Number(row.dataset.i));
    });
    J.$("#sfQ", el).addEventListener("input", J.debounce((e) => { f.q = e.target.value; repaint(); }, 120));
    J.$("#sfQ", el).addEventListener("keydown", (e) => { if (e.key === "Escape") { if (e.target.value) { e.target.value = ""; f.q = ""; repaint(); } e.target.blur(); } });
    [["#sfTool", "tool"], ["#sfConf", "conf"], ["#sfSt", "st"], ["#sfSort", "sort"]].forEach(([id, key]) =>
      J.$(id, el).addEventListener("change", (e) => { f[key] = e.target.value; if (key === "sort") f.dir = ""; repaint(); }));
  }

  // Expand/collapse one row in place: only that node is replaced, so scroll
  // position, focus and every other open row are untouched.
  function toggleRow(el, D, i, force) {
    const r = D.view[i];
    if (!r) return;
    const key = C.findingKey(r);
    const open = force !== undefined ? force : !D.expanded.has(key);
    open ? D.expanded.add(key) : D.expanded.delete(key);
    D.cursor = i;
    const item = J.$$(".sr-item", el).find((x) => Number(x.dataset.i) === i);
    if (!item) return;
    J.$$(".sr-row[tabindex='0']", el).forEach((b) => b.setAttribute("tabindex", "-1"));
    const badge = D.f.chg === "fixed" ? "gone" : D.cmp && D.cmp.newKeys.has(key) ? "new" : "";
    const fresh = J.html(C.findingRowHtml(r, i, { expanded: open, badge, tabbable: true }));
    item.replaceWith(fresh);
    const btn = J.$(".sr-row", fresh);
    if (btn) btn.focus({ preventScroll: true });
  }

  // ---- keyboard (called by the shell for this view; return true if handled) ----
  function onKey(e) {
    if (e.ctrlKey || e.metaKey || e.altKey) return false;
    const el = J.$("#page");
    if (e.key === "/") { const q = J.$("#sfQ", el) || J.$("#scQ", el); if (q) { e.preventDefault(); q.focus(); q.select(); return true; } return false; }
    const down = e.key === "j" || e.key === "ArrowDown", up = e.key === "k" || e.key === "ArrowUp";
    if (J.$("#sfList", el) && S.d) {
      const D = S.d;
      if (down || up) {
        e.preventDefault();
        let cur = D.cursor;
        const act = document.activeElement;
        if (!(act && act.classList && act.classList.contains("sr-row"))) {
          // Nothing focused yet: start from the first row actually on screen, not row 0 far above.
          const first = J.$$(".sr-row", el).find((b) => b.getBoundingClientRect().top > 90);
          if (first) cur = Number(first.dataset.i) - (down ? 1 : -1);
        }
        let i = Math.max(0, Math.min(D.view.length - 1, cur + (down ? 1 : -1)));
        if (down && i >= D.limit - 1 && D.limit < D.view.length) { D.limit += PAGE_FINDINGS; paintFindings(el, D); }
        D.cursor = i;
        J.$$(".sr-row", el).forEach((b) => b.setAttribute("tabindex", Number(b.dataset.i) === i ? "0" : "-1"));
        const b = J.$$(".sr-row", el).find((x) => Number(x.dataset.i) === i);
        if (b) { b.focus(); b.scrollIntoView({ block: "nearest" }); }
        return true;
      }
      if (e.key === "Escape") {
        const b = document.activeElement && document.activeElement.closest && document.activeElement.closest(".sr-item.open");
        if (b) { toggleRow(el, D, Number(b.dataset.i), false); return true; }
      }
      if (e.key === "[" || e.key === "]") return false;
      return false;
    }
    if (J.$("#scBody", el) && (down || up)) {
      const rows = J.$$(".run-row", el);
      if (!rows.length) return false;
      e.preventDefault();
      let i = rows.indexOf(document.activeElement);
      i = i < 0 ? (down ? 0 : rows.length - 1) : Math.max(0, Math.min(rows.length - 1, i + (down ? 1 : -1)));
      rows.forEach((r, k) => r.setAttribute("tabindex", k === i ? "0" : "-1"));
      rows[i].focus(); rows[i].scrollIntoView({ block: "nearest" });
      return true;
    }
    return false;
  }

  J.views.scans = {
    title: "Scans",
    onKey,
    render(el, params) {
      const my = ++S.token;
      stopObserver();
      S.d = null;
      const id = params.get("id");
      if (id) renderDetail(el, id, params, my); else renderList(el, params, my);
    },
    // New scans land while the dashboard is open: revalidate the list quietly.
    revalidate() {
      const el = J.$("#page");
      if (!el || !J.$("#scBody", el)) return;
      const my = S.token;
      // (an empty list repaints too: its example command embeds the register path, which arrives with /api/meta)
      fetchRuns().then((changed) => { if ((changed || !S.runs.length) && my === S.token && onRoute(null) && J.$("#scBody", el)) paintList(el); });
    },
  };
})();
