// Scans — pure logic and HTML-string builders. No DOM access, no fetches, so
// it can be exercised from node (tests/test_dashboard_scans_ui.py) and so every
// place where scan data becomes markup is in one auditable file.
//
// Trust model: everything in a scan record came from scan artifacts, which
// contain target-controlled text (titles, evidence, hostnames, tool output).
// Every dynamic value that reaches a template goes through J.esc (text and
// attribute context) or C.cls (CSS-class context, allow-list of characters).
(function () {
  const J = (window.J = window.J || {});
  const C = (J.scansCore = {});
  const { esc } = J;

  const SEV = ["critical", "high", "medium", "low", "info"];
  const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const CONF_RANK = { confirmed: 0, likely: 1, "needs-review": 2 };
  const HEALTH_RANK = { complete: 0, unverified: 1, partial: 2, degraded: 3 };

  C.SEV = SEV;
  C.cls = (v) => String(v == null ? "" : v).replace(/[^a-zA-Z0-9_-]/g, "");
  const n = (x) => Number(x || 0).toLocaleString();
  const icon = (name, c) => (J.icon ? J.icon(name, c) : "");

  // ---- run classification --------------------------------------------------
  C.kindOf = (run) => {
    if (run && run.kind) return String(run.kind);
    const parts = String((run && run.command) || "").split(/\s+/).filter(Boolean);
    return parts.length >= 2 ? parts.slice(0, 2).join(" ") : parts[0] || "scan";
  };
  C.kindLabel = (kind) => ({ "scan code": "Code", "scan recon": "Recon", "scan all": "Code + recon" }[kind] || String(kind).replace(/^scan\s+/, "") || "Scan");
  C.engagementOf = (run) => (run && run.engagement) || "(no engagement)";

  /**
   * What did this run actually execute? A run's findings are only as credible
   * as its engines, so the verdict is derived from tool status and recorded
   * gaps, never from the finding count:
   *   degraded   an engine failed
   *   partial    an engine was skipped (not installed / disabled) or a gap is recorded
   *   unverified no engine status was recorded at all (can't tell what ran)
   *   complete   every recorded engine ran ok and nothing is listed as a gap
   */
  // Engine-level rows (code / recon: ran | skipped | failed) recorded by newer
  // Janus versions count exactly like tool rows; "ran" means ok.
  C.allTools = (run) => ((run && run.engines) || []).map((e) => ({ id: e.id, status: e.status === "ran" ? "ok" : e.status, detail: e.detail, findings: e.findings }))
    .concat((run && run.tools) || []);
  C.health = (run) => {
    const tools = C.allTools(run);
    const gaps = (run && run.gaps) || [];
    const quality = String((run && (run.quality || (run.coverage && run.coverage.quality))) || "").toLowerCase();
    const failed = tools.filter((t) => t.status === "failed");
    const skipped = tools.filter((t) => t.status === "skipped");
    const other = tools.filter((t) => !["ok", "failed", "skipped"].includes(t.status));
    const ok = tools.filter((t) => t.status === "ok");
    const reasons = [];
    if (failed.length) reasons.push(`${failed.length} engine${failed.length > 1 ? "s" : ""} failed: ${failed.map((t) => t.id).join(", ")}`);
    if (skipped.length) reasons.push(`${skipped.length} engine${skipped.length > 1 ? "s" : ""} skipped: ${skipped.map((t) => t.id).join(", ")}`);
    if (other.length) reasons.push(`${other.length} engine${other.length > 1 ? "s" : ""} with an unrecognised status: ${other.map((t) => t.id).join(", ")}`);
    if (gaps.length) reasons.push(`${gaps.length} coverage gap${gaps.length > 1 ? "s" : ""} recorded`);
    let level, label, summary;
    if (failed.length || quality === "failed") { level = "degraded"; label = failed.length ? `${failed.length} failed` : "failed"; summary = "Some engines failed, so this run may be missing findings."; if (!failed.length) reasons.push("The recorded coverage quality is failed"); }
    else if (quality === "not-assessed" && !tools.length) {
      level = "unverified"; label = "status not assessed"; summary = "This run has no trustworthy execution coverage record.";
      reasons.push("Coverage was not recorded for this run");
    }
    else if (quality === "degraded" && !gaps.length) {
      level = "partial"; label = "degraded"; summary = "Parts of the target were not covered by this run.";
      reasons.push("The recorded coverage quality is degraded");
    }
    else if (skipped.length || other.length || gaps.length) {
      level = "partial";
      label = skipped.length ? `${skipped.length} skipped` : gaps.length ? `${gaps.length} gap${gaps.length > 1 ? "s" : ""}` : "partial";
      summary = "Parts of the target were not covered by this run.";
    } else if (!tools.length) {
      level = "unverified"; label = "status not recorded";
      reasons.push("No engine results were recorded for this run");
      summary = "This run did not record which engines executed, so it cannot be called complete.";
    } else { level = "complete"; label = `${ok.length}/${tools.length} ok`; summary = "Every recorded engine ran and no coverage gaps were reported."; }
    return { level, label, summary, reasons, failed, skipped, ok, tools: tools.length, gaps: gaps.length };
  };
  C.attention = (run) => C.health(run).level !== "complete";

  /** The honest way to say "0 findings". */
  C.resultClaim = (run) => {
    const total = Number((run && run.total) || 0);
    if (total > 0) return { tone: "n", text: `${n(total)} finding${total === 1 ? "" : "s"}`, clean: false };
    const h = C.health(run);
    if (h.level === "complete") return { tone: "ok", text: "Clean", clean: true };
    return { tone: "warn", text: "0 findings — not a clean bill", clean: false };
  };

  // A run with no earlier run of the same kind is a *baseline*: the server still
  // reports new = everything, but that is a starting point, not a regression.
  C.runDelta = (run) => {
    const d = (run && run.delta) || {};
    const baseline = run && run.baseline !== undefined ? !!run.baseline : !(run && run.previous_run_id);
    if (baseline) return { baseline: true, new: 0, fixed: 0, same: 0 };
    return { baseline: false, new: Number(d.new || 0), fixed: Number(d.fixed || 0), same: Number(d.same || 0) };
  };

  // ---- list: filter / sort / group -----------------------------------------
  C.filterRuns = (runs, f) => {
    const q = String(f.q || "").trim().toLowerCase();
    return runs.filter((r) => {
      if (f.kind && C.kindOf(r) !== f.kind) return false;
      if (f.eng && C.engagementOf(r) !== f.eng) return false;
      if (f.health === "attention" && !C.attention(r)) return false;
      if (f.health === "complete" && C.attention(r)) return false;
      if (!q) return true;
      return [r.run_id, r.command, r.engagement, r.mode, (r.lenses || []).join(" "), Object.keys(r.by_tool || {}).join(" ")]
        .filter(Boolean).join(" ").toLowerCase().includes(q);
    });
  };
  const byNewest = (a, b) => String(b.finished_at || "").localeCompare(String(a.finished_at || "")) || String(b.run_id).localeCompare(String(a.run_id));
  C.sortRuns = (runs, by) => {
    const out = runs.slice();
    if (by === "findings") out.sort((a, b) => (b.total || 0) - (a.total || 0) || byNewest(a, b));
    // A baseline's "new" is its whole content, not a change, so it must not outrank real regressions.
    else if (by === "new") out.sort((a, b) => (C.runDelta(b).new - C.runDelta(a).new) || byNewest(a, b));
    else out.sort(byNewest);
    return out;
  };
  C.groupRuns = (runs) => {
    const m = new Map();
    runs.forEach((r) => { const k = C.engagementOf(r); if (!m.has(k)) m.set(k, []); m.get(k).push(r); });
    return [...m.entries()].map(([key, rs]) => {
      const sorted = rs.slice().sort(byNewest);
      return { key, runs: rs, latest: sorted[0], attention: rs.filter(C.attention).length };
    }).sort((a, b) => byNewest(a.latest, b.latest));
  };
  /** Newest run per (engagement, kind): the "what changed since last time" headline. */
  C.latestPerKind = (runs) => {
    const seen = new Map();
    runs.slice().sort(byNewest).forEach((r) => { const k = C.engagementOf(r) + "|" + C.kindOf(r); if (!seen.has(k)) seen.set(k, r); });
    return [...seen.values()];
  };

  // ---- detail: compare / filter / sort ------------------------------------
  C.findingKey = (f) => f.fingerprint || f.title || "";
  C.diff = (current, previous) => {
    const cur = new Set(current.map(C.findingKey));
    const prev = new Set(previous.map(C.findingKey));
    return {
      newKeys: new Set([...cur].filter((k) => !prev.has(k))),
      sameKeys: new Set([...cur].filter((k) => prev.has(k))),
      fixed: previous.filter((f) => !cur.has(C.findingKey(f))),
    };
  };
  // Plain text (callers escape at the point of use) — built without template
  // literals so the "no raw interpolation" audit stays meaningful.
  C.locationOf = (f) => {
    if (f.path) return f.path + (f.line ? ":" + f.line : "");
    const base = f.target || f.host || "";
    return (base + (f.endpoint && !base.endsWith(f.endpoint) ? " " + f.endpoint : "")).trim();
  };
  C.filterFindings = (rows, f, cmp) => {
    const q = String(f.q || "").trim().toLowerCase();
    const sev = f.sev || [];
    return rows.filter((r) => {
      if (sev.length && !sev.includes(r.severity)) return false;
      if (f.tool && r.tool !== f.tool) return false;
      if (f.conf && (r.confidence || "needs-review") !== f.conf) return false;
      if (f.st && (r.status || "open") !== f.st) return false;
      if (f.chg && cmp) {
        const k = C.findingKey(r);
        if (f.chg === "new" && !cmp.newKeys.has(k)) return false;
        if (f.chg === "same" && !cmp.sameKeys.has(k)) return false;
      }
      if (q) {
        const hay = `${r.title || ""} ${C.locationOf(r)} ${r.rule_id || ""} ${r.tool || ""} ${(r.cwe || []).join(" ")} ${r.message || ""}`.toLowerCase();
        if (!q.split(/\s+/).every((t) => hay.includes(t))) return false;
      }
      return true;
    });
  };
  const sevCmp = (a, b) => ((SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9)) || ((CONF_RANK[a.confidence] ?? 9) - (CONF_RANK[b.confidence] ?? 9)) || String(a.title || "").localeCompare(String(b.title || ""));
  C.sortFindings = (rows, sort, dir) => {
    const cmp = {
      severity: sevCmp,
      title: (a, b) => String(a.title || "").localeCompare(String(b.title || "")),
      location: (a, b) => C.locationOf(a).localeCompare(C.locationOf(b)) || sevCmp(a, b),
      tool: (a, b) => String(a.tool || "").localeCompare(String(b.tool || "")) || sevCmp(a, b),
      confidence: (a, b) => ((CONF_RANK[a.confidence] ?? 9) - (CONF_RANK[b.confidence] ?? 9)) || sevCmp(a, b),
      status: (a, b) => String(a.status || "open").localeCompare(String(b.status || "open")) || sevCmp(a, b),
    }[sort] || sevCmp;
    const out = rows.slice().sort(cmp);
    return dir === "desc" ? out.reverse() : out;
  };
  C.countBy = (rows, fn) => { const m = {}; rows.forEach((r) => { const k = fn(r); m[k] = (m[k] || 0) + 1; }); return m; };

  // ---- html builders (every dynamic value escaped) --------------------------
  const HEALTH_ICON = { complete: "checkCircle", partial: "alert", degraded: "alert", unverified: "info" };
  C.healthChip = (run, { long = false } = {}) => {
    const h = C.health(run);
    const text = long ? ({ complete: "Complete", partial: "Partial", degraded: "Degraded", unverified: "Unverified" }[h.level]) + " · " + h.label : h.label;
    const tip = [h.summary].concat(h.reasons).join("\n");
    return `<span class="hchip h-${h.level}" data-tip="${esc(tip)}">${icon(HEALTH_ICON[h.level], "sm")}<span>${esc(text)}</span></span>`;
  };

  C.deltaHtml = (run, { big = false } = {}) => {
    const d = C.runDelta(run);
    const cls = big ? "delta big" : "delta";
    if (d.baseline) {
      return `<span class="${cls} is-baseline" data-tip="First run of this kind for this engagement — there is nothing earlier to compare with.">Baseline<span class="dsub">${n(run.total || 0)} to start from</span></span>`;
    }
    if (!d.new && !d.fixed) return `<span class="${cls} is-same" data-tip="Identical finding set to the previous run of the same kind.">No change<span class="dsub">${n(d.same)} same</span></span>`;
    return `<span class="${cls}">`
      + `<span class="d-new${d.new ? "" : " zero"}" data-tip="New since the previous run of the same kind">+${n(d.new)}<i>new</i></span>`
      + `<span class="d-fixed${d.fixed ? "" : " zero"}" data-tip="In the previous run, gone in this one">−${n(d.fixed)}<i>fixed</i></span>`
      + `<span class="d-same" data-tip="Present in both runs">${n(d.same)}<i>same</i></span></span>`;
  };

  C.sevBar = (counts) => {
    const total = SEV.reduce((a, s) => a + (counts[s] || 0), 0);
    if (!total) return `<span class="sbar thin empty" aria-hidden="true"></span>`;
    return `<span class="sbar thin" role="img" aria-label="${esc(SEV.filter((s) => counts[s]).map((s) => counts[s] + " " + s).join(", "))}">`
      + SEV.filter((s) => counts[s]).map((s) => `<i class="s-${s}" style="flex:${Number(counts[s]) || 0}" data-tip="${esc(counts[s] + " " + s)}"></i>`).join("") + `</span>`;
  };

  C.runRowHtml = (run, { tabbable = false } = {}) => {
    const claim = C.resultClaim(run);
    const kind = C.kindOf(run);
    const when = run.finished_at ? new Date(run.finished_at) : null;
    const whenTxt = when && !isNaN(when) ? when.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : "—";
    return `<a class="run-row" href="#/scans?id=${encodeURIComponent(run.run_id)}" data-run="${esc(run.run_id)}" tabindex="${tabbable ? 0 : -1}">
      <span class="r-when"><b>${esc(whenTxt)}</b><span class="mono muted">${esc(run.run_id)}</span></span>
      <span class="r-kind"><span class="kchip k-${C.cls(kind.replace(/^scan\s+/, ""))}">${esc(C.kindLabel(kind))}</span>${run.mode ? `<span class="muted">${esc(run.mode)}</span>` : ""}</span>
      <span class="r-delta">${C.deltaHtml(run)}</span>
      <span class="r-sev">${C.sevBar(run.by_severity || {})}<span class="r-claim tone-${claim.tone}">${esc(claim.text)}</span></span>
      <span class="r-health">${C.healthChip(run)}</span>
      <span class="r-go" aria-hidden="true">${icon("chevR", "sm")}</span>
    </a>`;
  };

  C.findingRowHtml = (f, i, { expanded = false, badge = "", tabbable = false } = {}) => {
    const loc = C.locationOf(f);
    const sub = [f.rule_id, (f.cwe || [])[0]].filter(Boolean).join(" · ");
    const conf = f.confidence || "needs-review";
    const st = f.status || "open";
    return `<div class="sr-item${expanded ? " open" : ""}${badge === "gone" ? " is-gone" : ""}" data-i="${i}" role="row">
      <button type="button" class="sr-row" tabindex="${tabbable ? 0 : -1}" aria-expanded="${expanded}" aria-controls="srd-${i}" data-i="${i}">
        <span class="sr-sev">${J.sevBadge ? J.sevBadge(f.severity) : esc(f.severity)}</span>
        <span class="sr-title"><b class="truncate">${esc(f.title || "(untitled)")}</b><span class="sr-sub truncate">${badge === "new" ? `<span class="badge-new">new</span>` : badge === "gone" ? `<span class="badge-gone">gone in this run</span>` : ""}${esc(sub)}</span></span>
        <span class="sr-loc mono truncate" title="${esc(loc)}">${esc(loc)}</span>
        <span class="sr-tool mono truncate">${esc(f.tool || "")}</span>
        <span class="sr-conf"><span class="cchip c-${C.cls(conf)}">${esc(conf)}</span></span>
        <span class="sr-st"><span class="pill ${C.cls(st)}">${esc(st)}</span></span>
        <span class="sr-caret" aria-hidden="true">${icon("chevD", "sm")}</span>
      </button>
      ${expanded ? C.findingDetailHtml(f, i) : ""}
    </div>`;
  };

  C.findingDetailHtml = (f, i) => {
    const ex = f.extra || {};
    const evidence = f.snippet || ex.evidence || ex.poc || "";
    const cwe = (f.cwe || []).concat(f.owasp || []);
    const kv = (k, v) => (v ? `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>` : "");
    return `<div class="sr-detail" id="srd-${i}" role="region" aria-label="Details">
      ${f.message ? `<section><h4>What’s wrong</h4><p>${esc(f.message)}</p></section>` : ""}
      ${f.remediation ? `<section><h4>How to fix</h4><p>${esc(f.remediation)}</p></section>` : ""}
      ${evidence ? `<section><h4>Evidence</h4><pre>${esc(String(evidence).slice(0, 4000))}</pre></section>` : ""}
      <dl class="kv">
        ${kv("Location", C.locationOf(f))}${kv("Tool", f.tool)}${kv("Confidence", f.confidence)}${kv("Status", f.status)}${kv("Rule", f.rule_id)}${kv("Category", f.category)}${kv("Method", f.method)}
        ${kv("Standards", cwe.join(", "))}${kv("Also reported by", (ex.also_reported_by || []).join(", "))}${kv("Fingerprint", f.fingerprint)}
      </dl>
      ${f.message || f.remediation || evidence ? "" : `<p class="muted">The tool recorded no further detail for this finding.</p>`}
    </div>`;
  };
})();
