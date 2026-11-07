// Timeline: trend and ageing derived client-side from first_seen / last_seen.
// (A real time-series endpoint would be better — see DESIGN_NOTES.md.)
(function () {
  const { esc, icon, n } = J;
  const T = { range: "all", feedLimit: 30 };
  let host = null;
  const H = 3600e3, D = 24 * H;

  function bucketise(all, range) {
    const now = Date.now();
    let rows = all.filter((f) => J.ts(f.first_seen) != null);
    if (range !== "all") { const cut = now - { "7d": 7, "30d": 30, "90d": 90 }[range] * D; rows = rows.filter((f) => J.ts(f.first_seen) >= cut); }
    if (!rows.length) return { buckets: [], unit: "day" };
    const ts = rows.map((f) => J.ts(f.first_seen));
    const min = Math.min(...ts), max = Math.max(...ts);
    const span = max - min;
    const unit = span <= 2 * D ? "hour" : span > 120 * D ? "week" : "day";
    const size = unit === "hour" ? H : unit === "day" ? D : 7 * D;
    const floor = (t) => (unit === "day" || unit === "week" ? startOfDay(t) : Math.floor(t / H) * H);
    const start = floor(min), end = floor(max);
    const before = range === "all" ? 0 : all.filter((f) => J.ts(f.first_seen) < start).length;
    const m = new Map();
    for (let t = start; t <= end; t += size) m.set(t, { t, counts: {}, total: 0 });
    rows.forEach((f) => {
      const b = m.get(floor(J.ts(f.first_seen)) - (unit === "week" ? 0 : 0)) || [...m.values()].reverse().find((x) => x.t <= J.ts(f.first_seen));
      if (!b) return;
      b.counts[f.severity] = (b.counts[f.severity] || 0) + 1; b.total++;
    });
    let cum = before;
    const buckets = [...m.values()].map((b) => {
      cum += b.total;
      const d = new Date(b.t);
      const label = unit === "hour" ? d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric" }) : unit === "week" ? "Week of " + J.absDate(b.t) : d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
      const short = unit === "hour" ? d.toLocaleTimeString(undefined, { hour: "numeric" }) : J.absDate(b.t);
      return { ...b, cum, label, short };
    });
    // Cap very long ranges to the most recent 60 buckets for legibility
    return { buckets: buckets.slice(-60), unit };
  }
  function startOfDay(t) { const d = new Date(t); d.setHours(0, 0, 0, 0); return d.getTime(); }

  function render(el) {
    host = el;
    if (!J.gate(el)) return;
    const all = J.store.findings;
    const now = Date.now();
    const active = all.filter(J.isActive);

    const { buckets, unit } = bucketise(all, T.range);
    const minFirst = Math.min(...all.map((f) => J.ts(f.first_seen) || Infinity));
    const new7 = all.filter((f) => (J.ts(f.first_seen) || 0) > now - 7 * D).length;
    const old30 = active.filter((f) => (J.ts(f.first_seen) || now) < now - 30 * D).length;
    const critOld = active.filter((f) => f.severity === "critical" && (J.ts(f.first_seen) || now) < now - 7 * D).length;

    // ageing of active findings
    const AGE = [["< 1 day", 0, D], ["1–7 days", D, 7 * D], ["1–4 weeks", 7 * D, 30 * D], ["> 30 days", 30 * D, Infinity]];
    const ageRows = AGE.map(([label, lo, hi]) => {
      const l = active.filter((f) => { const a = now - (J.ts(f.first_seen) || now); return a >= lo && a < hi; });
      return { label, list: l };
    });
    const ageMax = Math.max(1, ...ageRows.map((r) => r.list.length));

    // not re-detected (per-engine latest scan)
    const latest = {};
    all.forEach((f) => { const t = J.ts(f.last_seen) || 0; if (t > (latest[f.engine] || 0)) latest[f.engine] = t; });
    const stale = active.filter((f) => (J.ts(f.last_seen) || 0) < latest[f.engine] - 2 * H)
      .sort((a, b) => J.SEV_RANK[a.severity] - J.SEV_RANK[b.severity]);

    // feed
    const events = [];
    all.forEach((f) => {
      const a = J.ts(f.first_seen), b = J.ts(f.last_seen);
      if (a != null) events.push({ t: a, kind: "new", f });
      if (b != null && a != null && b - a > 5 * 60e3) events.push({ t: b, kind: "seen", f });
    });
    events.sort((x, y) => y.t - x.t);
    const feed = events.slice(0, T.feedLimit);
    let lastDay = "";
    const feedHtml = feed.map((e) => {
      const day = new Date(e.t).toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric", year: "numeric" });
      const head = day !== lastDay ? `<div class="feed-day">${esc(day)}</div>` : "";
      lastDay = day;
      return head + `<button class="feed-item" data-act="open" data-fp="${esc(e.f.fingerprint)}">
        <span class="feed-ico ${e.kind}">${icon(e.kind === "new" ? "plus" : "refresh", "sm")}</span>
        <span class="feed-main"><span class="truncate"><b>${e.kind === "new" ? "New" : "Re-detected"}</b> · ${esc(e.f.title)}</span><span class="muted truncate">${J.locationHtml(e.f)}</span></span>
        ${J.sevBadge(e.f.severity)}
        <span class="muted tnum feed-time" data-tip="${esc(J.abs(new Date(e.t).toISOString()))}">${esc(new Date(e.t).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" }))}</span>
      </button>`;
    }).join("");

    const single = buckets.length <= 1;
    el.innerHTML = `
      ${J.pageHead("Timeline", "How the register has grown and aged — derived from each finding’s first-seen and last-seen timestamps.",
        `<div class="seg" role="group" aria-label="Range">${[["7d", "7 days"], ["30d", "30 days"], ["90d", "90 days"], ["all", "All time"]].map(([v, l]) => `<button data-range="${v}" aria-pressed="${T.range === v}">${l}</button>`).join("")}</div>`)}
      <div class="stack">
        <div class="grid kpis">
          <div class="card kpi"><div class="k-label">${icon("clock", "sm")}Tracking since</div><div class="k-value" style="font-size:22px;padding:4px 0">${isFinite(minFirst) ? esc(new Date(minFirst).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })) : "—"}</div><div class="k-foot">${isFinite(minFirst) ? esc(J.rel(new Date(minFirst).toISOString())) : ""}</div></div>
          <div class="card kpi" style="--kpi-accent:var(--accent)"><div class="k-label">${icon("plus", "sm")}New in last 7 days</div><div class="k-value">${n(new7)}</div><div class="k-foot">first seen this week</div></div>
          <div class="card kpi" style="--kpi-accent:var(--sev-medium)"><div class="k-label">${icon("clock", "sm")}Active &gt; 30 days</div><div class="k-value">${n(old30)}</div><div class="k-foot">lingering without a resolution</div></div>
          <div class="card kpi" style="--kpi-accent:var(--sev-critical)"><div class="k-label">${icon("alert", "sm")}Critical &gt; 7 days</div><div class="k-value ${critOld ? "" : ""}" style="${critOld ? "color:var(--sev-critical-fg)" : ""}">${n(critOld)}</div><div class="k-foot">active, unresolved for over a week</div></div>
        </div>

        <div class="card">
          <div class="card-head"><h2>Findings first seen</h2><span class="hint">per ${unit}, stacked by severity · line = cumulative total tracked</span></div>
          <div class="card-body">
            ${buckets.length ? J.timeChart(buckets) : J.emptyState({ icon: "timeline", title: "No findings in this range", body: "Try a longer range." })}
            ${buckets.length ? `<div class="legend mt-2">${J.SEVERITIES.map((s) => `<span class="legend-item"><span class="legend-dot s-${s}"></span>${J.cap(s)}</span>`).join("")}<span class="legend-item"><span class="legend-dot" style="background:var(--accent)"></span>Cumulative</span></div>` : ""}
            ${single && buckets.length ? `<p class="muted mt-2">${icon("info", "sm")} Everything was first seen in a single window. A trend appears once the register spans multiple scans.</p>` : ""}
          </div>
        </div>

        <div class="grid split-1-2">
          <div class="stack">
            <div class="card">
              <div class="card-head"><h2>Age of active findings</h2><span class="hint">since first seen</span></div>
              <div class="card-body"><div class="hbar-list">
                ${ageRows.map((r) => `<div class="hbar"><span class="name">${r.label}</span><span style="width:${(r.list.length / ageMax) * 100}%">${J.sevBar(J.sevCounts(r.list))}</span><span class="n">${r.list.length}</span></div>`).join("")}
              </div></div>
            </div>
            <div class="card flush">
              <div class="card-head"><h2>Possibly fixed</h2><span class="hint">heuristic</span></div>
              <div class="card-body">
                <p class="muted" style="padding:0 16px 8px">Active findings not re-detected in the latest scan of their engine. Verify, then mark <b>Fixed</b>.</p>
                ${stale.length ? `<div class="qlist">${stale.slice(0, 6).map((f) => `<button class="qrow compact" data-act="open" data-fp="${esc(f.fingerprint)}">${J.sevBadge(f.severity)}<span class="qmain"><span class="qtitle truncate">${esc(f.title)}</span><span class="qloc truncate muted">last seen ${esc(J.rel(f.last_seen))}</span></span></button>`).join("")}</div>${stale.length > 6 ? `<p class="muted" style="padding:6px 16px">+ ${stale.length - 6} more</p>` : ""}`
                  : `<p class="muted" style="padding:6px 16px 10px">Nothing stale — every active finding was seen in its engine’s most recent scan.</p>`}
              </div>
            </div>
          </div>
          <div class="card flush">
            <div class="card-head"><h2>Activity</h2><span class="hint">${n(events.length)} events</span></div>
            <div class="card-body feed">${feedHtml || `<p class="muted" style="padding:10px 16px">No activity.</p>`}
              ${events.length > feed.length ? `<div class="more"><button class="btn" data-act="more-feed">Show more</button></div>` : ""}
            </div>
          </div>
        </div>
      </div>`;
    el.querySelectorAll("[data-range]").forEach((b) => b.addEventListener("click", () => { T.range = b.dataset.range; render(el); }));
    const mf = J.$('[data-act="more-feed"]', el);
    if (mf) mf.addEventListener("click", () => { T.feedLimit += 40; const y = scrollY; render(el); scrollTo(0, y); });
  }

  J.on("data", () => { if (host && document.body.contains(host) && location.hash.indexOf("#/timeline") === 0) render(host); });
  J.views.timeline = { title: "Timeline", render };
})();
