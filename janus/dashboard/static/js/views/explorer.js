// Findings explorer: presets, facet filters, grouping, sorting, bulk triage,
// keyboard navigation, incremental rendering for large registers.
(function () {
  const { esc, icon, n } = J;
  const PAGE = 120;

  const PRESETS = [
    { id: "active", label: "Active", st: J.ACTIVE, sev: [] },
    { id: "crit", label: "Critical & high", st: J.ACTIVE, sev: ["critical", "high"] },
    { id: "review", label: "Needs review", st: ["needs-review"], sev: [] },
    { id: "resolved", label: "Resolved", st: ["fixed", "ruled-out", "accepted-risk"], sev: [] },
    { id: "all", label: "All", st: [], sev: [] },
  ];
  const same = (a, b) => a.length === b.length && a.every((x) => b.includes(x));
  const FACETS = [
    { k: "sev", label: "Severity", icon: "alert" },
    { k: "status", label: "Status", icon: "circle" },
    { k: "eng", label: "Engine", icon: "layers" },
    { k: "cat", label: "Category", icon: "list" },
    { k: "tool", label: "Tool", icon: "wrench" },
    { k: "conf", label: "Confidence", icon: "eye" },
  ];
  const GROUPS = [["none", "No grouping"], ["severity", "Severity"], ["asset", "Asset"], ["category", "Category"], ["tool", "Tool"], ["status", "Status"], ["engine", "Engine"]];
  const SORTS = [["severity", "Severity"], ["last_seen", "Last seen"], ["first_seen", "First seen"], ["title", "Title"], ["status", "Status"], ["location", "Location"]];

  const X = (J.explorer = {
    f: J.emptyFilters(), selected: new Set(), cursor: null, limit: PAGE, collapsed: new Set(),
    rows: [], flat: [], el: null, lastClicked: null,
  });

  // ---- derive ------------------------------------------------------------
  function facetOptions(k) {
    const all = J.store.findings;
    const base = J.applyFilters(all, X.f, k);          // counts "if this filter weren't applied"
    const counts = J.countBy(base, (x) => J.facetValue(k, x));
    const seen = new Set(all.map((x) => J.facetValue(k, x)));
    let vals = [...seen];
    if (k === "sev") vals = J.SEVERITIES.filter((s) => seen.has(s));
    else if (k === "status") vals = J.STATUSES.map((s) => s.id).filter((s) => seen.has(s) || X.f.status.includes(s));
    else if (k === "conf") vals = J.CONFIDENCES.filter((s) => seen.has(s));
    else vals.sort((a, b) => (counts[b] || 0) - (counts[a] || 0) || String(a).localeCompare(String(b)));
    return vals.map((v) => ({ v, count: counts[v] || 0 }));
  }
  const facetLabel = (k, v) =>
    k === "status" ? J.statusLabel(v) : k === "cat" ? J.catLabel(v) : k === "eng" ? (J.ENGINES[v] ? J.ENGINES[v].label : v) : J.cap(v);

  function buildGroups(rows) {
    const g = X.f.group;
    if (g === "none") return [{ key: "__all", rows }];
    const keyOf = {
      severity: (r) => r.severity, category: (r) => r.category, tool: (r) => r.tool, status: (r) => r.status,
      engine: (r) => r.engine, asset: (r) => J.assetOf(r).key,
    }[g];
    const m = new Map();
    rows.forEach((r) => { const k = keyOf(r); if (!m.has(k)) m.set(k, []); m.get(k).push(r); });
    let out = [...m.entries()].map(([key, rs]) => ({ key, rows: rs }));
    if (g === "severity") out.sort((a, b) => J.SEV_RANK[a.key] - J.SEV_RANK[b.key]);
    else if (g === "status") out.sort((a, b) => J.STATUSES.findIndex((s) => s.id === a.key) - J.STATUSES.findIndex((s) => s.id === b.key));
    else if (g === "asset") out.sort((a, b) => J.riskScore(b.rows) - J.riskScore(a.rows) || b.rows.length - a.rows.length);
    else out.sort((a, b) => b.rows.length - a.rows.length);
    return out;
  }
  function groupLabel(g, key) {
    switch (X.f.group) {
      case "severity": return J.sevBadge(key);
      case "status": return J.statusPill(key);
      case "category": return `<b>${esc(J.catLabel(key))}</b>`;
      case "engine": return `<span class="eng ${esc(key)}"><i></i><b>${esc(J.ENGINES[key] ? J.ENGINES[key].face + " · " + J.ENGINES[key].label : key)}</b></span>`;
      case "asset": { const f = g.rows[0]; const a = J.assetOf(f); return `${icon(a.kind === "host" ? "globe" : "file", "sm")}<b class="mono">${esc(a.kind === "file" ? J.shortPath(key) : key)}</b>`; }
      default: return `<b>${esc(key)}</b>`;
    }
  }

  // ---- row HTML ----------------------------------------------------------
  function rowHtml(f) {
    const sel = X.selected.has(f.fingerprint);
    const sub = [f.rule_id, (f.cwe || [])[0], J.catLabel(f.category)].filter(Boolean).join(" · ");
    return `<div class="frow ${sel ? "selected" : ""} ${X.cursor === f.fingerprint ? "cursor" : ""} ${J.drawer.fp === f.fingerprint ? "open" : ""} ${J.isActive(f) ? "" : "done"}" role="row" data-fp="${esc(f.fingerprint)}" id="r-${esc(f.fingerprint)}">
      <div class="c c-chk" role="cell"><input type="checkbox" class="check" data-act="select" aria-label="Select finding" ${sel ? "checked" : ""}></div>
      <div class="c c-sev" role="cell">${J.sevBadge(f.severity)}</div>
      <div class="c c-title" role="cell"><div class="t-main truncate">${esc(f.title)}</div><div class="t-sub truncate">${esc(sub)}${f.notes ? ` <span class="has-note" data-tip="${esc(f.notes)}">${icon("list", "sm")}</span>` : ""}</div></div>
      <div class="c c-src" role="cell">${J.engineTag(f)}</div>
      <div class="c c-loc" role="cell">${J.locationHtml(f)}</div>
      <div class="c c-st" role="cell">${J.statusPill(f.status, true, f.fingerprint)}</div>
      <div class="c c-seen tnum" role="cell" data-tip="${esc(J.abs(f.last_seen))}">${esc(J.rel(f.last_seen))}</div>
    </div>`;
  }

  function listHtml() {
    const groups = buildGroups(X.rows);
    X.flat = [];
    let budget = X.limit, shown = 0, html = "";
    groups.forEach((g) => {
      const collapsed = X.collapsed.has(g.key);
      if (X.f.group !== "none") {
        const allSel = g.rows.every((r) => X.selected.has(r.fingerprint));
        const some = g.rows.some((r) => X.selected.has(r.fingerprint));
        html += `<div class="grow" role="row" data-group="${esc(g.key)}">
          <input type="checkbox" class="check" data-act="select-group" aria-label="Select group" ${allSel ? "checked" : ""} ${some && !allSel ? 'data-indeterminate="1"' : ""}>
          <button class="g-toggle" data-act="toggle-group" aria-expanded="${!collapsed}">${icon(collapsed ? "chevR" : "chevD", "sm")}<span class="g-label">${groupLabel(g, g.key)}</span>
          <span class="muted tnum">${g.rows.length}</span></button>
          <span class="g-bar">${J.sevBar(J.sevCounts(g.rows), "thin")}</span>
        </div>`;
      }
      if (collapsed) return;
      g.rows.forEach((r) => {
        X.flat.push(r.fingerprint);
        if (budget > 0) { html += rowHtml(r); budget--; shown++; }
      });
    });
    X.shown = shown;
    return html;
  }

  // ---- chrome updates ----------------------------------------------------
  function paint() {
    const el = X.el; if (!el) return;
    const all = J.store.findings;
    X.rows = J.sortRows(J.applyFilters(all, X.f), X.f);
    const body = J.$("#fbody", el);
    const scroller = document.scrollingElement;
    const y = scroller.scrollTop;
    body.innerHTML = X.rows.length ? listHtml() : "";
    body.querySelectorAll('input[data-indeterminate]').forEach((i) => (i.indeterminate = true));
    const empty = J.$("#fempty", el);
    if (!X.rows.length) {
      const hasFilters = J.filtersToParams(X.f).toString().replace(/(^|&)(sort|dir|group)=[^&]*/g, "") !== "";
      const activeDone = X.f.status.length && same(X.f.status, J.ACTIVE) && all.length && !X.f.q && !X.f.sev.length && !X.f.eng.length && !X.f.cat.length && !X.f.tool.length;
      empty.innerHTML = activeDone
        ? J.emptyState({ icon: "checkCircle", title: "Inbox zero", body: "No open or needs-review findings match. Everything in view has been triaged.", action: `<a class="btn mt-2" href="${J.href("findings", {})}">Show all findings</a>` })
        : J.emptyState({ icon: "search", title: hasFilters ? "No findings match these filters" : "No findings", body: hasFilters ? "Try removing a filter or widening the search." : "", action: hasFilters ? `<button class="btn mt-2" data-act="clear-filters">Clear all filters</button>` : "" });
    } else empty.innerHTML = "";
    J.$("#fhead", el).classList.toggle("hidden", !X.rows.length);
    scroller.scrollTop = y;
    chrome();
    J.drawer.setContext(X.flat);
    observeMore();
  }

  function chrome() {
    const el = X.el; if (!el) return;
    const all = J.store.findings;
    // tabs
    J.$$(".tabs button", el).forEach((b) => {
      const p = PRESETS.find((x) => x.id === b.dataset.preset);
      const on = same(p.st, X.f.status) && same(p.sev, X.f.sev);
      b.setAttribute("aria-selected", String(on));
      const c = all.filter((r) => (!p.st.length || p.st.includes(r.status)) && (!p.sev.length || p.sev.includes(r.severity))).length;
      J.$(".n", b).textContent = n(c);
    });
    // facet buttons
    FACETS.forEach(({ k, label }) => {
      const b = J.$(`[data-facet="${k}"]`, el); if (!b) return;
      const sel = X.f[k];
      b.classList.toggle("active", sel.length > 0);
      J.$(".fl", b).textContent = sel.length === 1 ? `${label}: ${facetLabel(k, sel[0])}` : sel.length ? `${label} · ${sel.length}` : label;
    });
    const search = J.$("#fsearch", el);
    if (document.activeElement !== search) search.value = X.f.q;
    search.parentElement.classList.toggle("has-value", !!X.f.q);
    J.$("#fgroup", el).value = X.f.group;
    J.$("#fsort", el).value = X.f.sort;
    J.$("#fdir", el).innerHTML = icon(X.f.dir ? "arrowUp" : "arrowDown", "sm");
    J.$("#fdir", el).setAttribute("data-tip", X.f.dir ? "Reversed order" : "Default order");
    // chips: only things the tabs/facet buttons don't already express
    const chips = [];
    if (X.f.asset) chips.push(`<span class="chip"><span class="k">Asset</span> ${esc(J.shortPath(X.f.asset))}<button data-act="rm-asset" aria-label="Remove asset filter">${icon("x", "sm")}</button></span>`);
    if (X.f.q) chips.push(`<span class="chip"><span class="k">Search</span> “${esc(X.f.q)}”<button data-act="rm-q" aria-label="Clear search">${icon("x", "sm")}</button></span>`);
    FACETS.forEach(({ k, label }) => X.f[k].forEach((v) => {
      if ((k === "status" || k === "sev") && PRESETS.some((p) => same(p.st, X.f.status) && same(p.sev, X.f.sev))) return;
      chips.push(`<span class="chip"><span class="k">${label}</span> ${esc(facetLabel(k, v))}<button data-act="rm-facet" data-k="${k}" data-v="${esc(v)}" aria-label="Remove ${esc(label)} filter">${icon("x", "sm")}</button></span>`);
    }));
    const hasAny = chips.length > 0;
    J.$("#fchips", el).innerHTML = chips.join("") + (hasAny ? `<button class="link-btn" data-act="clear-filters">Clear all</button>` : "");
    J.$("#fchips", el).classList.toggle("hidden", !chips.length && !hasAny);
    // meta
    const more = X.rows.length > X.shown;
    J.$("#fmeta", el).innerHTML = `Showing <b class="tnum">${n(Math.min(X.shown, X.rows.length))}</b> of <b class="tnum">${n(X.rows.length)}</b>${X.rows.length !== all.length ? ` <span class="muted">(${n(all.length)} total)</span>` : ""}`;
    J.$("#fmore", el).innerHTML = more ? `<button class="btn" data-act="more">Show ${n(Math.min(PAGE, X.rows.length - X.shown))} more</button>` : "";
    J.$("#fhead .c-chk input", el).checked = X.rows.length > 0 && X.rows.every((r) => X.selected.has(r.fingerprint));
    J.$("#fhead .c-chk input", el).indeterminate = X.selected.size > 0 && !X.rows.every((r) => X.selected.has(r.fingerprint));
    J.$$("#fhead [data-sort]", el).forEach((h) => {
      const on = X.f.sort === h.dataset.sort;
      h.setAttribute("aria-sort", on ? (X.f.dir ? "descending" : "ascending") : "none");
      J.$(".sort-ind", h).innerHTML = on ? icon(X.f.dir ? "arrowUp" : "arrowDown", "sm") : "";
    });
    bulkBar();
    J.emit("counts");
  }

  let io = null;
  function observeMore() {
    if (io) io.disconnect();
    const s = J.$("#fmore", X.el);
    if (!s || !("IntersectionObserver" in window) || !s.firstElementChild) return;
    io = new IntersectionObserver((es) => { if (es.some((e) => e.isIntersecting)) more(); }, { rootMargin: "300px" });
    io.observe(s);
  }
  function more() { X.limit += PAGE; paint(); }

  // ---- bulk bar ----------------------------------------------------------
  function bulkBar() {
    const bar = J.$("#bulk");
    const count = X.selected.size;
    bar.classList.toggle("show", count > 0);
    if (!count) return;
    bar.innerHTML = `
      <span class="b-count"><b class="tnum">${n(count)}</b> selected</span>
      <span class="b-sep"></span>
      <div class="b-actions">${J.STATUSES.map((s) => `<button class="btn sm" data-act="bulk" data-status="${s.id}" data-tip="Mark as ${esc(s.label)}  (${s.key})">${icon(s.icon, "sm")}<span>${esc(s.label)}</span></button>`).join("")}</div>
      <span class="b-sep"></span>
      <button class="btn sm ghost" data-act="bulk-clear">Clear <kbd>Esc</kbd></button>`;
  }

  // ---- state changes -----------------------------------------------------
  X.setFilters = (patch, { push = false } = {}) => {
    Object.assign(X.f, patch);
    X.limit = PAGE;
    const qs = J.filtersToParams(X.f).toString();
    const h = `#/findings${qs ? "?" + qs : ""}`;
    if (location.hash !== h) history[push ? "pushState" : "replaceState"](null, "", h);
    paint();
  };

  X.targets = () => {
    if (X.selected.size) return [...X.selected];
    if (J.drawer.fp) return [J.drawer.fp];
    return X.cursor ? [X.cursor] : [];
  };
  X.clearSelection = () => { X.selected.clear(); paintSelection(); };
  function paintSelection() {
    J.$$(".frow", X.el).forEach((r) => {
      const on = X.selected.has(r.dataset.fp);
      r.classList.toggle("selected", on);
      const c = J.$('input[data-act="select"]', r); if (c) c.checked = on;
    });
    chrome();
  }
  X.applyStatus = (status, fps) => {
    const ids = fps || X.targets();
    if (!ids.length) return;
    const items = ids.map((fp) => ({ fp, status }));
    const label = ids.length === 1 ? `Marked “${(J.byFp(ids[0]) || {}).title ? J.byFp(ids[0]).title.slice(0, 44) : "finding"}” as ${J.statusLabel(status)}` : `Marked ${ids.length} findings as ${J.statusLabel(status)}`;
    if (ids.length > 1) { X.selected.clear(); }
    const p = J.patch(items, { label });
    if (ids.length > 1) paintSelection();
    return p;
  };

  X.moveCursor = (dir) => {
    if (!X.flat.length) return;
    let i = X.flat.indexOf(X.cursor);
    i = i < 0 ? (dir > 0 ? 0 : X.flat.length - 1) : Math.max(0, Math.min(X.flat.length - 1, i + dir));
    if (i >= X.shown && X.shown < X.rows.length) { X.limit += PAGE; paint(); }
    X.setCursor(X.flat[i]);
    if (J.drawer.fp) J.drawer.open(X.cursor, X.flat);
  };
  X.setCursor = (fp) => {
    X.cursor = fp;
    J.$$(".frow.cursor", X.el).forEach((r) => r.classList.remove("cursor"));
    const row = rowEl(fp);
    if (row) { row.classList.add("cursor"); row.scrollIntoView({ block: "nearest" }); }
  };
  X.openCursor = () => { if (X.cursor) J.drawer.open(X.cursor, X.flat); };
  X.toggleSelectCursor = () => {
    if (!X.cursor) return;
    X.selected.has(X.cursor) ? X.selected.delete(X.cursor) : X.selected.add(X.cursor);
    paintSelection();
  };

  const rowEl = (fp) => J.$$(".frow", X.el).find((r) => r.dataset.fp === fp) || null;

  // ---- events ------------------------------------------------------------
  function onClick(e) {
    const t = e.target;
    const act = t.closest("[data-act]");
    const row = t.closest(".frow");
    if (act) {
      const a = act.dataset.act;
      if (a === "select" && row) {
        const fp = row.dataset.fp;
        if (e.shiftKey && X.lastClicked && X.flat.includes(X.lastClicked)) {
          const [i, j] = [X.flat.indexOf(X.lastClicked), X.flat.indexOf(fp)].sort((p, q) => p - q);
          X.flat.slice(i, j + 1).forEach((id) => X.selected.add(id));
        } else act.checked ? X.selected.add(fp) : X.selected.delete(fp);
        X.lastClicked = fp; X.cursor = fp;
        paintSelection(); return;
      }
      if (a === "select-group") {
        const g = act.closest(".grow").dataset.group;
        const grp = buildGroups(X.rows).find((x) => String(x.key) === g);
        grp.rows.forEach((r) => (act.checked ? X.selected.add(r.fingerprint) : X.selected.delete(r.fingerprint)));
        paint(); return;
      }
      if (a === "toggle-group") {
        const g = act.closest(".grow").dataset.group;
        X.collapsed.has(g) ? X.collapsed.delete(g) : X.collapsed.add(g);
        paint(); return;
      }
      if (a === "status-menu" && row) {
        e.stopPropagation();
        const fp = row.dataset.fp, f = J.byFp(fp);
        J.menu(act, [{ head: "Set status" }].concat(J.STATUSES.map((s) => ({ id: s.id, label: s.label, icon: s.icon, hint: s.key, current: s.id === f.status }))), (id) => X.applyStatus(id, [fp]));
        return;
      }
      if (a === "more") { more(); return; }
    }
    if (row) {
      X.cursor = row.dataset.fp;
      J.drawer.open(row.dataset.fp, X.flat);
      J.$$(".frow.open").forEach((r) => r.classList.remove("open"));
      row.classList.add("open"); J.$$(".frow.cursor", X.el).forEach((r) => r.classList.remove("cursor")); row.classList.add("cursor");
    }
  }

  function toolbarClick(e) {
    const t = e.target;
    const facet = t.closest("[data-facet]");
    if (facet) return openFacet(facet);
    const preset = t.closest("[data-preset]");
    if (preset) {
      const p = PRESETS.find((x) => x.id === preset.dataset.preset);
      return X.setFilters({ status: p.st.slice(), sev: p.sev.slice() });
    }
    const a = t.closest("[data-act]");
    if (!a) return;
    const act = a.dataset.act;
    if (act === "rm-facet") X.setFilters({ [a.dataset.k]: X.f[a.dataset.k].filter((v) => v !== a.dataset.v) });
    else if (act === "rm-q") X.setFilters({ q: "" });
    else if (act === "rm-asset") X.setFilters({ asset: "" });
    else if (act === "clear-filters") X.setFilters({ q: "", sev: [], eng: [], status: [], cat: [], tool: [], conf: [], asset: "" });
    else if (act === "clear-search") { X.setFilters({ q: "" }); J.$("#fsearch", X.el).focus(); }
    else if (act === "bulk") X.applyStatus(a.dataset.status);
    else if (act === "bulk-clear") X.clearSelection();
    else if (act === "more") more();
  }

  function openFacet(btn) {
    const k = btn.dataset.facet;
    const build = () => {
      const opts = facetOptions(k);
      return `<div class="menu-head">${esc(FACETS.find((x) => x.k === k).label)}</div>` +
        opts.map(({ v, count }) => `<label class="menu-item facet-opt"><input type="checkbox" class="check" value="${esc(v)}" ${X.f[k].includes(v) ? "checked" : ""}>
          ${k === "sev" ? `<span class="legend-dot s-${esc(v)}"></span>` : ""}${k === "status" ? icon(J.STATUS_BY_ID[v].icon, "sm") : ""}
          <span>${esc(facetLabel(k, v))}</span><span class="count">${n(count)}</span></label>`).join("") +
        `<div class="menu-foot"><button class="link-btn" data-clear>Clear</button><span class="muted">${X.f[k].length} selected</span></div>`;
    };
    const el = J.popover(btn, build(), { role: "dialog", focus: false });
    if (!el) return;
    const first = J.$("input", el); if (first) first.focus();
    el.addEventListener("change", (e) => {
      const vals = J.$$("input:checked", el).map((i) => i.value);
      X.setFilters({ [k]: vals });
      const pos = el.scrollTop; el.innerHTML = build(); el.scrollTop = pos;
      const again = J.$$("input", el).find((i) => i.value === e.target.value); if (again) again.focus();
    });
    el.addEventListener("click", (e) => { if (e.target.closest("[data-clear]")) { X.setFilters({ [k]: [] }); el.innerHTML = build(); } });
  }

  // ---- render ------------------------------------------------------------
  function render(el, params) {
    if (!J.gate(el, { skeleton: "list" })) { X.el = null; return; }
    // Fresh navigation → take filters from the URL; keep selection only if nothing changed.
    X.f = J.parseFilters(params);
    X.limit = PAGE;
    X.el = el;
    const total = J.store.findings.length;
    el.innerHTML = `
      ${J.pageHead("Findings", `<span id="fmeta2">${J.plural(total, "finding")} in the register.</span> Triage with the status menu, or select several for bulk actions.`,
        `<button class="btn" data-act="export-csv" data-tip="Download the filtered list as CSV">${icon("external", "sm")}Export CSV</button>`)}
      <div class="tabs" role="tablist" aria-label="Views">
        ${PRESETS.map((p) => `<button role="tab" data-preset="${p.id}" aria-selected="false">${esc(p.label)}<span class="n">0</span></button>`).join("")}
      </div>
      <div class="toolbar" id="ftools">
        <div class="search"><span>${icon("search", "sm")}</span><input id="fsearch" class="input" type="search" placeholder="Search title, host, path, rule, CWE…" autocomplete="off" spellcheck="false" aria-label="Search findings"/><kbd>/</kbd><button class="btn sm icon ghost clear" data-act="clear-search" aria-label="Clear search">${icon("x", "sm")}</button></div>
        <div class="facets">${FACETS.map((f) => `<button class="btn fbtn" data-facet="${f.k}" aria-haspopup="dialog" aria-expanded="false">${icon(f.icon, "sm")}<span class="fl">${f.label}</span>${icon("chevD", "sm caret")}</button>`).join("")}</div>
      </div>
      <div class="chips hidden" id="fchips"></div>
      <div class="results-meta"><span id="fmeta"></span>
        <div class="tool-right">
          <label class="sel-label" data-tip="Group rows">${icon("layers", "sm")}<select id="fgroup" class="select" aria-label="Group by">${GROUPS.map(([v, l]) => `<option value="${v}">${v === "none" ? "No grouping" : "Group: " + l}</option>`).join("")}</select></label>
          <label class="sel-label" data-tip="Sort order"><select id="fsort" class="select" aria-label="Sort by">${SORTS.map(([v, l]) => `<option value="${v}">Sort: ${l}</option>`).join("")}</select></label>
          <button class="btn icon" id="fdir" aria-label="Reverse sort order"></button>
        </div>
      </div>
      <div class="ftable card" role="table" aria-label="Findings">
        <div class="fhead" id="fhead" role="row">
          <div class="c c-chk"><input type="checkbox" class="check" data-act="select-all" aria-label="Select all"></div>
          <button class="c c-sev sortable" data-sort="severity">Severity<span class="sort-ind"></span></button>
          <button class="c c-title sortable" data-sort="title">Finding<span class="sort-ind"></span></button>
          <button class="c c-src sortable" data-sort="source">Source<span class="sort-ind"></span></button>
          <button class="c c-loc sortable" data-sort="location">Location<span class="sort-ind"></span></button>
          <button class="c c-st sortable" data-sort="status">Status<span class="sort-ind"></span></button>
          <button class="c c-seen sortable" data-sort="last_seen">Last seen<span class="sort-ind"></span></button>
        </div>
        <div id="fbody" role="rowgroup"></div>
        <div id="fempty"></div>
      </div>
      <div class="more" id="fmore"></div>`;

    // wire
    J.$("#ftools", el).addEventListener("click", toolbarClick);
    J.$(".tabs", el).addEventListener("click", toolbarClick);
    J.$("#fchips", el).addEventListener("click", toolbarClick);
    J.$("#fmore", el).addEventListener("click", toolbarClick);
    J.$("#fempty", el).addEventListener("click", toolbarClick);
    J.$("#fbody", el).addEventListener("click", onClick);
    J.$("#fsearch", el).addEventListener("input", J.debounce((e) => X.setFilters({ q: e.target.value }), 110));
    J.$("#fsearch", el).addEventListener("keydown", (e) => {
      if (e.key === "Escape") { if (e.target.value) { e.target.value = ""; X.setFilters({ q: "" }); } e.target.blur(); e.stopPropagation(); }
      else if (e.key === "ArrowDown" || e.key === "Enter") { e.preventDefault(); e.target.blur(); if (!X.cursor || !X.flat.includes(X.cursor)) X.moveCursor(1); }
    });
    J.$("#fgroup", el).addEventListener("change", (e) => X.setFilters({ group: e.target.value }));
    J.$("#fsort", el).addEventListener("change", (e) => X.setFilters({ sort: e.target.value, dir: "" }));
    J.$("#fdir", el).addEventListener("click", () => X.setFilters({ dir: X.f.dir ? "" : "reverse" }));
    J.$("#fhead", el).addEventListener("click", (e) => {
      const s = e.target.closest("[data-sort]");
      if (s) { const k = s.dataset.sort; X.setFilters(X.f.sort === k ? { dir: X.f.dir ? "" : "reverse" } : { sort: k, dir: "" }); return; }
      if (e.target.matches('[data-act="select-all"]')) {
        const on = e.target.checked;
        X.rows.forEach((r) => (on ? X.selected.add(r.fingerprint) : X.selected.delete(r.fingerprint)));
        paint();
      }
    });
    J.$('[data-act="export-csv"]', el).addEventListener("click", exportCsv);
    // drop selected/cursor ids that no longer exist
    X.selected = new Set([...X.selected].filter((fp) => J.byFp(fp)));
    paint();
  }

  function exportCsv() {
    const cols = ["severity", "status", "title", "engine", "tool", "category", "rule_id", "path", "line", "host", "endpoint", "confidence", "first_seen", "last_seen", "notes", "fingerprint"];
    const q = (v) => { v = String(v ?? ""); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v; };
    const csv = [cols.join(",")].concat(X.rows.map((r) => cols.map((c) => q(r[c])).join(","))).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    a.download = "janus-findings.csv"; document.body.appendChild(a); a.click(); a.remove();
    J.toast(`Exported ${J.plural(X.rows.length, "finding")}`);
  }

  // live data changes (optimistic triage, refresh)
  J.on("data", () => {
    if (!X.el || !document.body.contains(X.el) || location.hash.indexOf("#/findings") !== 0) return;
    X.selected = new Set([...X.selected].filter((fp) => J.byFp(fp)));
    paint();
  });
  J.on("drawer", ({ fp }) => {
    if (!X.el) return;
    J.$$(".frow.open", X.el).forEach((r) => r.classList.remove("open"));
    if (fp) { X.cursor = fp; const r = rowEl(fp); if (r) { r.classList.add("open", "cursor"); r.scrollIntoView({ block: "nearest" }); } }
  });

  J.views.findings = { title: "Findings", render, explorer: X };
})();
