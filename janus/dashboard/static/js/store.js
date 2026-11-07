// Data store: loading, optimistic triage updates (serialised through one
// queue so two quick clicks can never land out of order on the server),
// filtering/sorting, and URL <-> filter-state serialisation.
(function () {
  const store = (J.store = { findings: [], meta: null, loaded: false, loading: false, error: null, loadedAt: null });
  const byFp = () => new Map(store.findings.map((f) => [f.fingerprint, f]));
  J.byFp = (fp) => store.findings.find((f) => f.fingerprint === fp);

  // opts.silent: background poll — keep the UI as-is unless the register actually changed.
  J.load = async (opts = {}) => {
    if (opts.silent && (J.saving() || store.loading)) return;
    if (!opts.silent) { store.loading = true; store.error = null; J.emit("loading"); }
    try {
      const [fr, mr] = await Promise.all([fetch("/api/findings", { cache: "no-store" }), fetch("/api/meta", { cache: "no-store" })]);
      if (!fr.ok) throw new Error(`/api/findings returned ${fr.status}`);
      const raw = await fr.text();
      const changed = raw !== store.raw;
      if (opts.silent && !changed) { store.loadedAt = Date.now(); J.emit("tick"); return; }
      store.raw = raw;
      store.findings = JSON.parse(raw);
      store.meta = mr.ok ? await mr.json() : store.meta;
      store.loaded = true; store.loadedAt = Date.now(); store.error = null;
      if (opts.silent) J.toast("Register updated — new data loaded");
    } catch (e) {
      if (!opts.silent) store.error = e.message || String(e);
    } finally {
      store.loading = false;
      J.emit("data");
    }
  };

  // ---- triage writes -----------------------------------------------------
  let chain = Promise.resolve();
  let inflight = 0;
  const post = (fp, status, notes) =>
    fetch(`/api/findings/${encodeURIComponent(fp)}/status`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(notes === undefined ? { status } : { status, notes }),
    }).then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); });

  J.saving = () => inflight > 0;

  /**
   * items: [{fp, status, notes?}] — notes omitted = leave the server's note alone.
   * Updates the UI immediately, persists in order, rolls back per-item on failure.
   * Returns a Promise resolving to the number of successful writes.
   */
  J.patch = (items, { label = null, undo = true } = {}) => {
    const prev = [];
    const live = [];
    items.forEach((it) => {
      const f = J.byFp(it.fp);
      if (!f) return;
      if (f.status === it.status && (it.notes === undefined || it.notes === (f.notes || ""))) return;
      prev.push({ fp: f.fingerprint, status: f.status, notes: f.notes || "" });
      f.status = it.status;
      if (it.notes !== undefined) f.notes = it.notes;
      live.push(it);
    });
    if (!live.length) return Promise.resolve(0);
    J.emit("data", { patch: true, fps: live.map((i) => i.fp) });

    inflight += live.length;
    J.emit("saving");
    let ok = 0, failed = 0;
    const done = live.map((it) => {
      const p = chain.then(() => post(it.fp, it.status, it.notes));
      chain = p.catch(() => {});
      return p.then(() => { ok++; }).catch(() => {
        failed++;
        const old = prev.find((x) => x.fp === it.fp);
        const f = J.byFp(it.fp);
        if (f && old) { f.status = old.status; f.notes = old.notes; }
      }).finally(() => { inflight--; });
    });
    return Promise.all(done).then(() => {
      J.emit("data", { patch: true, fps: live.map((i) => i.fp) });
      J.emit("saving");
      if (failed) J.toast(`${failed} change${failed > 1 ? "s" : ""} could not be saved — reverted`, { error: true });
      else if (label) {
        J.toast(label, undo ? { action: { label: "Undo", run: () => J.patch(prev.map((p) => ({ fp: p.fp, status: p.status, notes: p.notes })), { label: "Change undone", undo: false }) } } : {});
      }
      return ok;
    });
  };

  // ---- filters -----------------------------------------------------------
  const LIST_KEYS = { sev: "sev", eng: "eng", st: "status", cat: "cat", tool: "tool", conf: "conf" };
  J.emptyFilters = () => ({ q: "", sev: [], eng: [], status: [], cat: [], tool: [], conf: [], asset: "", sort: "severity", dir: "", group: "none" });

  J.parseFilters = (params) => {
    const f = J.emptyFilters();
    f.q = params.get("q") || "";
    Object.entries(LIST_KEYS).forEach(([p, k]) => { const v = params.get(p); if (v) f[k] = v.split(",").filter(Boolean); });
    f.asset = params.get("asset") || "";
    f.sort = params.get("sort") || "severity";
    f.dir = params.get("dir") || "";
    f.group = params.get("group") || "none";
    return f;
  };
  J.filtersToParams = (f) => {
    const p = new URLSearchParams();
    if (f.q) p.set("q", f.q);
    Object.entries(LIST_KEYS).forEach(([param, k]) => { if (f[k].length) p.set(param, f[k].join(",")); });
    if (f.asset) p.set("asset", f.asset);
    if (f.sort && f.sort !== "severity") p.set("sort", f.sort);
    if (f.dir) p.set("dir", f.dir);
    if (f.group && f.group !== "none") p.set("group", f.group);
    return p;
  };
  const FIELD = { sev: (x) => x.severity, eng: (x) => x.engine, status: (x) => x.status, cat: (x) => x.category, tool: (x) => x.tool, conf: (x) => x.confidence || "needs-review" };

  // `skip` lets the filter popovers compute facet counts "as if this filter weren't applied".
  J.applyFilters = (rows, f, skip = null) => {
    const q = f.q.trim().toLowerCase();
    return rows.filter((x) => {
      for (const k of ["sev", "eng", "status", "cat", "tool", "conf"]) {
        if (k !== skip && f[k].length && !f[k].includes(FIELD[k](x))) return false;
      }
      if (f.asset && J.assetOf(x).key !== f.asset) return false;
      if (q) {
        const hay = `${x.title} ${x.host || ""} ${x.target || ""} ${x.path || ""} ${x.rule_id || ""} ${x.tool || ""} ${(x.cwe || []).join(" ")} ${x.endpoint || ""} ${x.notes || ""}`.toLowerCase();
        if (!q.split(/\s+/).every((tok) => hay.includes(tok))) return false;
      }
      return true;
    });
  };
  J.facetValue = (k, x) => FIELD[k](x);

  const cmp = {
    severity: (a, b) => (J.SEV_RANK[a.severity] - J.SEV_RANK[b.severity]) || (J.CONF_RANK[a.confidence] - J.CONF_RANK[b.confidence]) || (b.last_seen || "").localeCompare(a.last_seen || ""),
    last_seen: (a, b) => (b.last_seen || "").localeCompare(a.last_seen || ""),
    first_seen: (a, b) => (b.first_seen || "").localeCompare(a.first_seen || ""),
    title: (a, b) => (a.title || "").localeCompare(b.title || ""),
    status: (a, b) => J.STATUSES.findIndex((s) => s.id === a.status) - J.STATUSES.findIndex((s) => s.id === b.status) || cmp.severity(a, b),
    location: (a, b) => J.locationOf(a).localeCompare(J.locationOf(b)),
    source: (a, b) => `${a.engine}${a.tool}`.localeCompare(`${b.engine}${b.tool}`),
  };
  J.DEFAULT_DIR = { severity: "asc", last_seen: "asc", first_seen: "asc", title: "asc", status: "asc", location: "asc", source: "asc" };
  J.sortRows = (rows, f) => {
    const c = cmp[f.sort] || cmp.severity;
    const out = rows.slice().sort(c);
    if (f.dir === "reverse") out.reverse();
    return out;
  };
  void byFp;
})();
