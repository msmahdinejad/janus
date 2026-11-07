// Pieces shared by several views.
(function () {
  const { esc, icon } = J;
  J.views = J.views || {};

  // #/view?k=v links, so every number on the dashboard is a door into the data.
  J.href = (view, params) => {
    const p = new URLSearchParams();
    Object.entries(params || {}).forEach(([k, v]) => { if (v !== "" && v != null) p.set(k, Array.isArray(v) ? v.join(",") : v); });
    const qs = p.toString();
    return `#/${view}${qs ? "?" + qs : ""}`;
  };
  J.ACTIVE = ["open", "needs-review"];

  J.sevBadge = (s) => `<span class="sev sev-${esc(s)}">${esc(s)}</span>`;
  J.statusPill = (st, interactive, fp) => {
    const s = J.STATUS_BY_ID[st];
    const inner = `${icon(s ? s.icon : "circle")}${esc(s ? s.label : st)}`;
    return interactive
      ? `<button class="pill ${esc(st)}" data-act="status-menu" data-fp="${esc(fp)}" aria-haspopup="menu" aria-label="Status: ${esc(s ? s.label : st)}. Change">${inner}${icon("chevD", "sm")}</button>`
      : `<span class="pill ${esc(st)}">${inner}</span>`;
  };
  J.engineTag = (f) => `<span class="eng ${esc(f.engine)}"><i></i>${esc(J.ENGINES[f.engine] ? J.ENGINES[f.engine].label : f.engine)}<span class="tool">/ ${esc(f.tool)}</span></span>`;

  J.locationHtml = (f) => {
    if (f.path && f.engine !== "recon") {
      const { dir, base } = J.splitPath(f.path);
      const short = dir.length > 34 ? "…" + dir.slice(-32) : dir;
      return `<span class="loc mono" title="${esc(J.locationOf(f))}"><span class="loc-dir">${esc(short)}</span><span class="loc-base">${esc(base)}</span>${f.line ? `<span class="loc-line">:${f.line}</span>` : ""}</span>`;
    }
    const host = f.host || f.target || "";
    return `<span class="loc mono" title="${esc(J.locationOf(f))}"><span class="loc-base">${esc(host)}</span>${f.endpoint ? `<span class="loc-dir">${f.endpoint.startsWith("/") ? "" : " "}${esc(f.endpoint)}</span>` : ""}${f.method ? `<span class="loc-line"> ${esc(f.method)}</span>` : ""}</span>`;
  };

  J.emptyState = ({ icon: ic = "inbox", title, body = "", action = "", extra = "" }) =>
    `<div class="empty"><div class="art">${icon(ic)}</div><h2>${esc(title)}</h2>${body ? `<p>${body}</p>` : ""}${extra}${action}</div>`;

  J.noDataState = () => J.emptyState({
    icon: "findings", title: "No findings in this register yet",
    body: "Run a scan and Janus will merge its results into the register this dashboard reads — or load the synthetic demo data to look around.",
    extra: `<pre class="mono">janus scan code --scope scope.toml --out out\njanus dashboard --register out/register.json\n\njanus demo   # synthetic example data</pre>`,
  });

  J.skeleton = (kind) => {
    const b = (h, w = "100%") => `<div class="skel" style="height:${h}px;width:${w}"></div>`;
    if (kind === "list") return `<div class="card"><div class="card-body flex" style="flex-direction:column;gap:10px">${Array.from({ length: 9 }, () => b(34)).join("")}</div></div>`;
    return `<div class="stack"><div class="grid kpis">${Array.from({ length: 4 }, () => `<div class="card kpi">${b(12, "50%")}${b(30, "40%")}${b(12, "70%")}</div>`).join("")}</div>
      <div class="grid split-2-1"><div class="card card-body">${b(160)}</div><div class="card card-body">${b(160)}</div></div></div>`;
  };

  J.errorState = (msg) => `<div class="banner error" role="alert">${icon("alert")}<div><b>Couldn’t load findings.</b><div>${esc(msg)}</div><button class="btn sm mt-2" data-act="reload">${icon("refresh", "sm")}Retry</button></div></div>`;

  // Page chrome: gates on loading / error / empty, else hands off to fn.
  J.gate = (el, { skeleton = "page", allowEmpty = false } = {}) => {
    const s = J.store;
    if (s.error && !s.loaded) { el.innerHTML = J.errorState(s.error); return false; }
    if (!s.loaded) { el.innerHTML = J.skeleton(skeleton); return false; }
    if (!s.findings.length && !allowEmpty) { el.innerHTML = `<div class="card">${J.noDataState()}</div>`; return false; }
    return true;
  };

  J.pageHead = (title, sub, right = "") =>
    `<div class="page-head"><div><h1>${esc(title)}</h1>${sub ? `<p>${sub}</p>` : ""}</div><div class="flex items-center gap-2 wrap">${right}</div></div>`;
})();
