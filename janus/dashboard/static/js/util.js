// Janus dashboard — shared helpers. Classic scripts + one global namespace (J):
// no build step, and no dependence on the server sending a module MIME type.
(function () {
  const J = (window.J = window.J || {});

  J.SEVERITIES = ["critical", "high", "medium", "low", "info"];
  J.SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  J.SEV_WEIGHT = { critical: 10, high: 6, medium: 3, low: 1, info: 0.25 };
  J.CONF_RANK = { confirmed: 0, likely: 1, "needs-review": 2 };
  J.CONFIDENCES = ["confirmed", "likely", "needs-review"];

  // key = keyboard shortcut for the triage action. Order matters (1..5).
  J.STATUSES = [
    { id: "open", label: "Open", icon: "circle", key: "1", hint: "Not yet triaged" },
    { id: "needs-review", label: "Needs review", icon: "eye", key: "2", hint: "A human should look at this" },
    { id: "fixed", label: "Fixed", icon: "checkCircle", key: "3", hint: "Remediated" },
    { id: "ruled-out", label: "Ruled out", icon: "ban", key: "4", hint: "False positive / not applicable" },
    { id: "accepted-risk", label: "Accepted risk", icon: "shieldCheck", key: "5", hint: "Known, consciously accepted" },
  ];
  J.STATUS_BY_ID = Object.fromEntries(J.STATUSES.map((s) => [s.id, s]));
  J.statusLabel = (id) => (J.STATUS_BY_ID[id] ? J.STATUS_BY_ID[id].label : id || "—");
  J.isActive = (f) => f.status === "open" || f.status === "needs-review";

  const CAT_LABELS = {
    injection: "Injection", xss: "XSS", deserialization: "Deserialization", auth: "Authentication",
    "access-control": "Access control", secrets: "Secrets", crypto: "Cryptography", configuration: "Configuration",
    container: "Container", "ci-cd": "CI/CD", "supply-chain": "Supply chain", exposure: "Exposure",
    network: "Network", client: "Client-side", other: "Other",
  };
  J.catLabel = (c) => CAT_LABELS[c] || (c ? c.charAt(0).toUpperCase() + c.slice(1) : "—");
  J.ENGINES = {
    code: { id: "code", label: "Code", face: "Inward", blurb: "Source code, secrets & dependencies", icon: "code" },
    recon: { id: "recon", label: "Recon", face: "Outward", blurb: "Live attack surface", icon: "radar" },
  };

  J.esc = (s) =>
    String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  J.$ = (sel, root = document) => root.querySelector(sel);
  J.$$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  J.html = (s) => { const t = document.createElement("template"); t.innerHTML = s.trim(); return t.content.firstElementChild; };
  J.n = (x) => Number(x || 0).toLocaleString();
  J.plural = (n, one, many) => `${J.n(n)} ${n === 1 ? one : many || one + "s"}`;
  J.debounce = (fn, ms = 120) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
  J.cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

  // ---- tiny pub/sub ------------------------------------------------------
  const handlers = {};
  J.on = (ev, fn) => { (handlers[ev] = handlers[ev] || []).push(fn); return () => (handlers[ev] = handlers[ev].filter((h) => h !== fn)); };
  J.emit = (ev, data) => (handlers[ev] || []).slice().forEach((fn) => fn(data));

  // ---- time --------------------------------------------------------------
  J.ts = (iso) => { const t = Date.parse(iso || ""); return Number.isNaN(t) ? null : t; };
  J.rel = (iso, now = Date.now()) => {
    const t = J.ts(iso);
    if (t == null) return "—";
    const s = Math.round((now - t) / 1000);
    if (s < 45) return "just now";
    const m = Math.round(s / 60); if (m < 60) return `${m}m ago`;
    const h = Math.round(m / 60); if (h < 24) return `${h}h ago`;
    const d = Math.round(h / 24); if (d < 14) return `${d}d ago`;
    const w = Math.round(d / 7); if (w < 9) return `${w}w ago`;
    const mo = Math.round(d / 30); if (mo < 18) return `${mo}mo ago`;
    return `${Math.round(d / 365)}y ago`;
  };
  J.abs = (iso) => {
    const t = J.ts(iso);
    return t == null ? "—" : new Date(t).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  };
  J.absDate = (t) => new Date(t).toLocaleDateString(undefined, { month: "short", day: "numeric" });

  // ---- finding helpers ---------------------------------------------------
  // Where a finding lives, as one display string.
  J.locationOf = (f) => {
    if (f.engine === "code" || (f.path && !f.host)) return `${f.path || ""}${f.line ? ":" + f.line : ""}`;
    const base = f.target || f.host || "";
    return f.endpoint && !base.endsWith(f.endpoint) ? `${f.host || base}${f.endpoint}` : base || f.endpoint || "";
  };
  // The "asset" a finding belongs to: a host (outward) or a file (inward).
  J.assetOf = (f) => {
    if (f.host) return { kind: "host", key: f.host };
    if (f.path) return { kind: "file", key: f.path };
    if (f.target) return { kind: "host", key: f.target };
    return { kind: "other", key: "(unattributed)" };
  };
  J.shortPath = (p) => {
    const parts = String(p || "").replace(/\\/g, "/").split("/");
    if (parts.length <= 3) return parts.join("/");
    return "…/" + parts.slice(-3).join("/");
  };
  J.splitPath = (p) => {
    const s = String(p || "").replace(/\\/g, "/");
    const i = s.lastIndexOf("/");
    return i < 0 ? { dir: "", base: s } : { dir: s.slice(0, i + 1), base: s.slice(i + 1) };
  };
  J.riskScore = (list) => list.reduce((a, f) => a + (J.isActive(f) ? J.SEV_WEIGHT[f.severity] || 0 : 0), 0);
  J.countBy = (list, fn) => { const m = {}; list.forEach((x) => { const k = fn(x); m[k] = (m[k] || 0) + 1; }); return m; };
  J.sevCounts = (list) => { const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }; list.forEach((f) => { if (c[f.severity] !== undefined) c[f.severity]++; }); return c; };
  J.worstSeverity = (list) => { let w = 9; list.forEach((f) => { const r = J.SEV_RANK[f.severity]; if (r !== undefined && r < w) w = r; }); return J.SEVERITIES[w] || "info"; };

  J.copy = async (text, msg = "Copied") => {
    try { await navigator.clipboard.writeText(text); J.toast(msg); }
    catch (e) {
      const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); J.toast(msg); } catch (_) { J.toast("Copy failed", { error: true }); }
      ta.remove();
    }
  };

  // localStorage that never throws (private windows, blocked storage, previews)
  J.pref = {
    get(k, d) { try { const v = localStorage.getItem("janus." + k); return v == null ? d : v; } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem("janus." + k, v); } catch (e) { /* ignore */ } },
  };
})();
