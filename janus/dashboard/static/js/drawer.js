// Finding drawer: docked on wide screens, overlay on narrow ones. Triage
// (status + note) sits directly under the title, always visible, so the
// most-repeated action in the product is one click (or one number key).
(function () {
  const { esc, icon } = J;
  const D = (J.drawer = { fp: null, ctx: [], noteBase: "" });

  const root = () => J.$("#drawer");

  D.setContext = (fps) => { D.ctx = fps || []; if (D.fp) updateNav(); };

  D.open = (fp, ctx) => {
    if (ctx) D.ctx = ctx;
    const f = J.byFp(fp);
    if (!f) return;
    flushNote();                       // never lose a half-typed note by moving on
    D.fp = fp;
    render(f);
    root().classList.add("open");
    root().setAttribute("aria-hidden", "false");
    J.$("#main").classList.add("has-drawer");
    J.$("#drawerScrim").classList.add("show");
    J.emit("drawer", { fp });
  };

  D.close = () => {
    if (!D.fp) return;
    flushNote();
    D.fp = null;
    root().classList.remove("open");
    root().setAttribute("aria-hidden", "true");
    J.$("#main").classList.remove("has-drawer");
    J.$("#drawerScrim").classList.remove("show");
    J.emit("drawer", { fp: null });
  };

  D.step = (dir) => {
    const i = D.ctx.indexOf(D.fp);
    const next = D.ctx[i + dir];
    if (next) D.open(next);
  };

  function noteEl() { return J.$("#drNote"); }
  function flushNote() {
    const ta = noteEl();
    if (!ta || !D.fp) return;
    const f = J.byFp(D.fp);
    if (f && ta.value !== (f.notes || "")) J.patch([{ fp: f.fingerprint, status: f.status, notes: ta.value }]);
  }

  function updateNav() {
    const i = D.ctx.indexOf(D.fp);
    const pos = J.$("#drPos");
    if (pos) pos.textContent = i >= 0 && D.ctx.length > 1 ? `${i + 1} of ${D.ctx.length}` : "";
    const prev = J.$("#drPrev"), next = J.$("#drNext");
    if (prev) prev.disabled = i <= 0;
    if (next) next.disabled = i < 0 || i >= D.ctx.length - 1;
  }

  const kv = (k, v, mono) => (v == null || v === "" ? "" : `<dt>${k}</dt><dd class="${mono ? "mono" : ""}">${v}</dd>`);

  function statusButtons(f) {
    return J.STATUSES.map((s) => `
      <button class="st-btn ${s.id}" data-status="${s.id}" aria-pressed="${f.status === s.id}" data-tip="${esc(s.hint)}">
        ${icon(s.icon, "sm")}<span>${esc(s.label)}</span><kbd>${s.key}</kbd>
      </button>`).join("");
  }

  function render(f) {
    const loc = J.locationOf(f);
    const eng = J.ENGINES[f.engine] || { label: f.engine };
    const ex = f.extra || {};
    const cwes = (f.cwe || []).map((c) => {
      const m = /(\d+)/.exec(c);
      return m ? `<a class="tag mono" href="https://cwe.mitre.org/data/definitions/${m[1]}.html" target="_blank" rel="noopener noreferrer">${esc(c)}</a>` : `<span class="tag mono">${esc(c)}</span>`;
    }).join("");
    const owasp = (f.owasp || []).map((o) => `<span class="tag mono">${esc(o)}</span>`).join("");
    const locSample = Array.isArray(ex.locations_sample) ? ex.locations_sample : [];
    const also = Array.isArray(ex.also_reported_by) ? ex.also_reported_by : [];
    const evidence = f.snippet ? `<div class="code-block"><button class="btn sm ghost copy-btn" data-copy="snippet">${icon("copy", "sm")}Copy</button><pre>${esc(f.snippet)}</pre></div>` : "";
    const poc = ex.poc ? `<div class="mt-2"><h3>Proof of concept</h3><div class="code-block"><pre>${esc(ex.poc)}</pre></div></div>` : "";

    root().innerHTML = `
      <div class="dr-head">
        <div class="dr-bar">
          <div class="flex items-center gap-2">
            <button class="btn sm icon ghost" id="drPrev" aria-label="Previous finding" data-tip="Previous  (k)">${icon("chevU", "sm")}</button>
            <button class="btn sm icon ghost" id="drNext" aria-label="Next finding" data-tip="Next  (j)">${icon("chevD", "sm")}</button>
            <span class="muted tnum" id="drPos"></span>
          </div>
          <button class="btn sm icon ghost" id="drClose" aria-label="Close details" data-tip="Close  (Esc)">${icon("x")}</button>
        </div>
        <div class="dr-badges">
          <span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span>
          <span class="eng ${esc(f.engine)}"><i></i>${esc(eng.label)}<span class="tool">/ ${esc(f.tool)}</span></span>
          <span class="tag" data-tip="Confidence in the finding">${esc(f.confidence || "needs-review")}</span>
          <span class="tag">${esc(J.catLabel(f.category))}</span>
        </div>
        <h2 class="dr-title">${esc(f.title)}</h2>
        ${loc ? `<div class="dr-loc"><code class="mono">${esc(loc)}</code><button class="btn sm ghost icon copy-btn" data-copy="loc" aria-label="Copy location">${icon("copy", "sm")}</button></div>` : ""}
      </div>

      <div class="dr-triage">
        <div class="dr-triage-head"><h3>Triage</h3><span class="muted" id="drSaved"></span></div>
        <div class="st-row" role="group" aria-label="Status">${statusButtons(f)}</div>
        <textarea class="textarea" id="drNote" rows="2" placeholder="Add a triage note — why it’s fixed, ticket link, justification…  (Ctrl+Enter to save)">${esc(f.notes || "")}</textarea>
        <div class="flex items-center gap-2">
          <label class="muted flex items-center gap-2" style="cursor:pointer"><input type="checkbox" class="check" id="drAdvance" ${J.pref.get("advance", "0") === "1" ? "checked" : ""}/> Advance to next after status change</label>
          <button class="btn sm primary ml-auto" id="drSave" disabled>Save note</button>
        </div>
      </div>

      <div class="dr-body">
        <section><h3>What’s wrong</h3><p>${esc(f.message || "No description provided by the tool.")}</p></section>
        ${f.remediation ? `<section><h3>How to fix</h3><p>${esc(f.remediation)}</p></section>` : ""}
        ${evidence || poc ? `<section><h3>Evidence</h3>${evidence}${poc}</section>` : ""}
        ${cwes || owasp ? `<section><h3>Standards</h3><div class="flex wrap gap-2">${cwes}${owasp}</div></section>` : ""}
        <section>
          <h3>Details</h3>
          <dl class="kv">
            ${kv("Engine", `${esc(eng.label)} · ${esc(f.tool)}`)}
            ${kv("Rule", esc(f.rule_id), true)}
            ${kv("Category", esc(J.catLabel(f.category)))}
            ${kv("Confidence", esc(f.confidence || "needs-review"))}
            ${kv("Method", esc(f.method), true)}
            ${kv("Endpoint", esc(f.endpoint), true)}
            ${kv("Host", esc(f.host), true)}
            ${kv("Target", esc(f.target), true)}
            ${kv("File", f.path ? esc(f.path) + (f.line ? `:${f.line}${f.end_line && f.end_line !== f.line ? "–" + f.end_line : ""}` : "") : "", true)}
            ${kv("Sources", esc((f.sources || []).join(", ")))}
            ${ex.occurrences ? kv("Occurrences", esc(ex.occurrences)) : ""}
            ${also.length ? kv("Also reported by", esc(also.join(", "))) : ""}
            ${kv("First seen", `<span data-tip="${esc(J.abs(f.first_seen))}">${esc(J.rel(f.first_seen))}</span>`)}
            ${kv("Last seen", `<span data-tip="${esc(J.abs(f.last_seen))}">${esc(J.rel(f.last_seen))}</span>`)}
            ${kv("Fingerprint", `${esc(f.fingerprint)} <button class="btn sm ghost icon copy-btn" data-copy="fp" aria-label="Copy fingerprint">${icon("copy", "sm")}</button>`, true)}
          </dl>
          ${locSample.length ? `<h3 class="mt-3">More locations</h3><ul class="loc-list">${locSample.slice(0, 12).map((l) => `<li class="mono">${esc(typeof l === "string" ? l : JSON.stringify(l))}</li>`).join("")}</ul>` : ""}
        </section>
        <details class="raw"><summary>Raw record</summary><pre>${esc(JSON.stringify(f, null, 2))}</pre></details>
      </div>`;
    D.noteBase = f.notes || "";
    wire(f);
    updateNav();
    root().scrollTop = 0;
    const body = J.$(".dr-body", root()); if (body) body.scrollTop = 0;
  }

  function wire(f) {
    const r = root();
    J.$("#drClose", r).onclick = D.close;
    J.$("#drPrev", r).onclick = () => D.step(-1);
    J.$("#drNext", r).onclick = () => D.step(1);
    const ta = J.$("#drNote", r), save = J.$("#drSave", r);
    ta.addEventListener("input", () => { save.disabled = ta.value === (J.byFp(D.fp).notes || ""); J.$("#drSaved").textContent = save.disabled ? "" : "Unsaved note"; });
    ta.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); save.click(); }
      else if (e.key === "Escape") { e.stopPropagation(); ta.blur(); }
    });
    save.onclick = async () => {
      const cur = J.byFp(D.fp);
      save.disabled = true;
      const n = await J.patch([{ fp: cur.fingerprint, status: cur.status, notes: ta.value }]);
      J.$("#drSaved").textContent = n ? "Saved ✓" : "";
    };
    J.$("#drAdvance", r).addEventListener("change", (e) => J.pref.set("advance", e.target.checked ? "1" : "0"));
    r.querySelectorAll(".st-btn").forEach((b) => b.addEventListener("click", () => D.setStatus(b.dataset.status)));
    r.querySelectorAll("[data-copy]").forEach((b) =>
      b.addEventListener("click", () => {
        const cur = J.byFp(D.fp);
        const what = b.dataset.copy;
        J.copy(what === "fp" ? cur.fingerprint : what === "loc" ? J.locationOf(cur) : cur.snippet || "", "Copied to clipboard");
      }));
  }

  // Triage the open finding from the drawer (buttons or number keys).
  D.setStatus = async (status) => {
    const f = J.byFp(D.fp);
    if (!f) return;
    const ta = noteEl();
    const notes = ta ? ta.value : undefined;
    const nextFp = D.ctx[D.ctx.indexOf(D.fp) + 1];
    const adv = J.$("#drAdvance") && J.$("#drAdvance").checked;
    await J.patch([{ fp: f.fingerprint, status, notes }], { label: `Marked “${truncate(f.title, 44)}” as ${J.statusLabel(status)}` });
    if (adv && nextFp) D.open(nextFp);
  };

  const truncate = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

  // Keep the open drawer in sync with optimistic updates / refreshes.
  J.on("data", () => {
    if (!D.fp) return;
    const f = J.byFp(D.fp);
    if (!f) { D.close(); return; }
    const r = root();
    r.querySelectorAll(".st-btn").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.status === f.status)));
    const ta = noteEl();
    if (ta && document.activeElement !== ta && ta.value !== (f.notes || "") && !J.$("#drSave").disabled === false) ta.value = f.notes || "";
    const save = J.$("#drSave"); if (save && ta) save.disabled = ta.value === (f.notes || "");
  });

  document.addEventListener("DOMContentLoaded", () => {
    J.$("#drawerScrim").addEventListener("click", D.close);
  });
})();
