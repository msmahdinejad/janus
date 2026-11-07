// UI primitives: toast, tooltip, popover/menu, modal.
(function () {
  const { esc, $, icon } = Object.assign({}, J, { icon: J.icon });

  // ---- toast -------------------------------------------------------------
  J.toast = (msg, opts = {}) => {
    const host = $("#toasts");
    if (!host) return;
    const el = J.html(`<div class="toast ${opts.error ? "error" : ""}" role="status"><span>${esc(msg)}</span></div>`);
    if (opts.action) {
      const b = document.createElement("button");
      b.textContent = opts.action.label;
      b.addEventListener("click", () => { opts.action.run(); el.remove(); });
      el.appendChild(b);
    }
    host.appendChild(el);
    while (host.children.length > 3) host.firstChild.remove();
    setTimeout(() => el.remove(), opts.ms || (opts.action ? 7000 : 3200));
  };

  // ---- tooltip (delegated: any element with data-tip) ---------------------
  let tipEl = null;
  function showTip(target) {
    const text = target.getAttribute("data-tip");
    if (!text) return;
    hideTip();
    tipEl = J.html(`<div class="tip" role="tooltip"></div>`);
    tipEl.innerHTML = esc(text).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>");
    document.body.appendChild(tipEl);
    const r = target.getBoundingClientRect();
    const t = tipEl.getBoundingClientRect();
    let x = r.left + r.width / 2 - t.width / 2;
    let y = r.top - t.height - 7;
    if (y < 6) y = r.bottom + 7;
    x = Math.max(6, Math.min(x, innerWidth - t.width - 6));
    tipEl.style.left = x + "px"; tipEl.style.top = y + "px";
  }
  function hideTip() { if (tipEl) { tipEl.remove(); tipEl = null; } }
  document.addEventListener("mouseover", (e) => { const t = e.target.closest && e.target.closest("[data-tip]"); if (t) showTip(t); });
  document.addEventListener("mouseout", (e) => { const t = e.target.closest && e.target.closest("[data-tip]"); if (t) hideTip(); });
  document.addEventListener("scroll", hideTip, true);
  document.addEventListener("mousedown", hideTip);
  J.hideTip = hideTip;

  // ---- popover -----------------------------------------------------------
  let current = null;
  J.closePopover = () => {
    if (!current) return;
    const { el, anchor, onClose, off } = current;
    current = null;
    el.remove(); off();
    if (anchor && anchor.setAttribute) anchor.setAttribute("aria-expanded", "false");
    if (onClose) onClose();
  };
  // Opens `content` (HTML string or element) anchored under `anchor`.
  J.popover = (anchor, content, opts = {}) => {
    const isSame = current && current.anchor === anchor;
    J.closePopover();
    if (isSame && !opts.force) return null;
    const el = J.html(`<div class="popover" role="${opts.role || "menu"}"></div>`);
    if (typeof content === "string") el.innerHTML = content; else el.appendChild(content);
    if (opts.width) el.style.width = opts.width + "px";
    document.body.appendChild(el);
    if (anchor.setAttribute) anchor.setAttribute("aria-expanded", "true");
    const place = () => {
      const r = anchor.getBoundingClientRect ? anchor.getBoundingClientRect() : anchor;
      const w = el.offsetWidth, h = el.offsetHeight;
      let x = opts.align === "right" ? r.right - w : r.left;
      let y = r.bottom + 6;
      if (y + h > innerHeight - 8 && r.top - h - 6 > 8) y = r.top - h - 6;
      x = Math.max(8, Math.min(x, innerWidth - w - 8));
      el.style.left = x + "px"; el.style.top = Math.max(8, y) + "px";
    };
    place();
    const onDown = (e) => { if (!el.contains(e.target) && !(anchor.contains && anchor.contains(e.target))) J.closePopover(); };
    const onKey = (e) => {
      if (e.key === "Escape") { e.stopPropagation(); J.closePopover(); if (anchor.focus) anchor.focus(); }
      else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        const items = Array.from(el.querySelectorAll(".menu-item"));
        if (!items.length) return;
        e.preventDefault();
        let i = items.indexOf(document.activeElement);
        i = e.key === "ArrowDown" ? (i + 1) % items.length : (i - 1 + items.length) % items.length;
        items[i].focus();
      }
    };
    document.addEventListener("mousedown", onDown, true);
    document.addEventListener("keydown", onKey, true);
    window.addEventListener("resize", J.closePopover);
    const off = () => {
      document.removeEventListener("mousedown", onDown, true);
      document.removeEventListener("keydown", onKey, true);
      window.removeEventListener("resize", J.closePopover);
    };
    current = { el, anchor, onClose: opts.onClose, off };
    const first = el.querySelector(".menu-item[data-autofocus], .menu-item.current, .menu-item");
    if (first && opts.focus !== false) first.focus({ preventScroll: true });
    return el;
  };

  // A menu of discrete choices. items: [{id,label,icon?,dot?,hint?,current?,sep?,head?}]
  J.menu = (anchor, items, onSelect, opts = {}) => {
    const body = items.map((it) => {
      if (it.sep) return `<div class="menu-sep"></div>`;
      if (it.head) return `<div class="menu-head">${esc(it.head)}</div>`;
      return `<button class="menu-item ${it.current ? "current" : ""}" role="menuitem" data-id="${esc(it.id)}">
        ${it.dot ? `<span class="dot" style="--c:${it.dot}"></span>` : ""}${it.icon ? icon(it.icon, "sm") : ""}
        <span>${esc(it.label)}</span>
        ${it.hint ? `<kbd class="kbd-hint">${esc(it.hint)}</kbd>` : it.count != null ? `<span class="count">${J.n(it.count)}</span>` : ""}
        ${it.current && !it.hint ? icon("check", "sm") : ""}
      </button>`;
    }).join("");
    const el = J.popover(anchor, body, opts);
    if (!el) return;
    el.addEventListener("click", (e) => {
      const b = e.target.closest(".menu-item");
      if (!b) return;
      J.closePopover();
      onSelect(b.getAttribute("data-id"));
    });
  };

  // ---- modal -------------------------------------------------------------
  let modal = null;
  J.closeModal = () => {
    if (!modal) return;
    const { scrim, el, prev, off } = modal; modal = null;
    scrim.remove(); el.remove(); off();
    if (prev && prev.focus) prev.focus({ preventScroll: true });
  };
  J.openModal = (html, opts = {}) => {
    J.closeModal(); J.closePopover();
    const prev = document.activeElement;
    const scrim = J.html(`<div class="scrim"></div>`);
    const el = J.html(`<div class="modal" role="dialog" aria-modal="true" aria-label="${esc(opts.label || "Dialog")}"></div>`);
    el.innerHTML = html;
    document.body.append(scrim, el);
    scrim.addEventListener("mousedown", J.closeModal);
    const onKey = (e) => { if (e.key === "Escape") { e.stopPropagation(); J.closeModal(); } };
    document.addEventListener("keydown", onKey, true);
    modal = { scrim, el, prev, off: () => document.removeEventListener("keydown", onKey, true) };
    return el;
  };
  J.modalOpen = () => !!modal;
})();
