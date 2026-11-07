// Hand-rolled SVG/CSS charts — themed via CSS variables, zero dependencies,
// works offline (a security tool shouldn't need a CDN to draw a donut).
(function () {
  const SEV_VAR = { critical: "--sev-critical", high: "--sev-high", medium: "--sev-medium", low: "--sev-low", info: "--sev-info" };
  J.sevColor = (s) => `var(${SEV_VAR[s] || "--sev-info"})`;

  // Horizontal stacked severity bar (HTML flex).
  J.sevBar = (counts, cls = "") => {
    const total = J.SEVERITIES.reduce((a, s) => a + (counts[s] || 0), 0);
    if (!total) return `<div class="sbar ${cls}"></div>`;
    return `<div class="sbar ${cls}" role="img" aria-label="${J.SEVERITIES.filter((s) => counts[s]).map((s) => counts[s] + " " + s).join(", ")}">` +
      J.SEVERITIES.filter((s) => counts[s]).map((s) =>
        `<i class="s-${s}" style="flex:${counts[s]}" data-tip="${counts[s]} ${s}"></i>`).join("") + `</div>`;
  };

  J.legend = (counts) =>
    `<div class="legend">` + J.SEVERITIES.map((s) =>
      `<span class="legend-item"><span class="legend-dot s-${s}"></span>${J.cap(s)} <b class="tnum">${counts[s] || 0}</b></span>`).join("") + `</div>`;

  // Donut. segs: [{key,label,value,color}]
  J.donut = (segs, { size = 168, thick = 20, center = null, attr = "data-seg" } = {}) => {
    const r = (size - thick) / 2, c = 2 * Math.PI * r;
    const total = segs.reduce((a, s) => a + s.value, 0);
    let off = 0;
    const gap = segs.filter((s) => s.value).length > 1 ? 2.5 : 0;
    const arcs = total
      ? segs.filter((s) => s.value).map((s) => {
          const len = (s.value / total) * c;
          const dash = Math.max(len - gap, 0.5);
          const out = `<circle class="arc" cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${s.color}" stroke-width="${thick}"
            stroke-dasharray="${dash} ${c - dash}" stroke-dashoffset="${-off}" ${attr}="${J.esc(s.key)}" data-tip="${J.esc(s.label)}: ${s.value} (${Math.round((s.value / total) * 100)}%)"/>`;
          off += len;
          return out;
        }).join("")
      : "";
    return `<div class="donut" style="width:${size}px;height:${size}px">
      <svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img">
        <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="var(--surface-3)" stroke-width="${thick}"/>
        <g transform="rotate(-90 ${size / 2} ${size / 2})">${arcs}</g>
      </svg>
      ${center ? `<div class="donut-center"><div class="v">${center.value}</div><div class="l">${J.esc(center.label)}</div></div>` : ""}
    </div>`;
  };

  // Stacked-by-severity column chart with a cumulative line.
  // buckets: [{t, label, counts:{sev:n}, total, cum}]
  J.timeChart = (buckets, { height = 230 } = {}) => {
    const W = 760, H = height, m = { l: 34, r: 40, t: 14, b: 26 };
    const iw = W - m.l - m.r, ih = H - m.t - m.b;
    const maxBar = Math.max(1, ...buckets.map((b) => b.total));
    const maxCum = Math.max(1, ...buckets.map((b) => b.cum));
    const yMax = niceMax(maxBar);
    const step = iw / buckets.length;
    const bw = Math.min(46, step * 0.62);
    const y = (v) => m.t + ih - (v / yMax) * ih;
    const yc = (v) => m.t + ih - (v / maxCum) * ih;

    let grid = "";
    for (let i = 0; i <= 4; i++) {
      const v = (yMax / 4) * i, yy = y(v);
      grid += `<line x1="${m.l}" x2="${W - m.r}" y1="${yy}" y2="${yy}" stroke="var(--border)" ${i ? 'stroke-dasharray="3 4"' : ""}/>
        <text x="${m.l - 8}" y="${yy + 3.5}" text-anchor="end" class="ax">${fmtTick(v)}</text>`;
    }
    let bars = "", labels = "", pts = [];
    const every = Math.ceil(buckets.length / 10);
    buckets.forEach((b, i) => {
      const cx = m.l + step * i + step / 2;
      let acc = 0;
      const tip = `**${b.label}**\n${b.total} new · ${b.cum} total` + J.SEVERITIES.filter((s) => b.counts[s]).map((s) => `\n${b.counts[s]} ${s}`).join("");
      let seg = "";
      J.SEVERITIES.slice().reverse().forEach((s) => {
        const v = b.counts[s] || 0;
        if (!v) return;
        const y1 = y(acc + v), y0 = y(acc);
        seg += `<rect x="${cx - bw / 2}" y="${y1}" width="${bw}" height="${Math.max(y0 - y1 - 1, 1)}" rx="2" fill="var(${SEV_VAR[s]})"/>`;
        acc += v;
      });
      bars += `<g class="col" data-tip="${J.esc(tip)}"><rect x="${cx - step / 2}" y="${m.t}" width="${step}" height="${ih}" fill="transparent"/>${seg}</g>`;
      if (i % every === 0) labels += `<text x="${cx}" y="${H - 7}" text-anchor="middle" class="ax">${J.esc(b.short)}</text>`;
      pts.push([cx, yc(b.cum)]);
    });
    const line = pts.length > 1 ? `<polyline points="${pts.map((p) => p.join(",")).join(" ")}" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>` : "";
    const dots = pts.map((p) => `<circle cx="${p[0]}" cy="${p[1]}" r="3" fill="var(--surface)" stroke="var(--accent)" stroke-width="2"/>`).join("");
    const rAxis = [0, 1].map((i) => `<text x="${W - m.r + 8}" y="${m.t + ih - ih * i + 3.5}" text-anchor="start" class="ax ax-r">${i ? maxCum : 0}</text>`).join("");
    return `<svg class="tchart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Findings first seen over time">${grid}${bars}${line}${dots}${labels}${rAxis}</svg>`;
  };
  function niceMax(v) {
    if (v <= 4) return 4;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    const n = v / p;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 4 ? 4 : n <= 8 ? 8 : 10) * p;
  }
  function fmtTick(v) { return Number.isInteger(v) ? String(v) : v.toFixed(1); }
})();
