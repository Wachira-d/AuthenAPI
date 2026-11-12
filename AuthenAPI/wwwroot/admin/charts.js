// Small SVG/HTML charts. Colors come from CSS custom properties via classes (see styles.css "viz").
import { h, s, clear, fmtNum, fmtCompact, fmtMs, fmtClock, fmtTime, fmtPct } from './ui.js';
import { t } from './i18n.js';

// ---------- shared tooltip ----------
let tip;
function tooltipEl() {
  if (!tip) {
    tip = h('div.viz-tip', { role: 'tooltip' });
    document.body.append(tip);
  }
  return tip;
}
/** rows: [{ value, label, key: 'line-s1'|'swatch-good'… }] */
export function showTip(x, y, title, rows) {
  const el = tooltipEl();
  clear(el);
  if (title) el.append(h('div.viz-tip-title', { text: title }));
  for (const r of rows) {
    el.append(h('div.viz-tip-row',
      r.key ? h(`span.viz-key.${r.key}`, { 'aria-hidden': 'true' }) : null,
      h('strong.viz-tip-val', { text: r.value }),
      h('span.viz-tip-label', { text: r.label })));
  }
  el.classList.add('show');
  const pad = 14;
  const rect = el.getBoundingClientRect();
  let left = x + pad, top = y + pad;
  if (left + rect.width > window.innerWidth - 8) left = x - rect.width - pad;
  if (top + rect.height > window.innerHeight - 8) top = y - rect.height - pad;
  el.style.left = `${Math.max(8, left)}px`;
  el.style.top = `${Math.max(8, top)}px`;
}
export function hideTip() { if (tip) tip.classList.remove('show'); }

export function legend(items) {
  return h('div.viz-legend', items.map((i) => h('span.viz-legend-item',
    h(`span.viz-swatch.${i.cls}`, { 'aria-hidden': 'true' }),
    h('span', { text: i.label }))));
}

function niceMax(v) {
  if (v <= 0) return 4;
  const pow = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 4, 5, 10]) if (m * pow >= v) return m * pow;
  return 10 * pow;
}

/** Re-render on container resize (debounced). Returns a disconnect fn stored on the node. */
function responsive(container, draw) {
  let last = 0;
  const run = () => {
    if (last && !container.isConnected) { ro.disconnect(); return; }
    const w = Math.round(container.clientWidth);
    if (!w || w === last) return;
    last = w;
    draw(w);
  };
  const ro = new ResizeObserver(() => requestAnimationFrame(run));
  ro.observe(container);
  requestAnimationFrame(run);
}

function roundedTopRect(x, y, w, hgt, r) {
  r = Math.max(0, Math.min(r, w / 2, hgt));
  return `M${x},${y + hgt}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + hgt}Z`;
}

/**
 * Stacked column chart over time.
 * buckets: [{ start: Date, values: number[] }]; series: [{ label, cls }] bottom → top.
 * opts: { bucketMinutes, height, ariaLabel }
 */
export function stackedColumns(buckets, series, opts = {}) {
  const wrap = h('div.viz-chart');
  const H = opts.height || 200;
  const AX = 22; // x-axis band
  const ML = 44, MR = 8, MT = 8;
  const fmtX = (d) => fmtClock(d, (opts.bucketMinutes || 60) >= 360);
  const totals = buckets.map((b) => b.values.reduce((a, v) => a + (v || 0), 0));
  const yMax = niceMax(Math.max(0, ...totals));

  responsive(wrap, (W) => {
    clear(wrap);
    const pw = W - ML - MR, ph = H - MT;
    const n = buckets.length || 1;
    const band = pw / n;
    const barW = Math.max(1, Math.min(24, band >= 4 ? band - Math.max(2, band * 0.3) : band - 0.5));
    const y = (v) => MT + ph - (v / yMax) * ph;
    const svg = s('svg', { class: 'viz-svg', width: W, height: H + AX, viewBox: `0 0 ${W} ${H + AX}`, role: 'img', 'aria-label': opts.ariaLabel || '', tabindex: '0' });

    // grid + y ticks
    for (let i = 0; i <= 4; i++) {
      const v = (yMax / 4) * i;
      const yy = Math.round(y(v)) + 0.5;
      svg.append(s('line', { class: i === 0 ? 'viz-axis' : 'viz-grid', x1: ML, x2: W - MR, y1: yy, y2: yy }));
      svg.append(s('text', { class: 'viz-tick', x: ML - 6, y: yy + 4, 'text-anchor': 'end', text: fmtCompact(v) }));
    }
    // x ticks
    const tickEvery = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(pw / 90))));
    buckets.forEach((b, i) => {
      if (i % tickEvery !== 0) return;
      const cx = ML + band * i + band / 2;
      svg.append(s('text', { class: 'viz-tick', x: cx, y: H + 15, 'text-anchor': i === 0 ? 'start' : 'middle', text: fmtX(b.start) }));
    });

    const hl = s('rect', { class: 'viz-band-hl', x: 0, y: MT, width: band, height: ph, visibility: 'hidden' });
    svg.append(hl);

    // bars
    buckets.forEach((b, i) => {
      const x = ML + band * i + (band - barW) / 2;
      let acc = 0;
      const nonZero = b.values.map((v, k) => (v > 0 ? k : -1)).filter((k) => k >= 0);
      const topK = nonZero[nonZero.length - 1];
      b.values.forEach((v, k) => {
        if (!(v > 0)) return;
        const y0 = y(acc), y1 = y(acc + v);
        acc += v;
        let top = y1, hgt = y0 - y1;
        if (k !== nonZero[0] && hgt > 2) { hgt -= 2; } // 2px surface gap above the segment below
        if (hgt < 0.75) { top = y0 - 0.75; hgt = 0.75; }
        const cls = `viz-mark ${series[k].cls}`;
        svg.append(k === topK
          ? s('path', { class: cls, d: roundedTopRect(x, top, barW, hgt, 4) })
          : s('rect', { class: cls, x, y: top, width: barW, height: hgt }));
      });
    });

    // hit layer
    const hit = s('rect', { x: ML, y: MT, width: pw, height: ph, class: 'viz-hit' });
    svg.append(hit);
    let active = -1;
    const show = (i, cx, cy) => {
      active = i;
      const b = buckets[i];
      hl.setAttribute('x', ML + band * i);
      hl.setAttribute('visibility', 'visible');
      const end = new Date(b.start.getTime() + (opts.bucketMinutes || 60) * 60000);
      const rows = [{ value: fmtNum(totals[i]), label: t('dash.total') }]
        .concat(series.map((se, k) => ({ value: fmtNum(b.values[k] || 0), label: se.label, key: se.cls.replace('fill', 'line') })).reverse());
      showTip(cx, cy, `${fmtTime(b.start.toISOString(), { seconds: false })} – ${fmtClock(end)}`, rows);
    };
    const hide = () => { active = -1; hl.setAttribute('visibility', 'hidden'); hideTip(); };
    hit.addEventListener('pointermove', (e) => {
      const r = svg.getBoundingClientRect();
      const i = Math.min(n - 1, Math.max(0, Math.floor((e.clientX - r.left - ML) / band)));
      show(i, e.clientX, e.clientY);
    });
    hit.addEventListener('pointerleave', hide);
    svg.addEventListener('blur', hide);
    svg.addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
      e.preventDefault();
      const i = Math.min(n - 1, Math.max(0, (active < 0 ? n : active) + (e.key === 'ArrowRight' ? 1 : -1)));
      const r = svg.getBoundingClientRect();
      show(i, r.left + ML + band * i + band / 2, r.top + MT + 20);
    });
    wrap.append(svg);
  });
  return wrap;
}

/**
 * One cell per health sample (ok = good, fail = critical). Runs of equal state are merged for drawing only.
 * samples: HealthSample[] oldest first.
 */
export function availabilityStrip(samples, opts = {}) {
  const wrap = h('div.viz-strip');
  const H = opts.height || 28;
  responsive(wrap, (W) => {
    clear(wrap);
    const n = samples.length;
    const cw = W / n;
    const svg = s('svg', { class: 'viz-svg', width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': opts.ariaLabel || '', tabindex: '0' });
    // runs
    let i = 0;
    const gap = cw >= 4 ? 2 : 0;
    while (i < n) {
      let j = i;
      while (j + 1 < n && !!samples[j + 1].ok === !!samples[i].ok && gap === 0) j++;
      const x = i * cw;
      let w = (j - i + 1) * cw - gap;
      if (!samples[i].ok) w = Math.max(w, 2);
      // Height is the secondary encoding (good vs critical alone is not CVD-safe): failures stand full height.
      const okH = Math.round(H * 0.55);
      svg.append(samples[i].ok
        ? s('rect', { class: 'viz-cell fill-good', x, y: H - okH, width: Math.max(w, 0.5), height: okH, rx: cw >= 6 ? 2 : 0 })
        : s('rect', { class: 'viz-cell fill-critical', x, y: 0, width: Math.max(w, 0.5), height: H, rx: cw >= 6 ? 2 : 0 }));
      i = j + 1;
    }
    const cursor = s('rect', { class: 'viz-cursor', x: 0, y: 0, width: Math.max(2, cw), height: H, visibility: 'hidden' });
    svg.append(cursor);
    let active = -1;
    const show = (idx, cx, cy) => {
      active = idx;
      const sm = samples[idx];
      cursor.setAttribute('x', idx * cw);
      cursor.setAttribute('visibility', 'visible');
      const rows = [
        { value: sm.ok ? t('dash.availOk') : t('dash.availFail'), label: '', key: sm.ok ? 'line-good' : 'line-critical' },
        { value: fmtMs(sm.latencyMs), label: t('col.latency') },
      ];
      if (sm.strategy) rows.push({ value: sm.strategy, label: t('col.strategy') });
      if (sm.error) rows.push({ value: sm.error, label: t('col.error') });
      showTip(cx, cy, fmtTime(sm.timestamp), rows);
    };
    const hide = () => { active = -1; cursor.setAttribute('visibility', 'hidden'); hideTip(); };
    svg.addEventListener('pointermove', (e) => {
      const r = svg.getBoundingClientRect();
      show(Math.min(n - 1, Math.max(0, Math.floor((e.clientX - r.left) / cw))), e.clientX, e.clientY);
    });
    svg.addEventListener('pointerleave', hide);
    svg.addEventListener('blur', hide);
    svg.addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
      e.preventDefault();
      const step = e.shiftKey ? 60 : 1;
      const idx = Math.min(n - 1, Math.max(0, (active < 0 ? n : active) + (e.key === 'ArrowRight' ? step : -step)));
      const r = svg.getBoundingClientRect();
      show(idx, r.left + idx * cw, r.bottom);
    });
    wrap.append(svg);
  });
  const first = samples[0], last = samples[samples.length - 1];
  const axis = h('div.viz-strip-axis',
    h('span', { text: first ? fmtClock(new Date(first.timestamp), true) : '' }),
    h('span', { text: last ? fmtClock(new Date(last.timestamp), true) : '' }));
  return h('div', null, wrap, axis);
}

/** Ranked horizontal bars, one color. items: [{ label: Node|string, value, title }] */
export function hBars(items, opts = {}) {
  const max = Math.max(1, ...items.map((i) => i.value));
  const total = items.reduce((a, i) => a + i.value, 0) || 1;
  return h('div.viz-hbars', { role: 'list' }, items.map((it) => {
    const bar = h('span.viz-hbar.fill-s1');
    bar.style.width = `${Math.max(0.5, (it.value / max) * 100)}%`;
    const row = h('div.viz-hbar-row', { role: 'listitem', tabindex: '0' },
      h('span.viz-hbar-label', null, it.label),
      h('span.viz-hbar-track', null, bar, h('span.viz-hbar-val', { text: fmtNum(it.value) })));
    const showIt = (x, y) => showTip(x, y, it.title || (typeof it.label === 'string' ? it.label : ''), [
      { value: fmtNum(it.value), label: opts.valueLabel || t('col.count'), key: 'line-s1' },
      { value: fmtPct((it.value / total) * 100), label: '' },
    ]);
    row.addEventListener('pointermove', (e) => showIt(e.clientX, e.clientY));
    row.addEventListener('pointerleave', hideTip);
    row.addEventListener('focus', () => { const r = row.getBoundingClientRect(); showIt(r.right - 120, r.bottom); });
    row.addEventListener('blur', hideTip);
    return row;
  }));
}

/** Small sparkline-ish column chart for the key usage modal: reuses stackedColumns with a lower height. */
export function miniColumns(buckets, series, bucketMinutes) {
  return stackedColumns(buckets, series, { height: 120, bucketMinutes });
}
