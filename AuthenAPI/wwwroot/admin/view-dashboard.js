import { t } from './i18n.js';
import { get, post, qs } from './api.js';
import {
  h, replace, fmtNum, fmtCompact, fmtPct, fmtMs, fmtDuration, fmtTime, fmtRelative, ratePct, timeEl,
  badge, healthBadge, statusCodeEl, boolBadge, spinner, errorState, emptyState, table, kvList, toast, toastError,
  busy, visibleInterval,
} from './ui.js';
import { stackedColumns, availabilityStrip, hBars, legend } from './charts.js';

let range = '24h';

export function tile(label, value, sub, extra, opts = {}) {
  return h(`section.tile${opts.cls ? `.${opts.cls}` : ''}`, null,
    h('h3.tile-label', { text: label }),
    h('div.tile-value', null, value),
    extra ? h('div.tile-extra', null, extra) : null,
    sub ? h('div.tile-sub', null, sub) : null);
}

/** Card with a title, optional legend, a chart, and a table-view twin. */
export function chartCard(title, subtitle, chartNode, tableNode, legendNode, cls) {
  const tableWrap = h('div.chart-table', { hidden: true }, tableNode);
  const toggle = tableNode ? h('button.btn.btn-sm.btn-ghost', { type: 'button', text: t('common.showTable'), 'aria-expanded': 'false' }) : null;
  if (toggle) {
    toggle.addEventListener('click', () => {
      tableWrap.hidden = !tableWrap.hidden;
      toggle.textContent = tableWrap.hidden ? t('common.showTable') : t('common.hideTable');
      toggle.setAttribute('aria-expanded', String(!tableWrap.hidden));
    });
  }
  return h(`section.card${cls ? `.${cls}` : ''}`, null,
    h('div.card-head', null,
      h('div', null, h('h2.card-title', { text: title }), subtitle ? h('div.card-sub', { text: subtitle }) : null),
      toggle),
    legendNode || null,
    chartNode,
    tableWrap);
}

export function timelineBuckets(timeline) {
  return (timeline || []).map((b) => {
    const total = b.total || 0, err = Math.min(total, b.errors || 0);
    return { start: new Date(b.bucketStart), values: [total - err, err], raw: b };
  });
}
export const TIMELINE_SERIES = () => [
  { label: t('dash.seriesOk'), cls: 'fill-s1' },
  { label: t('dash.seriesErrors'), cls: 'fill-critical' },
];
export function timelineTable(timeline) {
  return table([
    { label: t('col.time'), render: (b) => fmtTime(b.bucketStart, { seconds: false }) },
    { label: t('dash.total'), num: true, render: (b) => fmtNum(b.total) },
    { label: t('col.errors'), num: true, render: (b) => fmtNum(b.errors) },
    { label: t('col.avgLatency'), num: true, render: (b) => fmtMs(b.avgLatencyMs) },
    { label: t('col.authOk'), num: true, render: (b) => fmtNum(b.authSuccess) },
    { label: t('col.authFail'), num: true, render: (b) => fmtNum(b.authFailure) },
  ], [...(timeline || [])].reverse());
}

export async function mount(root, ctx) {
  const rangeBtns = ['1h', '24h', '7d'].map((r) => h('button.seg-btn', {
    type: 'button', text: t(`dash.range.${r}`), 'aria-pressed': String(r === range), dataset: { r },
  }));
  const updated = h('span.muted.small');
  const checkBtn = ctx.isAdmin ? h('button.btn', { type: 'button', text: t('dash.checkNow') }) : null;
  const body = h('div.dash-body', null, spinner());

  replace(root,
    h('div.page-head', null,
      h('h1', { text: t('dash.title') }),
      h('div.toolbar', null,
        h('div.seg', { role: 'group', 'aria-label': t('dash.range') }, rangeBtns),
        h('span.muted.small', { text: t('dash.autoNote') }),
        updated,
        h('div.spacer'),
        checkBtn)),
    body);

  let alive = true;
  let loading = false;

  async function load() {
    if (loading || !alive) return;
    loading = true;
    body.classList.add('is-refreshing');
    const [health, metrics, history] = await Promise.allSettled([
      get('/health'),
      get(`/metrics${qs({ range })}`),
      get(`/health/history${qs({ hours: 24 })}`),
    ]);
    loading = false;
    if (!alive) return;
    body.classList.remove('is-refreshing');
    if (health.status === 'fulfilled') ctx.setHealth(health.value);
    render(health.status === 'fulfilled' ? health.value : null, metrics, history, health);
    updated.textContent = t('common.lastUpdated', { time: fmtTime(new Date().toISOString()) });
  }

  function render(hr, metricsRes, historyRes, healthRes) {
    const m = metricsRes.status === 'fulfilled' ? metricsRes.value : null;
    const hist = historyRes.status === 'fulfilled' ? historyRes.value || [] : null;
    if (!hr && !m) {
      replace(body, errorState(healthRes.reason || metricsRes.reason, load));
      return;
    }
    const parts = [];
    parts.push(renderTiles(hr, m, hist));
    if (!hr) parts.push(errorState(healthRes.reason, load));

    // charts
    if (m) {
      const buckets = timelineBuckets(m.timeline);
      const series = TIMELINE_SERIES();
      parts.push(chartCard(
        t('dash.chartRequests'), t('dash.chartRequestsSub', { n: m.bucketMinutes }),
        buckets.length ? stackedColumns(buckets, series, { bucketMinutes: m.bucketMinutes, ariaLabel: t('dash.chartRequests') }) : emptyState(),
        timelineTable(m.timeline),
        legend(series.map((x) => ({ label: x.label, cls: x.cls }))), 'card-wide'));
    } else {
      parts.push(errorState(metricsRes.reason, load));
    }
    parts.push(availabilityCard(hist, historyRes));

    const grid = h('div.grid-2');
    if (m) {
      const codes = [...(m.byStatusCode || [])].sort((a, b) => b.count - a.count);
      grid.append(chartCard(t('dash.chartStatus'), null,
        codes.length ? hBars(codes.map((c) => ({ label: statusCodeEl(c.statusCode), title: `HTTP ${c.statusCode}`, value: c.count }))) : emptyState(),
        table([{ label: t('col.statusCode'), render: (c) => statusCodeEl(c.statusCode) }, { label: t('col.count'), num: true, render: (c) => fmtNum(c.count) }], codes)));
    }
    if (hr) grid.append(checksCard(hr));
    parts.push(grid);

    if (m) {
      parts.push(h('div.grid-2', null,
        listCard(t('dash.topEndpoints'), table([
          { label: t('col.endpoint'), cls: 'mono wrap', render: (r) => r.endpoint },
          { label: t('col.count'), num: true, render: (r) => fmtNum(r.count) },
          { label: t('col.errors'), num: true, render: (r) => errCount(r.errors) },
          { label: t('col.avgLatency'), num: true, render: (r) => fmtMs(r.avgLatencyMs) },
        ], m.byEndpoint)),
        listCard(t('dash.topKeys'), table([
          { label: t('col.apiKey'), render: (r) => r.apiKeyName || h('span.muted', { text: r.apiKeyId || t('common.none') }) },
          { label: t('col.count'), num: true, render: (r) => fmtNum(r.count) },
          { label: t('col.errors'), num: true, render: (r) => errCount(r.errors) },
          { label: t('col.lastSeen'), render: (r) => timeEl(r.lastSeen) },
        ], m.byApiKey)),
        listCard(t('dash.topIps'), table([
          { label: t('col.ip'), cls: 'mono', render: (r) => r.ip },
          { label: t('col.count'), num: true, render: (r) => fmtNum(r.count) },
          { label: t('col.errors'), num: true, render: (r) => errCount(r.errors) },
        ], m.byClientIp)),
        listCard(t('dash.topFailedUsers'), table([
          { label: t('col.username'), cls: 'mono', render: (r) => r.username },
          { label: t('col.count'), num: true, render: (r) => fmtNum(r.count) },
        ], m.topFailedUsers))));
    }

    if (hr) {
      parts.push(h('div.grid-2', null,
        listCard(t('dash.ports'), table([
          { label: t('col.server'), cls: 'mono', render: (p) => p.server },
          { label: t('col.port'), num: true, render: (p) => String(p.port) },
          { label: t('col.ssl'), render: (p) => (p.ssl ? badge('good', 'SSL') : badge('neutral', t('common.noValue'))) },
          { label: t('col.reachable'), render: (p) => boolBadge(p.reachable) },
          { label: t('col.latency'), num: true, render: (p) => fmtMs(p.latencyMs) },
          { label: t('col.error'), cls: 'wrap', render: (p) => p.error },
        ], (hr.ldap && hr.ldap.ports) || [])),
        systemCard(hr)));
    }
    replace(body, parts);
  }

  function errCount(n) {
    return n ? h('span.text-critical', { text: fmtNum(n) }) : h('span.muted', { text: '0' });
  }

  function renderTiles(hr, m, hist) {
    const ldap = hr && hr.ldap;
    const tiles = [];
    tiles.push(tile(t('dash.overall'), hr ? healthBadge(hr.status) : '—',
      hr ? [t('sys.checkedAt'), ' ', fmtRelative(hr.checkedAt)].join('') : null, null, { cls: 'tile-status' }));
    tiles.push(tile(t('dash.ldap'), ldap ? healthBadge(ldap.status) : '—',
      ldap ? t('dash.ldapStrategy', { s: ldap.activeStrategy || t('common.none') }) : null,
      ldap ? h('span.tile-badges', null,
        ldap.secure === false ? badge('warning', t('dash.ldapInsecure'), t('dash.ldapInsecureTitle'))
          : ldap.secure === true ? badge('good', t('dash.ldapSecure')) : null,
        ldap.latencyMs != null ? h('span.muted.small', { text: fmtMs(ldap.latencyMs) }) : null) : null,
      { cls: 'tile-status' }));
    let histSub = null;
    if (hist && hist.length) {
      const ok = hist.filter((x) => x.ok).length;
      histSub = t('dash.availSummary', { ok: fmtNum(ok), n: fmtNum(hist.length), pct: fmtPct((ok / hist.length) * 100) });
    }
    tiles.push(tile(t('dash.availability'), ldap ? fmtPct(ldap.availability24h, 2) : '—', histSub));
    tiles.push(tile(t('dash.uptime'), hr ? fmtDuration(hr.uptimeSeconds) : '—', hr ? t('dash.uptimeSince', { time: fmtTime(hr.startedAt, { seconds: false }) }) : null));
    if (m) {
      tiles.push(tile(`${t('dash.requests')} (${t(`dash.range.${range}`)})`, fmtCompact(m.totalRequests), t('dash.requestsSub', { n: fmtNum(m.uniqueClients) })));
      const er = ratePct(m.errorRate);
      tiles.push(tile(t('dash.errorRate'), fmtPct(er, 2), t('dash.errorRateSub', { c: fmtNum(m.clientErrors), s: fmtNum(m.serverErrors) })));
      tiles.push(tile(t('dash.p95'), fmtMs(m.p95LatencyMs), t('dash.p95Sub', { p50: fmtMs(m.p50LatencyMs), p99: fmtMs(m.p99LatencyMs) })));
      const att = m.authAttempts || (m.authSuccesses + m.authFailures);
      tiles.push(tile(t('dash.auth'), att ? fmtPct((m.authSuccesses / att) * 100) : '—', t('dash.authSub', { ok: fmtNum(m.authSuccesses), fail: fmtNum(m.authFailures) })));
    }
    return h('div.tiles', null, tiles);
  }

  function availabilityCard(hist, res) {
    if (!hist) return h('section.card.card-wide', null, h('h2.card-title', { text: t('dash.chartAvailability') }), errorState(res.reason, load));
    const ok = hist.filter((x) => x.ok).length;
    const fails = hist.filter((x) => !x.ok).reverse();
    const failTable = fails.length ? table([
      { label: t('col.time'), render: (x) => timeEl(x.timestamp) },
      { label: t('col.strategy'), cls: 'mono', render: (x) => x.strategy },
      { label: t('col.latency'), num: true, render: (x) => fmtMs(x.latencyMs) },
      { label: t('col.error'), cls: 'wrap', render: (x) => x.error },
    ], fails.slice(0, 200)) : emptyState(`${t('dash.availFail')}: 0`);
    return chartCard(t('dash.chartAvailability'),
      hist.length ? t('dash.availSummary', { ok: fmtNum(ok), n: fmtNum(hist.length), pct: fmtPct((ok / hist.length) * 100, 2) }) : null,
      hist.length ? availabilityStrip(hist, { ariaLabel: t('dash.chartAvailability') }) : emptyState(),
      failTable,
      legend([{ label: t('dash.availOk'), cls: 'fill-good.swatch-short' }, { label: t('dash.availFail'), cls: 'fill-critical.swatch-tall' }]),
      'card-wide');
  }

  function checksCard(hr) {
    const checks = hr.checks || [];
    return listCard(t('dash.healthChecks'), checks.length ? h('ul.checks', checks.map((c) => h('li.check-row', null,
      healthBadge(c.status),
      h('div', null, h('div.check-name', { text: c.name }), c.message ? h('div.muted.small.wrap', { text: c.message }) : null)))) : emptyState());
  }

  function systemCard(hr) {
    const p = hr.process || {}, st = hr.storage || {}, c = hr.cache || {}, l = hr.ldap || {};
    const dir = (path, ok) => h('span', null, h('span.mono.wrap', { text: path || t('common.none') }), ' ', boolBadge(ok, t('sys.writable'), t('sys.notWritable')));
    return listCard(t('dash.system'), kvList([
      [t('sys.version'), `${hr.version || ''} · ${hr.environment || ''}`],
      [t('sys.machine'), hr.machineName],
      [t('sys.framework'), hr.frameworkVersion],
      [t('sys.checkedAt'), timeEl(hr.checkedAt)],
      [t('sys.ldapServer'), h('span.mono', { text: [l.server, ...(l.fallbackServers || [])].filter(Boolean).join(', ') })],
      [t('sys.ldapLastSuccess'), timeEl(l.lastSuccessAt, { emptyText: t('common.never') })],
      [t('sys.ldapLastFailure'), timeEl(l.lastFailureAt, { emptyText: t('common.never') })],
      l.lastError ? [t('sys.ldapLastError'), h('span.text-critical.wrap', { text: l.lastError })] : null,
      [t('sys.memory'), `${fmtNum(p.workingSetMb, 1)} MB`],
      [t('sys.gcHeap'), `${fmtNum(p.gcHeapMb, 1)} MB`],
      [t('sys.threads'), fmtNum(p.threadCount)],
      [t('sys.cpu'), fmtPct(p.cpuPercent)],
      [t('sys.logDir'), dir(st.logDirectory, st.logDirectoryWritable)],
      [t('sys.dataDir'), dir(st.dataDirectory, st.dataDirectoryWritable)],
      [t('sys.diskFree'), `${fmtNum(st.diskFreeGb, 1)} GB`],
      [t('sys.cache'), t('sys.cacheValue', { entries: fmtNum(c.entries), hits: fmtNum(c.hits), misses: fmtNum(c.misses) })],
    ]));
  }

  rangeBtns.forEach((b) => b.addEventListener('click', () => {
    range = b.dataset.r;
    rangeBtns.forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
    load();
  }));

  if (checkBtn) {
    checkBtn.addEventListener('click', () => busy(checkBtn, t('dash.checking'), async () => {
      try {
        const rep = await post('/health/check-now');
        ctx.setHealth(rep);
        toast(t('dash.checkDone'));
        await load();
      } catch (e) { toastError(e); }
    }));
  }

  await load();
  const stop = visibleInterval(load, 30000);
  return {
    destroy() { alive = false; stop(); },
  };
}

function listCard(title, content) {
  return h('section.card', null, h('div.card-head', null, h('h2.card-title', { text: title })), content);
}
