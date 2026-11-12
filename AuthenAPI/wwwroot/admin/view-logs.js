import { t } from './i18n.js';
import { get, qs, API_BASE } from './api.js';
import {
  h, replace, fmtNum, fmtMs, timeEl, badge, statusCodeEl, spinner, errorState, table, pager, kvList, drawer,
  toLocalInput, fromLocalInput, visibleInterval, downloadUrl, fmtTime,
} from './ui.js';

const PAGE = 50;
const RANGE_MS = { '15m': 15 * 60e3, '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3 };

// Filters survive navigation between pages during the session.
const memory = {
  requests: { range: '24h', from: '', to: '', method: '', status: '', path: '', apiKeyId: '', ip: '', username: '', search: '', minDurationMs: '', skip: 0, auto: false },
  audit: { range: '7d', from: '', to: '', action: '', username: '', success: '', ip: '', skip: 0 },
};

function rangeParams(f) {
  if (f.range === 'custom') return { from: fromLocalInput(f.from), to: fromLocalInput(f.to) };
  if (f.range === 'all' || !RANGE_MS[f.range]) return {};
  return { from: new Date(Date.now() - RANGE_MS[f.range]).toISOString() };
}

function input(type, value, attrs = {}) {
  return h('input.input', { type, value, ...attrs });
}
function select(options, value, attrs = {}) {
  return h('select.input', attrs, options.map(([v, label]) => h('option', { value: v, text: label, selected: v === value })));
}
function filterField(label, control, cls) {
  return h(`label.filter${cls ? `.${cls}` : ''}`, null, h('span.filter-label', { text: label }), control);
}

/** Generic paged log page. */
function logPage(root, ctx, cfg) {
  const f = memory[cfg.kind];
  const controls = {};
  const rangeSel = select([
    ...(cfg.ranges.map((r) => [r, t(`req.f.range.${r}`)])),
    ['custom', t('req.f.range.custom')],
  ], f.range, { 'aria-label': t('req.f.range') });
  const fromIn = input('datetime-local', f.from || toLocalInput(new Date(Date.now() - 86400e3).toISOString()));
  const toIn = input('datetime-local', f.to);
  const customBox = h('span.custom-range', null, fromIn, h('span.muted', { text: '–' }), toIn);
  const syncCustom = () => { customBox.hidden = rangeSel.value !== 'custom'; };
  syncCustom();
  rangeSel.addEventListener('change', () => { syncCustom(); if (rangeSel.value !== 'custom') apply(); });

  const fields = cfg.fields(f, controls);
  const applyBtn = h('button.btn.btn-primary', { type: 'submit', text: t('common.apply') });
  const resetBtn = h('button.btn.btn-ghost', { type: 'button', text: t('common.reset') });
  const exportBtn = h('button.btn', { type: 'button', text: t('common.exportCsv') });
  const autoBox = cfg.auto ? h('input', { type: 'checkbox', checked: f.auto }) : null;
  const updated = h('span.muted.small');

  const form = h('form.filters', { novalidate: true },
    filterField(t('req.f.range'), h('span.range-box', null, rangeSel, customBox), 'filter-range'),
    fields,
    h('div.filter-actions', null, applyBtn, resetBtn));

  const body = h('div', null, spinner());
  replace(root,
    h('div.page-head', null,
      h('h1', { text: cfg.title }),
      h('div.toolbar', null,
        updated,
        h('div.spacer'),
        autoBox ? h('label.check', null, autoBox, h('span', { text: `${t('common.autoRefresh')} (15 s)` })) : null,
        exportBtn)),
    h('section.card.card-filters', null, form),
    body);

  function readForm() {
    f.range = rangeSel.value;
    f.from = fromIn.value;
    f.to = toIn.value;
    for (const [k, el] of Object.entries(controls)) f[k] = el.value.trim();
  }
  function params(withPaging) {
    const p = { ...rangeParams(f) };
    for (const k of Object.keys(controls)) p[k] = f[k];
    if (withPaging) { p.skip = f.skip; p.take = PAGE; }
    return p;
  }
  function apply() { readForm(); f.skip = 0; load(); }

  let alive = true;
  let seq = 0;
  async function load() {
    const my = ++seq;
    body.classList.add('is-refreshing');
    try {
      const res = await get(`${cfg.path}${qs(params(true))}`);
      if (!alive || my !== seq) return;
      const items = (res && res.items) || [];
      const total = (res && res.total) || 0;
      if (f.skip > 0 && !items.length && total) { f.skip = Math.max(0, Math.floor((total - 1) / PAGE) * PAGE); load(); return; }
      replace(body, h('section.card.card-flush', null,
        table(cfg.columns(), items, { empty: cfg.empty, onRowClick: (row) => cfg.detail(row), rowClass: cfg.rowClass }),
        total > PAGE || f.skip ? pager(total, f.skip, PAGE, (s) => { f.skip = s; load(); }) : h('div.pager', null, h('span.pager-info', { text: t('common.pageInfo', { from: total ? 1 : 0, to: fmtNum(total), total: fmtNum(total) }) }))));
      updated.textContent = t('common.lastUpdated', { time: fmtTime(new Date().toISOString()) });
    } catch (e) {
      if (alive && my === seq) replace(body, errorState(e, load));
    } finally {
      if (my === seq) body.classList.remove('is-refreshing');
    }
  }

  form.addEventListener('submit', (e) => { e.preventDefault(); apply(); });
  resetBtn.addEventListener('click', () => {
    Object.assign(f, cfg.defaults());
    rangeSel.value = f.range;
    syncCustom();
    for (const [k, el] of Object.entries(controls)) el.value = f[k] || '';
    load();
  });
  exportBtn.addEventListener('click', () => {
    readForm();
    downloadUrl(`${API_BASE}${cfg.path}/export${qs(params(false))}`);
  });

  let stopAuto = null;
  const syncAuto = () => {
    if (stopAuto) { stopAuto(); stopAuto = null; }
    if (autoBox && autoBox.checked) stopAuto = visibleInterval(() => { if (f.skip === 0) load(); }, 15000);
  };
  if (autoBox) autoBox.addEventListener('change', () => { f.auto = autoBox.checked; syncAuto(); });
  syncAuto();

  load();
  return { destroy() { alive = false; if (stopAuto) stopAuto(); } };
}

function outcomeBadge(outcome) {
  if (!outcome) return null;
  const kind = outcome === 'Success' ? 'good'
    : outcome === 'Error' ? 'critical'
      : /^(AuthFailed|ApiKey|RateLimited|IpBlocked)/.test(outcome) ? 'warning' : 'neutral';
  return badge(kind, outcome);
}

function detailRows(entry, keys) {
  return keys.map(([k, render]) => [t(`fld.${k}`), render ? render(entry[k], entry) : (entry[k] === null || entry[k] === undefined || entry[k] === '' ? null : h('span.wrap.mono-soft', { text: String(entry[k]) }))]);
}

// ---------- Request logs ----------
export function mountRequests(root, ctx) {
  let keyOptions = [['', t('common.any')]];
  const keySel = select(keyOptions, memory.requests.apiKeyId, {});
  get('/keys').then((keys) => {
    keyOptions = [['', t('common.any')], ...(keys || []).map((k) => [k.id, `${k.name}${k.prefix ? ` (${k.prefix}…)` : ''}`])];
    replace(keySel, keyOptions.map(([v, l]) => h('option', { value: v, text: l, selected: v === memory.requests.apiKeyId })));
  }).catch(() => {});

  return logPage(root, ctx, {
    kind: 'requests',
    title: t('req.title'),
    path: '/requests',
    ranges: ['15m', '1h', '24h', '7d', '30d', 'all'],
    auto: true,
    empty: t('req.empty'),
    defaults: () => ({ range: '24h', from: '', to: '', method: '', status: '', path: '', apiKeyId: '', ip: '', username: '', search: '', minDurationMs: '', skip: 0 }),
    fields(f, c) {
      c.method = select([['', t('common.any')], ...['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'].map((m) => [m, m])], f.method);
      c.status = input('text', f.status, { placeholder: t('req.f.statusPh'), list: 'status-options', size: '6', pattern: '[1-5](xx|\\d\\d)' });
      c.path = input('text', f.path, { placeholder: '/api/ldap/…' });
      c.apiKeyId = keySel;
      c.ip = input('text', f.ip, { placeholder: '10.0.0.1' });
      c.username = input('text', f.username);
      c.search = input('search', f.search);
      c.minDurationMs = input('number', f.minDurationMs, { min: '0', step: '1', placeholder: '1000' });
      return [
        filterField(t('req.f.method'), c.method),
        filterField(t('req.f.status'), h('span', null, c.status,
          h('datalist', { id: 'status-options' }, ['2xx', '4xx', '5xx', '400', '401', '403', '404', '429', '500', '503'].map((v) => h('option', { value: v }))))),
        filterField(t('req.f.path'), c.path),
        filterField(t('req.f.apiKey'), c.apiKeyId),
        filterField(t('req.f.ip'), c.ip),
        filterField(t('req.f.username'), c.username),
        filterField(t('req.f.search'), c.search, 'filter-grow'),
        filterField(t('req.f.minDuration'), c.minDurationMs, 'filter-narrow'),
      ];
    },
    columns: () => [
      { label: t('col.time'), render: (r) => timeEl(r.timestamp) },
      { label: t('col.method'), cls: 'mono', render: (r) => r.method },
      { label: t('col.path'), cls: 'mono wrap path-cell', render: (r) => h('span', { title: r.queryString ? `${r.path}${r.queryString}` : r.path, text: r.path }) },
      { label: t('col.status'), render: (r) => statusCodeEl(r.statusCode) },
      { label: t('col.duration'), num: true, render: (r) => fmtMs(r.durationMs) },
      { label: t('col.clientIp'), cls: 'mono', render: (r) => r.clientIp },
      { label: t('col.apiKey'), render: (r) => r.apiKeyName || (r.apiKeyId ? h('span.mono.muted', { text: r.apiKeyId }) : null) },
      { label: t('col.username'), cls: 'mono', render: (r) => r.username },
      { label: t('col.outcome'), render: (r) => outcomeBadge(r.outcome) },
    ],
    rowClass: (r) => (r.statusCode >= 500 ? 'row-critical' : null),
    detail(row) {
      const content = h('div');
      const render = (e) => replace(content, kvList(detailRows(e, [
        ['timestamp', (v) => timeEl(v)],
        ['method'], ['path'], ['queryString'],
        ['statusCode', (v) => statusCodeEl(v)],
        ['durationMs', (v) => fmtMs(v)],
        ['outcome', (v) => outcomeBadge(v)],
        ['errorMessage', (v) => (v ? h('span.text-critical.wrap', { text: v }) : null)],
        ['clientIp'], ['userAgent'], ['apiKeyName'], ['apiKeyId'], ['username'], ['ldapStrategy'], ['traceId'], ['id'],
      ]), 'kv-detail'));
      render(row);
      drawer(t('req.detailTitle'), content);
      if (row.id !== undefined && row.id !== null) {
        get(`/requests/${encodeURIComponent(row.id)}`).then((full) => { if (full && content.isConnected) render(full); }).catch(() => {});
      }
    },
  });
}

// ---------- Audit logs ----------
export function mountAudit(root, ctx) {
  const f = memory.audit;
  const actionSel = select([['', t('common.any')]], f.action);
  get('/audit/actions').then((actions) => {
    replace(actionSel, [['', t('common.any')], ...(actions || []).map((a) => [a, a])].map(([v, l]) => h('option', { value: v, text: l, selected: v === f.action })));
  }).catch(() => {});

  return logPage(root, ctx, {
    kind: 'audit',
    title: t('audit.title'),
    path: '/audit',
    ranges: ['1h', '24h', '7d', '30d', 'all'],
    auto: false,
    empty: t('audit.empty'),
    defaults: () => ({ range: '7d', from: '', to: '', action: '', username: '', success: '', ip: '', skip: 0 }),
    fields(fl, c) {
      c.action = actionSel;
      c.username = input('text', fl.username);
      c.success = select([['', t('common.any')], ['true', t('audit.f.successTrue')], ['false', t('audit.f.successFalse')]], fl.success);
      c.ip = input('text', fl.ip, { placeholder: '10.0.0.1' });
      return [
        filterField(t('audit.f.action'), c.action),
        filterField(t('req.f.username'), c.username),
        filterField(t('audit.f.success'), c.success),
        filterField(t('req.f.ip'), c.ip),
      ];
    },
    columns: () => [
      { label: t('col.time'), render: (r) => timeEl(r.timestamp) },
      { label: t('col.action'), cls: 'mono', render: (r) => r.action },
      { label: t('col.username'), cls: 'mono', render: (r) => r.username },
      { label: t('col.result'), render: (r) => (r.success ? badge('good', t('audit.f.successTrue')) : badge('critical', t('audit.f.successFalse'))) },
      { label: t('col.ip'), cls: 'mono', render: (r) => r.ipAddress },
      { label: t('col.request'), cls: 'mono wrap path-cell', render: (r) => (r.requestPath ? `${r.httpMethod || ''} ${r.requestPath}`.trim() : null) },
      { label: t('col.status'), render: (r) => (r.statusCode ? statusCodeEl(r.statusCode) : null) },
      { label: t('col.duration'), num: true, render: (r) => (r.durationMs != null ? fmtMs(r.durationMs) : null) },
      { label: t('common.details'), cls: 'details-cell', render: (r) => (r.details ? h('span.truncate', { title: r.details, text: r.details }) : null) },
    ],
    rowClass: (r) => (r.success ? null : 'row-warn'),
    detail(row) {
      drawer(t('audit.detailTitle'), kvList(detailRows(row, [
        ['timestamp', (v) => timeEl(v)],
        ['action'], ['username'],
        ['success', (v) => (v ? badge('good', t('audit.f.successTrue')) : badge('critical', t('audit.f.successFalse')))],
        ['ipAddress'], ['userAgent'], ['httpMethod'], ['requestPath'],
        ['statusCode', (v) => (v ? statusCodeEl(v) : null)],
        ['durationMs', (v) => (v != null ? fmtMs(v) : null)],
        ['details', (v) => (v ? h('pre.pre', { text: prettyMaybeJson(v) }) : null)],
        ['id'],
      ]), 'kv-detail'));
    },
  });
}

function prettyMaybeJson(v) {
  if (typeof v !== 'string') return JSON.stringify(v, null, 2);
  const s = v.trim();
  if (s.startsWith('{') || s.startsWith('[')) {
    try { return JSON.stringify(JSON.parse(s), null, 2); } catch { /* not JSON */ }
  }
  return v;
}
