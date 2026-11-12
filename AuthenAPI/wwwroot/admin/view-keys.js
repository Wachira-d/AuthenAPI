import { t } from './i18n.js';
import { get, post, put, del, qs, errorFields } from './api.js';
import {
  h, replace, fmtNum, fmtMs, fmtTime, timeEl, badge, spinner, errorState, errorBox, table, kvList, field, checkField,
  modal, confirmDialog, toast, toastError, busy, copyText, toLocalInput, fromLocalInput, lines, alertBox, emptyState, menuButton,
} from './ui.js';
import { stackedColumns, legend } from './charts.js';
import { chartCard, timelineBuckets, TIMELINE_SERIES, timelineTable } from './view-dashboard.js';

const STATUS_KIND = { Active: 'good', Disabled: 'neutral', Expired: 'warning', Revoked: 'critical' };

// Loose client-side check; the server is authoritative.
const IPV4 = /^(\d{1,3})(\.\d{1,3}){3}(\/\d{1,2})?$/;
const IPV6 = /^[0-9a-f:]+(\/\d{1,3})?$/i;
function validIp(v) {
  if (IPV4.test(v)) {
    const [ip, bits] = v.split('/');
    return ip.split('.').every((o) => Number(o) <= 255) && (bits === undefined || Number(bits) <= 32);
  }
  return v.includes(':') && IPV6.test(v);
}

export async function mount(root, ctx) {
  const admin = ctx.isAdmin;
  const search = h('input.input.input-search', { type: 'search', placeholder: t('keys.search'), 'aria-label': t('keys.search') });
  const createBtn = admin ? h('button.btn.btn-primary', { type: 'button', text: `+ ${t('keys.create')}` }) : null;
  const refreshBtn = h('button.btn', { type: 'button', text: t('common.refresh') });
  const body = h('div', null, spinner());
  replace(root,
    h('div.page-head', null,
      h('h1', { text: t('keys.title') }),
      h('div.toolbar', null, search, h('div.spacer'), refreshBtn, createBtn)),
    admin ? null : alertBox('info', h('span', { text: t('common.readOnlyViewer') })),
    body);

  let keys = [];
  let scopes = [];
  let alive = true;

  async function load() {
    body.classList.add('is-refreshing');
    try {
      const [k, sc] = await Promise.all([get('/keys'), scopes.length ? Promise.resolve(scopes) : get('/keys/scopes')]);
      keys = k || [];
      scopes = sc || [];
      if (alive) renderTable();
    } catch (e) {
      if (alive) replace(body, errorState(e, load));
    } finally { body.classList.remove('is-refreshing'); }
  }

  function renderTable() {
    const q = search.value.trim().toLowerCase();
    const rows = q ? keys.filter((k) => `${k.name} ${k.prefix} ${k.description || ''}`.toLowerCase().includes(q)) : keys;
    replace(body, h('section.card.card-flush.keys-table', null, table([
      {
        label: t('col.name'), cls: 'wrap-cell', render: (k) => h('div', null,
          h('div.strong', { text: k.name }),
          k.source === 'appsettings' ? h('div.ro-source', { title: t('keys.readOnlyHint') }, badge('neutral', `${t('keys.source.appsettings')} · ${t('keys.readOnly')}`)) : null,
          k.description ? h('div.muted.small.wrap', { text: k.description }) : null),
      },
      { label: t('col.prefix'), cls: 'mono', render: (k) => k.prefix ? `${k.prefix}…` : null },
      { label: t('col.status'), render: (k) => badge(STATUS_KIND[k.status] || 'neutral', t(`keys.st.${k.status}`)) },
      { label: t('col.scopes'), render: (k) => chips(k.scopes, t('keys.allScopes')) },
      { label: t('col.allowedIps'), render: (k) => chips(k.allowedIps, t('keys.anyIp'), true) },
      { label: t('col.rateLimit'), num: true, render: (k) => (k.rateLimitPerMinute ? t('keys.perMin', { n: fmtNum(k.rateLimitPerMinute) }) : h('span.muted', { text: t('keys.noLimit') })) },
      { label: t('col.expires'), render: (k) => timeEl(k.expiresAt, { emptyText: t('keys.noExpiry'), dateOnly: true }) },
      {
        label: `${t('col.lastUsed')} / ${t('col.usage')}`, render: (k) => h('div.ts', null,
          timeEl(k.lastUsedAt, { emptyText: t('common.never'), compact: true }),
          h('span.ts-rel', { text: t('keys.usageCount', { n: fmtNum(k.usageCount || 0) }) })),
      },
      { label: t('common.actions'), cls: 'actions', render: actions },
    ], rows, { empty: t('keys.empty'), rowClass: (k) => (k.status === 'Revoked' ? 'row-dim' : null) })));
  }

  function chips(list, emptyText, mono) {
    if (!list || !list.length) return h('span.muted', { text: emptyText });
    return h('div.chips', list.map((x) => h(`span.chip${mono ? '.mono' : ''}`, { text: x })));
  }

  function actions(k) {
    const btns = [h('button.btn.btn-sm', { type: 'button', text: t('keys.usage'), onclick: () => usage(k) })];
    if (admin && k.source !== 'appsettings') {
      const more = [];
      if (k.status !== 'Revoked') {
        btns.push(h('button.btn.btn-sm', { type: 'button', text: t('keys.edit'), onclick: () => editForm(k) }));
        more.push({ label: t('keys.rotate'), onClick: () => rotate(k) });
        more.push({ label: t('keys.revoke'), danger: true, onClick: () => revoke(k) });
      }
      more.push({ label: t('keys.delete'), danger: true, onClick: () => remove(k) });
      btns.push(menuButton('⋯', more, `${t('common.actions')}: ${k.name}`));
    } else if (k.source === 'appsettings') {
      btns.push(h('span.info-dot', { title: t('keys.readOnlyHint'), tabindex: '0', 'aria-label': t('keys.readOnlyHint'), text: 'i' }));
    }
    return h('div.btn-row', null, btns);
  }

  // ---- create / edit ----
  function editForm(existing) {
    const isNew = !existing;
    const k = existing || { name: '', description: '', scopes: [], allowedIps: [], rateLimitPerMinute: null, expiresAt: null, isActive: true };
    const name = h('input.input', { type: 'text', maxlength: '100', value: k.name, required: true, autofocus: true });
    const desc = h('textarea.input', { rows: '2' }); desc.value = k.description || '';
    const scopeBoxes = scopes.map((sc) => {
      const cb = h('input', { type: 'checkbox', value: sc.scope, checked: (k.scopes || []).includes(sc.scope) });
      return { cb, node: h('label.check.scope-check', null, cb, h('span', null, h('span.mono.strong', { text: sc.scope }), sc.description ? h('span.muted.small', { text: ` — ${sc.description}` }) : null)) };
    });
    const allHint = h('div.scope-all');
    const syncScopes = () => {
      const none = !scopeBoxes.some((x) => x.cb.checked);
      replace(allHint, none ? badge('warning', t('keys.allScopes')) : null);
    };
    scopeBoxes.forEach((x) => x.cb.addEventListener('change', syncScopes));
    syncScopes();
    const ips = h('textarea.input.mono', { rows: '4', spellcheck: 'false' }); ips.value = (k.allowedIps || []).join('\n');
    const rate = h('input.input', { type: 'number', min: '1', step: '1', value: k.rateLimitPerMinute ?? '' });
    const exp = h('input.input', { type: 'datetime-local', value: toLocalInput(k.expiresAt) });
    const active = h('input', { type: 'checkbox', checked: k.isActive !== false });
    const errs = h('div.form-errors');

    const form = h('form.form-grid', { novalidate: true },
      field(t('keys.f.name'), name, t('keys.f.nameHint'), { name: 'name', wide: true }),
      field(t('keys.f.description'), desc, null, { name: 'description', wide: true }),
      h('fieldset.field.field-wide', { dataset: { field: 'scopes' } },
        h('legend.field-label', { text: t('keys.f.scopes') }),
        h('div.scope-list', null, scopeBoxes.map((x) => x.node)),
        allHint,
        h('div.field-hint', { text: t('keys.f.scopesHint') })),
      field(t('keys.f.allowedIps'), ips, t('keys.f.allowedIpsHint'), { name: 'allowedips', wide: true }),
      field(t('keys.f.rateLimit'), rate, t('keys.f.rateLimitHint'), { name: 'ratelimitperminute' }),
      field(t('keys.f.expiresAt'), exp, t('keys.f.expiresHint'), { name: 'expiresat' }),
      isNew ? null : checkField(t('keys.f.isActive'), active, null, { name: 'isactive', wide: true }),
      errs);

    const save = h('button.btn.btn-primary', { type: 'submit', text: t('common.save') });
    const cancel = h('button.btn', { type: 'button', text: t('common.cancel') });
    const m = modal({ title: isNew ? t('keys.formCreate') : t('keys.formEdit', { name: k.name }), body: form, footer: [cancel, save], wide: true });
    cancel.addEventListener('click', () => m.close(null));
    save.addEventListener('click', (e) => { e.preventDefault(); form.requestSubmit(); });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      form.querySelectorAll('.has-error').forEach((n) => n.classList.remove('has-error'));
      const problems = [];
      const nm = name.value.trim();
      if (!nm) problems.push(['name', t('keys.v.nameRequired')]);
      else if (nm.length > 100) problems.push(['name', t('keys.v.nameLong')]);
      const ipList = lines(ips.value);
      ipList.filter((v) => !validIp(v)).forEach((v) => problems.push(['allowedips', t('keys.v.ip', { v })]));
      let rl = null;
      if (rate.value !== '') {
        rl = Number(rate.value);
        if (!Number.isInteger(rl) || rl < 1) problems.push(['ratelimitperminute', t('keys.v.rateLimit')]);
      }
      if (problems.length) {
        problems.forEach(([f]) => { const n = form.querySelector(`[data-field="${f}"]`); if (n) n.classList.add('has-error'); });
        replace(errs, errorBox(new Error(problems.map((p) => p[1]).join('\n'))));
        return;
      }
      replace(errs);
      const payload = {
        name: nm,
        description: desc.value.trim() || null,
        scopes: scopeBoxes.filter((x) => x.cb.checked).map((x) => x.cb.value),
        allowedIps: ipList,
        rateLimitPerMinute: rl,
        expiresAt: fromLocalInput(exp.value),
      };
      if (!isNew) payload.isActive = active.checked;
      await busy(save, t('common.saving'), async () => {
        try {
          if (isNew) {
            const res = await post('/keys', payload);
            m.close(true);
            toast(t('keys.created'));
            showSecret(res.key, res.plainTextKey);
          } else {
            await put(`/keys/${encodeURIComponent(k.id)}`, payload);
            m.close(true);
            toast(t('keys.updated'));
          }
          load();
        } catch (err) {
          if (err.status === 400) {
            replace(errs, errorBox(err));
            errorFields(err).forEach((f) => { const n = form.querySelector(`[data-field="${f}"]`); if (n) n.classList.add('has-error'); });
          } else if (err.status !== 401 && err.status !== 403) {
            replace(errs, errorBox(err));
          }
        }
      });
    });
  }

  function showSecret(key, plain) {
    const input = h('input.input.mono.secret-input', { type: 'text', readonly: true, value: plain, spellcheck: 'false', 'aria-label': 'API Key' });
    input.addEventListener('focus', () => input.select());
    const copyBtn = h('button.btn', { type: 'button', text: t('common.copy') });
    let copied = false;
    copyBtn.addEventListener('click', async () => {
      const ok = await copyText(plain);
      if (ok) { copied = true; copyBtn.textContent = `✓ ${t('common.copied')}`; } else { input.focus(); input.select(); toast(t('common.copyFailed'), 'warning'); }
    });
    const done = h('button.btn.btn-primary', { type: 'button', text: t('keys.secretDone') });
    const header = ctx.settingsHeader || 'X-API-Key';
    const m = modal({
      title: t('keys.secretTitle', { name: key ? key.name : '' }),
      dismissible: false,
      body: [
        alertBox('warning', h('strong', { text: t('keys.secretWarn') })),
        h('div.secret-row', null, input, copyBtn),
        h('p.muted.small', { text: t('keys.secretHeader', { header }) }),
      ],
      footer: [done],
    });
    done.addEventListener('click', async () => {
      if (!copied) {
        const ok = await confirmDialog({ title: t('keys.secretDone'), message: t('keys.secretConfirmClose'), confirmLabel: t('common.close'), danger: true });
        if (!ok) return;
      }
      m.dismissible = true;
      m.close(true);
    });
    setTimeout(() => { input.focus(); input.select(); }, 0);
  }

  async function rotate(k) {
    const ok = await confirmDialog({ title: t('keys.confirmRotateTitle', { name: k.name }), message: t('keys.confirmRotate'), confirmLabel: t('keys.rotate'), danger: true });
    if (!ok) return;
    try {
      const res = await post(`/keys/${encodeURIComponent(k.id)}/rotate`);
      toast(t('keys.rotated'));
      showSecret(res.key || k, res.plainTextKey);
      load();
    } catch (e) { toastError(e); }
  }

  async function revoke(k) {
    const ok = await confirmDialog({ title: t('keys.confirmRevokeTitle', { name: k.name }), message: t('keys.confirmRevoke'), confirmLabel: t('keys.revoke'), danger: true, strong: true });
    if (!ok) return;
    try { await post(`/keys/${encodeURIComponent(k.id)}/revoke`); toast(t('keys.revoked')); load(); } catch (e) { toastError(e); }
  }

  async function remove(k) {
    const ok = await confirmDialog({ title: t('keys.confirmDeleteTitle', { name: k.name }), message: t('keys.confirmDelete'), confirmLabel: t('keys.delete'), danger: true, typeWord: k.name });
    if (!ok) return;
    try { await del(`/keys/${encodeURIComponent(k.id)}`); toast(t('keys.deleted')); load(); } catch (e) { toastError(e); }
  }

  // ---- usage ----
  async function usage(k) {
    const content = h('div', null, spinner());
    modal({ title: t('keys.usageTitle', { name: k.name }), body: content, wide: true });
    try {
      const m = await get(`/metrics${qs({ range: '24h', apiKeyId: k.id })}`);
      const buckets = timelineBuckets(m.timeline);
      const series = TIMELINE_SERIES();
      replace(content,
        h('div.mini-tiles', null,
          mini(t('keys.usageRequests'), fmtNum(m.totalRequests)),
          mini(t('keys.usageErrors'), fmtNum((m.clientErrors || 0) + (m.serverErrors || 0))),
          mini(t('keys.usageP95'), fmtMs(m.p95LatencyMs)),
          mini(t('col.lastUsed'), timeEl(k.lastUsedAt, { emptyText: t('common.never') }), k.lastUsedIp ? t('keys.usageLastUsed', { ip: k.lastUsedIp }) : null)),
        chartCard(t('dash.chartRequests'), t('dash.chartRequestsSub', { n: m.bucketMinutes }),
          buckets.length && m.totalRequests ? stackedColumns(buckets, series, { height: 140, bucketMinutes: m.bucketMinutes, ariaLabel: t('dash.chartRequests') }) : emptyState(),
          timelineTable(m.timeline), legend(series)),
        h('section.card', null, h('h2.card-title', { text: t('dash.topEndpoints') }), table([
          { label: t('col.endpoint'), cls: 'mono wrap', render: (r) => r.endpoint },
          { label: t('col.count'), num: true, render: (r) => fmtNum(r.count) },
          { label: t('col.errors'), num: true, render: (r) => fmtNum(r.errors) },
          { label: t('col.avgLatency'), num: true, render: (r) => fmtMs(r.avgLatencyMs) },
        ], m.byEndpoint)),
        kvList([
          [t('col.source'), t(`keys.source.${k.source}`)],
          k.createdAt ? [t('common.details'), t('keys.createdBy', { by: k.createdBy || '—', at: fmtTime(k.createdAt) })] : null,
          k.revokedAt ? [t('keys.st.Revoked'), t('keys.revokedBy', { by: k.revokedBy || '—', at: fmtTime(k.revokedAt) })] : null,
        ]));
    } catch (e) { replace(content, errorState(e)); }
  }

  function mini(label, value, sub) {
    return h('div.mini-tile', null, h('div.tile-label', { text: label }), h('div.mini-value', null, value), sub ? h('div.muted.small', { text: sub }) : null);
  }

  search.addEventListener('input', () => renderTable());
  refreshBtn.addEventListener('click', () => busy(refreshBtn, null, load));
  if (createBtn) createBtn.addEventListener('click', () => editForm(null));

  // Header name for the "send it in …" hint (best-effort; settings are readable by both roles).
  get('/settings').then((st) => { if (st && st.security) ctx.settingsHeader = st.security.apiKeyHeaderName; }).catch(() => {});

  await load();
  return { destroy() { alive = false; } };
}
