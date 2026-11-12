import { t, has } from './i18n.js';
import { get, post, qs } from './api.js';
import {
  h, replace, badge, spinner, errorState, errorBox, table, kvList, field, confirmDialog, toast, toastError, busy,
  alertBox, fmtMs, fmtNum, fmtPct, timeEl, boolBadge, emptyState,
} from './ui.js';

export async function mount(root, ctx) {
  const admin = ctx.isAdmin;
  const strategiesBody = h('div', null, spinner());
  const cards = [];

  if (admin) cards.push(diagnosticsCard(), testAuthCard());
  cards.push(lookupCard());
  if (admin) cards.push(maintenanceCard());

  replace(root,
    h('div.page-head', null, h('h1', { text: t('tools.title') })),
    admin ? null : alertBox('info', h('span', { text: t('common.readOnlyViewer') })),
    h('div.tools-grid', null, cards),
    h('section.card', null,
      h('div.card-head', null, h('h2.card-title', { text: t('tools.strategies') }),
        h('button.btn.btn-sm', { type: 'button', text: t('common.refresh'), onclick: loadStrategies })),
      strategiesBody));

  async function loadStrategies() {
    strategiesBody.classList.add('is-refreshing');
    try {
      const list = await get('/ldap/strategies');
      replace(strategiesBody, table([
        {
          label: t('col.strategy'), render: (s) => h('span', null, h('span.mono', { text: s.name }), ' ',
            s.isPreferred ? badge('good', t('tools.preferred')) : null),
        },
        { label: t('col.server'), cls: 'mono', render: (s) => `${s.server}:${s.port}` },
        { label: t('col.ssl'), render: (s) => (s.ssl ? badge('good', 'SSL') : badge('neutral', t('common.noValue'))) },
        { label: t('col.successCount'), num: true, render: (s) => fmtNum(s.successCount) },
        { label: t('col.failureCount'), num: true, render: (s) => fmtNum(s.failureCount) },
        {
          label: t('col.successRate'), num: true, render: (s) => {
            const n = (s.successCount || 0) + (s.failureCount || 0);
            return n ? fmtPct((s.successCount / n) * 100) : null;
          },
        },
        { label: t('col.avgLatency'), num: true, render: (s) => fmtMs(s.avgLatencyMs) },
        { label: t('col.lastSuccess'), render: (s) => timeEl(s.lastSuccessAt, { emptyText: t('common.never') }) },
        { label: t('col.lastFailure'), render: (s) => timeEl(s.lastFailureAt, { emptyText: t('common.never') }) },
        { label: t('col.lastError'), cls: 'wrap small', render: (s) => s.lastError },
      ], list || [], { rowClass: (s) => (s.isPreferred ? 'row-preferred' : null) }));
    } catch (e) { replace(strategiesBody, errorState(e, loadStrategies)); } finally { strategiesBody.classList.remove('is-refreshing'); }
  }

  // ---------- diagnostics ----------
  function diagnosticsCard() {
    const out = h('div.tool-out');
    const btn = h('button.btn.btn-primary', { type: 'button', text: t('tools.diagRun') });
    btn.addEventListener('click', async () => {
      const started = Date.now();
      const label = h('span');
      const tick = () => { label.textContent = t('tools.diagRunning', { s: Math.floor((Date.now() - started) / 1000) }); };
      tick();
      const timer = setInterval(tick, 1000);
      replace(out, h('div.state.state-loading', { role: 'status' }, h('span.spin', { 'aria-hidden': 'true' }), label));
      btn.disabled = true;
      try {
        const r = await post('/tools/ldap-diagnostics');
        replace(out, renderDiagnostics(r));
        loadStrategies();
      } catch (e) {
        replace(out, errorBox(e));
      } finally { clearInterval(timer); btn.disabled = false; }
    });
    return h('section.card.tool-card.tool-wide', null,
      h('h2.card-title', { text: t('tools.diag') }),
      alertBox('warning', h('span', { text: t('tools.diagHint') })),
      h('div.form-actions', null, btn),
      out);
  }

  function strategyTable(list) {
    return table([
      { label: t('col.strategy'), cls: 'mono', render: (s) => s.strategyName },
      { label: t('col.server'), cls: 'mono', render: (s) => `${s.server}:${s.port}` },
      { label: t('col.ssl'), render: (s) => (s.useSSL ? badge('good', 'SSL') : badge('neutral', t('common.noValue'))) },
      { label: t('col.authType'), render: (s) => s.authType },
      { label: t('col.usernameFormat'), cls: 'mono', render: (s) => s.usernameFormat },
      { label: t('col.responseTime'), num: true, render: (s) => fmtMs(s.responseTimeMs) },
      { label: t('col.errorCode'), cls: 'mono', render: (s) => (s.errorCode != null && s.errorCode !== 0 ? String(s.errorCode) : null) },
      { label: t('col.error'), cls: 'wrap small', render: (s) => s.errorMessage },
    ], list || []);
  }

  function renderDiagnostics(r) {
    const ok = r.successfulStrategies || [];
    const bad = r.failedStrategies || [];
    return h('div', null,
      r.success
        ? alertBox('good', h('div', null, h('strong', { text: `${t('tools.diagRecommended')}: ` }), h('span.mono', { text: r.recommendedStrategy ? `${r.recommendedStrategy.strategyName} (${r.recommendedStrategy.server}:${r.recommendedStrategy.port}, ${r.recommendedStrategy.usernameFormat})` : '—' })))
        : alertBox('critical', h('strong', { text: t('set.ldap.testFail') })),
      r.summary ? h('pre.pre', { text: r.summary }) : null,
      h('p.muted.small', { text: `${r.server || ''}${r.configuredPort ? `:${r.configuredPort}` : ''} · ${t('tools.diagTotal', { ms: fmtMs(r.totalTestTimeMs) })}` }),
      h('h3.sub-title', { text: t('tools.diagSuccessful', { n: ok.length }) }),
      ok.length ? strategyTable(ok) : emptyState(),
      h('h3.sub-title', { text: t('tools.diagFailed', { n: bad.length }) }),
      bad.length ? strategyTable(bad) : emptyState());
  }

  // ---------- test auth ----------
  function testAuthCard() {
    const user = h('input.input', { type: 'text', autocomplete: 'off', spellcheck: 'false' });
    const pass = h('input.input', { type: 'password', autocomplete: 'new-password' });
    const out = h('div.tool-out');
    const btn = h('button.btn.btn-primary', { type: 'submit', text: t('tools.testAuthRun') });
    const form = h('form.form-grid', { novalidate: true },
      field(t('login.username'), user),
      field(t('login.password'), pass),
      h('div.form-actions.field-wide', null, btn));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (!user.value.trim() || !pass.value) { replace(out, errorBox(new Error(t('login.required')))); return; }
      busy(btn, null, async () => {
        replace(out, spinner());
        try {
          const r = await post('/tools/test-auth', { username: user.value.trim(), password: pass.value });
          pass.value = '';
          replace(out, renderAuth(r));
        } catch (e2) { replace(out, errorBox(e2)); }
      });
    });
    return h('section.card.tool-card', null,
      h('h2.card-title', { text: t('tools.testAuth') }),
      alertBox('critical', h('span', { text: t('tools.testAuthWarn') })),
      form, out);
  }

  function reasonText(reason) {
    const key = `fr.${reason}`;
    return has(key) ? t(key) : String(reason);
  }

  function renderAuth(r) {
    return h('div', null,
      r.success
        ? alertBox('good', h('strong', { text: t('tools.testAuthOk') }))
        : alertBox('critical', h('div', null, h('strong', { text: t('tools.testAuthFail') }), h('div', { text: reasonText(r.failureReason) }),
          r.failureReason ? h('div.muted.small.mono', { text: r.failureReason }) : null)),
      kvList([
        [t('tools.method'), r.method],
        [t('tools.strategy'), r.strategy ? h('span.mono', { text: r.strategy }) : null],
        [t('tools.duration'), fmtMs(r.durationMs)],
      ]),
      r.user ? renderUser(r.user) : null);
  }

  // ---------- lookup ----------
  function lookupCard() {
    const user = h('input.input', { type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: 'somchai.j' });
    const out = h('div.tool-out');
    const btn = h('button.btn.btn-primary', { type: 'submit', text: t('tools.lookupRun') });
    const form = h('form.inline-form', { novalidate: true }, field(t('login.username'), user), btn);
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const u = user.value.trim();
      if (!u) { user.focus(); return; }
      busy(btn, null, async () => {
        replace(out, spinner());
        try {
          const info = await get(`/tools/lookup-user${qs({ username: u })}`);
          replace(out, info ? renderUser(info) : emptyState(t('tools.lookupNotFound', { u })));
        } catch (e2) {
          replace(out, e2.status === 404 ? alertBox('warning', h('span', { text: t('tools.lookupNotFound', { u }) })) : errorBox(e2));
        }
      });
    });
    return h('section.card.tool-card', null,
      h('h2.card-title', { text: t('tools.lookup') }),
      h('p.muted.small', { text: t('tools.lookupHint') }),
      form, out);
  }

  function renderUser(u) {
    const groups = (u.groups || []).map((g) => (typeof g === 'string' ? g : (g && (g.name || g.distinguishedName)) || JSON.stringify(g)));
    const cn = (g) => { const m = /^CN=([^,]+)/i.exec(g); return m ? m[1] : g; };
    const status = h('span.tile-badges', null,
      u.isEnabled === false ? badge('critical', t('tools.userDisabled')) : badge('good', t('tools.userEnabled')),
      u.isLocked ? badge('critical', t('tools.userLocked')) : null);
    const f = (k) => [t(`ui.${k}`), u[k]];
    return h('div.user-info', null,
      h('div.user-head', null, h('strong', { text: u.displayName || u.samAccountName || '' }), status),
      kvList([
        f('samAccountName'), f('userPrincipalName'), f('email'), f('firstName'), f('lastName'),
        f('title'), f('department'), f('company'), f('office'), f('phone'), f('mobile'), f('employeeId'),
        [t('ui.manager'), u.manager ? h('span.wrap.small', { text: u.manager }) : null],
        [t('ui.distinguishedName'), u.distinguishedName ? h('span.mono.wrap.small', { text: u.distinguishedName }) : null],
        [t('ui.whenCreated'), timeEl(u.whenCreated)],
        [t('ui.whenChanged'), timeEl(u.whenChanged)],
        [t('ui.lastLogon'), timeEl(u.lastLogon, { emptyText: t('common.never') })],
      ]),
      h('h3.sub-title', { text: t('tools.groups', { n: groups.length }) }),
      groups.length ? h('div.chips', groups.map((g) => h('span.chip', { title: g, text: cn(g) }))) : h('p.muted', { text: t('tools.noGroups') }));
  }

  // ---------- maintenance ----------
  function maintenanceCard() {
    const clearBtn = h('button.btn', { type: 'button', text: t('tools.clearCache') });
    const resetBtn = h('button.btn', { type: 'button', text: t('tools.resetStrategy') });
    clearBtn.addEventListener('click', async () => {
      if (!(await confirmDialog({ title: t('tools.clearCache'), message: t('tools.clearCacheConfirm'), confirmLabel: t('tools.clearCache') }))) return;
      busy(clearBtn, null, async () => {
        try { await post('/tools/clear-cache'); toast(t('tools.cacheCleared')); } catch (e) { toastError(e); }
      });
    });
    resetBtn.addEventListener('click', async () => {
      if (!(await confirmDialog({ title: t('tools.resetStrategy'), message: t('tools.resetStrategyConfirm'), confirmLabel: t('common.confirm') }))) return;
      busy(resetBtn, null, async () => {
        try { await post('/tools/reset-ldap-strategy'); toast(t('tools.strategyReset')); loadStrategies(); } catch (e) { toastError(e); }
      });
    });
    return h('section.card.tool-card', null,
      h('h2.card-title', { text: t('tools.maintenance') }),
      h('div.maint-row', null, h('div', null, h('div.strong', { text: t('tools.clearCache') }), h('div.muted.small', { text: t('tools.clearCacheHint') })), clearBtn),
      h('div.maint-row', null, h('div', null, h('div.strong', { text: t('tools.resetStrategy') }), h('div.muted.small', { text: t('tools.resetStrategyHint') })), resetBtn));
  }

  loadStrategies();
  return {};
}
