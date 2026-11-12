import { t } from './i18n.js';
import { get, put, del, post, errorFields } from './api.js';
import {
  h, replace, badge, spinner, errorState, errorBox, field, checkField, confirmDialog, toast, toastError, busy, lines,
  alertBox, table, fmtMs, boolBadge,
} from './ui.js';

// type: text | number | bool | list | password
const SCHEMA = {
  ldap: [
    ['server', 'text', { hint: true }],
    ['fallbackServers', 'list', { hint: true }],
    ['port', 'number', { min: 1, max: 65535 }],
    ['useSSL', 'bool'],
    ['baseDN', 'text', { hint: true, wide: true }],
    ['domain', 'text'],
    ['netBiosDomain', 'text', { hint: true }],
    ['serviceAccountUsername', 'text'],
    ['serviceAccountPassword', 'password'],
    ['connectionTimeout', 'number', { min: 1 }],
    ['skipCertificateValidation', 'bool', { hint: true, danger: true }],
    ['allowInsecureFallback', 'bool', { hint: true, danger: true }],
    ['chaseReferrals', 'bool', { hint: true }],
    ['enableCache', 'bool'],
    ['cacheDurationMinutes', 'number', { min: 0 }],
  ],
  security: [
    ['enableApiKeyAuth', 'bool'],
    ['apiKeyHeaderName', 'text'],
    ['enableIpWhitelist', 'bool'],
    ['allowedIpAddresses', 'list', { hint: true, wide: true }],
    ['enableRateLimiting', 'bool'],
    ['rateLimitMaxRequests', 'number', { min: 1 }],
    ['rateLimitWindowSeconds', 'number', { min: 1 }],
  ],
  audit: [
    ['enabled', 'bool'],
    ['enableFileLogging', 'bool'],
    ['retentionDays', 'number', { min: 1 }],
    ['requestLogRetentionDays', 'number', { min: 1 }],
    ['failedLoginThreshold', 'number', { min: 1 }],
    ['failedLoginWindowMinutes', 'number', { min: 1 }],
    ['autoPurgeEnabled', 'bool'],
  ],
  admin: [
    ['adminUsers', 'list', { hint: true }],
    ['adminGroups', 'list', { hint: true }],
    ['viewerUsers', 'list'],
    ['viewerGroups', 'list'],
    ['allowedIpAddresses', 'list', { hint: true, wide: true }],
    ['sessionTimeoutMinutes', 'number', { min: 1 }],
  ],
};
const SECTIONS = ['ldap', 'security', 'audit', 'admin'];
let activeTab = 'ldap';

export async function mount(root, ctx) {
  const admin = ctx.isAdmin;
  const body = h('div', null, spinner());
  replace(root, h('div.page-head', null, h('h1', { text: t('set.title') })), body);
  let data;
  const sections = {};
  let alive = true;

  async function load() {
    try {
      data = await get('/settings');
      if (alive) render();
    } catch (e) { if (alive) replace(body, errorState(e, load)); }
  }

  function render() {
    const tabs = h('div.tabs', { role: 'tablist' });
    const panels = h('div.tab-panels');
    SECTIONS.forEach((sec) => {
      const tab = h('button.tab', { type: 'button', role: 'tab', id: `tab-${sec}`, 'aria-controls': `panel-${sec}`, 'aria-selected': String(sec === activeTab) },
        h('span', { text: t(`set.tab.${sec}`) }),
        data.overridden && data.overridden[sec] ? h('span.tab-dot', { title: t('set.overridden'), 'aria-label': t('set.overridden') }) : null,
        h('span.tab-dirty', { hidden: true, text: '•', title: t('common.unsaved') }));
      tab.addEventListener('click', () => select(sec));
      tabs.append(tab);
      const s = buildSection(sec, tab);
      sections[sec] = s;
      s.panel.hidden = sec !== activeTab;
      panels.append(s.panel);
    });
    // arrow-key tab navigation
    tabs.addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      const i = SECTIONS.indexOf(activeTab) + (e.key === 'ArrowRight' ? 1 : -1);
      const next = SECTIONS[(i + SECTIONS.length) % SECTIONS.length];
      select(next);
      document.getElementById(`tab-${next}`).focus();
    });
    replace(body,
      admin ? null : alertBox('info', h('span', { text: t('common.readOnlyViewer') })),
      data.dataDirectory ? h('p.muted.small', { text: t('set.dataDir', { dir: data.dataDirectory }) }) : null,
      tabs, panels);
  }

  function select(sec) {
    activeTab = sec;
    SECTIONS.forEach((s) => {
      sections[s].panel.hidden = s !== sec;
      document.getElementById(`tab-${s}`).setAttribute('aria-selected', String(s === sec));
    });
  }

  function buildSection(sec, tabBtn) {
    let original = data[sec] || {};
    const controls = {};
    const fieldsWrap = h('fieldset.form-grid', { disabled: !admin });
    for (const [key, type, opts = {}] of SCHEMA[sec]) {
      const label = t(`set.${sec}.${key}`);
      const hint = opts.hint ? t(`set.${sec}.${key}Hint`) : null;
      let ctl, node;
      const v = original[key];
      if (type === 'bool') {
        ctl = h('input', { type: 'checkbox', checked: !!v });
        node = checkField(label, ctl, hint, { name: key.toLowerCase() });
        if (opts.danger) node.classList.add('field-danger');
      } else if (type === 'list') {
        ctl = h('textarea.input.mono', { rows: '4', spellcheck: 'false' });
        ctl.value = (v || []).join('\n');
        node = field(label, ctl, hint || t('common.onePerLine'), { name: key.toLowerCase(), wide: opts.wide });
      } else if (type === 'number') {
        ctl = h('input.input', { type: 'number', value: v ?? '', min: opts.min, max: opts.max, step: '1' });
        node = field(label, ctl, hint, { name: key.toLowerCase() });
      } else if (type === 'password') {
        ctl = h('input.input', {
          type: 'password', value: '', autocomplete: 'new-password',
          placeholder: original.serviceAccountPasswordSet ? t('set.ldap.passwordUnchanged') : t('set.ldap.passwordNotSet'),
        });
        node = field(label, ctl, t('set.ldap.passwordHint'), { name: key.toLowerCase() });
      } else {
        ctl = h('input.input', { type: 'text', value: v ?? '', spellcheck: 'false' });
        node = field(label, ctl, hint, { name: key.toLowerCase(), wide: opts.wide });
      }
      controls[key] = { ctl, type };
      fieldsWrap.append(node);
    }

    function read() {
      const out = {};
      for (const [key, { ctl, type }] of Object.entries(controls)) {
        if (type === 'bool') out[key] = ctl.checked;
        else if (type === 'list') out[key] = lines(ctl.value);
        else if (type === 'number') out[key] = ctl.value === '' ? null : Number(ctl.value);
        else if (type === 'password') out[key] = ctl.value;
        else out[key] = ctl.value.trim();
      }
      if (sec === 'ldap') out.serviceAccountPasswordSet = original.serviceAccountPasswordSet;
      return out;
    }
    function comparable(o) {
      const c = {};
      for (const [key, { type }] of Object.entries(controls)) {
        let v = o[key];
        if (type === 'list') v = (v || []).join('\n');
        if (type === 'password') v = v || '';
        if (type === 'number') v = v === null || v === undefined || v === '' ? null : Number(v);
        if (type === 'bool') v = !!v;
        if (type === 'text') v = (v ?? '').toString().trim();
        c[key] = v;
      }
      return JSON.stringify(c);
    }
    const isDirty = () => comparable(read()) !== comparable({ ...original, serviceAccountPassword: '' });

    const errs = h('div.form-errors');
    const saveBtn = h('button.btn.btn-primary', { type: 'button', text: t('common.save'), disabled: true });
    const discardBtn = h('button.btn.btn-ghost', { type: 'button', text: t('set.discard'), hidden: true });
    const revertBtn = h('button.btn.btn-danger-ghost', { type: 'button', text: t('set.revert') });
    const dirtyNote = h('span.dirty-note', { hidden: true, text: t('common.unsaved') });
    const overBadge = h('span');
    const syncOverridden = () => {
      const ov = !!(data.overridden && data.overridden[sec]);
      replace(overBadge, ov ? badge('warning', t('set.overridden'), t('set.overriddenTitle')) : badge('neutral', t('set.fromFile')));
      revertBtn.disabled = !ov;
      const dot = tabBtn.querySelector('.tab-dot');
      if (dot) dot.hidden = !ov;
    };
    syncOverridden();
    const syncDirty = () => {
      const d = isDirty();
      saveBtn.disabled = !d;
      discardBtn.hidden = !d;
      dirtyNote.hidden = !d;
      tabBtn.querySelector('.tab-dirty').hidden = !d;
    };
    fieldsWrap.addEventListener('input', syncDirty);
    fieldsWrap.addEventListener('change', syncDirty);

    function fill(dto) {
      for (const [key, { ctl, type }] of Object.entries(controls)) {
        const v = dto[key];
        if (type === 'bool') ctl.checked = !!v;
        else if (type === 'list') ctl.value = (v || []).join('\n');
        else if (type === 'password') { ctl.value = ''; ctl.placeholder = dto.serviceAccountPasswordSet ? t('set.ldap.passwordUnchanged') : t('set.ldap.passwordNotSet'); }
        else ctl.value = v ?? '';
      }
    }

    discardBtn.addEventListener('click', () => { fill(original); replace(errs); clearErrors(); syncDirty(); });

    function clearErrors() { fieldsWrap.querySelectorAll('.has-error').forEach((n) => n.classList.remove('has-error')); }
    function showErrors(e) {
      replace(errs, errorBox(e));
      errorFields(e).forEach((f) => { const n = fieldsWrap.querySelector(`[data-field="${f}"]`); if (n) n.classList.add('has-error'); });
    }

    async function confirmRisky(next) {
      const checks = [];
      if (sec === 'security') {
        if (original.enableApiKeyAuth && !next.enableApiKeyAuth) checks.push(['set.c.apiKeyOffTitle', 'set.c.apiKeyOff']);
        if (original.enableIpWhitelist && !next.enableIpWhitelist) checks.push(['set.c.ipOffTitle', 'set.c.ipOff']);
      }
      if (sec === 'ldap' && !original.skipCertificateValidation && next.skipCertificateValidation) checks.push(['set.c.skipCertTitle', 'set.c.skipCert']);
      if (sec === 'ldap' && !original.allowInsecureFallback && next.allowInsecureFallback) checks.push(['set.c.insecureTitle', 'set.c.insecure']);
      if (sec === 'admin') checks.push(['set.c.adminTitle', 'set.c.admin']);
      for (const [title, msg] of checks) {
        // eslint-disable-next-line no-await-in-loop
        const ok = await confirmDialog({ title: t(title), message: t(msg), confirmLabel: t('common.save'), danger: true, strong: true });
        if (!ok) return false;
      }
      return true;
    }

    saveBtn.addEventListener('click', async () => {
      clearErrors();
      replace(errs);
      const next = read();
      if (!(await confirmRisky(next))) return;
      const payload = { ...next };
      if (sec === 'ldap') {
        delete payload.serviceAccountPasswordSet;
        if (!payload.serviceAccountPassword) payload.serviceAccountPassword = null;
      }
      await busy(saveBtn, t('common.saving'), async () => {
        try {
          const updated = await put(`/settings/${sec}`, payload);
          original = updated || { ...original, ...next, serviceAccountPassword: '' };
          if (sec === 'ldap' && next.serviceAccountPassword && !(updated && 'serviceAccountPasswordSet' in updated)) original.serviceAccountPasswordSet = true;
          data[sec] = original;
          data.overridden = { ...(data.overridden || {}), [sec]: true };
          fill(original);
          syncOverridden();
          toast(t('set.saved'));
        } catch (e) {
          if (e.status !== 401 && e.status !== 403) showErrors(e);
        }
      });
      syncDirty();
    });

    revertBtn.addEventListener('click', async () => {
      const title = sec === 'admin' ? t('set.c.adminRevertTitle') : t('set.revertTitle', { section: t(`set.tab.${sec}`) });
      const message = sec === 'admin' ? `${t('set.revertBody')}\n\n${t('set.c.admin')}` : t('set.revertBody');
      const ok = await confirmDialog({ title, message, confirmLabel: t('set.revert'), danger: true, strong: sec === 'admin' });
      if (!ok) return;
      await busy(revertBtn, null, async () => {
        try {
          await del(`/settings/${sec}`);
          toast(t('set.reverted'));
          const fresh = await get('/settings');
          data = fresh;
          original = fresh[sec] || {};
          fill(original);
          clearErrors();
          replace(errs);
          syncOverridden();
          syncDirty();
        } catch (e) { toastError(e); }
      });
    });

    // LDAP test connection
    let testArea = null;
    let testBtn = null;
    if (sec === 'ldap' && admin) {
      testArea = h('div.test-result');
      testBtn = h('button.btn', { type: 'button', text: t('set.ldap.test') });
      testBtn.addEventListener('click', () => busy(testBtn, t('set.ldap.testing'), async () => {
        replace(testArea, spinner(t('set.ldap.testing')));
        const payload = read();
        delete payload.serviceAccountPasswordSet;
        if (!payload.serviceAccountPassword) payload.serviceAccountPassword = null;
        try {
          const r = await post('/settings/ldap/test', payload);
          replace(testArea, renderTest(r));
        } catch (e) {
          if (e.status === 400) showErrors(e);
          replace(testArea, errorBox(e));
        }
      }));
    }

    const panel = h('section.card.settings-panel', { role: 'tabpanel', id: `panel-${sec}`, 'aria-labelledby': `tab-${sec}` },
      h('div.card-head', null,
        h('div.head-badges', null, h('h2.card-title', { text: t(`set.tab.${sec}`) }), overBadge),
        admin ? revertBtn : null),
      sec === 'admin' ? alertBox('warning', h('span', { text: t('set.admin.warn') })) : null,
      errs,
      fieldsWrap,
      admin ? h('div.form-actions', null,
        testBtn ? h('span.test-wrap', null, testBtn, h('span.muted.small', { text: ` ${t('set.ldap.testHint')}` })) : null,
        h('div.spacer'), dirtyNote, discardBtn, saveBtn) : null,
      testArea);

    return { panel, isDirty };
  }

  function renderTest(r) {
    const head = r.success
      ? alertBox('good', h('strong', { text: t('set.ldap.testOk', { strategy: r.strategy || '—', ms: r.latencyMs ?? '—' }) }))
      : alertBox('critical', h('strong', { text: t('set.ldap.testFail') }), r.error ? h('div.wrap', { text: r.error }) : null);
    return h('div', null, head,
      r.attempts && r.attempts.length ? h('div', null,
        h('h3.sub-title', { text: t('set.ldap.attempts') }),
        table([
          { label: t('col.strategy'), cls: 'mono', render: (a) => a.strategy },
          { label: t('col.success'), render: (a) => boolBadge(a.success, t('audit.f.successTrue'), t('audit.f.successFalse')) },
          { label: t('col.latency'), num: true, render: (a) => fmtMs(a.latencyMs) },
          { label: t('col.error'), cls: 'wrap', render: (a) => a.error },
        ], r.attempts)) : null);
  }

  await load();
  return {
    destroy() { alive = false; },
    canLeave: () => !Object.values(sections).some((s) => s.isDirty()),
  };
}
