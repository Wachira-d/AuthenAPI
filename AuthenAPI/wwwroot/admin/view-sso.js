// Applications (SSO): OpenID Connect clients. Contract: docs/ADMIN_PORTAL.md section 7.
import { t } from './i18n.js';
import { get, post, put, del, errorLines, errorFields } from './api.js';
import {
  h, replace, fmtNum, fmtTime, timeEl, badge, spinner, errorState, table, kvList, field, checkField,
  modal, confirmDialog, toast, toastError, busy, copyText, lines, alertBox, menuButton,
} from './ui.js';

const CLIENT_ID = /^[a-z0-9][a-z0-9._-]{1,63}$/;
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/** Absolute https URL, or http only for localhost. Returns an i18n error key or null. */
function uriProblem(v) {
  let u;
  try { u = new URL(v); } catch { return 'sso.v.uriAbsolute'; }
  if (u.protocol === 'https:') return u.hash ? 'sso.v.uriFragment' : null;
  if (u.protocol === 'http:') {
    if (!LOCAL_HOSTS.has(u.hostname)) return 'sso.v.uriHttps';
    return u.hash ? 'sso.v.uriFragment' : null;
  }
  return 'sso.v.uriHttps';
}

/** 400 errors are one "; "-joined string, each message starting with the field name. */
function serverErrors(err) {
  const msgs = errorLines(err).flatMap((l) => l.split(/;\s+/)).map((x) => x.trim()).filter(Boolean);
  const fields = new Set(errorFields(err));
  msgs.forEach((m) => {
    const f = /^([A-Za-z][\w.[\]]*)/.exec(m);
    if (f) fields.add(f[1].split('.').pop().replace(/\[\d+\]$/, '').toLowerCase());
  });
  return { msgs, fields: [...fields] };
}

function listBox(msgs) {
  return h('div.alert.alert-critical', { role: 'alert' },
    msgs.length > 1 ? h('ul', msgs.map((l) => h('li', { text: l }))) : h('span', { text: msgs[0] || t('err.generic') }));
}

function copyButton(value, label) {
  const btn = h('button.btn.btn-sm', { type: 'button', text: t('common.copy'), 'aria-label': label ? `${t('common.copy')}: ${label}` : null });
  btn.addEventListener('click', async () => {
    if (await copyText(value)) {
      btn.textContent = `✓ ${t('common.copied')}`;
      setTimeout(() => { btn.textContent = t('common.copy'); }, 1800);
    } else toast(t('common.copyFailed'), 'warning');
  });
  return btn;
}

/** Full SsoClientInput from a view, for PUT. */
function toInput(c) {
  return {
    clientId: c.clientId,
    displayName: c.displayName,
    type: c.type,
    redirectUris: c.redirectUris || [],
    postLogoutRedirectUris: c.postLogoutRedirectUris || [],
    frontChannelLogoutUri: c.frontChannelLogoutUri || null,
    allowedGroups: c.allowedGroups || [],
    requirePkce: !!c.requirePkce,
    isActive: c.isActive !== false,
  };
}

export async function mount(root, ctx) {
  const admin = ctx.isAdmin;
  const search = h('input.input.input-search', { type: 'search', placeholder: t('sso.search'), 'aria-label': t('sso.search') });
  const createBtn = admin ? h('button.btn.btn-primary', { type: 'button', text: `+ ${t('sso.create')}` }) : null;
  const refreshBtn = h('button.btn', { type: 'button', text: t('common.refresh') });
  const infoBox = h('div', null, spinner());
  const body = h('div', null, spinner());
  replace(root,
    h('div.page-head', null,
      h('h1', { text: t('sso.title') }),
      h('div.toolbar', null, search, h('div.spacer'), refreshBtn, createBtn)),
    admin ? null : alertBox('info', h('span', { text: t('common.readOnlyViewer') })),
    infoBox,
    body);

  let info = null;
  let clients = [];
  let alive = true;

  async function load() {
    body.classList.add('is-refreshing');
    infoBox.classList.add('is-refreshing');
    try {
      const [i, c] = await Promise.allSettled([get('/sso/info'), get('/sso/clients')]);
      if (!alive) return;
      if (i.status === 'fulfilled') { info = i.value; renderInfo(); } else replace(infoBox, h('section.card', null, errorState(i.reason, load)));
      if (c.status === 'fulfilled') { clients = c.value || []; renderTable(); } else replace(body, errorState(c.reason, load));
    } finally {
      body.classList.remove('is-refreshing');
      infoBox.classList.remove('is-refreshing');
    }
  }

  // ---- info card ----
  function renderInfo() {
    const i = info || {};
    const urlRow = (label, value) => [label, value
      ? h('div.url-row', null, h('span.mono.url-text', { text: value }), copyButton(value, label))
      : null];
    const urls = [
      [t('sso.i.issuer'), i.issuer],
      [t('sso.i.discovery'), i.discoveryUrl],
      [t('sso.i.authorize'), i.authorizeUrl],
      [t('sso.i.token'), i.tokenUrl],
      [t('sso.i.userinfo'), i.userinfoUrl],
      [t('sso.i.logout'), i.logoutUrl],
      [t('sso.i.loginPage'), i.loginPageUrl],
    ];
    const allText = urls.filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`).join('\n');
    const chips = (list) => (list && list.length
      ? h('div.chips', list.map((x) => h('span.chip.mono', { text: x })))
      : null);
    replace(infoBox, h('section.card.sso-info', null,
      h('div.card-head', null,
        h('div', null,
          h('h2.card-title', { text: t('sso.i.title') }),
          h('div.card-sub', { text: t('sso.i.sub') })),
        h('div.head-badges', null,
          i.enabled ? badge('good', t('sso.i.enabled')) : badge('warning', t('sso.i.disabled')),
          badge('neutral', t('sso.i.sessions', { n: fmtNum(i.activeSessions || 0) })),
          allText ? copyButton(allText, t('sso.i.copyAll')) : null)),
      i.enabled ? null : alertBox('warning', h('span', { text: t('sso.i.disabledHint') })),
      kvList(urls.map(([k, v]) => urlRow(k, v)), 'kv-urls'),
      kvList([
        [t('sso.i.sessionHours'), i.sessionHours != null ? t('sso.i.hours', { n: fmtNum(i.sessionHours) }) : null],
        [t('sso.i.activeSessions'), fmtNum(i.activeSessions || 0)],
        [t('sso.i.scopes'), chips(i.scopes)],
        [t('sso.i.claims'), chips(i.claims)],
      ])));
  }

  // ---- table ----
  function renderTable() {
    const q = search.value.trim().toLowerCase();
    const rows = q ? clients.filter((c) => `${c.displayName} ${c.clientId}`.toLowerCase().includes(q)) : clients;
    replace(body, h('section.card.card-flush.keys-table.sso-table', null, table([
      {
        label: `${t('sso.col.name')} / ${t('sso.col.clientId')}`, cls: 'wrap-cell', render: (c) => h('div', null,
          h('div.strong', { text: c.displayName }),
          h('div.mono.muted.client-id', { text: c.clientId })),
      },
      {
        label: `${t('sso.col.type')} / PKCE`, render: (c) => h('div.type-cell', null, typeBadge(c),
          h(`span.small${c.requirePkce ? '' : '.muted'}`, { text: `PKCE: ${c.requirePkce ? t('sso.pkceRequired') : t('sso.pkceOptional')}` })),
      },
      { label: t('sso.col.redirects'), cls: 'uri-cell', render: (c) => uriList(c.redirectUris) },
      {
        label: t('sso.col.groups'), render: (c) => (c.allowedGroups && c.allowedGroups.length
          ? h('div.chips', c.allowedGroups.map((g) => h('span.chip', { text: g })))
          : h('span.muted', { text: t('sso.allUsers') })),
      },
      {
        label: `${t('col.status')} / ${t('sso.col.lastLogin')}`, render: (c) => h('div.type-cell', null,
          c.isActive !== false ? badge('good', t('sso.st.active')) : badge('neutral', t('sso.st.disabled')),
          h('div.ts', null,
            timeEl(c.lastLoginAt, { emptyText: t('sso.neverLoggedIn'), compact: true }),
            h('span.ts-rel', { text: t('sso.loginCount', { n: fmtNum(c.loginCount || 0) }) }))),
      },
      { label: t('common.actions'), cls: 'actions', render: actions },
    ], rows, { empty: t(q ? 'sso.noMatch' : 'sso.empty'), rowClass: (c) => (c.isActive === false ? 'row-dim' : null) })));
  }

  function typeBadge(c) {
    const pub = c.type === 'public';
    const b = badge(pub ? 'neutral' : 'info', t(pub ? 'sso.type.public' : 'sso.type.confidential'), t(pub ? 'sso.type.publicHint' : 'sso.type.confidentialHint'));
    if (!pub) b.classList.add('badge-accent');
    return b;
  }

  function uriList(list) {
    if (!list || !list.length) return h('span.muted', { text: t('common.none') });
    const first = h('span.mono.truncate', { text: list[0], title: list.join('\n') });
    if (list.length === 1) return first;
    return h('details.uri-details', { title: list.join('\n') },
      h('summary', null, h('span.mono.truncate', { text: list[0] }), h('span.muted.small', { text: t('sso.moreUris', { n: list.length - 1 }) })),
      h('ul.uri-list', list.map((u) => h('li.mono', { text: u }))));
  }

  function actions(c) {
    const config = () => showConfig(c, null);
    if (!admin) return h('div.btn-row', null, h('button.btn.btn-sm', { type: 'button', text: t('sso.config'), onclick: config }));
    const btns = [h('button.btn.btn-sm', { type: 'button', text: t('sso.edit'), onclick: () => editForm(c) })];
    {
      const more = [{ label: t('sso.config'), onClick: config }];
      if (c.type !== 'public') more.push({ label: t('sso.rotate'), onClick: () => rotate(c) });
      more.push(c.isActive !== false
        ? { label: t('sso.disable'), onClick: () => setActive(c, false) }
        : { label: t('sso.enable'), onClick: () => setActive(c, true) });
      more.push({ label: t('sso.delete'), danger: true, onClick: () => remove(c) });
      btns.push(menuButton('⋯', more, `${t('common.actions')}: ${c.clientId}`));
    }
    return h('div.btn-row', null, btns);
  }

  // ---- create / edit ----
  function editForm(existing) {
    const isNew = !existing;
    const c = existing || {
      clientId: '', displayName: '', type: 'confidential', redirectUris: [], postLogoutRedirectUris: [],
      frontChannelLogoutUri: null, allowedGroups: [], requirePkce: true, isActive: true,
    };
    const clientId = h('input.input.mono', { type: 'text', value: c.clientId, maxlength: '64', spellcheck: 'false', autocapitalize: 'off', autocomplete: 'off', readonly: !isNew, autofocus: isNew });
    const displayName = h('input.input', { type: 'text', value: c.displayName, required: true, autofocus: !isNew });
    const typeRadios = ['confidential', 'public'].map((ty) => {
      const r = h('input', { type: 'radio', name: 'sso-type', value: ty, checked: c.type === ty, disabled: !isNew });
      return { r, node: h('label.check.type-option', null, r, h('span', null,
        h('span.strong', { text: t(`sso.type.${ty}`) }),
        h('span.muted.small.type-hint', { text: t(`sso.type.${ty}Hint`) }))) };
    });
    const ta = (list, rows) => { const n = h('textarea.input.mono', { rows: String(rows), spellcheck: 'false', autocapitalize: 'off' }); n.value = (list || []).join('\n'); return n; };
    const redirects = ta(c.redirectUris, 3);
    const postLogout = ta(c.postLogoutRedirectUris, 2);
    const frontChannel = h('input.input.mono', { type: 'url', value: c.frontChannelLogoutUri || '', spellcheck: 'false', placeholder: 'https://app.example.com/signout-oidc' });
    const groups = ta(c.allowedGroups, 3);
    groups.classList.remove('mono');
    const pkce = h('input', { type: 'checkbox', checked: c.requirePkce !== false });
    const active = h('input', { type: 'checkbox', checked: c.isActive !== false });
    const pkceHint = h('div.field-hint');
    const errs = h('div.form-errors');

    const currentType = () => (typeRadios.find((x) => x.r.checked) || typeRadios[0]).r.value;
    const syncType = () => {
      const pub = currentType() === 'public';
      if (pub) pkce.checked = true;
      pkce.disabled = pub;
      pkceHint.textContent = pub ? t('sso.f.pkcePublic') : t('sso.f.pkceHint');
    };
    typeRadios.forEach((x) => x.r.addEventListener('change', syncType));
    syncType();

    const meta = isNew ? null : kvList([
      c.createdAt ? [t('sso.m.created'), t('sso.m.by', { by: c.createdBy || '—', at: fmtTime(c.createdAt) })] : null,
      c.updatedAt ? [t('sso.m.updated'), fmtTime(c.updatedAt)] : null,
      c.type !== 'public' ? [t('sso.m.secretRotated'), c.secretRotatedAt ? fmtTime(c.secretRotatedAt) : t('common.never')] : null,
    ], 'field-wide');

    const form = h('form.form-grid', { novalidate: true },
      field(t('sso.f.clientId'), clientId, isNew ? t('sso.f.clientIdHint') : t('sso.f.clientIdFixed'), { name: 'clientid' }),
      field(t('sso.f.displayName'), displayName, t('sso.f.displayNameHint'), { name: 'displayname' }),
      h('fieldset.field.field-wide', { dataset: { field: 'type' } },
        h('legend.field-label', { text: t('sso.f.type') }),
        h('div.type-options', null, typeRadios.map((x) => x.node)),
        isNew ? null : h('div.field-hint', { text: t('sso.f.typeFixed') })),
      field(t('sso.f.redirectUris'), redirects, t('sso.f.redirectUrisHint'), { name: 'redirecturis', wide: true }),
      field(t('sso.f.postLogoutUris'), postLogout, t('sso.f.postLogoutUrisHint'), { name: 'postlogoutredirecturis', wide: true }),
      field(t('sso.f.frontChannel'), frontChannel, t('sso.f.frontChannelHint'), { name: 'frontchannellogouturi', wide: true }),
      field(t('sso.f.groups'), groups, t('sso.f.groupsHint'), { name: 'allowedgroups', wide: true }),
      h('div.field.field-check', { dataset: { field: 'requirepkce' } },
        h('label.check', null, pkce, h('span', { text: t('sso.f.pkce') })), pkceHint),
      checkField(t('sso.f.isActive'), active, t('sso.f.isActiveHint'), { name: 'isactive' }),
      meta,
      errs);

    const save = h('button.btn.btn-primary', { type: 'submit', text: isNew ? t('sso.createSubmit') : t('common.save') });
    const cancel = h('button.btn', { type: 'button', text: t('common.cancel') });
    const m = modal({ title: isNew ? t('sso.formCreate') : t('sso.formEdit', { name: c.clientId }), body: form, footer: [cancel, save], wide: true });
    cancel.addEventListener('click', () => m.close(null));
    save.addEventListener('click', (e) => { e.preventDefault(); form.requestSubmit(); });

    const mark = (fields) => fields.forEach((f) => { const n = form.querySelector(`[data-field="${f}"]`); if (n) n.classList.add('has-error'); });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      form.querySelectorAll('.has-error').forEach((n) => n.classList.remove('has-error'));
      const problems = [];
      const id = clientId.value.trim();
      if (isNew && !CLIENT_ID.test(id)) problems.push(['clientid', t('sso.v.clientId')]);
      if (isNew && CLIENT_ID.test(id) && clients.some((x) => x.clientId === id)) problems.push(['clientid', t('sso.v.clientIdTaken', { id })]);
      const dn = displayName.value.trim();
      if (!dn) problems.push(['displayname', t('sso.v.displayName')]);
      const ru = lines(redirects.value);
      if (!ru.length) problems.push(['redirecturis', t('sso.v.redirectRequired')]);
      const checkUris = (list, f) => list.forEach((v) => { const p = uriProblem(v); if (p) problems.push([f, t(p, { v })]); });
      checkUris(ru, 'redirecturis');
      const pl = lines(postLogout.value);
      checkUris(pl, 'postlogoutredirecturis');
      const fc = frontChannel.value.trim();
      if (fc) checkUris([fc], 'frontchannellogouturi');
      if (problems.length) {
        mark(problems.map((p) => p[0]));
        replace(errs, listBox(problems.map((p) => p[1])));
        return;
      }
      replace(errs);
      const type = isNew ? currentType() : c.type;
      const payload = {
        clientId: isNew ? id : c.clientId,
        displayName: dn,
        type,
        redirectUris: ru,
        postLogoutRedirectUris: pl,
        frontChannelLogoutUri: fc || null,
        allowedGroups: lines(groups.value),
        requirePkce: type === 'public' ? true : pkce.checked,
        isActive: active.checked,
      };
      await busy(save, t('common.saving'), async () => {
        try {
          if (isNew) {
            const res = await post('/sso/clients', payload);
            m.close(true);
            toast(t('sso.created'));
            showConfig(res && res.client ? res.client : payload, res ? res.clientSecret : null, true);
          } else {
            await put(`/sso/clients/${encodeURIComponent(c.clientId)}`, payload);
            m.close(true);
            toast(t('sso.updated'));
          }
          load();
        } catch (err) {
          if (err.status === 401 || err.status === 403) return;
          const { msgs, fields } = serverErrors(err);
          if (err.status === 400) mark(fields);
          replace(errs, listBox(msgs));
        }
      });
    });
  }

  // ---- secret + config snippet ----
  async function issuer() {
    if (!info) { try { info = await get('/sso/info'); } catch { /* placeholder below */ } }
    return info && info.issuer ? info.issuer : '<issuer>';
  }

  /** secret: string = shown once (after create/rotate); null = config only. fresh: just created. */
  async function showConfig(c, secret, fresh) {
    const pub = c.type === 'public';
    const once = !pub && !!secret;
    const authority = await issuer();
    const cfg = { Authority: authority, ClientId: c.clientId };
    if (!pub) cfg.ClientSecret = secret || t('sso.secretPlaceholder');
    const snippet = `"Sso": ${JSON.stringify(cfg, null, 2)}`;

    const parts = [];
    let copied = !once;
    if (once) {
      const input = h('input.input.mono.secret-input', { type: 'text', readonly: true, value: secret, spellcheck: 'false', 'aria-label': 'Client secret' });
      input.addEventListener('focus', () => input.select());
      const copyBtn = h('button.btn', { type: 'button', text: t('common.copy') });
      copyBtn.addEventListener('click', async () => {
        if (await copyText(secret)) { copied = true; copyBtn.textContent = `✓ ${t('common.copied')}`; } else { input.focus(); input.select(); toast(t('common.copyFailed'), 'warning'); }
      });
      parts.push(alertBox('warning', h('strong', { text: t('sso.secretWarn') })),
        h('div.field', null, h('span.field-label', { text: t('sso.secretLabel') }), h('div.secret-row', null, input, copyBtn)));
      setTimeout(() => { input.focus(); input.select(); }, 0);
    } else if (pub) {
      parts.push(alertBox('info', h('span', { text: fresh ? t('sso.publicCreated') : t('sso.publicNoSecret') })));
    } else {
      parts.push(alertBox('info', h('span', { text: t('sso.secretNotShown') })));
    }
    const snippetCopy = copyButton(snippet, t('sso.snippet'));
    snippetCopy.addEventListener('click', () => { if (once) copied = true; });
    parts.push(
      h('div.snippet-head', null, h('span.field-label', { text: t('sso.snippet') }), snippetCopy),
      h('pre.pre.snippet', { text: snippet }),
      h('p.muted.small', { text: t('sso.snippetHint') }),
      kvList([
        [t('sso.f.redirectUris'), (c.redirectUris || []).length ? h('div', (c.redirectUris || []).map((u) => h('div.mono.wrap', { text: u }))) : null],
        [t('sso.i.discovery'), info && info.discoveryUrl ? h('span.mono.wrap', { text: info.discoveryUrl }) : null],
      ]));

    const done = h('button.btn.btn-primary', { type: 'button', text: once ? t('sso.secretDone') : t('common.close') });
    const m = modal({
      title: once ? t('sso.secretTitle', { name: c.displayName || c.clientId }) : t('sso.configTitle', { name: c.displayName || c.clientId }),
      dismissible: !once,
      body: parts,
      footer: [done],
      wide: true,
    });
    done.addEventListener('click', async () => {
      if (!copied) {
        const ok = await confirmDialog({ title: t('sso.secretDone'), message: t('sso.secretConfirmClose'), confirmLabel: t('common.close'), danger: true });
        if (!ok) return;
      }
      m.dismissible = true;
      m.close(true);
    });
  }

  async function rotate(c) {
    const ok = await confirmDialog({ title: t('sso.confirmRotateTitle', { name: c.clientId }), message: t('sso.confirmRotate'), confirmLabel: t('sso.rotate'), danger: true });
    if (!ok) return;
    try {
      const res = await post(`/sso/clients/${encodeURIComponent(c.clientId)}/rotate-secret`);
      toast(t('sso.rotated'));
      showConfig((res && res.client) || c, res ? res.clientSecret : null);
      load();
    } catch (e) { toastError(e); }
  }

  async function setActive(c, on) {
    if (!on) {
      const ok = await confirmDialog({ title: t('sso.confirmDisableTitle', { name: c.clientId }), message: t('sso.confirmDisable'), confirmLabel: t('sso.disable'), danger: true });
      if (!ok) return;
    }
    try {
      await put(`/sso/clients/${encodeURIComponent(c.clientId)}`, { ...toInput(c), isActive: on });
      toast(on ? t('sso.enabled') : t('sso.disabled'));
      load();
    } catch (e) { toastError(e); }
  }

  async function remove(c) {
    const ok = await confirmDialog({ title: t('sso.confirmDeleteTitle', { name: c.clientId }), message: t('sso.confirmDelete'), confirmLabel: t('sso.delete'), danger: true, typeWord: c.clientId });
    if (!ok) return;
    try { await del(`/sso/clients/${encodeURIComponent(c.clientId)}`); toast(t('sso.deleted')); load(); } catch (e) { toastError(e); }
  }

  search.addEventListener('input', () => renderTable());
  refreshBtn.addEventListener('click', () => busy(refreshBtn, null, load));
  if (createBtn) createBtn.addEventListener('click', () => editForm(null));

  await load();
  return { destroy() { alive = false; } };
}
