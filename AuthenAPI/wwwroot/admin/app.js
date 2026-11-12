// Shell: session, login, layout, hash router, global API error handling.
import { t, getLang, setLang } from './i18n.js';
import { configureApi, get, post, ApiError } from './api.js';
import { h, replace, clear, toast, closeAllModals, healthBadge, confirmDialog, fmtSeconds, visibleInterval } from './ui.js';
import * as dashboard from './view-dashboard.js';
import * as keys from './view-keys.js';
import * as logs from './view-logs.js';
import * as settings from './view-settings.js';
import * as tools from './view-tools.js';

const ROUTES = {
  dashboard: { label: 'nav.dashboard', icon: 'M3 13h8V3H3zm0 8h8v-6H3zm10 0h8V11h-8zm0-18v6h8V3z', mount: dashboard.mount },
  keys: { label: 'nav.keys', icon: 'M7 14a4 4 0 1 1 3.9-5H21v4h-2v3h-3v-3h-5.1A4 4 0 0 1 7 14zm0-2a2 2 0 1 0 0-4 2 2 0 0 0 0 4z', mount: keys.mount },
  requests: { label: 'nav.requests', icon: 'M4 5h16v2H4zm0 6h16v2H4zm0 6h10v2H4z', mount: logs.mountRequests },
  audit: { label: 'nav.audit', icon: 'M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5zm-1 14-4-4 1.4-1.4L11 13.2l5.6-5.6L18 9z', mount: logs.mountAudit },
  settings: { label: 'nav.settings', icon: 'M19.4 13a7.5 7.5 0 0 0 0-2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-1.7-1L15 3.5h-4L10.7 6a7 7 0 0 0-1.7 1l-2.4-1-2 3.4 2 1.6a7.5 7.5 0 0 0 0 2l-2 1.6 2 3.4 2.4-1a7 7 0 0 0 1.7 1l.3 2.5h4l.3-2.5a7 7 0 0 0 1.7-1l2.4 1 2-3.4zM13 15.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7z', mount: settings.mount },
  tools: { label: 'nav.tools', icon: 'M21.7 18.6 13 9.9a5.5 5.5 0 0 0-7-7l3.3 3.3-2.8 2.8L3.2 5.7a5.5 5.5 0 0 0 7 7l8.7 8.7z', mount: tools.mount },
};

const state = {
  session: null,
  view: null,        // { destroy?, canLeave? }
  route: null,
  lastHash: '',
  ignoreHash: false,
  health: null,
  stopHealthPoll: null,
};

const appRoot = document.getElementById('app');
const netBanner = document.getElementById('net-banner');

// ---------- global API handling ----------
let forbiddenToastAt = 0;
configureApi({
  unauthorized() {
    if (!state.session) return;
    state.session = null;
    teardownShell();
    showLogin(t('login.sessionExpired'));
  },
  forbidden() {
    const now = Date.now();
    if (now - forbiddenToastAt > 1500) toast(t('err.forbidden'), 'critical');
    forbiddenToastAt = now;
  },
  network(down) {
    netBanner.textContent = t('err.network');
    netBanner.hidden = !down;
  },
});

// ---------- routing ----------
function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [name, query] = raw.split('?');
  return { name: ROUTES[name] ? name : null, params: new URLSearchParams(query || '') };
}

async function onHashChange() {
  if (state.ignoreHash) { state.ignoreHash = false; return; }
  if (!state.session) return;
  const { name } = parseHash();
  if (!name) { location.replace('#/dashboard'); return; }
  if (state.view && state.view.canLeave && !state.view.canLeave() && name !== state.route) {
    const target = location.hash;
    state.ignoreHash = true;
    location.hash = state.lastHash;
    const ok = await confirmDialog({ title: t('common.unsaved'), message: t('common.leaveUnsaved'), confirmLabel: t('common.leave'), danger: true });
    if (!ok) return;
    state.view.canLeave = null;
    location.hash = target;
    return;
  }
  renderRoute();
}

function renderRoute() {
  const { name, params } = parseHash();
  if (!name) { location.replace('#/dashboard'); return; }
  const main = document.getElementById('main');
  if (!main) return;
  if (state.view && state.view.destroy) { try { state.view.destroy(); } catch (e) { console.error(e); } }
  state.view = null;
  state.route = name;
  state.lastHash = location.hash;
  document.querySelectorAll('.nav-link').forEach((a) => a.classList.toggle('active', a.dataset.route === name));
  clear(main);
  document.title = `${t(ROUTES[name].label)} · ${t('app.title')}`;
  const ctx = {
    session: state.session,
    isAdmin: state.session.role === 'Admin',
    params,
    setHealth,
    get health() { return state.health; },
  };
  Promise.resolve(ROUTES[name].mount(main, ctx)).then((v) => {
    if (state.route === name && main.isConnected) state.view = v || {};
    else if (v && v.destroy) v.destroy();
  }).catch((e) => console.error(e));
}

window.addEventListener('hashchange', onHashChange);
window.addEventListener('beforeunload', (e) => {
  if (state.view && state.view.canLeave && !state.view.canLeave()) { e.preventDefault(); e.returnValue = ''; }
});

// ---------- status pill ----------
function setHealth(report) {
  state.health = report;
  const pill = document.getElementById('status-pill');
  if (!pill) return;
  replace(pill, h('span.pill-label', { text: t('top.status') }), healthBadge(report ? report.status : null));
}
async function pollHealth() {
  try { setHealth(await get('/health')); } catch (e) { if (!(e instanceof ApiError)) console.error(e); }
}

// ---------- shell ----------
function navIcon(d) {
  const svgNS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(svgNS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', 'nav-icon');
  svg.setAttribute('aria-hidden', 'true');
  const p = document.createElementNS(svgNS, 'path');
  p.setAttribute('d', d);
  svg.append(p);
  return svg;
}

function langButton(onSwitch, guard) {
  return h('button.btn.btn-ghost.lang-btn', {
    type: 'button', title: t('lang.toggleTitle'), text: t('lang.toggle'),
    onclick: () => {
      if (guard && !guard()) return;
      setLang(getLang() === 'th' ? 'en' : 'th');
      onSwitch();
    },
  });
}

function renderShell() {
  const ses = state.session;
  const nav = h('nav.sidebar', { 'aria-label': 'Main' },
    h('div.brand', null, h('span.brand-mark', { 'aria-hidden': 'true', text: 'A' }), h('span', { text: t('app.title') })),
    h('ul.nav', Object.entries(ROUTES).map(([k, r]) => h('li', null,
      h('a.nav-link', { href: `#/${k}`, dataset: { route: k } }, navIcon(r.icon), h('span', { text: t(r.label) }))))));

  const top = h('header.topbar',
    h('div#status-pill.status-pill', { 'aria-live': 'polite' }),
    h('div.topbar-spacer'),
    h('div.user-box', null,
      h('div.user-name', { text: ses.displayName || ses.username, title: ses.username }),
      h('div.user-meta', null,
        h(`span.role.role-${ses.role === 'Admin' ? 'admin' : 'viewer'}`, { text: t(`role.${ses.role}`) }),
        h('span.muted', { text: ` · ${t(`auth.${ses.authMethod}`) === `auth.${ses.authMethod}` ? ses.authMethod : t(`auth.${ses.authMethod}`)}` }))),
    langButton(renderShell, () => {
      const v = state.view;
      if (v && v.canLeave && !v.canLeave()) { toast(t('common.unsaved'), 'warning'); return false; }
      return true;
    }),
    h('button.btn.btn-ghost', { type: 'button', text: t('top.logout'), onclick: logout }));

  if (state.view && state.view.destroy) state.view.destroy();
  state.view = null;
  replace(appRoot, h('div.layout', null, nav, h('div.content', null, top, h('main#main.main', { tabindex: '-1' }))));
  setHealth(state.health);
  if (!state.stopHealthPoll) {
    pollHealth();
    state.stopHealthPoll = visibleInterval(pollHealth, 60000);
  }
  renderRoute();
}

function teardownShell() {
  closeAllModals();
  if (state.view && state.view.destroy) { try { state.view.destroy(); } catch { /* ignore */ } }
  state.view = null;
  state.route = null;
  if (state.stopHealthPoll) { state.stopHealthPoll(); state.stopHealthPoll = null; }
}

async function logout() {
  if (state.view && state.view.canLeave && !state.view.canLeave()) {
    const ok = await confirmDialog({ title: t('common.unsaved'), message: t('common.leaveUnsaved'), confirmLabel: t('top.logout'), danger: true });
    if (!ok) return;
  }
  try { await post('/auth/logout', undefined, { quiet: true }); } catch { /* ignore */ }
  state.session = null;
  state.health = null;
  teardownShell();
  showLogin();
}

// ---------- login ----------
let lockTimer = null;
function showLogin(notice) {
  if (lockTimer) { clearInterval(lockTimer); lockTimer = null; }
  document.title = t('app.title');
  const user = h('input.input', { type: 'text', name: 'username', autocomplete: 'username', autocapitalize: 'off', spellcheck: 'false', required: true });
  const pass = h('input.input', { type: 'password', name: 'password', autocomplete: 'current-password', required: true });
  const msg = h('div.login-msg', { 'aria-live': 'assertive' });
  const submit = h('button.btn.btn-primary.btn-block', { type: 'submit', text: t('login.submit') });

  const showMsg = (kind, ...children) => {
    replace(msg, h(`div.alert.alert-${kind}`, { role: 'alert' }, children));
  };
  if (notice) showMsg('warning', h('span', { text: notice }));

  const lockout = (seconds) => {
    let left = Math.max(0, Math.ceil(Number(seconds) || 0));
    const counter = h('strong');
    const tick = () => {
      if (left <= 0) {
        clearInterval(lockTimer); lockTimer = null;
        submit.disabled = false;
        showMsg('warning', h('span', { text: t('login.lockedNow') }));
        return;
      }
      counter.textContent = t('login.lockedRetry', { time: fmtSeconds(left) });
      left -= 1;
    };
    submit.disabled = true;
    showMsg('critical', h('div', { text: t('login.locked') }), counter);
    if (lockTimer) clearInterval(lockTimer);
    tick();
    lockTimer = setInterval(tick, 1000);
  };

  const form = h('form.login-form', { novalidate: true },
    h('label.field', null, h('span.field-label', { text: t('login.username') }), user),
    h('label.field', null, h('span.field-label', { text: t('login.password') }), pass),
    msg,
    submit,
    h('p.login-hint', { text: t('login.hint') }));

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!user.value.trim() || !pass.value) { showMsg('critical', h('span', { text: t('login.required') })); return; }
    submit.disabled = true;
    submit.textContent = t('login.submitting');
    let ses;
    try {
      ses = await post('/auth/login', { username: user.value.trim(), password: pass.value }, { quiet: true });
    } catch (err) {
      pass.value = '';
      if (err instanceof ApiError && err.status === 423) {
        submit.textContent = t('login.submit');
        lockout(err.data && err.data.retryAfterSeconds);
        return;
      }
      let text;
      if (err instanceof ApiError && err.status === 401) text = t('login.failed');
      else if (err instanceof ApiError && err.status === 403) text = t('login.forbidden');
      else text = err.message || t('err.generic');
      showMsg('critical', h('span', { text }));
      submit.disabled = false;
      submit.textContent = t('login.submit');
      pass.focus();
      return;
    }
    if (lockTimer) { clearInterval(lockTimer); lockTimer = null; }
    state.session = ses;
    if (!parseHash().name) location.replace('#/dashboard');
    renderShell();
  });

  replace(appRoot, h('div.login-page', null,
    h('div.login-card', null,
      h('div.login-head', null,
        h('div.brand', null, h('span.brand-mark', { 'aria-hidden': 'true', text: 'A' }), h('span', { text: t('app.short') })),
        langButton(() => showLogin(notice))),
      h('h1', { text: t('login.title') }),
      form)));
  setTimeout(() => user.focus(), 0);
}

// ---------- boot ----------
async function boot() {
  try {
    state.session = await get('/auth/me', { quiet: true });
  } catch (err) {
    showLogin(err instanceof ApiError && err.status === 0 ? t('err.networkShort') : null);
    return;
  }
  if (!parseHash().name) location.replace('#/dashboard');
  renderShell();
}
boot();
