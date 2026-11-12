// DOM + formatting helpers. Every string child becomes a text node, so API data is never parsed as HTML.
import { t, locale, getLang } from './i18n.js';
import { errorLines } from './api.js';

/**
 * h('div.card.wide', { onclick, attrs... }, child, [children], 'text')
 * Props: class, text, dataset, on<Event>, any attribute; boolean true sets an empty attribute; false/null skips.
 */
export function h(tag, props, ...children) {
  const [nameId, ...classes] = tag.split('.');
  const [name, id] = nameId.split('#');
  const node = document.createElement(name || 'div');
  if (id) node.id = id;
  if (classes.length) node.className = classes.join(' ');
  if (isChild(props)) { children.unshift(props); props = null; }
  applyProps(node, props);
  append(node, children);
  return node;
}

function isChild(v) {
  return Array.isArray(v) || v instanceof Node || typeof v === 'string' || typeof v === 'number';
}

const SVG_NS = 'http://www.w3.org/2000/svg';
export function s(tag, attrs, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') node.setAttribute('class', v);
      else if (k === 'text') node.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, String(v));
    }
  }
  append(node, children);
  return node;
}

function applyProps(node, props) {
  if (!props) return;
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = [node.className, v].filter(Boolean).join(' ');
    else if (k === 'text') node.textContent = String(v);
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k === 'value') node.value = v;
    else if (k === 'checked') node.checked = !!v;
    else if (k === 'disabled') node.disabled = !!v;
    else if (k === 'selected') node.selected = !!v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
    else if (v === true) node.setAttribute(k, '');
    else node.setAttribute(k, String(v));
  }
}

export function append(node, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

export function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }
export function replace(node, ...children) { clear(node); return append(node, children); }

// ---------- formatting ----------
export function fmtNum(n, digits = 0) {
  if (n === null || n === undefined || Number.isNaN(n)) return t('common.none');
  return new Intl.NumberFormat(locale(), { maximumFractionDigits: digits, minimumFractionDigits: 0 }).format(n);
}
export function fmtCompact(n) {
  if (n === null || n === undefined) return t('common.none');
  if (Math.abs(n) < 10000) return fmtNum(n);
  return new Intl.NumberFormat(locale(), { notation: 'compact', maximumFractionDigits: 1 }).format(n);
}
export function fmtPct(p, digits = 1) {
  if (p === null || p === undefined || Number.isNaN(p)) return t('common.none');
  return `${fmtNum(p, digits)}%`;
}
/** errorRate may be a 0..1 fraction or a 0..100 percentage; the contract does not say. */
export function ratePct(r) {
  if (r === null || r === undefined) return null;
  return r <= 1 ? r * 100 : r;
}
export function fmtMs(ms) {
  if (ms === null || ms === undefined) return t('common.none');
  if (ms >= 10000) return `${fmtNum(ms / 1000, 1)} s`;
  return `${fmtNum(ms, ms < 10 ? 1 : 0)} ms`;
}
export function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return t('common.none');
  const sec = Math.floor(seconds);
  const d = Math.floor(sec / 86400), hh = Math.floor((sec % 86400) / 3600), mm = Math.floor((sec % 3600) / 60);
  const th = getLang() === 'th';
  const parts = [];
  if (d) parts.push(th ? `${d} วัน` : `${d}d`);
  if (hh || d) parts.push(th ? `${hh} ชม.` : `${hh}h`);
  parts.push(th ? `${mm} นาที` : `${mm}m`);
  if (!d && !hh) parts.push(th ? `${sec % 60} วินาที` : `${sec % 60}s`);
  return parts.join(' ');
}
export function fmtSeconds(sec) {
  const m = Math.floor(sec / 60), r = sec % 60;
  return m ? `${m}:${String(r).padStart(2, '0')} ${getLang() === 'th' ? 'นาที' : 'min'}` : `${r} ${getLang() === 'th' ? 'วินาที' : 's'}`;
}

export function parseTime(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}
export function fmtTime(iso, { seconds = true, dateOnly = false } = {}) {
  const d = parseTime(iso);
  if (!d) return t('common.none');
  const opts = dateOnly
    ? { year: 'numeric', month: 'short', day: 'numeric' }
    : { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', ...(seconds ? { second: '2-digit' } : {}), hour12: false };
  return new Intl.DateTimeFormat(locale(), opts).format(d);
}
export function fmtClock(d, withDate) {
  const opts = withDate
    ? { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }
    : { hour: '2-digit', minute: '2-digit', hour12: false };
  return new Intl.DateTimeFormat(locale(), opts).format(d);
}
export function fmtRelative(iso) {
  const d = parseTime(iso);
  if (!d) return '';
  const diff = (d.getTime() - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return t('time.justNow');
  const rtf = new Intl.RelativeTimeFormat(getLang() === 'th' ? 'th' : 'en', { numeric: 'auto', style: 'short' });
  const units = [['year', 31536000], ['month', 2592000], ['week', 604800], ['day', 86400], ['hour', 3600], ['minute', 60]];
  for (const [u, n] of units) if (abs >= n) return rtf.format(Math.round(diff / n), u);
  return rtf.format(Math.round(diff), 'second');
}
/** <time> with local time and a relative hint; title shows the raw UTC value. */
export function timeEl(iso, opts) {
  if (!iso) return h('span.muted', { text: opts && opts.emptyText ? opts.emptyText : t('common.none') });
  const d = parseTime(iso);
  if (!d) return h('span', { text: String(iso) });
  if (opts && opts.compact) {
    return h('time.ts', { datetime: d.toISOString(), title: `${fmtTime(iso)} · ${d.toISOString()} (UTC)` },
      h('span', { text: fmtRelative(iso) }));
  }
  return h('time.ts', { datetime: d.toISOString(), title: `${d.toISOString()} (UTC)` },
    h('span.ts-abs', { text: fmtTime(iso, opts) }),
    h('span.ts-rel', { text: fmtRelative(iso) }));
}

/** ISO → value for <input type="datetime-local"> in local time. */
export function toLocalInput(iso) {
  const d = parseTime(iso);
  if (!d) return '';
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
export function fromLocalInput(v) {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

export function lines(text) {
  return String(text || '').split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
}

// ---------- badges ----------
const STATUS_ICON = { good: '✓', warning: '!', serious: '!', critical: '✕', neutral: '•', info: 'i' };
export function badge(kind, label, title) {
  return h(`span.badge.badge-${kind}`, { title },
    h('span.badge-icon', { 'aria-hidden': 'true', text: STATUS_ICON[kind] || '•' }),
    h('span', { text: label }));
}
export function healthKind(status) {
  return status === 'Healthy' ? 'good' : status === 'Degraded' ? 'warning' : status === 'Unhealthy' ? 'critical' : 'neutral';
}
export function healthBadge(status) {
  const key = `status.${status || 'Unknown'}`;
  return badge(healthKind(status), t(key) === key ? String(status) : t(key));
}
export function statusClass(code) {
  if (code >= 500) return 'critical';
  if (code >= 400) return 'warning';
  if (code >= 300) return 'neutral';
  return 'good';
}
export function statusCodeEl(code) {
  return h(`span.code.code-${statusClass(code)}`, { text: code == null ? t('common.none') : String(code) });
}
export function boolBadge(v, yes = t('common.yesValue'), no = t('common.noValue')) {
  return v ? badge('good', yes) : badge('critical', no);
}

// ---------- loading / empty / error ----------
export function spinner(label) {
  return h('div.state.state-loading', { role: 'status' }, h('span.spin', { 'aria-hidden': 'true' }), h('span', { text: label || t('common.loading') }));
}
export function emptyState(text) { return h('div.state.state-empty', { text: text || t('common.empty') }); }
export function errorState(err, retry) {
  return h('div.state.state-error', { role: 'alert' },
    h('div', ...errorLines(err).map((l) => h('div', { text: l }))),
    retry ? h('button.btn.btn-sm', { type: 'button', onclick: retry, text: t('common.retry') }) : null);
}
export function errorBox(err) {
  const ls = errorLines(err);
  return h('div.alert.alert-critical', { role: 'alert' }, ls.length > 1 ? h('ul', ls.map((l) => h('li', { text: l }))) : h('span', { text: ls[0] || t('err.generic') }));
}
export function alertBox(kind, ...children) {
  return h(`div.alert.alert-${kind}`, { role: kind === 'critical' ? 'alert' : null },
    h('span.alert-icon', { 'aria-hidden': 'true', text: STATUS_ICON[kind] || 'i' }), h('div', children));
}

// ---------- toasts ----------
let toastHost;
export function toast(message, kind = 'good', ms = 4500) {
  if (!toastHost) {
    toastHost = h('div.toasts', { 'aria-live': 'polite' });
    document.body.append(toastHost);
  }
  const node = h(`div.toast.toast-${kind}`, { role: kind === 'critical' ? 'alert' : 'status' },
    h('span.toast-icon', { 'aria-hidden': 'true', text: STATUS_ICON[kind] || 'i' }),
    h('span.toast-msg', { text: message }),
    h('button.toast-x', { type: 'button', 'aria-label': t('common.close'), text: '×', onclick: () => node.remove() }));
  toastHost.append(node);
  setTimeout(() => node.remove(), ms);
}
export function toastError(err) {
  if (err && (err.status === 401 || err.status === 403 || err.status === 0)) return; // handled globally
  toast(errorLines(err).join(' · ') || t('err.generic'), 'critical', 7000);
}

// ---------- modal ----------
const openModals = [];
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && openModals.length) {
    const top = openModals[openModals.length - 1];
    if (top.dismissible) top.close(null);
  }
});

/**
 * modal({ title, body: Node|Node[], footer: Node[], wide, dismissible, onClose })
 * returns { close(result), root, body, footer, result: Promise }
 */
export function modal({ title, body, footer, wide, dismissible = true, onClose, className }) {
  let resolve;
  const result = new Promise((r) => { resolve = r; });
  const prevFocus = document.activeElement;
  const titleId = `m-${Math.random().toString(36).slice(2)}`;
  const bodyEl = h('div.modal-body', body);
  const footEl = h('div.modal-foot', footer || []);
  const dialog = h(`div.modal${wide ? '.modal-wide' : ''}`, { role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId, class: className },
    h('div.modal-head',
      h('h2', { id: titleId, text: title }),
      dismissible ? h('button.icon-btn', { type: 'button', 'aria-label': t('common.close'), text: '×', onclick: () => api.close(null) }) : null),
    bodyEl, footEl);
  const root = h('div.overlay', null, dialog);
  root.addEventListener('mousedown', (e) => { if (e.target === root && dismissible) api.close(null); });
  const api = {
    root, body: bodyEl, footer: footEl, result, dismissible,
    close(v) {
      if (!root.isConnected) return;
      if (onClose && onClose(v) === false) return;
      root.remove();
      const i = openModals.indexOf(api);
      if (i >= 0) openModals.splice(i, 1);
      resolve(v);
      if (prevFocus && prevFocus.focus) prevFocus.focus();
    },
  };
  openModals.push(api);
  document.body.append(root);
  setTimeout(() => {
    const f = dialog.querySelector('[autofocus], input:not([type=hidden]):not([disabled]), textarea, select, .modal-foot .btn-primary');
    (f || dialog).focus && (f || dialog).focus();
  }, 0);
  return api;
}

export function closeAllModals() { [...openModals].forEach((m) => { m.dismissible = true; m.close(null); }); }

/**
 * Confirmation dialog. strong: user must tick "I understand"; typeWord: user must type the word.
 * Resolves true/false.
 */
export function confirmDialog({ title, message, confirmLabel, danger, strong, typeWord, extra }) {
  const okBtn = h(`button.btn${danger ? '.btn-danger' : '.btn-primary'}`, { type: 'button', text: confirmLabel || t('common.confirm') });
  const cancelBtn = h('button.btn', { type: 'button', text: t('common.cancel') });
  const body = [h('p.confirm-msg', { text: message })];
  if (extra) body.push(extra);
  let check, input;
  const sync = () => {
    okBtn.disabled = (check && !check.checked) || (input && input.value.trim() !== typeWord);
  };
  if (strong) {
    check = h('input', { type: 'checkbox', onchange: sync });
    body.push(h('label.check.confirm-check', null, check, h('span', { text: t('common.iUnderstand') })));
  }
  if (typeWord) {
    input = h('input.input', { type: 'text', autocomplete: 'off', spellcheck: 'false', oninput: sync });
    body.push(h('label.field', null, h('span.field-label', { text: t('common.typeToConfirm', { word: typeWord }) }), input));
  }
  const m = modal({ title, body, footer: [cancelBtn, okBtn], className: danger || strong ? 'modal-danger' : '' });
  okBtn.addEventListener('click', () => m.close(true));
  cancelBtn.addEventListener('click', () => m.close(false));
  sync();
  if (!strong && !typeWord) setTimeout(() => cancelBtn.focus(), 0);
  return m.result.then((v) => v === true);
}

// ---------- drawer ----------
export function drawer(title, content) {
  const m = modal({ title, body: content, className: 'drawer' });
  m.root.classList.add('overlay-drawer');
  return m;
}

/** Key/value list. rows: [label, value(Node|string)] */
export function kvList(rows, cls = '') {
  return h(`dl.kv${cls ? `.${cls}` : ''}`, rows.filter(Boolean).map(([k, v]) => [
    h('dt', { text: k }),
    h('dd', v instanceof Node ? v : (v === null || v === undefined || v === '' ? h('span.muted', { text: t('common.none') }) : String(v))),
  ]));
}

// ---------- tables ----------
/**
 * columns: [{ label, render(row) -> Node|string, cls, num, title }]
 * opts: { empty, onRowClick(row), rowClass(row), caption }
 */
export function table(columns, rows, opts = {}) {
  if (!rows || !rows.length) return emptyState(opts.empty);
  const thead = h('thead', null, h('tr', columns.map((c) => h(`th${c.num ? '.num' : ''}`, { scope: 'col', class: c.cls, title: c.title, text: c.label }))));
  const tbody = h('tbody', rows.map((r) => {
    const tr = h('tr', { class: opts.rowClass ? opts.rowClass(r) : null },
      columns.map((c) => {
        const v = c.render(r);
        return h(`td${c.num ? '.num' : ''}`, { class: c.cls }, v === null || v === undefined || v === '' ? h('span.muted', { text: t('common.none') }) : v);
      }));
    if (opts.onRowClick) {
      tr.classList.add('clickable');
      tr.tabIndex = 0;
      tr.addEventListener('click', (e) => { if (!e.target.closest('button, a, input')) opts.onRowClick(r); });
      tr.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target === tr) opts.onRowClick(r); });
    }
    return tr;
  }));
  return h('div.table-wrap', null, h('table.tbl', null, opts.caption ? h('caption.sr-only', { text: opts.caption }) : null, thead, tbody));
}

export function pager(total, skip, take, onChange) {
  const from = total ? skip + 1 : 0;
  const to = Math.min(skip + take, total);
  return h('div.pager',
    h('span.pager-info', { text: t('common.pageInfo', { from: fmtNum(from), to: fmtNum(to), total: fmtNum(total) }) }),
    h('button.btn.btn-sm', { type: 'button', disabled: skip <= 0, text: `‹ ${t('common.prev')}`, onclick: () => onChange(Math.max(0, skip - take)) }),
    h('button.btn.btn-sm', { type: 'button', disabled: skip + take >= total, text: `${t('common.next')} ›`, onclick: () => onChange(skip + take) }));
}

// ---------- form fields ----------
export function field(label, control, hint, opts = {}) {
  const id = control.id || `f-${Math.random().toString(36).slice(2)}`;
  control.id = id;
  const hintId = hint ? `${id}-hint` : null;
  if (hintId) control.setAttribute('aria-describedby', hintId);
  return h(`div.field${opts.wide ? '.field-wide' : ''}`, { dataset: opts.name ? { field: opts.name } : undefined },
    h('label.field-label', { for: id, text: label }),
    control,
    hint ? h('div.field-hint', { id: hintId, text: hint }) : null);
}
export function checkField(label, input, hint, opts = {}) {
  return h(`div.field.field-check${opts.wide ? '.field-wide' : ''}`, { dataset: opts.name ? { field: opts.name } : undefined },
    h('label.check', null, input, h('span', { text: label })),
    hint ? h('div.field-hint', { text: hint }) : null);
}

export async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* fall through */ }
  const ta = h('textarea.offscreen', { readonly: true });
  ta.value = text;
  document.body.append(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch { ok = false; }
  ta.remove();
  return ok;
}

/** Run an async action with a button showing a busy label. */
export async function busy(btn, label, fn) {
  const prev = btn.textContent;
  btn.disabled = true;
  btn.classList.add('is-busy');
  if (label) btn.textContent = label;
  try { return await fn(); } finally {
    btn.disabled = false;
    btn.classList.remove('is-busy');
    btn.textContent = prev;
  }
}

export function downloadUrl(url) {
  const a = h('a', { href: url, download: '' });
  document.body.append(a);
  a.click();
  a.remove();
}

/** setInterval that pauses while the tab is hidden and fires once on return. Returns stop(). */
export function visibleInterval(fn, ms) {
  let id = null;
  const start = () => { if (id === null) id = setInterval(fn, ms); };
  const stop = () => { if (id !== null) { clearInterval(id); id = null; } };
  const onVis = () => {
    if (document.hidden) stop();
    else { fn(); start(); }
  };
  document.addEventListener('visibilitychange', onVis);
  if (!document.hidden) start();
  return () => { stop(); document.removeEventListener('visibilitychange', onVis); };
}

// ---------- menu button ----------
let openMenu = null;
function closeMenu() { if (openMenu) { openMenu.remove(); openMenu = null; } }
document.addEventListener('mousedown', (e) => { if (openMenu && !openMenu.contains(e.target)) closeMenu(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeMenu(); });
window.addEventListener('scroll', closeMenu, true);
/** items: [{ label, danger, onClick }] */
export function menuButton(label, items, ariaLabel) {
  const btn = h('button.btn.btn-sm.menu-btn', { type: 'button', 'aria-haspopup': 'menu', 'aria-label': ariaLabel || label, text: label });
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    const wasMine = openMenu && openMenu.dataset.owner === btn.dataset.mid;
    closeMenu();
    if (wasMine) return;
    btn.dataset.mid = btn.dataset.mid || Math.random().toString(36).slice(2);
    const menu = h('div.menu', { role: 'menu', dataset: { owner: btn.dataset.mid } }, items.map((it) => h(`button.menu-item${it.danger ? '.menu-danger' : ''}`, {
      type: 'button', role: 'menuitem', text: it.label,
      onclick: () => { closeMenu(); it.onClick(); },
    })));
    document.body.append(menu);
    const r = btn.getBoundingClientRect();
    const mw = menu.offsetWidth;
    menu.style.left = `${Math.max(8, Math.min(window.innerWidth - mw - 8, r.right - mw))}px`;
    const below = r.bottom + 4 + menu.offsetHeight < window.innerHeight;
    menu.style.top = `${below ? r.bottom + 4 : r.top - menu.offsetHeight - 4}px`;
    openMenu = menu;
    const first = menu.querySelector('button');
    if (first) first.focus();
  });
  return btn;
}
