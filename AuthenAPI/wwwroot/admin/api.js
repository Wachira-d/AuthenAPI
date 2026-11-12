// Thin fetch wrapper for /api/admin/*. Unwraps the { success, data, error } envelope.
import { t } from './i18n.js';

export const API_BASE = '/api/admin';

export class ApiError extends Error {
  constructor(status, message, body) {
    super(message);
    this.status = status;
    this.body = body || null;
    this.data = body && body.data;
    this.details = body && body.error;
  }
}

const handlers = {
  unauthorized: () => {},
  forbidden: () => {},
  network: () => {},
};

export function configureApi(h) { Object.assign(handlers, h); }

/** Turn the envelope's `error` (string | string[] | {field: string[]} | {message}) into display lines. */
export function errorLines(err) {
  const out = [];
  const walk = (v, prefix) => {
    if (v == null || v === '') return;
    if (typeof v === 'string') { out.push(prefix ? `${prefix}: ${v}` : v); return; }
    if (typeof v === 'number' || typeof v === 'boolean') { out.push(String(v)); return; }
    if (Array.isArray(v)) { v.forEach((x) => walk(x, prefix)); return; }
    if (typeof v === 'object') {
      if (typeof v.message === 'string' && Object.keys(v).length <= 3) { walk(v.message, prefix); return; }
      // ASP.NET ProblemDetails / ModelState shapes
      if (v.errors && typeof v.errors === 'object') { walk(v.errors, prefix); return; }
      for (const [k, val] of Object.entries(v)) walk(val, k);
    }
  };
  if (err instanceof ApiError) {
    walk(err.details, '');
    if (!out.length && err.message) out.push(err.message);
  } else if (err) {
    out.push(err.message || String(err));
  }
  return [...new Set(out)];
}

/** Field names mentioned in a validation error object (lower-cased, last path segment). */
export function errorFields(err) {
  const d = err instanceof ApiError ? err.details : null;
  const src = d && typeof d === 'object' && !Array.isArray(d) ? (d.errors && typeof d.errors === 'object' ? d.errors : d) : null;
  if (!src) return [];
  return Object.keys(src).map((k) => k.split('.').pop().replace(/\[\d+\]$/, '').toLowerCase());
}

/**
 * @param {string} method
 * @param {string} path  path below /api/admin, e.g. "/keys"
 * @param {*} [body]
 * @param {{ quiet?: boolean, signal?: AbortSignal }} [opts]  quiet: skip global 401/403 handling
 */
export async function api(method, path, body, opts = {}) {
  const init = {
    method,
    credentials: 'same-origin',
    headers: { Accept: 'application/json' },
    signal: opts.signal,
  };
  if (method !== 'GET') init.headers['X-Admin-Request'] = '1';
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  let res;
  try {
    res = await fetch(API_BASE + path, init);
  } catch (e) {
    if (e && e.name === 'AbortError') throw e;
    handlers.network(true);
    throw new ApiError(0, t('err.networkShort'));
  }
  handlers.network(false);

  let json = null;
  const ct = res.headers.get('Content-Type') || '';
  if (ct.includes('json')) {
    try { json = await res.json(); } catch { json = null; }
  }

  if (!res.ok) {
    if (res.status === 401 && !opts.quiet) handlers.unauthorized();
    if (res.status === 403 && !opts.quiet) handlers.forbidden();
    let msg = (json && (json.message || (typeof json.error === 'string' ? json.error : '') || json.title)) || '';
    if (!msg) {
      if (res.status === 403) msg = t('err.forbidden');
      else if (res.status === 404) msg = t('err.notFound');
      else if (res.status === 400) msg = t('err.validation');
      else msg = t('err.http', { status: res.status });
    }
    throw new ApiError(res.status, msg, json);
  }
  if (json && typeof json === 'object' && 'data' in json) return json.data;
  return json;
}

export const get = (p, o) => api('GET', p, undefined, o);
export const post = (p, b, o) => api('POST', p, b, o);
export const put = (p, b, o) => api('PUT', p, b, o);
export const del = (p, o) => api('DELETE', p, undefined, o);

/** Build a query string, dropping empty values. */
export function qs(params) {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    u.set(k, String(v));
  }
  const s = u.toString();
  return s ? `?${s}` : '';
}
