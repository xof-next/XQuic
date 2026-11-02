'use strict';

// HTTP field-section validation and normalization layer.

const TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const FIELD_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const PSEUDO_NAME_RE = /^:[a-z0-9!#$%&'*+\-.^_`|~]+$/;
const SCHEME_RE = /^[A-Za-z][A-Za-z0-9+.-]*$/;
const CONNECTION_SPECIFIC = new Set([
  'connection',
  'keep-alive',
  'proxy-connection',
  'transfer-encoding',
  'upgrade'
]);

function headersObject(list) {
  const out = Object.create(null);
  for (const [name, value] of list) {
    // Cookie field lines are joined using "; " before being
    // exposed to a generic HTTP application (outside HTTP/2 or HTTP/3).
    if (name === 'cookie') {
      if (out.cookie === undefined) out.cookie = String(value);
      else out.cookie = `${out.cookie}; ${String(value)}`;
      continue;
    }
    if (out[name] === undefined) out[name] = value;
    else if (Array.isArray(out[name])) out[name].push(value);
    else out[name] = [out[name], value];
  }
  return out;
}

/**
 * Convert application-supplied fields to the lowercase form required before
 * HTTP/3/QPACK encoding. Inbound decoded fields must NOT use this function:
 * uppercase received names are malformed and must be rejected, not repaired.
 */
function normalizeOutgoingHeaders(headers) {
  if (headers == null) return [];
  const entries = Array.isArray(headers) ? headers : Object.entries(headers);
  return entries.map((entry) => {
    if (!Array.isArray(entry) || entry.length < 2) {
      throw new TypeError('Each HTTP field must be a [name, value] pair');
    }
    const name = String(entry[0]).toLowerCase();
    const value = String(entry[1] ?? '');
    return [name, value];
  });
}

function isPseudo(name) {
  return name.startsWith(':');
}

function validateHeaders(list, { response = false, trailers = false } = {}) {
  if (!Array.isArray(list)) throw new TypeError('HTTP field section must be an array');

  const seenPseudo = new Set();
  let regular = false;
  let size = 0;
  const methods = [];
  const schemes = [];
  const authorities = [];
  const paths = [];
  const protocols = [];
  const statuses = [];
  const hosts = [];

  for (const field of list) {
    if (!Array.isArray(field) || field.length < 2) {
      throw new Error('Malformed HTTP field entry');
    }
    const originalName = String(field[0]);
    const name = originalName.toLowerCase();
    const value = String(field[1] ?? '');

    // field names in received field sections MUST be lowercase.
    // Outgoing callers are normalized before reaching this validator.
    if (name !== originalName) throw new Error('Uppercase HTTP/3 field name');
    if (!name || /[\r\n\x00]/.test(name)) throw new Error('Invalid HTTP/3 field name');
    if (!isPseudo(name) && !FIELD_NAME_RE.test(name)) throw new Error('Invalid HTTP/3 field name');
    if (isPseudo(name) && !PSEUDO_NAME_RE.test(name)) throw new Error('Invalid HTTP/3 pseudo-header name');

    // requires field-content characters from RFC 9110 §5.5.
    // HTAB is permitted; other CTLs and DEL are not.
    if (/[\x00-\x08\x0A-\x1F\x7F]/.test(value)) {
      throw new Error('Invalid HTTP/3 field value character');
    }

    size += Buffer.byteLength(name) + Buffer.byteLength(value) + 32;

    if (isPseudo(name)) {
      if (trailers) throw new Error('Pseudo-header forbidden in trailers');
      if (regular) throw new Error('Pseudo-header after regular header');
      if (seenPseudo.has(name)) throw new Error('Duplicate HTTP/3 pseudo-header');
      seenPseudo.add(name);
      if (response) {
        if (name !== ':status') throw new Error('Invalid response pseudo-header');
      } else if (![':method', ':scheme', ':authority', ':path', ':protocol'].includes(name)) {
        throw new Error('Invalid request pseudo-header');
      }
    } else {
      regular = true;
      if (name === 'host') hosts.push(value);
    }

    if (CONNECTION_SPECIFIC.has(name)) {
      throw new Error('Connection-specific HTTP/3 field is forbidden');
    }
    if (name === 'te' && value.toLowerCase() !== 'trailers') {
      throw new Error('TE must equal trailers in HTTP/3');
    }

    switch (name) {
      case ':method': methods.push(value); break;
      case ':scheme': schemes.push(value); break;
      case ':authority': authorities.push(value); break;
      case ':path': paths.push(value); break;
      case ':protocol': protocols.push(value); break;
      case ':status': statuses.push(value); break;
    }
  }

  if (trailers) {
    return { list, size };
  }

  if (response) {
    if (statuses.length !== 1) throw new Error('Exactly one :status is required');
    if (!/^[0-9]{3}$/.test(statuses[0])) throw new Error('Invalid :status');
    const status = Number(statuses[0]);
    if (status < 100 || status > 599 || status === 101) {
      throw new Error('Invalid :status for HTTP/3');
    }
    return { list, size, status };
  }

  if (methods.length !== 1) throw new Error('Exactly one :method is required');
  const method = methods[0];
  if (!TOKEN_RE.test(method)) throw new Error('Invalid :method');
  if (hosts.length > 1) throw new Error('Duplicate Host field');
  if (hosts.length === 1 && hosts[0] === '') throw new Error('Empty Host field');

  if (protocols.length && method !== 'CONNECT') throw new Error(':protocol requires CONNECT');
  if (protocols.length && !TOKEN_RE.test(protocols[0])) {
    throw new Error('Invalid :protocol');
  }

  const scheme = schemes[0];
  const authority = authorities[0];
  const path = paths[0];
  const protocol = protocols[0];

  if (method === 'CONNECT' && protocol === undefined) {
    if (schemes.length || paths.length || authorities.length !== 1 || !authority) {
      throw new Error('Invalid CONNECT pseudo-headers');
    }
    // CONNECT uses authority-form, not URI userinfo syntax.
    if (authority.includes('@')) throw new Error('CONNECT :authority must not include userinfo');
    if (hosts.length && hosts[0] !== authority) {
      throw new Error('Host does not match :authority');
    }
    return { list, size, method };
  }

  if (schemes.length !== 1 || paths.length !== 1) {
    throw new Error('Missing required request pseudo-header');
  }
  if (!SCHEME_RE.test(scheme)) throw new Error('Invalid :scheme');
  if (path.includes('#')) throw new Error('HTTP :path must not include a URI fragment');

  const httpScheme = /^https?$/i.test(scheme);
  if (httpScheme && !path) throw new Error('Empty :path');
  if (authorities.length === 1 && !authority) throw new Error('Empty :authority');
  if (authority && hosts.length && authority !== hosts[0]) throw new Error('Host does not match :authority');
  if (httpScheme) {
    if (authorities.length > 1 || (authorities.length === 0 && hosts.length === 0)) {
      throw new Error('HTTP(S) request requires :authority or Host');
    }
    if (authorities.length === 1 && !authority) throw new Error('Empty :authority');
    if (authority && authority.includes('@')) {
      throw new Error(':authority must not include userinfo');
    }
    if (authority && hosts.length && authority !== hosts[0]) {
      throw new Error('Host does not match :authority');
    }
    if (protocol !== undefined && (!authority || !scheme || !path)) {
      throw new Error('Invalid extended CONNECT pseudo-headers');
    }
    if (path.includes('#') || (path[0] !== '/' && !(path === '*' && method === 'OPTIONS'))) {
      throw new Error('Invalid :path');
    }
  } else if (protocol !== undefined) {
    if (authorities.length !== 1 || !authority || !scheme || !path) {
      throw new Error('Invalid extended CONNECT pseudo-headers');
    }
  }

  if (path === '*' && method !== 'OPTIONS') {
    throw new Error('Asterisk-form :path requires OPTIONS');
  }

  return { list, size, method, scheme, authority, path, protocol };
}

function parseContentLength(list) {
  const values = list
    .filter(([name]) => String(name).toLowerCase() === 'content-length')
    .map(([, value]) => String(value));
  if (!values.length) return null;
  if (values.some((value) => !/^[0-9]+$/.test(value))) throw new Error('Invalid Content-Length');
  const first = BigInt(values[0]);
  if (values.some((value) => BigInt(value) !== first)) throw new Error('Conflicting Content-Length');
  if (first > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Content-Length exceeds implementation limit');
  return Number(first);
}

module.exports = {
  headersObject,
  normalizeOutgoingHeaders,
  validateHeaders,
  parseContentLength,
  isPseudo
};
