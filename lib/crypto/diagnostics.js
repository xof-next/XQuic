'use strict';

const crypto = require('node:crypto');

function clone(value) {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(clone);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = clone(v);
    return out;
  }
  return value;
}

function attachDetails(value, details) {
  if (process.env.XOF_PACKET_DETAILS !== '1') return value;
  const copy = clone(details);
  if (value && (typeof value === 'object' || typeof value === 'function')) {
    Object.defineProperty(value, 'details', {
      value: copy,
      enumerable: false,
      configurable: true,
      writable: false
    });
    Object.defineProperty(value, 'detail', {
      value: copy,
      enumerable: false,
      configurable: true,
      writable: false
    });
  }
  return value;
}

function hex(value) {
  return Buffer.from(value || []).toString('hex');
}

function computeJA3({ version = 771, cipherSuites = [], extensions = [], supportedGroups = [], ecPointFormats = [] } = {}) {
  const extensionTypes = extensions.map((x) => Number(typeof x === 'object' && x !== null ? x.type : x));
  const raw = [
    Number(version),
    cipherSuites.map(Number).join('-'),
    extensionTypes.join('-'),
    supportedGroups.map(Number).join('-'),
    ecPointFormats.map(Number).join('-')
  ].join(',');
  return {
    raw,
    hash: crypto.createHash('md5').update(raw, 'ascii').digest('hex')
  };
}

module.exports = { attachDetails, clone, hex, computeJA3 };
module.exports.default = module.exports;
