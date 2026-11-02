'use strict';

// Capsule Protocol stream framing (Capsule Type, Length, Value).
const { EventEmitter } = require('node:events');
const { encodeVarInt, decodeVarInt } = require('../codec/varint');
const { parseItem } = require('./structured-fields');

const CAPSULE_TYPE = Object.freeze({ DATAGRAM: 0x00n });
const DEFAULT_MAX_CAPSULE_SIZE = 1024 * 1024;
const DEFAULT_MAX_CAPSULES_PER_PUSH = 65536;

function toType(value) {
  let n;
  if (typeof value === 'bigint') n = value;
  else if (typeof value === 'number' && Number.isSafeInteger(value)) n = BigInt(value);
  else throw new TypeError('Capsule type must be a BigInt or safe integer');
  if (n < 0n || n > 0x3fffffffffffffffn) throw new RangeError('Capsule type is outside the QUIC variable-length integer range');
  return n;
}
function asBuffer(value) {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (value === undefined || value === null) return Buffer.alloc(0);
  throw new TypeError('Capsule value must be a Buffer or Uint8Array');
}
function encodeCapsule(type, value = Buffer.alloc(0), options = {}) {
  const payload = asBuffer(value);
  const maxCapsuleSize = options.maxCapsuleSize ?? DEFAULT_MAX_CAPSULE_SIZE;
  if (!Number.isSafeInteger(maxCapsuleSize) || maxCapsuleSize < 0) throw new RangeError('maxCapsuleSize must be a non-negative safe integer');
  if (payload.length > maxCapsuleSize) throw new RangeError('Capsule payload exceeds configured size limit');
  return Buffer.concat([encodeVarInt(toType(type)), encodeVarInt(payload.length), payload]);
}
function decodeType(value) { return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value; }
function tryVarInt(buffer, offset) {
  if (offset >= buffer.length) return null;
  const length = 1 << (buffer[offset] >>> 6);
  if (offset + length > buffer.length) return null;
  return decodeVarInt(buffer, offset);
}

class CapsuleParser extends EventEmitter {
  constructor(options = {}) {
    super();
    this.maxCapsuleSize = options.maxCapsuleSize ?? DEFAULT_MAX_CAPSULE_SIZE;
    this.knownTypes = options.knownTypes ? new Set([...options.knownTypes].map((v) => toType(v).toString())) : null;
    this.dropUnknown = options.dropUnknown ?? Boolean(this.knownTypes);
    this.maxCapsulesPerPush = options.maxCapsulesPerPush ?? DEFAULT_MAX_CAPSULES_PER_PUSH;
    if (!Number.isSafeInteger(this.maxCapsuleSize) || this.maxCapsuleSize < 0) throw new RangeError('maxCapsuleSize must be a non-negative safe integer');
    if (!Number.isSafeInteger(this.maxCapsulesPerPush) || this.maxCapsulesPerPush < 1) throw new RangeError('maxCapsulesPerPush must be a positive safe integer');
    this.pending = Buffer.alloc(0);
    this.closed = false;
    this.totalCapsules = 0;
  }
  push(chunk) {
    if (this.closed) throw new Error('Capsule parser is already finished');
    const incoming = asBuffer(chunk);
    if (!incoming.length) return [];
    const buffer = this.pending.length ? Buffer.concat([this.pending, incoming]) : incoming;
    const capsules = [];
    let offset = 0;
    let parsedOnPush = 0;
    while (offset < buffer.length) {
      const start = offset;
      let type, length;
      try { type = tryVarInt(buffer, offset); }
      catch (cause) { throw Object.assign(new Error('Malformed Capsule Type'), { cause, code: 'ERR_HTTP_CAPSULE_FRAME' }); }
      if (!type) break;
      offset = type.offset;
      try { length = tryVarInt(buffer, offset); }
      catch (cause) { throw Object.assign(new Error('Malformed Capsule Length'), { cause, code: 'ERR_HTTP_CAPSULE_FRAME' }); }
      if (!length) { offset = start; break; }
      offset = length.offset;
      if (length.value > BigInt(this.maxCapsuleSize)) {
        throw Object.assign(new RangeError('Capsule payload exceeds configured size limit'), { code: 'ERR_HTTP_CAPSULE_TOO_LARGE', capsuleType: type.value, capsuleLength: length.value });
      }
      const size = Number(length.value);
      if (offset + size > buffer.length) { offset = start; break; }
      if (++parsedOnPush > this.maxCapsulesPerPush) throw Object.assign(new Error('Capsule count per input chunk exceeds configured limit'), { code: 'ERR_HTTP_CAPSULE_COUNT' });
      const capsule = { type: decodeType(type.value), payload: Buffer.from(buffer.subarray(offset, offset + size)) };
      const known = !this.knownTypes || this.knownTypes.has(type.value.toString());
      this.totalCapsules++;
      if (known || !this.dropUnknown) capsules.push(capsule);
      offset += size;
    }
    this.pending = Buffer.from(buffer.subarray(offset));
    // One incomplete capsule can be no larger than its configured payload
    // limit plus the two 8-byte QUIC varint headers.
    if (this.pending.length > this.maxCapsuleSize + 16) throw Object.assign(new Error('Capsule parser pending buffer exceeds configured limit'), { code: 'ERR_HTTP_CAPSULE_BUFFER' });
    for (const capsule of capsules) this.emit('capsule', capsule);
    return capsules;
  }
  finish() {
    if (this.closed) return;
    this.closed = true;
    if (this.pending.length) throw Object.assign(new Error('Truncated Capsule Protocol stream'), { code: 'ERR_HTTP_CAPSULE_TRUNCATED', remainingBytes: this.pending.length });
    this.emit('end');
  }
  reset() {
    this.pending = Buffer.alloc(0);
    this.closed = true;
  }
}
function parseCapsules(input, options = {}) {
  const parser = new CapsuleParser(options);
  const result = parser.push(input);
  parser.finish();
  return result;
}
function encodeDatagramCapsule(payload = Buffer.alloc(0), options = {}) {
  return encodeCapsule(CAPSULE_TYPE.DATAGRAM, payload, options);
}
function parseCapsuleProtocol(value) {
  // this is an Item Structured Field whose bare value MUST
  // be Boolean. Malformed values, non-booleans, and combined field lines
  // (which parse as a List) are treated as if the field were absent.
  if (typeof value !== 'string') return false;
  try {
    const item = parseItem(value, { maxInputLength: 8192, maxMembers: 64 });
    return item.value === true || item.value === false ? item.value : false;
  } catch { return false; }
}
function capsuleProtocolHeaders(headers) {
  const result = new Map();
  if (Array.isArray(headers)) {
    for (const [name, value] of headers) {
      const key = String(name).toLowerCase();
      if (key === 'capsule-protocol' && result.has(key)) result.set(key, `${result.get(key)}, ${value}`);
      else result.set(key, value);
    }
  } else if (headers && typeof headers === 'object') {
    for (const [name, value] of Object.entries(headers)) result.set(name.toLowerCase(), value);
  }
  return result;
}
function validateCapsuleProtocolUse({ method, statusCode, headers } = {}) {
  const fields = capsuleProtocolHeaders(headers);
  if (!parseCapsuleProtocol(fields.get('capsule-protocol'))) return { enabled: false };
  for (const forbidden of ['content-length', 'content-type', 'transfer-encoding']) {
    if (fields.has(forbidden)) throw Object.assign(new Error(`Capsule Protocol forbids ${forbidden}`), { code: 'ERR_HTTP_CAPSULE_HEADER' });
  }
  if (method !== undefined && String(method).toUpperCase() !== 'CONNECT') {
    throw Object.assign(new Error('Capsule Protocol requires CONNECT in HTTP/2 and HTTP/3'), { code: 'ERR_HTTP_CAPSULE_METHOD' });
  }
  if (statusCode !== undefined) {
    const status = Number(statusCode);
    // This helper is for HTTP/3: 101 Switching Protocols is not a valid
    // HTTP/3 response status. Capsule Protocol can only become active after a
    // successful 2xx response for HTTP/2 and HTTP/3 CONNECT.
    if (!Number.isInteger(status) || status < 200 || status >= 300 || [204, 205, 206].includes(status)) {
      throw Object.assign(new Error('Status is not permitted for Capsule Protocol'), { code: 'ERR_HTTP_CAPSULE_STATUS' });
    }
  }
  return { enabled: true };
}

module.exports = { CAPSULE_TYPE, CapsuleParser, encodeCapsule, parseCapsules, encodeDatagramCapsule, parseCapsuleProtocol, validateCapsuleProtocolUse, DEFAULT_MAX_CAPSULE_SIZE };
module.exports.default = module.exports;
