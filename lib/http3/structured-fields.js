'use strict';

// Structured Field Values for HTTP.
// The public data model is deliberately explicit for types that JavaScript
// primitives cannot distinguish (Token, Byte Sequence, Date, Display String).

const MAX_INTEGER = 999999999999999;
const DEFAULT_MAX_INPUT = 1024 * 1024;
const DEFAULT_MAX_MEMBERS = 4096;
const TOKEN_RE = /^[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*$/;
const KEY_RE = /^[a-z*][a-z0-9_.*-]*$/;
const TCHAR_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z:/]$/;
const UTF8_FATAL = new TextDecoder('utf-8', { fatal: true });

class StructuredFieldError extends SyntaxError {
  constructor(message, offset = 0) {
    super(`${message} at offset ${offset}`);
    this.name = 'StructuredFieldError';
    this.offset = offset;
    this.code = 'ERR_HTTP_STRUCTURED_FIELD';
  }
}

function token(value) { return { type: 'token', value: String(value) }; }
function decimal(value) { return { type: 'decimal', value }; }
function byteSequence(value) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) throw new TypeError('Byte Sequence requires a Buffer or Uint8Array');
  return { type: 'bytes', value: Buffer.from(value) };
}
function date(value) { return { type: 'date', value }; }
function displayString(value) { return { type: 'display-string', value: String(value) }; }
function innerList(items, params = {}) { return { type: 'inner-list', items, params }; }

class Parser {
  constructor(input, options = {}) {
    if (typeof input !== 'string') {
      if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
        const b = Buffer.from(input);
        for (const octet of b) if (octet > 0x7e) throw new StructuredFieldError('Structured Field input must be ASCII', 0);
        input = b.toString('ascii');
      } else throw new TypeError('Structured Field input must be a string, Buffer, or Uint8Array');
    }
    if (input.length > (options.maxInputLength ?? DEFAULT_MAX_INPUT)) throw new StructuredFieldError('Structured Field input exceeds configured limit', 0);
    for (let i = 0; i < input.length; i++) {
      const c = input.charCodeAt(i);
      if (c > 0x7e) throw new StructuredFieldError('Structured Field input must be ASCII', i);
    }
    this.s = input;
    this.i = 0;
    this.maxMembers = options.maxMembers ?? DEFAULT_MAX_MEMBERS;
    this.count = 0;
  }
  fail(message) { throw new StructuredFieldError(message, this.i); }
  peek() { return this.s[this.i]; }
  eof() { return this.i >= this.s.length; }
  consume(ch) {
    if (this.peek() !== ch) this.fail(`Expected ${JSON.stringify(ch)}`);
    this.i++;
  }
  skipOWS() { while (this.peek() === ' ' || this.peek() === '\t') this.i++; }
  countMember() { if (++this.count > this.maxMembers) this.fail('Structured Field member limit exceeded'); }
  parseKey() {
    const start = this.i;
    if (!/[a-z*]/.test(this.peek() || '')) this.fail('Invalid dictionary/parameter key');
    this.i++;
    while (/[a-z0-9_.*-]/.test(this.peek() || '')) this.i++;
    const key = this.s.slice(start, this.i);
    if (key.length > 256) this.fail('Structured Field key exceeds implementation limit');
    return key;
  }
  parseNumber() {
    const start = this.i;
    if (this.peek() === '-') this.i++;
    if (!/[0-9]/.test(this.peek() || '')) this.fail('Invalid number');
    while (/[0-9]/.test(this.peek() || '')) this.i++;
    let isDecimal = false;
    if (this.peek() === '.') {
      isDecimal = true;
      this.i++;
      if (!/[0-9]/.test(this.peek() || '')) this.fail('Decimal requires fractional digits');
      while (/[0-9]/.test(this.peek() || '')) this.i++;
    }
    const raw = this.s.slice(start, this.i);
    const unsigned = raw[0] === '-' ? raw.slice(1) : raw;
    const dot = unsigned.indexOf('.');
    const integerDigits = dot === -1 ? unsigned.length : dot;
    const fractionDigits = dot === -1 ? 0 : unsigned.length - dot - 1;
    if (isDecimal) {
      if (integerDigits > 12 || fractionDigits > 3) this.fail('Decimal is outside RFC 9651 limits');
    } else if (integerDigits > 15) this.fail('Integer is outside RFC 9651 limits');
    const n = Number(raw);
    if (!Number.isFinite(n)) this.fail('Invalid number');
    return isDecimal ? decimal(n) : n;
  }
  parseString() {
    this.consume('"');
    let out = '';
    while (!this.eof()) {
      const ch = this.s[this.i++];
      if (ch === '"') return out;
      if (ch === '\\') {
        if (this.eof()) this.fail('Incomplete string escape');
        const next = this.s[this.i++];
        if (next !== '"' && next !== '\\') this.fail('Invalid string escape');
        out += next;
        continue;
      }
      const c = ch.charCodeAt(0);
      if (!(c === 0x20 || (c >= 0x21 && c <= 0x7e))) this.fail('Invalid character in Structured Field String');
      out += ch;
    }
    this.fail('Unterminated string');
  }
  parseToken() {
    const start = this.i;
    if (!/[A-Za-z*]/.test(this.peek() || '')) this.fail('Invalid token');
    this.i++;
    while (!this.eof() && TCHAR_RE.test(this.peek())) this.i++;
    return token(this.s.slice(start, this.i));
  }
  parseBytes() {
    this.consume(':');
    const start = this.i;
    while (!this.eof() && this.peek() !== ':') this.i++;
    if (this.eof()) this.fail('Unterminated byte sequence');
    const encoded = this.s.slice(start, this.i);
    this.consume(':');
    // accepting unpadded Base64 and non-zero pad
    // bits when the implementation can decode them. Reject malformed alphabet,
    // embedded padding, impossible length, and incorrectly placed '=' padding.
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) this.fail('Invalid Base64 byte sequence');
    const unpadded = encoded.replace(/=+$/, '');
    const padding = encoded.length - unpadded.length;
    const remainder = unpadded.length % 4;
    if (remainder === 1 || (padding > 0 && (encoded.length % 4 !== 0 || (padding === 1 && remainder !== 3) || (padding === 2 && remainder !== 2)))) {
      this.fail('Invalid Base64 byte sequence padding');
    }
    const padded = unpadded + '='.repeat((4 - remainder) % 4);
    const buf = Buffer.from(padded, 'base64');
    if (buf.length > (this.options?.maxByteSequenceLength ?? 1024 * 1024)) this.fail('Byte sequence exceeds implementation limit');
    return byteSequence(buf);
  }
  parseBoolean() {
    this.consume('?');
    if (this.peek() === '1') { this.i++; return true; }
    if (this.peek() === '0') { this.i++; return false; }
    this.fail('Invalid boolean');
  }
  parseDisplayString() {
    this.consume('%');
    this.consume('"');
    const bytes = [];
    while (!this.eof()) {
      const ch = this.s[this.i++];
      if (ch === '"') {
        try { return displayString(UTF8_FATAL.decode(Uint8Array.from(bytes))); }
        catch { this.fail('Invalid UTF-8 in Display String'); }
      }
      const c = ch.charCodeAt(0);
      if (!(c === 0x20 || (c >= 0x21 && c <= 0x7e))) this.fail('Invalid raw character in Display String');
      if (ch === '%') {
        const hex = this.s.slice(this.i, this.i + 2);
        if (!/^[0-9a-f]{2}$/.test(hex)) this.fail('Display String escapes require lowercase hexadecimal');
        bytes.push(parseInt(hex, 16));
        this.i += 2;
      } else bytes.push(c);
    }
    this.fail('Unterminated Display String');
  }
  parseBareItem() {
    const ch = this.peek();
    if (ch === '-' || /[0-9]/.test(ch || '')) return this.parseNumber();
    if (ch === '"') return this.parseString();
    if (ch === ':') return this.parseBytes();
    if (ch === '?') return this.parseBoolean();
    if (ch === '@') {
      this.i++;
      const n = this.parseNumber();
      if (typeof n !== 'number' || !Number.isInteger(n)) this.fail('Date must be an integer');
      // Date parsing uses the same signed 15-digit Integer grammar.
      // requires support for at least years 1-9999, but permits larger values.
      if (Math.abs(n) > MAX_INTEGER) this.fail('Date outside RFC 9651 integer range');
      return date(n);
    }
    if (ch === '%') return this.parseDisplayString();
    if (/[A-Za-z*]/.test(ch || '')) return this.parseToken();
    this.fail('Unrecognized Structured Field item');
  }
  parseParameters() {
    const params = {};
    while (this.peek() === ';') {
      this.i++;
      while (this.peek() === ' ') this.i++;
      const key = this.parseKey();
      let value = true;
      if (this.peek() === '=') { this.i++; value = this.parseBareItem(); }
      this.countMember();
      Object.defineProperty(params, key, { value, enumerable: true, configurable: true, writable: true });
    }
    return params;
  }
  parseItem() {
    const value = this.parseBareItem();
    const params = this.parseParameters();
    return { value, params };
  }
  parseMember() {
    if (this.peek() !== '(') return this.parseItem();
    this.i++;
    const items = [];
    while (true) {
      const beforeWhitespace = this.i;
      while (this.peek() === ' ') this.i++;
      const separated = this.i > beforeWhitespace;
      if (this.peek() === ')') { this.i++; break; }
      if (this.eof()) this.fail('Unterminated inner list');
      if (items.length && !separated) this.fail('Inner-list items must be separated by whitespace');
      items.push(this.parseItem());
      this.countMember();
    }
    return { type: 'inner-list', items, params: this.parseParameters() };
  }
  finish(value) {
    this.skipOWS();
    if (!this.eof()) this.fail('Unexpected trailing input');
    return value;
  }
  parseTopItem() { this.skipOWS(); return this.finish(this.parseItem()); }
  parseList() {
    this.skipOWS();
    const out = [];
    if (this.eof()) return [];
    while (true) {
      out.push(this.parseMember()); this.countMember();
      this.skipOWS();
      if (this.eof()) return out;
      this.consume(','); this.skipOWS();
      if (this.eof()) this.fail('Trailing comma in List');
    }
  }
  parseDictionary() {
    this.skipOWS();
    const out = {};
    if (this.eof()) return out;
    while (true) {
      const key = this.parseKey();
      let member;
      if (this.peek() === '=') { this.i++; member = this.parseMember(); }
      else member = { value: true, params: this.parseParameters() };
      Object.defineProperty(out, key, { value: member, enumerable: true, configurable: true, writable: true });
      this.countMember();
      this.skipOWS();
      if (this.eof()) return out;
      this.consume(','); this.skipOWS();
      if (this.eof()) this.fail('Trailing comma in Dictionary');
    }
  }
}

function createParser(input, options) {
  const p = new Parser(input, options);
  p.options = options || {};
  return p;
}
function parseItem(input, options = {}) { return createParser(input, options).parseTopItem(); }
function parseList(input, options = {}) { const p = createParser(input, options); return p.finish(p.parseList()); }
function parseDictionary(input, options = {}) { const p = createParser(input, options); return p.finish(p.parseDictionary()); }

function paramsEntries(params) {
  if (params === undefined || params === null) return [];
  if (params instanceof Map) return [...params.entries()];
  if (typeof params !== 'object' || Array.isArray(params)) throw new TypeError('Structured Field parameters must be an object or Map');
  return Object.entries(params);
}
function serializeKey(key) {
  if (typeof key !== 'string' || !KEY_RE.test(key)) throw new TypeError(`Invalid Structured Field key: ${String(key)}`);
  return key;
}
function serializeDecimal(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new TypeError('Structured Field Decimal must be finite');
  const rounded = roundTiesToEven(value, 3);
  const abs = Math.abs(rounded);
  if (Math.floor(abs) > 999999999999) throw new RangeError('Structured Field decimal outside RFC 9651 range');
  let s = rounded.toFixed(3).replace(/0+$/, '').replace(/\.$/, '.0');
  if (!s.includes('.')) s += '.0';
  return s;
}
function serializeBareItem(value) {
  if (typeof value === 'boolean') return value ? '?1' : '?0';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Structured Field number must be finite');
    if (Number.isInteger(value)) {
      if (Math.abs(value) > MAX_INTEGER) throw new RangeError('Structured Field integer outside RFC 9651 range');
      return String(value);
    }
    return serializeDecimal(value);
  }
  if (typeof value === 'string') {
    if (!/^[\x20-\x7e]*$/.test(value)) throw new TypeError('Structured Field String must contain only ASCII SP/VCHAR');
    return `"${value.replace(/[\\"]/g, '\\$&')}"`;
  }
  if (value && typeof value === 'object') {
    if (value.type === 'decimal') return serializeDecimal(value.value);
    if (value.type === 'token') {
      if (typeof value.value !== 'string' || !TOKEN_RE.test(value.value)) throw new TypeError('Invalid Structured Field Token');
      return value.value;
    }
    if (value.type === 'bytes') {
      const b = value.value;
      if (!Buffer.isBuffer(b) && !(b instanceof Uint8Array)) throw new TypeError('Byte Sequence requires a Buffer or Uint8Array');
      return `:${Buffer.from(b).toString('base64')}:`;
    }
    if (value.type === 'date') {
      if (!Number.isInteger(value.value) || !Number.isSafeInteger(value.value) || Math.abs(value.value) > MAX_INTEGER) throw new RangeError('Structured Field Date outside RFC 9651 integer range');
      return `@${value.value}`;
    }
    if (value.type === 'display-string') {
      if (typeof value.value !== 'string') throw new TypeError('Display String requires a string');
      // TextEncoder replaces unpaired surrogates, so reject them explicitly.
      for (let i = 0; i < value.value.length; i++) {
        const c = value.value.charCodeAt(i);
        if (c >= 0xd800 && c <= 0xdbff) {
          const next = value.value.charCodeAt(i + 1);
          if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError('Display String contains an unpaired surrogate');
          i++;
        } else if (c >= 0xdc00 && c <= 0xdfff) throw new TypeError('Display String contains an unpaired surrogate');
      }
      const bytes = Buffer.from(value.value, 'utf8');
      let encoded = '%"';
      for (const b of bytes) {
        if (b === 0x25 || b === 0x22 || b <= 0x1f || b >= 0x7f) encoded += `%${b.toString(16).padStart(2, '0')}`;
        else encoded += String.fromCharCode(b);
      }
      return `${encoded}"`;
    }
    if (value.type === 'inner-list') throw new TypeError('Inner List is not a bare item');
  }
  throw new TypeError('Unsupported Structured Field bare item');
}
function roundTiesToEven(value, places) {
  const scale = 10 ** places;
  const scaled = Math.abs(value) * scale;
  const floor = Math.floor(scaled);
  const fraction = scaled - floor;
  let rounded;
  if (fraction > 0.5) rounded = floor + 1;
  else if (fraction < 0.5) rounded = floor;
  else rounded = floor % 2 === 0 ? floor : floor + 1;
  return Math.sign(value) * rounded / scale;
}
function serializeParameters(params) {
  let out = '';
  for (const [keyRaw, value] of paramsEntries(params)) {
    const key = serializeKey(keyRaw);
    out += `;${key}`;
    if (value !== true) out += `=${serializeBareItem(value)}`;
  }
  return out;
}
function serializeItem(item) {
  if (!item || typeof item !== 'object' ||
      !Object.prototype.hasOwnProperty.call(item, 'value') ||
      !Object.prototype.hasOwnProperty.call(item, 'params') ||
      typeof item.type === 'string') {
    return serializeBareItem(item);
  }
  return serializeBareItem(item.value) + serializeParameters(item.params);
}
function serializeMember(member) {
  if (member && member.type === 'inner-list') {
    if (!Array.isArray(member.items)) throw new TypeError('Inner List items must be an array');
    return `(${member.items.map(serializeItem).join(' ')})${serializeParameters(member.params)}`;
  }
  return serializeItem(member);
}
function serializeList(list) {
  if (!Array.isArray(list)) throw new TypeError('Structured Field List must be an array');
  return list.map(serializeMember).join(', ');
}
function serializeDictionary(dictionary) {
  const entries = dictionary instanceof Map ? [...dictionary.entries()] : Object.entries(dictionary || {});
  return entries.map(([keyRaw, member]) => {
    const key = serializeKey(keyRaw);
    if (member === true) return key;
    if (member && member.type !== 'inner-list' && member.value === true && paramsEntries(member.params).length === 0) return key;
    if (member && member.type !== 'inner-list' && member.value === true && member.params && paramsEntries(member.params).length) {
      return `${key}${serializeParameters(member.params)}`;
    }
    return `${key}=${serializeMember(member)}`;
  }).join(', ');
}

module.exports = {
  StructuredFieldError,
  token,
  decimal,
  byteSequence,
  date,
  displayString,
  innerList,
  parseItem,
  parseList,
  parseDictionary,
  serializeItem,
  serializeList,
  serializeDictionary
};
module.exports.default = module.exports;
