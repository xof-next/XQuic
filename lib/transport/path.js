'use strict';
const { randomBytes } = require('node:crypto');

class PathManager {
  constructor(connection) {
    this.connection = connection;
    this.current = connection.address ? { address: connection.address.address, port: Number(connection.address.port) } : null;
    this.validated = new Set(this.current && connection.addressValidated ? [this.key(this.current)] : []);
    this.pending = new Map();
    this.challengeRate = new Map();
    this.maxPending = 8;
  }

  key(address) {
    return JSON.stringify([String(address.address), Number(address.port)]);
  }

  isCurrent(address) { return !!address && !!this.current && this.key(address) === this.key(this.current); }
  isValidated(address) { return !!address && this.validated.has(this.key(address)); }

  markValidated(address, { makeCurrent = false, emit = false } = {}) {
    if (!address) return false;
    const a = { address: String(address.address), port: Number(address.port) };
    if (!Number.isInteger(a.port) || a.port < 0 || a.port > 65535) return false;
    const key = this.key(a);
    this.validated.add(key);
    const prior = this.current;
    if (makeCurrent || !this.current) {
      this.current = a;
      this.connection.setPeerAddress(a, true);
    } else {
      // Preserve byte counters when validation status changes.
      const pathBytesKey = this.connection._pathBytesKey ? this.connection._pathBytesKey(a) : `${a.address}:${a.port}`;
      const counters = this.connection.pathBytes?.get(pathBytesKey) || { rx: 0, tx: 0, validated: false };
      counters.validated = true;
      this.connection.pathBytes?.set(pathBytesKey, counters);
    }
    if (emit && (!prior || this.key(prior) !== key)) this.connection.emit('pathValidated', { ...a });
    return true;
  }

  observe(address) {
    if (!address) return false;
    const a = { address: String(address.address), port: Number(address.port) };
    if (!Number.isInteger(a.port) || a.port < 0 || a.port > 65535) return false;
    if (this.isCurrent(a)) return true;
    if (this.connection.readyState !== 'open') return false;
    const k = this.key(a);
    if (this.validated.has(k)) {
      this.current = a;
      this.connection.setPeerAddress(a, true);
      return true;
    }
    if (this.pending.has(k) || this.pending.size >= this.maxPending) return false;
    const now = Date.now();
    for (const [key, ts] of this.challengeRate) if (now - ts > 60_000) this.challengeRate.delete(key);
    const last = this.challengeRate.get(k) || 0;
    if (now - last < 1000) return false;
    this.challengeRate.set(k, now);
    const data = randomBytes(8);
    this.pending.set(k, { address: a, data, created: now });
    try {
      // A PATH_CHALLENGE must be sent on the candidate path being validated.
      this.connection.sendFrames('app', 'app', [{ type: 0x1a, data }], { probe: true, address: a });
    } catch {
      this.pending.delete(k);
    }
    return false;
  }

  response(data, address = null) {
    if (!Buffer.isBuffer(data) && !(data instanceof Uint8Array)) return null;
    const got = Buffer.from(data);
    if (got.length !== 8) return null;
    const expectedAddress = address ? { address: String(address.address), port: Number(address.port) } : null;
    for (const [k, v] of this.pending) {
      if (expectedAddress && k !== this.key(expectedAddress)) continue;
      if (got.equals(v.data)) {
        this.pending.delete(k);
        const previous = this.current;
        this.markValidated(v.address, { makeCurrent: true });
        if (previous && this.key(previous) !== k) {
          // Switching paths may also require switching to a fresh peer-issued CID.
          try { this.connection.onPathValidated?.(v.address, previous); } catch (err) { this.connection.emit('error', err); }
        }
        this.connection.emit('pathValidated', { ...v.address });
        return v.address;
      }
    }
    return null;
  }

  failExpired(maxAgeMs = 15000) {
    const now = Date.now();
    for (const [k, v] of this.pending) {
      if (now - v.created > maxAgeMs) {
        this.pending.delete(k);
        // Keep the rate-limit record for a short period to prevent challenge floods.
      }
    }
  }

  close() {
    this.pending.clear();
    this.challengeRate.clear();
    this.validated.clear();
  }
}
module.exports = { PathManager };
module.exports.default = module.exports;
