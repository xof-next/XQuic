'use strict';

const { EventEmitter } = require('node:events');

const QUIC_MIN_DATAGRAM_SIZE = 1200;
const DEFAULT_MAX_PROBE_SIZE = 1452;
const DEFAULT_PROBE_TIMEOUT_MS = 16_000;
const DEFAULT_MAX_PROBES = 3;

/**
 * Conservative DPLPMTUD search state for QUIC datagram payload sizes.
 * The QUIC connection itself supplies the probe packet and ACK/loss feedback.
 * ICMP input is intentionally not accepted here: requires validation
 * of path/port/connection metadata before PTB information may affect an MPS.
 */
class PathMtuDiscovery extends EventEmitter {
  constructor(connection, options = {}) {
    super();
    this.connection = connection;
    this.minSize = Number(options.minSize ?? QUIC_MIN_DATAGRAM_SIZE);
    this.maxSize = Number(options.maxSize ?? DEFAULT_MAX_PROBE_SIZE);
    this.probeTimeoutMs = Number(options.probeTimeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS);
    this.maxProbes = Number(options.maxProbes ?? DEFAULT_MAX_PROBES);
    if (!Number.isSafeInteger(this.minSize) || this.minSize < QUIC_MIN_DATAGRAM_SIZE) throw new TypeError('minSize must be at least 1200');
    if (!Number.isSafeInteger(this.maxSize) || this.maxSize < this.minSize || this.maxSize > 65527) throw new TypeError('maxSize must be between minSize and 65527');
    if (!Number.isFinite(this.probeTimeoutMs) || this.probeTimeoutMs < 1000) throw new TypeError('probeTimeoutMs must be at least 1000 ms');
    if (!Number.isSafeInteger(this.maxProbes) || this.maxProbes < 1 || this.maxProbes > 10) throw new TypeError('maxProbes must be between 1 and 10');
    this.nextId = 1;
    this.paths = new Map();
    this.probes = new Map();
    this.closed = false;
  }

  _key(address) {
    const a = address || this.connection?.address;
    if (!a || !a.address || !Number.isInteger(Number(a.port))) throw new TypeError('A remote path address is required');
    return JSON.stringify([String(a.address), Number(a.port)]);
  }

  _effectiveMax() {
    // max_udp_payload_size describes what the peer is willing to receive.
    const peerMax = Number(this.connection?.peerTransportParameters?.maxUdpPayloadSize ?? 65527);
    return Math.max(this.minSize, Math.min(this.maxSize, Number.isFinite(peerMax) && peerMax > 0 ? peerMax : this.minSize));
  }

  _state(address) {
    const key = this._key(address);
    let state = this.paths.get(key);
    if (!state) {
      const max = this._effectiveMax();
      state = {
        key,
        address: { address: String((address || this.connection.address).address), port: Number((address || this.connection.address).port) },
        state: max <= this.minSize ? 'complete' : 'searching',
        currentSize: this.minSize,
        low: this.minSize,
        high: max,
        candidateSize: null,
        candidateFailures: 0,
        activeProbeId: null,
        successfulProbes: 0,
        failedProbes: 0,
        updatedAt: Date.now()
      };
      this.paths.set(key, state);
    }
    const max = this._effectiveMax();
    if (state.high > max) state.high = max;
    if (state.currentSize > max) state.currentSize = max;
    if (state.low > max) state.low = max;
    if (state.low >= state.high) state.state = 'complete';
    return state;
  }

  nextProbeSize(address = null) {
    if (this.closed) return null;
    const state = this._state(address);
    if (state.activeProbeId !== null || state.state === 'complete') return null;
    if (state.candidateSize !== null && state.candidateFailures < this.maxProbes) return state.candidateSize;
    if (state.high <= state.low + 1) {
      state.state = 'complete';
      return null;
    }
    state.candidateSize = Math.floor((state.low + state.high + 1) / 2);
    state.candidateFailures = 0;
    state.state = 'searching';
    return state.candidateSize;
  }

  startProbe(address = null) {
    if (this.closed) throw new Error('Path MTU discovery is closed');
    this._trimHistory();
    if (this.probes.size >= 64) throw new Error('Too many outstanding/history PMTU probes; wait for feedback before starting another');
    const actualAddress = address || this.connection?.address;
    const size = this.nextProbeSize(actualAddress);
    if (size === null) return null;
    const state = this._state(actualAddress);
    const id = this.nextId++;
    const probe = { id, size, key: state.key, address: { ...state.address }, status: 'pending', startedAt: Date.now(), timer: null };
    probe.timer = setTimeout(() => this.onProbeTimeout(id), this.probeTimeoutMs);
    probe.timer.unref?.();
    state.activeProbeId = id;
    this.probes.set(id, probe);
    this._trimHistory();
    this.emit('probe', { id, size, address: { ...probe.address } });
    return { id, size, address: { ...probe.address } };
  }

  cancelProbe(id) {
    const probe = this.probes.get(Number(id));
    if (!probe || probe.status !== 'pending') return false;
    if (probe.timer) clearTimeout(probe.timer);
    probe.status = 'cancelled';
    const state = this.paths.get(probe.key);
    if (state?.activeProbeId === probe.id) state.activeProbeId = null;
    this.probes.delete(probe.id);
    return true;
  }

  onProbeAck(id) {
    const probe = this.probes.get(Number(id));
    if (!probe || probe.status === 'acknowledged' || probe.status === 'cancelled') return false;
    if (probe.timer) clearTimeout(probe.timer);
    probe.status = 'acknowledged';
    const state = this.paths.get(probe.key);
    if (!state) return false;
    state.low = Math.max(state.low, probe.size);
    state.high = Math.max(state.high, probe.size);
    state.currentSize = Math.max(state.currentSize, probe.size);
    state.candidateSize = null;
    state.candidateFailures = 0;
    state.successfulProbes++;
    state.updatedAt = Date.now();
    state.state = state.high <= state.low + 1 ? 'complete' : 'searching';
    if (state.activeProbeId === probe.id) state.activeProbeId = null;

    // The current recovery/path MTU is shared by packet construction and async chunking.
    if (this.connection?._pathBytesKey && this.connection._pathBytesKey(this.connection.address) === probe.key && this.connection.recovery) {
      this.connection.recovery.maxDatagramSize = state.currentSize;
      this.connection.emit?.('pathMtuUpdate', this.snapshot(probe.address));
    }
    this.emit('update', this.snapshot(probe.address));
    return true;
  }

  onProbeLost(id) {
    return this._failProbe(Number(id), 'loss');
  }

  onProbeTimeout(id) {
    return this._failProbe(Number(id), 'timeout');
  }

  _failProbe(id, reason) {
    const probe = this.probes.get(id);
    if (!probe || probe.status === 'acknowledged' || probe.status === 'cancelled' || probe.status === 'failed') return false;
    if (probe.timer) clearTimeout(probe.timer);
    probe.status = 'failed';
    const state = this.paths.get(probe.key);
    if (!state) return false;
    if (state.activeProbeId === id) state.activeProbeId = null;
    state.candidateFailures++;
    state.failedProbes++;
    state.updatedAt = Date.now();
    if (state.candidateFailures >= this.maxProbes) {
      state.high = Math.min(state.high, probe.size - 1);
      state.candidateSize = null;
      state.candidateFailures = 0;
    }
    state.state = state.high <= state.low + 1 ? 'complete' : 'searching';
    this.emit('probeFailure', { id, size: probe.size, reason, ...this.snapshot(probe.address) });
    return true;
  }

  snapshot(address = null) {
    const state = this._state(address);
    return {
      state: state.state,
      currentSize: state.currentSize,
      low: state.low,
      high: state.high,
      candidateSize: state.candidateSize,
      candidateFailures: state.candidateFailures,
      activeProbeId: state.activeProbeId,
      successfulProbes: state.successfulProbes,
      failedProbes: state.failedProbes,
      address: { ...state.address }
    };
  }

  _trimHistory() {
    while (this.probes.size >= 64) {
      let removable = null;
      for (const [id, probe] of this.probes) {
        if (probe.status !== 'pending') { removable = id; break; }
      }
      if (removable === null) break;
      const old = this.probes.get(removable);
      if (old?.timer) clearTimeout(old.timer);
      this.probes.delete(removable);
    }
  }

  close() {
    this.closed = true;
    for (const probe of this.probes.values()) if (probe.timer) clearTimeout(probe.timer);
    this.probes.clear();
    this.paths.clear();
  }
}

module.exports = { PathMtuDiscovery, QUIC_MIN_DATAGRAM_SIZE, DEFAULT_MAX_PROBE_SIZE };
module.exports.default = module.exports;
