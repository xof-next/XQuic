'use strict';

const { QUICError } = require('../errors');
const { QUIC_ERROR } = require('../constants');

function bi(v, name = 'value') {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  throw new QUICError(`${name} must be a non-negative integer`, { code: QUICError.ERR_INVALID_ARGUMENT });
}

class StreamState {
  constructor(id, opts = {}) {
    this.id = BigInt(id);
    this.sendMax = bi(opts.sendMax ?? 0n, 'sendMax');
    this.recvMax = bi(opts.recvMax ?? 0n, 'recvMax');
    this.sendOffset = 0n;
    // recvMaxOffset is the contiguous delivery cursor; recvHighestOffset is the
    // per-stream high-water mark used by QUIC connection-level flow control.
    this.recvMaxOffset = 0n;
    this.recvHighestOffset = 0n;
    this.recvConsumed = 0n;
    this.recvFinalSize = null;
    this.finSent = false;
    this.finReceived = false;
    this.sendOpened = false;
    this.recvOpened = false;
    this.resetSent = false;
    this.resetReceived = false;
    this.stopped = false;
    this.rx = new Map();
    this.bufferedBytes = 0;
    this.maxBufferedBytes = Math.max(64 * 1024, Number(opts.maxBufferedBytes ?? 16 * 1024 * 1024));
    this.ready = false;
    this._highestSent = 0n;
  }

  checkSend(offset, length, final) {
    offset = bi(offset, 'offset');
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new QUICError('Invalid stream data length', { code: QUICError.ERR_INVALID_ARGUMENT });
    }
    const end = offset + BigInt(length);
    if (this.resetSent) {
      throw new QUICError('Cannot send on a stream whose send side was reset', { code: QUICError.ERR_STREAM_STATE });
    }
    // An empty FIN at the already-fixed final size is idempotent. This is
    // useful for callers whose end() path may be invoked more than once.
    if (this.finSent) {
      if (final && length === 0 && end === this._highestSent) return end;
      throw new QUICError('Cannot send on a stream whose send side is already closed', { code: QUICError.ERR_STREAM_STATE });
    }
    if (end > this.sendMax) {
      throw new QUICError('STREAM flow control blocked', { code: QUICError.ERR_FLOW_CONTROL });
    }
    // A FIN fixes the final size. It cannot truncate data sent at a higher
    // offset, even if that data was sent in a previous STREAM frame.
    if (final && end < this._highestSent) {
      throw new QUICError('STREAM final size is smaller than previously sent data', { code: QUICError.ERR_FINAL_SIZE });
    }
    return end;
  }

  noteSent(offset, length, final) {
    const end = bi(offset, 'offset') + BigInt(length);
    if (end > this._highestSent) this._highestSent = end;
    this.sendOpened = true;
    if (final) this.finSent = true;
    this.sendOffset = this._highestSent;
  }

  receive(offset, data, fin) {
    this.recvOpened = true;
    offset = bi(offset, 'offset');
    let buf = Buffer.from(data);
    const originalEnd = offset + BigInt(buf.length);

    if (originalEnd > this.recvMax) {
      throw new QUICError('STREAM flow control exceeded', { code: QUICError.ERR_FLOW_CONTROL });
    }
    if (this.recvFinalSize !== null && originalEnd > this.recvFinalSize) {
      throw new QUICError('Data exceeds final size', { code: QUICError.ERR_FINAL_SIZE });
    }
    if (fin) {
      const finalSize = originalEnd;
      if (this.recvFinalSize !== null && this.recvFinalSize !== finalSize) {
        throw new QUICError('Conflicting final size', { code: QUICError.ERR_FINAL_SIZE });
      }
      if (finalSize < this.recvHighestOffset) {
        throw new QUICError('Final size is smaller than previously received data', { code: QUICError.ERR_FINAL_SIZE });
      }
      this.recvFinalSize = finalSize;
      this.finReceived = true;
    }

    if (originalEnd > this.recvHighestOffset) this.recvHighestOffset = originalEnd;
    // Ignore already-delivered bytes on retransmission; they must not consume
    // reassembly memory or cause an identical retransmission to hit the cap.
    if (originalEnd <= this.recvMaxOffset) return Buffer.alloc(0);
    if (offset < this.recvMaxOffset) {
      const deliveredPrefix = Number(this.recvMaxOffset - offset);
      buf = buf.subarray(deliveredPrefix);
      offset = this.recvMaxOffset;
    }
    const end = offset + BigInt(buf.length);

    let buffered = 0;
    let coveredBytes = 0n;
    for (const [k, chunk] of this.rx) {
      buffered += chunk.length;
      const a = BigInt(k);
      const b = a + BigInt(chunk.length);
      const overlapStart = a > offset ? a : offset;
      const overlapEnd = b < end ? b : end;
      if (overlapEnd > overlapStart) coveredBytes += overlapEnd - overlapStart;
    }
    const uniqueIncoming = BigInt(buf.length) - coveredBytes;
    if (uniqueIncoming < 0n) throw new QUICError('Invalid STREAM reassembly accounting', { code: QUICError.ERR_INTERNAL });
    if (BigInt(buffered) + uniqueIncoming > BigInt(this.maxBufferedBytes)) {
      throw new QUICError('STREAM reassembly limit exceeded', { code: QUICError.ERR_FLOW_CONTROL });
    }

    let unionStart = offset;
    let unionEnd = end;
    const overlaps = [];
    for (const [k, existing] of this.rx) {
      const a = BigInt(k);
      const b = a + BigInt(existing.length);
      if (b <= offset || a >= end) continue;
      overlaps.push([a, existing]);
      if (a < unionStart) unionStart = a;
      if (b > unionEnd) unionEnd = b;
    }
    if (overlaps.length) {
      const merged = Buffer.alloc(Number(unionEnd - unionStart));
      buf.copy(merged, Number(offset - unionStart));
      for (const [a, existing] of overlaps) {
        const pos = Number(a - unionStart);
        const srcStart = Math.max(0, Number(unionStart - a));
        const srcEnd = Math.min(existing.length, Number(unionEnd - a));
        for (let i = srcStart; i < srcEnd; i++) {
          const dst = pos + i;
          if (dst >= 0 && dst < merged.length) {
            const absolute = a + BigInt(i);
            const incomingByte = merged[dst];
            const existingByte = existing[i];
            if (absolute >= offset && absolute < end && incomingByte !== existingByte) {
              throw new QUICError('Conflicting STREAM overlap', { code: QUICError.ERR_PROTOCOL });
            }
            merged[dst] = existingByte;
          }
        }
      }
      for (const [a] of overlaps) this.rx.delete(String(a));
      if (unionEnd > unionStart) this.rx.set(String(unionStart), merged);
    } else if (buf.length) {
      this.rx.set(String(offset), buf);
    }

    let next = this.recvMaxOffset;
    const pieces = [];
    let progressed = true;
    while (progressed) {
      progressed = false;
      for (const [k, chunk] of [...this.rx]) {
        const start = BigInt(k);
        const chunkEnd = start + BigInt(chunk.length);
        if (chunkEnd <= next) {
          this.rx.delete(k);
          continue;
        }
        if (start <= next) {
          const trim = Number(next - start);
          const part = trim ? chunk.subarray(trim) : chunk;
          this.rx.delete(k);
          if (part.length) {
            pieces.push(part);
            next += BigInt(part.length);
          }
          progressed = true;
        }
      }
    }
    this.recvMaxOffset = next;
    this.bufferedBytes = 0;
    for (const chunk of this.rx.values()) this.bufferedBytes += chunk.length;
    return Buffer.concat(pieces);
  }

  consume(n) {
    n = bi(n, 'consume');
    this.recvConsumed += n;
  }

  isReadableFinished() {
    return this.finReceived && this.recvFinalSize !== null && this.recvMaxOffset >= this.recvFinalSize;
  }

  isTerminal() {
    return this.finSent || this.resetSent || this.finReceived || this.resetReceived;
  }
}

class FlowControl {
  constructor(opts = {}) {
    this.localMaxData = bi(opts.maxData ?? 1024 * 1024, 'maxData');
    this.remoteMaxData = bi(opts.maxData ?? 1024 * 1024, 'maxData');
    this.localMaxStreamData = bi(opts.maxStreamData ?? 1024 * 1024, 'maxStreamData');
    this.remoteMaxStreamData = bi(opts.maxStreamData ?? 1024 * 1024, 'maxStreamData');
    this.localMaxStreamDataBidiLocal = bi(opts.maxStreamDataBidiLocal ?? opts.maxStreamData ?? 1024 * 1024, 'maxStreamDataBidiLocal');
    this.localMaxStreamDataBidiRemote = bi(opts.maxStreamDataBidiRemote ?? opts.maxStreamData ?? 1024 * 1024, 'maxStreamDataBidiRemote');
    this.localMaxStreamDataUni = bi(opts.maxStreamDataUni ?? opts.maxStreamData ?? 1024 * 1024, 'maxStreamDataUni');
    this.remoteMaxStreamDataBidiLocal = bi(opts.remoteMaxStreamDataBidiLocal ?? opts.maxStreamData ?? 1024 * 1024, 'remoteMaxStreamDataBidiLocal');
    this.remoteMaxStreamDataBidiRemote = bi(opts.remoteMaxStreamDataBidiRemote ?? opts.maxStreamData ?? 1024 * 1024, 'remoteMaxStreamDataBidiRemote');
    this.remoteMaxStreamDataUni = bi(opts.remoteMaxStreamDataUni ?? opts.maxStreamData ?? 1024 * 1024, 'remoteMaxStreamDataUni');
    this.localMaxStreams = bi(opts.maxStreams ?? 16, 'maxStreams');
    this.remoteMaxStreams = bi(opts.remoteMaxStreams ?? opts.maxStreams ?? 16, 'remoteMaxStreams');
    this.recvData = 0n;
    this.sentData = 0n;
    this.consumedData = 0n;
    this.streams = new Map();
    this.nextBidi = opts.isServer ? 1n : 0n;
    this.nextUni = opts.isServer ? 3n : 2n;
    this.localMaxStreamsUni = bi(opts.maxStreamsUni ?? 16, 'maxStreamsUni');
    this.remoteMaxStreamsUni = bi(opts.remoteMaxStreamsUni ?? opts.maxStreamsUni ?? 16, 'remoteMaxStreamsUni');
    this.openedLocalUni = 0n;
    this.openedRemoteUni = 0n;
    this.openedLocalBidi = 0n;
    this.openedRemoteBidi = 0n;
    // Highest stream ordinal opened by a locally sent STREAM/RESET_STREAM.
    // A higher stream ID implicitly opens lower IDs of the same type.
    this.wireOpenedLocalBidi = 0n;
    this.wireOpenedLocalUni = 0n;
  }

  stream(id, create = false, opts = {}) {
    const key = String(BigInt(id));
    let s = this.streams.get(key);
    if (s) return s;
    if (!create) return null;
    s = new StreamState(id, opts);
    this.streams.set(key, s);
    return s;
  }

  isLocalInitiated(id, isServer) {
    return Boolean((BigInt(id) & 1n) === (isServer ? 1n : 0n));
  }

  isBidirectional(id) { return (BigInt(id) & 2n) === 0n; }

  streamLimits(id, isServer) {
    id = BigInt(id);
    const localInitiated = this.isLocalInitiated(id, isServer);
    const bidirectional = this.isBidirectional(id);
    if (bidirectional) {
      return {
        // A peer's bidi_remote limit applies to streams we initiate; bidi_local
        // applies to streams the peer initiates.
        sendMax: localInitiated ? this.remoteMaxStreamDataBidiRemote : this.remoteMaxStreamDataBidiLocal,
        recvMax: localInitiated ? this.localMaxStreamDataBidiLocal : this.localMaxStreamDataBidiRemote
      };
    }
    return {
      sendMax: localInitiated ? this.remoteMaxStreamDataUni : 0n,
      recvMax: localInitiated ? 0n : this.localMaxStreamDataUni
    };
  }

  checkNewRemoteStream(id, isServer) {
    id = BigInt(id);
    if (!this.isBidirectional(id)) return;
    if (this.isLocalInitiated(id, isServer)) return;
    const ordinal = id >> 2n;
    if (ordinal >= this.localMaxStreams) {
      throw new QUICError('Maximum remote bidirectional streams exceeded', { code: QUICError.ERR_STREAM_LIMIT });
    }
  }

  noteRemoteStream(id, isServer) {
    id = BigInt(id);
    if (!this.isBidirectional(id) || this.isLocalInitiated(id, isServer)) return;
    const ordinal = (id >> 2n) + 1n;
    if (ordinal > this.openedRemoteBidi) this.openedRemoteBidi = ordinal;
  }

  noteLocalStream(id, isServer, onWire = false) {
    id = BigInt(id);
    if (!this.isLocalInitiated(id, isServer)) {
      throw new QUICError('Cannot mark a remotely initiated stream as locally opened', { code: QUICError.ERR_STREAM_STATE });
    }
    const ordinal = (id >> 2n) + 1n;
    if (this.isBidirectional(id)) {
      if (ordinal > this.remoteMaxStreams) throw new QUICError('Maximum local bidirectional streams exceeded', { code: QUICError.ERR_STREAM_LIMIT });
      if (ordinal > this.openedLocalBidi) this.openedLocalBidi = ordinal;
      if (id >= this.nextBidi) this.nextBidi = id + 4n;
      if (onWire && ordinal > this.wireOpenedLocalBidi) this.wireOpenedLocalBidi = ordinal;
    } else {
      if (ordinal > this.remoteMaxStreamsUni) throw new QUICError('Maximum local unidirectional streams exceeded', { code: QUICError.ERR_STREAM_LIMIT });
      if (ordinal > this.openedLocalUni) this.openedLocalUni = ordinal;
      if (id >= this.nextUni) this.nextUni = id + 4n;
      if (onWire && ordinal > this.wireOpenedLocalUni) this.wireOpenedLocalUni = ordinal;
    }
  }

  checkSendData(currentSent, length) {
    const end = BigInt(currentSent) + BigInt(length);
    if (end > this.remoteMaxData) {
      throw new QUICError('Connection flow control blocked', { code: QUICError.ERR_FLOW_CONTROL });
    }
  }

  noteSent(_offset, length) {
    const n = BigInt(length);
    this.sentData += n;
  }

  noteReceived(delta) {
    const d = BigInt(delta);
    if (d < 0n) throw new QUICError('Invalid received data delta', { code: QUICError.ERR_INVALID_ARGUMENT });
    this.recvData += d;
    if (this.recvData > this.localMaxData) {
      throw new QUICError('Connection flow control exceeded', { code: QUICError.ERR_FLOW_CONTROL });
    }
  }

  consume(delta) {
    const d = BigInt(delta);
    if (d < 0n) throw new QUICError('Invalid consumed data delta', { code: QUICError.ERR_INVALID_ARGUMENT });
    this.consumedData += d;
  }

  maybeMaxData() {
    const threshold = this.localMaxData / 2n;
    if (this.localMaxData - this.consumedData <= threshold) {
      this.localMaxData = this.consumedData + (this.localMaxData || 1n);
      return this.localMaxData;
    }
    return null;
  }

  maybeMaxStreamData(stream) {
    if (stream.recvMax - stream.recvConsumed <= stream.recvMax / 2n) {
      stream.recvMax = stream.recvConsumed + (stream.recvMax || 1n);
      return stream.recvMax;
    }
    return null;
  }

  noteRemoteUni(id, isServer) {
    id = BigInt(id);
    if ((id & 2n) === 0n || this.isLocalInitiated(id, isServer)) return;
    const ordinal = (id >> 2n) + 1n;
    if (ordinal > this.openedRemoteUni) this.openedRemoteUni = ordinal;
  }

  allocUni() {
    if (this.openedLocalUni >= this.remoteMaxStreamsUni) {
      throw new QUICError('Maximum local unidirectional streams exceeded', { code: QUICError.ERR_STREAM_LIMIT });
    }
    const id = this.nextUni;
    this.nextUni += 4n;
    this.openedLocalUni += 1n;
    return id;
  }

  checkNewRemoteUni(id, isServer) {
    id = BigInt(id);
    if ((id & 2n) === 0n) return;
    if (this.isLocalInitiated(id, isServer)) return;
    const ordinal = id >> 2n;
    if (ordinal >= this.localMaxStreamsUni) {
      throw new QUICError('Maximum remote unidirectional streams exceeded', { code: QUICError.ERR_STREAM_LIMIT });
    }
  }

  allocBidi() {
    if (this.openedLocalBidi >= this.remoteMaxStreams) {
      throw new QUICError('Maximum local bidirectional streams exceeded', { code: QUICError.ERR_STREAM_LIMIT });
    }
    const id = this.nextBidi;
    this.nextBidi += 4n;
    this.openedLocalBidi += 1n;
    return id;
  }
}

module.exports = { FlowControl, StreamState };
module.exports.default = module.exports;
