'use strict';

const { EventEmitter } = require('node:events');
const { QUICError } = require('../errors');

const INITIAL_RTT = 333;
const GRANULARITY = 1;
const MAX_ACK_DELAY = 25;
const PACKET_THRESHOLD = 3;
const TIME_THRESHOLD_NUM = 9;
const TIME_THRESHOLD_DEN = 8;
const MAX_PTO = 60_000;

function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

class RTTStats {
  constructor() {
    this.latestRtt = 0;
    this.smoothedRtt = 0;
    this.rttvar = 0;
    this.minRtt = 0;
  }

  onAckSample(sampleMs, ackDelayMs = 0, applyAckDelay = true) {
    // send-to-ACK sample. Only the sample fed into smoothed_rtt/rttvar may
    // have the peer's ACK delay subtracted, and only when it exceeds min_rtt.
    const latest = Math.max(GRANULARITY, Number(sampleMs) || GRANULARITY);
    if (!this.minRtt || latest < this.minRtt) this.minRtt = latest;
    this.latestRtt = latest;

    let adjusted = latest;
    const ackDelay = Math.max(0, Number(ackDelayMs) || 0);
    if (applyAckDelay && latest > this.minRtt + ackDelay) {
      adjusted = latest - ackDelay;
    }

    if (!this.smoothedRtt) {
      this.smoothedRtt = adjusted;
      this.rttvar = adjusted / 2;
      return;
    }
    this.rttvar = 0.75 * this.rttvar + 0.25 * Math.abs(this.smoothedRtt - adjusted);
    this.smoothedRtt = 0.875 * this.smoothedRtt + 0.125 * adjusted;
  }

  pto(maxAckDelay = MAX_ACK_DELAY, includeAckDelay = true) {
    const srtt = this.smoothedRtt || INITIAL_RTT;
    const variance = Math.max(4 * (this.rttvar || INITIAL_RTT / 2), GRANULARITY);
    const mad = includeAckDelay ? maxAckDelay : 0;
    return clamp(srtt + variance + mad, GRANULARITY, MAX_PTO);
  }
}

class Recovery extends EventEmitter {
  constructor(connection, opts = {}) {
    super();
    this.connection = connection;
    this.maxDatagramSize = opts.maxDatagramSize ?? 1200;
    this.maxAckDelay = opts.maxAckDelay ?? MAX_ACK_DELAY;
    this.rtt = new RTTStats();
    this.ptoCount = 0;
    this.timer = null;
    this.timerDeadline = 0;
    this.spaces = {
      initial: this._space(),
      handshake: this._space(),
      app: this._space(),
    };
    this.cwnd = Math.max(2 * this.maxDatagramSize, Math.min(10 * this.maxDatagramSize, Math.max(14720, 2 * this.maxDatagramSize)));
    this.ssthresh = Infinity;
    this.bytesInFlight = 0;
    this.recoveryStartTime = 0;
    this.maxAckElicitingBytes = this.cwnd;
  }

  _space() {
    return { sent: new Map(), largestAcked: -1n, lossTime: 0, ptoTime: 0 };
  }

  isAppLimited() {
    return false;
  }

  canSend(bytes) {
    return this.bytesInFlight + bytes <= this.cwnd;
  }

  onPacketSent(spaceName, packet) {
    const space = this.spaces[spaceName];
    if (!packet.ackEliciting) return;
    packet.sentAt = packet.sentAt ?? Date.now();
    packet.inFlight = true;
    space.sent.set(packet.pn, packet);
    this.bytesInFlight += packet.bytes;
    this._rearmTimer();
  }

  onAck(spaceName, ackFrame) {
    const space = this.spaces[spaceName];
    const now = Date.now();
    const newlyAcked = [];
    const largest = BigInt(ackFrame.largestAcked);
    const ranges = (ackFrame.ranges || []).map(r => ({ start: BigInt(r.start), end: BigInt(r.end) }));
    const nextPacketNumber = this.connection?.spaces?.[spaceName]?.sendPN;
    if (nextPacketNumber !== undefined && largest >= BigInt(nextPacketNumber)) {
      throw new QUICError('ACK acknowledges a packet number that was never sent', { code: QUICError.ERR_PROTOCOL });
    }

    for (const [pn, packet] of space.sent) {
      if (!this._inRanges(pn, ranges)) continue;
      space.sent.delete(pn);
      if (packet.timer) clearTimeout(packet.timer);
      if (packet.inFlight) {
        this.bytesInFlight = Math.max(0, this.bytesInFlight - packet.bytes);
        packet.inFlight = false;
      }
      newlyAcked.push(packet);
    }

    const samplePacket = space.sent.get(largest);
    const candidate = newlyAcked.find(p => p.pn === largest);
    if (candidate && candidate.sentAt) {
      const ackDelay = Number(ackFrame.ackDelay || 0n);
      this.rtt.onAckSample(now - candidate.sentAt, ackDelay, spaceName === 'app' && ackFrame.applyAckDelay !== false);
    }

    if (newlyAcked.length) this.ptoCount = 0;
    space.largestAcked = space.largestAcked < largest ? largest : space.largestAcked;

    const lost = this.detectLost(spaceName, largest, now);
    for (const packet of lost) this._onLost(spaceName, packet);

    for (const packet of newlyAcked) this._onAcked(packet);
    this._rearmTimer();
    this.emit('ack', { space: spaceName, acked: newlyAcked, lost, rtt: this.rtt });
    return { acked: newlyAcked, lost };
  }

  _inRanges(pn, ranges) {
    for (const r of ranges) if (pn >= r.start && pn <= r.end) return true;
    return false;
  }

  detectLost(spaceName, largestAcked, now = Date.now()) {
    const space = this.spaces[spaceName];
    const largest = BigInt(largestAcked);
    const lossDelay = TIME_THRESHOLD_NUM / TIME_THRESHOLD_DEN * Math.max(
      this.rtt.latestRtt || INITIAL_RTT,
      this.rtt.smoothedRtt || INITIAL_RTT,
      GRANULARITY,
    );
    const lost = [];
    let earliest = 0;

    for (const [pn, packet] of space.sent) {
      // time-threshold loss is only applicable to packets with a
      // packet number lower than the largest newly acknowledged packet. An
      // old packet must not be declared lost just because no newer packet was
      // acknowledged yet; PTO handles that case.
      if (pn >= largest) continue;

      const packetThreshold = pn + BigInt(PACKET_THRESHOLD) <= largest;
      const deadline = packet.sentAt + lossDelay;
      const timeThreshold = deadline <= now;
      if (packetThreshold || timeThreshold) {
        space.sent.delete(pn);
        if (packet.inFlight) {
          this.bytesInFlight = Math.max(0, this.bytesInFlight - packet.bytes);
          packet.inFlight = false;
        }
        lost.push(packet);
      } else if (!earliest || deadline < earliest) {
        earliest = deadline;
      }
    }
    space.lossTime = earliest;
    return lost;
  }

  onPTO(spaceName) {
    const space = this.spaces[spaceName];
    this.ptoCount++;
    this.emit('pto', { space: spaceName, count: this.ptoCount });
    const candidates = [...space.sent.values()]
      .sort((a, b) => Number(a.pn - b.pn));
    const probe = candidates.slice(0, 2);
    this.connection.sendProbe(spaceName, probe);
    this._rearmTimer();
  }

  onCongestionEvent(sentTime = Date.now()) {
    if (this.recoveryStartTime && sentTime <= this.recoveryStartTime) return;
    this.recoveryStartTime = Date.now();
    this.ssthresh = Math.max(this.cwnd / 2, 2 * this.maxDatagramSize);
    this.cwnd = this.ssthresh;
    this.emit('congestion', { cwnd: this.cwnd, ssthresh: this.ssthresh });
  }

  _onAcked(packet) {
    if (packet.isPmtuProbe && packet.pmtuProbeId !== null && packet.pmtuProbeId !== undefined) {
      this.connection?.pathMtu?.onProbeAck(packet.pmtuProbeId);
    }
    if (this.recoveryStartTime && packet.sentAt <= this.recoveryStartTime) return;
    if (this.cwnd < this.ssthresh) {
      this.cwnd += packet.bytes;
    } else {
      this.cwnd += (this.maxDatagramSize * packet.bytes) / Math.max(this.cwnd, 1);
    }
  }

  _onLost(spaceName, packet) {
    this.emit('loss', { space: spaceName, packet });
    if (packet.timer) clearTimeout(packet.timer);
    if (packet.isPmtuProbe) {
      // lost PMTU probe is not a reliable congestion signal.
      this.connection?.pathMtu?.onProbeLost(packet.pmtuProbeId);
      return;
    }
    this.onCongestionEvent(packet.sentAt);
    if (packet.frames?.length) this.connection.retransmit(spaceName, packet);
  }

  _ptoDeadlineForSpace(name, space) {
    if (!space.sent.size) return 0;
    // PTO is measured from the most recently sent ack-eliciting packet in the
    // packet-number space, not the oldest outstanding packet. Using the oldest
    // packet makes PTO spuriously fire during a sustained send burst.
    const latest = [...space.sent.values()].reduce((a, b) => (!a || b.sentAt > a.sentAt ? b : a), null);
    if (!latest) return 0;
    const handshakeConfirmed = Boolean(this.connection?.handshakeConfirmed);
    const includeAckDelay = name === 'app' && handshakeConfirmed;
    const ackDelay = includeAckDelay ? this.maxAckDelay : 0;
    const pto = this.rtt.pto(ackDelay, includeAckDelay) * (2 ** this.ptoCount);
    return latest.sentAt + pto;
  }

  _rearmTimer() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const now = Date.now();
    let best = 0;
    let bestSpace = null;
    for (const name of Object.keys(this.spaces)) {
      const s = this.spaces[name];
      const lossDeadline = s.lossTime || 0;
      const ptoDeadline = this._ptoDeadlineForSpace(name, s);
      const deadline = lossDeadline && ptoDeadline
        ? Math.min(lossDeadline, ptoDeadline)
        : (lossDeadline || ptoDeadline);
      if (deadline && (!best || deadline < best)) { best = deadline; bestSpace = name; }
    }
    if (!best || !bestSpace) return;
    this.timerDeadline = best;
    this.timer = setTimeout(() => {
      this.timer = null;
      const s = this.spaces[bestSpace];
      const now2 = Date.now();
      if (s.lossTime && s.lossTime <= now2) {
        const largest = s.largestAcked < 0n ? 0n : s.largestAcked;
        const lost = this.detectLost(bestSpace, largest, now2);
        for (const packet of lost) this._onLost(bestSpace, packet);
      } else {
        this.onPTO(bestSpace);
      }
      this._rearmTimer();
    }, Math.max(GRANULARITY, best - now));
  }

  close() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    for (const s of Object.values(this.spaces)) {
      for (const packet of s.sent.values()) if (packet.timer) clearTimeout(packet.timer);
    }
  }
}

module.exports = { Recovery, RTTStats };
module.exports.default = module.exports;
