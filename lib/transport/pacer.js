'use strict';

const { EventEmitter } = require('node:events');

const DEFAULT_RTT_MS = 333;
const DEFAULT_GAIN = 1.25;

/**
 * Conservative connection-local packet pacing helper.
 *
 * It schedules asynchronous application writes. Synchronous control-frame sends
 * are deliberately not queued by this helper; ACK-only traffic must stay timely.
 */
class QUICPacer extends EventEmitter {
  constructor(options = {}) {
    super();
    this.enabled = options.enabled !== false;
    this.gain = Number(options.gain ?? DEFAULT_GAIN);
    if (!Number.isFinite(this.gain) || this.gain < 1 || this.gain > 2) {
      throw new TypeError('pacing gain must be between 1 and 2');
    }
    this.getCongestionWindow = typeof options.getCongestionWindow === 'function'
      ? options.getCongestionWindow : () => Number(options.congestionWindow ?? 12000);
    this.getSmoothedRtt = typeof options.getSmoothedRtt === 'function'
      ? options.getSmoothedRtt : () => Number(options.smoothedRtt ?? DEFAULT_RTT_MS);
    this.nextSendAt = 0;
    this.scheduledBytes = 0;
  }

  schedule(bytes, { ackEliciting = true, now = Date.now() } = {}) {
    const amount = Number(bytes);
    if (!Number.isSafeInteger(amount) || amount < 0) throw new TypeError('bytes must be a non-negative safe integer');
    if (!this.enabled || !ackEliciting || amount === 0) {
      return { delayMs: 0, sendAt: Number(now), intervalMs: 0, rateBytesPerMs: Infinity };
    }
    const cwnd = Number(this.getCongestionWindow());
    const srtt = Number(this.getSmoothedRtt());
    const safeCwnd = Number.isFinite(cwnd) && cwnd > 0 ? cwnd : 2 * 1200;
    const safeRtt = Number.isFinite(srtt) && srtt > 0 ? srtt : DEFAULT_RTT_MS;
    const rateBytesPerMs = (this.gain * safeCwnd) / safeRtt;
    const sendAt = Math.max(Number(now), this.nextSendAt || Number(now));
    const delayMs = Math.max(0, sendAt - Number(now));
    const intervalMs = amount / rateBytesPerMs;
    this.nextSendAt = sendAt + intervalMs;
    this.scheduledBytes += amount;
    const result = { delayMs, sendAt, intervalMs, rateBytesPerMs };
    this.emit('schedule', { bytes: amount, ...result });
    return result;
  }

  async wait(bytes, { signal, ackEliciting = true } = {}) {
    if (signal?.aborted) throw signal.reason || Object.assign(new Error('Paced write aborted'), { code: 'ABORT_ERR' });
    const slot = this.schedule(bytes, { ackEliciting });
    if (slot.delayMs <= 0) return slot;
    await new Promise((resolve, reject) => {
      let timer = null;
      const cleanup = () => {
        if (timer) clearTimeout(timer);
        if (signal) signal.removeEventListener('abort', onAbort);
      };
      const finish = (error) => {
        cleanup();
        error ? reject(error) : resolve();
      };
      const onAbort = () => finish(signal.reason || Object.assign(new Error('Paced write aborted'), { code: 'ABORT_ERR' }));
      timer = setTimeout(() => finish(), Math.ceil(slot.delayMs));
      if (signal) signal.addEventListener('abort', onAbort, { once: true });
      // Cover an AbortSignal that changed between the initial check and listener registration.
      if (signal?.aborted) onAbort();
    });
    this.emit('release', { bytes: Number(bytes), scheduledAt: slot.sendAt });
    return slot;
  }

  reset() {
    this.nextSendAt = 0;
    this.scheduledBytes = 0;
  }

  snapshot() {
    return { enabled: this.enabled, gain: this.gain, nextSendAt: this.nextSendAt, scheduledBytes: this.scheduledBytes };
  }
}

module.exports = { QUICPacer };
module.exports.default = module.exports;
