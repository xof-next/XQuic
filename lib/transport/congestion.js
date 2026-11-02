'use strict';

const { EventEmitter } = require('node:events');
class NewReno extends EventEmitter {
	constructor(opts = {}) {
		super();
		this.maxDatagramSize = opts.maxDatagramSize ?? 1200;
		this.cwnd = Math.max(2 * this.maxDatagramSize, opts.initialWindow ?? 10 * this.maxDatagramSize);
		this.ssthresh = Infinity;
		this.bytesInFlight = 0;
		this.recoveryStartTime = 0;
	}
	canSend(bytes) {
		return this.bytesInFlight + bytes <= this.cwnd;
	}
	onSent(bytes, inFlight = true) {
		if(inFlight) this.bytesInFlight += bytes;
	}
	onAck(bytes, sentTime = Date.now()) {
		this.bytesInFlight = Math.max(0, this.bytesInFlight - bytes);
		if(this.recoveryStartTime && sentTime <= this.recoveryStartTime) return;
		if(this.cwnd < this.ssthresh) this.cwnd += bytes;
		else this.cwnd += (this.maxDatagramSize * bytes) / Math.max(this.cwnd, 1);
		this.emit('update', this.snapshot());
	}
	onLoss(bytes = 0, sentTime = Date.now()) {
		this.bytesInFlight = Math.max(0, this.bytesInFlight - bytes);
		if(this.recoveryStartTime && sentTime <= this.recoveryStartTime) return;
		this.recoveryStartTime = Date.now();
		this.ssthresh = Math.max(this.cwnd / 2, 2 * this.maxDatagramSize);
		this.cwnd = this.ssthresh;
		this.emit('update', this.snapshot());
	}
	snapshot() {
		return {
			cwnd: this.cwnd,
			ssthresh: this.ssthresh,
			bytesInFlight: this.bytesInFlight
		};
	}
}

module.exports = {
	NewReno
};

module.exports.default = module.exports;