'use strict';

const crypto = require('node:crypto');
const { PACKET_LIMITS } = require('../constants');
class StatelessResetManager {
	constructor(secret) {
		this.secret = Buffer.isBuffer(secret) ? Buffer.from(secret) : crypto.createHash('sha256').update(String(secret || crypto.randomBytes(32))).digest();
	}
	token(connectionId) {
		const cid = Buffer.from(connectionId);
		return crypto.createHmac('sha256', this.secret).update(cid).digest().subarray(0, PACKET_LIMITS.STATELESS_RESET_TOKEN_LENGTH);
	}
	packet({ length = 39, token }) {
		length = Math.max(PACKET_LIMITS.STATELESS_RESET_TOKEN_LENGTH + 5, Number(length));
		const resetToken = token ? Buffer.from(token) : crypto.randomBytes(PACKET_LIMITS.STATELESS_RESET_TOKEN_LENGTH);
		if(resetToken.length !== PACKET_LIMITS.STATELESS_RESET_TOKEN_LENGTH) throw new RangeError('Invalid stateless reset token');
		const out = crypto.randomBytes(length);
		out[0] = 0x40 | (out[0] & 0x3f);
		resetToken.copy(out, out.length - resetToken.length);
		return out;
	}
	matches(packet, token) {
		const p = Buffer.from(packet);
		const t = Buffer.from(token);
		if(p.length < t.length + 5 || t.length !== PACKET_LIMITS.STATELESS_RESET_TOKEN_LENGTH) return false;
		return crypto.timingSafeEqual(p.subarray(p.length - t.length), t);
	}
}

module.exports = {
	StatelessResetManager
};

module.exports.default = module.exports;