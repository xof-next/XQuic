'use strict';

const crypto = require('node:crypto');

class RetryTokenManager {
	constructor(secret) {
		this.secret = Buffer.isBuffer(secret) ? Buffer.from(secret) : crypto.createHash('sha256').update(String(secret || crypto.randomBytes(32))).digest();
	}
	issue({ address, port, odcid, version }) {
		const ts = BigInt(Math.floor(Date.now() / 1000));
		const nonce = crypto.randomBytes(8);
		const ip = Buffer.from(String(address));
		const body = Buffer.concat([Buffer.from('XOF1'), Buffer.from([ip.length]), ip, Buffer.from([port >> 8, port & 255]), Buffer.from([Buffer.from(odcid).length]), Buffer.from(odcid), Buffer.alloc(4)]);
		body.writeUInt32BE(Number(ts & 0xffffffffn), body.length - 4);
		const mac = crypto.createHmac('sha256', this.secret).update(body).digest().subarray(0, 16);
		return Buffer.concat([body, mac, Buffer.from([version === 0x6b3343cf ? 2 : 1]), nonce]);
	}
	verify(token, { address, port, odcid, version, maxAge = 60 }) {
		const t = Buffer.from(token);
		if(t.length < 4 + 1 + 1 + 2 + 1 + 1 + 4 + 16 + 1 + 8) return false;
		let o = 0;
		if(t.subarray(0, 4).toString() !== 'XOF1') return false;
		o += 4;
		const il = t[o++];
		if(o + il + 2 > t.length) return false;
		const ip = t.subarray(o, o + il).toString();
		o += il;
		const p = (t[o++] << 8) | t[o++];
		if(ip !== String(address) || p !== port) return false;
		const cl = t[o++];
		if(o + cl + 4 + 16 + 1 + 8 !== t.length) return false;
		const cid = t.subarray(o, o + cl);
		o += cl;
		const ts = t.readUInt32BE(o);
		o += 4;
		const mac = t.subarray(o, o + 16);
		o += 16;
		const verByte = t[o++];
		const body = t.subarray(0, 4 + 1 + il + 2 + 1 + cl + 4);
		const expected = crypto.createHmac('sha256', this.secret).update(body).digest().subarray(0, 16);
		if(!crypto.timingSafeEqual(mac, expected)) return false;
		const now = Math.floor(Date.now() / 1000);
		if(now < ts || now - ts > maxAge) return false;
		if(odcid !== undefined && odcid !== null) {
			const want = Buffer.from(odcid);
			if(cid.length !== want.length || !crypto.timingSafeEqual(cid, want)) return false;
		}
		return verByte === (version === 0x6b3343cf ? 2 : 1);
	}
	decode(token) {
		const t = Buffer.from(token);
		let o = 4;
		if(t.length < 20 || t.subarray(0, 4).toString() !== 'XOF1') return null;
		const il = t[o++];
		o += il + 2;
		const cl = t[o++];
		const odcid = Buffer.from(t.subarray(o, o + cl));
		o += cl;
		const ts = t.readUInt32BE(o);
		return {
			odcid,
			timestamp: ts
		};
	}
}

module.exports = {
	RetryTokenManager
};

module.exports.default = module.exports;