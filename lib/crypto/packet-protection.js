'use strict';

const crypto = require('node:crypto');
const { QUICError } = require('../errors');
const { attachDetails } = require('./diagnostics');

function b(v, n) {
	if(Buffer.isBuffer(v)) return v;
	if(v instanceof Uint8Array) return Buffer.from(v.buffer, v.byteOffset, v.byteLength);
	throw new QUICError(n + ' must be Buffer or Uint8Array', {
		code: QUICError.ERR_INVALID_ARGUMENT
	})
}

function nonce(iv, pn) {
	if(b(iv, 'iv').length !== 12) throw new QUICError('QUIC IV must be 12 bytes', {
		code: QUICError.ERR_CRYPTO
	});
	if(typeof pn !== 'bigint') pn = BigInt(pn);
	if(pn < 0n) throw new QUICError('Invalid packet number', {
		code: QUICError.ERR_INVALID_PACKET_NUMBER
	});
	if(pn > 0xffffffffffffffffn) throw new QUICError('Packet number too large', {
		code: QUICError.ERR_INVALID_PACKET_NUMBER
	});
	const ivBuf = Buffer.isBuffer(iv) ? iv : Buffer.from(iv.buffer, iv.byteOffset, iv.byteLength);
	const n = Buffer.allocUnsafe(12);
	ivBuf.copy(n);
	n[0] ^= 0; n[1] ^= 0; n[2] ^= 0; n[3] ^= 0;
	n[4] ^= Number((pn >> 56n) & 0xffn);
	n[5] ^= Number((pn >> 48n) & 0xffn);
	n[6] ^= Number((pn >> 40n) & 0xffn);
	n[7] ^= Number((pn >> 32n) & 0xffn);
	n[8] ^= Number((pn >> 24n) & 0xffn);
	n[9] ^= Number((pn >> 16n) & 0xffn);
	n[10] ^= Number((pn >> 8n) & 0xffn);
	n[11] ^= Number(pn & 0xffn);
	return n
}

function seal({ key, iv, packetNumber, aad, plaintext }) {
	const k = b(key, 'key');
	if(k.length !== 16) throw new QUICError('QUIC AES-128 key must be 16 bytes', {
		code: QUICError.ERR_CRYPTO
	});
	const nonceValue = nonce(iv, packetNumber);
	const aadValue = b(aad, 'aad');
	const plaintextValue = b(plaintext, 'plaintext');
	const c = crypto.createCipheriv('aes-128-gcm', k, nonceValue, {
		authTagLength: 16
	});
	c.setAAD(aadValue);
	const out = c.update(plaintextValue);
	c.final();
	const authTag = c.getAuthTag();
	const result = Buffer.allocUnsafe(out.length + 16);
	out.copy(result, 0);
	authTag.copy(result, out.length);
	return attachDetails(result, {
		algorithm: 'AES-128-GCM',
		key: Buffer.from(k),
		iv: Buffer.from(iv),
		packetNumber: BigInt(packetNumber),
		nonce: Buffer.from(nonceValue),
		aad: Buffer.from(aadValue),
		plaintext: Buffer.from(plaintextValue),
		ciphertext: Buffer.from(out),
		authTag: Buffer.from(authTag),
		result: Buffer.from(result)
	})
}

function open({ key, iv, packetNumber, aad, ciphertext }) {
	const k = b(key, 'key'),
		ct = b(ciphertext, 'ciphertext');
	if(ct.length < 16) throw new QUICError('Ciphertext too short', {
		code: QUICError.ERR_CRYPTO
	});
	const tag = ct.subarray(ct.length - 16),
		body = ct.subarray(0, -16);
	const nonceValue = nonce(iv, packetNumber);
	const aadValue = b(aad, 'aad');
	const d = crypto.createDecipheriv('aes-128-gcm', k, nonceValue, {
		authTagLength: 16
	});
	d.setAAD(aadValue);
	d.setAuthTag(tag);
	try {
		const out = d.update(body);
		d.final();
		const result = out;
		return attachDetails(result, {
			algorithm: 'AES-128-GCM',
			key: Buffer.from(k),
			iv: Buffer.from(iv),
			packetNumber: BigInt(packetNumber),
			nonce: Buffer.from(nonceValue),
			aad: Buffer.from(aadValue),
			ciphertext: Buffer.from(body),
			authTag: Buffer.from(tag),
			plaintext: Buffer.from(result)
		})
	} catch (cause) {
		throw new QUICError('QUIC AEAD authentication failed', {
			code: QUICError.ERR_CRYPTO,
			cause
		})
	}
}

module.exports = {
	nonce,
	seal,
	open
};

module.exports.default = module.exports;