'use strict';

const crypto = require('node:crypto');
const { QUICError } = require('../errors');
const { attachDetails } = require('./diagnostics');

function buf(v, name) {
	if(Buffer.isBuffer(v)) return v;
	if(v instanceof Uint8Array) return Buffer.from(v.buffer, v.byteOffset, v.byteLength);
	throw new QUICError(name + ' must be Buffer or Uint8Array', {
		code: QUICError.ERR_INVALID_ARGUMENT
	});
}

function mask(key, sample) {
	const k = buf(key, 'key');
	const s = buf(sample, 'sample');
	if(k.length !== 16) throw new QUICError('Header protection key must be 16 bytes', {
		code: QUICError.ERR_CRYPTO
	});
	if(s.length < 16) throw new QUICError('Header protection sample must be 16 bytes', {
		code: QUICError.ERR_CRYPTO
	});
	const c = crypto.createCipheriv('aes-128-ecb', k, null);
	c.setAutoPadding(false);
	const block = c.update(s.subarray(0, 16));
	c.final();
	const result = block.subarray(0, 5);
	return attachDetails(result, {
		algorithm: 'AES-128-ECB',
		key: Buffer.from(k),
		sample: Buffer.from(s.subarray(0, 16)),
		block: Buffer.from(block),
		mask: Buffer.from(result)
	});
}

function protectLong(header, pnOffset, sample, hpKey) {
	const out = Buffer.from(header);
	const m = mask(hpKey, sample);
	out[0] ^= m[0] & 0x0f;
	for(let i = 0; i < 4; i++) out[pnOffset + i] ^= m[i + 1];
	return attachDetails(out, {
		type: 'long',
		pnOffset,
		rawHeader: Buffer.from(header),
		mask: Buffer.from(m),
		protectedHeader: Buffer.from(out)
	});
}

function protectShort(header, pnOffset, sample, hpKey) {
	const out = Buffer.from(header);
	const m = mask(hpKey, sample);
	out[0] ^= m[0] & 0x1f;
	for(let i = 0; i < 4; i++) out[pnOffset + i] ^= m[i + 1];
	return attachDetails(out, {
		type: 'short',
		pnOffset,
		rawHeader: Buffer.from(header),
		mask: Buffer.from(m),
		protectedHeader: Buffer.from(out)
	});
}

function unprotectLong(packet, pnOffset, hpKey) {
	if(pnOffset + 4 + 16 > packet.length) throw new QUICError('Packet too short for header protection sample', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const out = Buffer.from(packet);
	const m = mask(hpKey, out.subarray(pnOffset + 4, pnOffset + 4 + 16));
	out[0] ^= m[0] & 0x0f;
	const pnLen = (out[0] & 3) + 1;
	if(pnOffset + pnLen > out.length) throw new QUICError('Truncated protected packet number', {
		code: QUICError.ERR_INVALID_PACKET
	});
	for(let i = 0; i < pnLen; i++) out[pnOffset + i] ^= m[i + 1];
	return {
		packet: out,
		packetNumberLength: pnLen,
		details: {
			type: 'long',
			pnOffset,
			rawPacket: Buffer.from(packet),
		sample: Buffer.from(out.subarray(pnOffset + 4, pnOffset + 4 + 16)),
			mask: Buffer.from(m),
			protectedPacketNumberLength: pnLen,
			unprotectedPacket: Buffer.from(out)
		}
	};
}

function unprotectShort(packet, pnOffset, hpKey) {
	if(pnOffset + 4 + 16 > packet.length) throw new QUICError('Packet too short for header protection sample', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const out = Buffer.from(packet);
	const m = mask(hpKey, out.subarray(pnOffset + 4, pnOffset + 4 + 16));
	out[0] ^= m[0] & 0x1f;
	const pnLen = (out[0] & 3) + 1;
	if(pnOffset + pnLen > out.length) throw new QUICError('Truncated protected packet number', {
		code: QUICError.ERR_INVALID_PACKET
	});
	for(let i = 0; i < pnLen; i++) out[pnOffset + i] ^= m[i + 1];
	return {
		packet: out,
		packetNumberLength: pnLen,
		details: {
			type: 'short',
			pnOffset,
			rawPacket: Buffer.from(packet),
			sample: Buffer.from(out.subarray(pnOffset + 4, pnOffset + 4 + 16)),
			mask: Buffer.from(m),
			protectedPacketNumberLength: pnLen,
			unprotectedPacket: Buffer.from(out)
		}
	};
}

module.exports = {
	mask,
	protectLong,
	protectShort,
	unprotectLong,
	unprotectShort
};

module.exports.default = module.exports;