'use strict';

const { VARINT } = require('../constants');
const { QUICError } = require('../errors');

function fail(m, c = QUICError.ERR_INVALID_VARINT) {
	throw new QUICError(m, {
		code: c
	})
}

function norm(v) {
	if(typeof v === 'bigint') return v;
	if(typeof v === 'number' && Number.isSafeInteger(v)) return BigInt(v);
	fail('QUIC varint must be BigInt or safe integer')
}

function getEncodedLength(v) {
	v = norm(v);
	if(v < 0n || v > VARINT.MAX) fail('QUIC varint out of range');
	return v <= 63n ? 1 : v <= 16383n ? 2 : v <= 1073741823n ? 4 : 8
}

function encodeVarInt(v) {
	v = norm(v);
	const l = getEncodedLength(v);
	if(l === 1) return Buffer.from([Number(v)]);
	if(l === 2) return Buffer.from([0x40 | Number(v >> 8n), Number(v & 255n)]);
	if(l === 4) {
		const b = Buffer.allocUnsafe(4);
		b.writeUInt32BE((0x80000000 | Number(v)) >>> 0);
		return b
	}
	const b = Buffer.allocUnsafe(8);
	b.writeBigUInt64BE(0xc000000000000000n | v);
	return b
}

function decodeVarInt(input, offset = 0) {
	if(!Buffer.isBuffer(input) && !(input instanceof Uint8Array)) fail('Invalid input', QUICError.ERR_INVALID_ARGUMENT);
	const b = Buffer.isBuffer(input) ? input : Buffer.from(input);
	if(!Number.isSafeInteger(offset) || offset < 0) fail('Invalid offset', QUICError.ERR_INVALID_ARGUMENT);
	if(offset >= b.length) fail('Missing QUIC varint');
	const l = 1 << (b[offset] >>> 6);
	if(offset + l > b.length) fail('Truncated QUIC varint');
	let v = BigInt(b[offset] & 63);
	for(let i = 1; i < l; i++) v = (v << 8n) | BigInt(b[offset + i]);
	return {
		value: v,
		length: l,
		offset: offset + l
	}
}

function isCanonicalVarInt(i) {
	const d = decodeVarInt(i);
	return Buffer.from(i).equals(encodeVarInt(d.value))
}

module.exports = {
	encodeVarInt,
	decodeVarInt,
	getEncodedLength,
	isCanonicalVarInt
};

module.exports.default = module.exports;