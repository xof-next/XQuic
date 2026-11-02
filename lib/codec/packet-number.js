'use strict';

const { PACKET_NUMBER } = require('../constants');
const { QUICError } = require('../errors');

function fail(m, c = QUICError.ERR_INVALID_PACKET_NUMBER) {
	throw new QUICError(m, {
		code: c
	})
}

function n(v) {
	if(typeof v === 'bigint') return v;
	if(typeof v === 'number' && Number.isSafeInteger(v)) return BigInt(v);
	fail('Invalid packet number')
}

function validateLength(l) {
	if(!Number.isInteger(l) || l < 1 || l > 4) fail('Packet number length must be 1-4')
}

function getMaxValue(l) {
	validateLength(l);
	return (1n << BigInt(l * 8)) - 1n
}

function encodePacketNumber(v, l) {
	v = n(v);
	validateLength(l);
	if(v < 0n || v > getMaxValue(l)) fail('Packet number does not fit');
	const o = Buffer.allocUnsafe(l);
	for(let i = l - 1; i >= 0; i--) {
		o[i] = Number(v & 255n);
		v >>= 8n
	}
	return o
}

function decodePacketNumber(x, o, l) {
	if(!Buffer.isBuffer(x) && !(x instanceof Uint8Array)) fail('Invalid input', QUICError.ERR_INVALID_ARGUMENT);
	const b = Buffer.from(x);
	if(!Number.isSafeInteger(o) || o < 0) fail('Invalid offset', QUICError.ERR_INVALID_ARGUMENT);
	validateLength(l);
	if(o + l > b.length) throw new QUICError('Truncated packet number', {
		code: QUICError.ERR_INVALID_PACKET
	});
	let v = 0n;
	for(let i = 0; i < l; i++) v = (v << 8n) | BigInt(b[o + i]);
	return {
		value: v,
		offset: o + l,
		length: l
	}
}

module.exports = {
	encodePacketNumber,
	decodePacketNumber,
	getMaxValue,
	validateLength
};

module.exports.default = module.exports;