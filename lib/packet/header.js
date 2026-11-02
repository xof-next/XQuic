'use strict';

const { QUICError } = require('../errors');
const { QUIC_VERSION, PACKET_TYPE_V1, PACKET_TYPE_V2 } = require('../constants');

function encodeType(t, v) {
	const a = v === QUIC_VERSION.V1 ? [
		[PACKET_TYPE_V1.INITIAL, 0],
		[PACKET_TYPE_V1.ZERO_RTT, 1],
		[PACKET_TYPE_V1.HANDSHAKE, 2],
		[PACKET_TYPE_V1.RETRY, 3] ] : [
		[PACKET_TYPE_V2.RETRY, 0],
		[PACKET_TYPE_V2.INITIAL, 1],
		[PACKET_TYPE_V2.ZERO_RTT, 2],
		[PACKET_TYPE_V2.HANDSHAKE, 3]
	];
	for(const [x, b] of a)
		if(x === t) return b;
	throw new QUICError('Invalid packet type', {
		code: QUICError.ERR_INVALID_ARGUMENT
	})
}

function decodeType(b, v) {
	const a = v === QUIC_VERSION.V1 ? [PACKET_TYPE_V1.INITIAL, PACKET_TYPE_V1.ZERO_RTT, PACKET_TYPE_V1.HANDSHAKE, PACKET_TYPE_V1.RETRY] : [PACKET_TYPE_V2.RETRY, PACKET_TYPE_V2.INITIAL, PACKET_TYPE_V2.ZERO_RTT, PACKET_TYPE_V2.HANDSHAKE];
	return a[b]
}

function encodeLongHeaderFirstByte({ version = QUIC_VERSION.V1, packetType, packetNumberLength = 4 } = {}) {
	if(![QUIC_VERSION.V1, QUIC_VERSION.V2].includes(version)) throw new QUICError('Unsupported QUIC version', {
		code: QUICError.ERR_INVALID_ARGUMENT
	});
	if(!Number.isInteger(packetNumberLength) || packetNumberLength < 1 || packetNumberLength > 4) throw new QUICError('Invalid packet number length', {
		code: QUICError.ERR_INVALID_PACKET_NUMBER
	});
	return 0xc0 | (encodeType(packetType, version) << 4) | (packetNumberLength - 1)
}

function decodeLongHeaderFirstByte(f, v) {
	if((f & 0xc0) !== 0xc0) throw new QUICError('Invalid Long Header first byte', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const t = decodeType((f >>> 4) & 3, v);
	if(t === undefined) throw new QUICError('Invalid packet type', {
		code: QUICError.ERR_INVALID_PACKET
	});
	return {
		type: t,
		typeBits: (f >>> 4) & 3,
		reservedBits: (f >>> 2) & 3,
		packetNumberLength: (f & 3) + 1
	}
}

module.exports = {
	encodeLongHeaderFirstByte,
	decodeLongHeaderFirstByte
};

module.exports.default = module.exports;