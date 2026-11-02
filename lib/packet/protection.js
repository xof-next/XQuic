'use strict';

const crypto = require('node:crypto');
const { QUICError } = require('../errors');
const { attachDetails } = require('../crypto/diagnostics');
const { seal, open } = require('../crypto/packet-protection');
const { encodeVarInt, decodeVarInt } = require('../codec/varint');
const { retryIntegrityTag, verifyRetryIntegrity } = require('../crypto/retry');
const { QUIC_VERSION, PACKET_TYPE_V1, PACKET_TYPE_V2 } = require('../constants');
const { encodeLongHeaderFirstByte, decodeLongHeaderFirstByte } = require('./header');
const { encodePacketNumber, decodePacketNumber } = require('../codec/packet-number');
const { protectLong, protectShort, unprotectLong, unprotectShort } = require('../crypto/header-protection');

const PACKET_DETAILS = process.env.XOF_PACKET_DETAILS === '1';

function b(v, name) {
	if(Buffer.isBuffer(v)) return v;
	if(v instanceof Uint8Array) return Buffer.from(v);
	throw new QUICError(name + ' must be Buffer or Uint8Array', {
		code: QUICError.ERR_INVALID_ARGUMENT
	});
}

function pnBytes(n, len = 4) {
	return encodePacketNumber(BigInt(n), len);
}

function longType(version, type) {
	return version === QUIC_VERSION.V2 ? ({
		retry: 0,
		initial: 1,
		zero_rtt: 2,
		handshake: 3
	} [type]) : ({
		initial: 0,
		zero_rtt: 1,
		handshake: 2,
		retry: 3
	} [type]);
}

function longTypeName(version, bits) {
	return version === QUIC_VERSION.V2 ? ['retry', 'initial', 'zero_rtt', 'handshake'][bits] : ['initial', 'zero_rtt', 'handshake', 'retry'][bits];
}

function buildLongPacket({ version = QUIC_VERSION.V1, type = 'initial', dcid, scid, token = Buffer.alloc(0), packetNumber = 0n, packetNumberLength = 4, frames, keys, minSize = 0 }) {
	dcid = b(dcid, 'dcid');
	scid = b(scid, 'scid');
	token = b(token, 'token');
	frames = b(frames, 'frames');
	if(type === 'retry') throw new QUICError('Retry builder not implemented in this transport slice', {
		code: QUICError.ERR_INVALID_ARGUMENT
	});
	const typeBits = longType(version, type);
	const first = encodeLongHeaderFirstByte({
		version,
		packetType: typeBits === 0 ? 0 : type === 'initial' ? (version === QUIC_VERSION.V2 ? PACKET_TYPE_V2.INITIAL : PACKET_TYPE_V1.INITIAL) : type === 'handshake' ? (version === QUIC_VERSION.V2 ? PACKET_TYPE_V2.HANDSHAKE : PACKET_TYPE_V1.HANDSHAKE) : (version === QUIC_VERSION.V2 ? PACKET_TYPE_V2.ZERO_RTT : PACKET_TYPE_V1.ZERO_RTT),
		packetNumberLength
	});
	const versionBuf = Buffer.alloc(4);
	versionBuf.writeUInt32BE(version >>> 0);
	const base = [Buffer.from([first]), versionBuf, Buffer.from([dcid.length]), dcid, Buffer.from([scid.length]), scid];
	if(type === 'initial') base.push(encodeVarInt(token.length), token);
	const pn = pnBytes(packetNumber, packetNumberLength);
	// Header Protection sample starts at
	// pn_offset + 4, not at the beginning of the ciphertext. For a short
	// packet number, that position is inside the ciphertext, so ensure enough
	// PADDING bytes exist to make a full 16-byte sample available.
	let plaintext = Buffer.from(frames);
	const minSamplePadding = Math.max(0, 4 - packetNumberLength - plaintext.length);
	if(minSamplePadding) plaintext = Buffer.concat([plaintext, Buffer.alloc(minSamplePadding)]);
	let length = packetNumberLength + plaintext.length + 16;
	let header = Buffer.concat([base[0], base[1], base[2], base[3], base[4], base[5], ...(type === 'initial' ? base.slice(6) : []), encodeVarInt(length), pn]);
	while(minSize && (header.length - packetNumberLength) + length < minSize) {
		const need = minSize - ((header.length - packetNumberLength) + length);
		plaintext = Buffer.concat([plaintext, Buffer.alloc(need, 0)]);
		length = packetNumberLength + plaintext.length + 16;
		header = Buffer.concat([base[0], base[1], base[2], base[3], base[4], base[5], ...(type === 'initial' ? base.slice(6) : []), encodeVarInt(length), pn]);
	}
	const ciphertext = seal({
		key: keys.key,
		iv: keys.iv,
		packetNumber,
		aad: header,
		plaintext
	});
	const pnOffset = header.length - packetNumberLength;
	const unprotectedPacket = Buffer.concat([header, ciphertext]);
	const sample = unprotectedPacket.subarray(pnOffset + 4, pnOffset + 20);
	if(sample.length !== 16) throw new QUICError('Packet too short for Header Protection sample', { code: QUICError.ERR_INVALID_PACKET });
	const protectedHeader = protectLong(header, pnOffset, sample, keys.headerProtectionKey);
	const packet = Buffer.concat([protectedHeader, ciphertext]);
	if(!PACKET_DETAILS) return packet;
	return attachDetails(packet, {
		type: 'long',
		version,
		packetType: type,
		packetNumber: BigInt(packetNumber),
		packetNumberLength,
		dcid: Buffer.from(dcid),
		scid: Buffer.from(scid),
		token: Buffer.from(token),
		plaintext: Buffer.from(plaintext),
		header: Buffer.from(header),
		protectedHeader: Buffer.from(protectedHeader),
		ciphertext: Buffer.from(ciphertext),
		aead: ciphertext.details || null,
		headerProtection: protectedHeader.details || null,
		packet: Buffer.from(packet)
	});
}

function buildShortPacket({ dcid, packetNumber = 0n, packetNumberLength = 4, keyPhase = 0, spin = 0, frames, keys }) {
	dcid = b(dcid, 'dcid');
	frames = b(frames, 'frames');
	const pn = pnBytes(packetNumber, packetNumberLength);
	const first = 0x40 | (spin ? 0x20 : 0) | (keyPhase ? 0x04 : 0) | (packetNumberLength - 1);
	const header = Buffer.concat([Buffer.from([first]), dcid, pn]);
	let plaintext = Buffer.from(frames);
	const minSamplePadding = Math.max(0, 4 - packetNumberLength - plaintext.length);
	if(minSamplePadding) plaintext = Buffer.concat([plaintext, Buffer.alloc(minSamplePadding)]);
	const ciphertext = seal({
		key: keys.key,
		iv: keys.iv,
		packetNumber,
		aad: header,
		plaintext
	});
	const pnOffset = 1 + dcid.length;
	const unprotectedPacket = Buffer.concat([header, ciphertext]);
	const sample = unprotectedPacket.subarray(pnOffset + 4, pnOffset + 20);
	if(sample.length !== 16) throw new QUICError('Packet too short for Header Protection sample', { code: QUICError.ERR_INVALID_PACKET });
	const protectedHeader = protectShort(header, pnOffset, sample, keys.headerProtectionKey);
	const packet = Buffer.concat([protectedHeader, ciphertext]);
	if(!PACKET_DETAILS) return packet;
	return attachDetails(packet, {
		type: 'short',
		packetNumber: BigInt(packetNumber),
		packetNumberLength,
		keyPhase: !!keyPhase,
		spin: !!spin,
		dcid: Buffer.from(dcid),
		plaintext: Buffer.from(frames),
		header: Buffer.from(header),
		protectedHeader: Buffer.from(protectedHeader),
		ciphertext: Buffer.from(ciphertext),
		aead: ciphertext.details || null,
		headerProtection: protectedHeader.details || null,
		packet: Buffer.from(packet)
	});
}

function parseLongHeaderUnprotected(packet) {
	const p = b(packet, 'packet');
	if(p.length < 7) throw new QUICError('Packet too short', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const first = p[0],
		version = p.readUInt32BE(1);
	let o = 5;
	const dl = p[o++];
	if(o + dl > p.length) throw new QUICError('Truncated DCID', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const dcid = Buffer.from(p.subarray(o, o + dl));
	o += dl;
	if(o >= p.length) throw new QUICError('Missing SCID length', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const sl = p[o++];
	if(o + sl > p.length) throw new QUICError('Truncated SCID', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const scid = Buffer.from(p.subarray(o, o + sl));
	o += sl;
	const typeBits = (first >>> 4) & 3;
	const type = longTypeName(version, typeBits);
	if(type === 'retry') return {
		version,
		first,
		packetType: 'retry',
		dcid,
		scid,
		token: Buffer.from(p.subarray(o, p.length - 16)),
		integrityTag: Buffer.from(p.subarray(Math.max(o, p.length - 16))),
		length: p.length - o,
		pnOffset: null,
		packetEnd: p.length
	};
	if(type === 'initial') {
		const t = decodeVarInt(p, o);
		o = t.offset;
		if(o + Number(t.value) > p.length) throw new QUICError('Truncated Initial token', {
			code: QUICError.ERR_INVALID_PACKET
		});
		o += Number(t.value);
	}
	const lv = decodeVarInt(p, o);
	o = lv.offset;
	const length = Number(lv.value);
	if(o + length > p.length) throw new QUICError('Invalid QUIC length', {
		code: QUICError.ERR_INVALID_LENGTH
	});
	return {
		version,
		first,
		packetType: type,
		dcid,
		scid,
		length,
		pnOffset: o,
		packetEnd: o + length
	};
}

function decodePnFull(truncated, largestReceived = -1n) {
	const pnLen = truncated.length;
	let x = 0n;
	for(const c of truncated) x = (x << 8n) | BigInt(c);
	if(largestReceived < 0n) return x;
	const expected = largestReceived + 1n;
	const window = 1n << BigInt(pnLen * 8);
	const half = window >> 1n;
	const mask = window - 1n;
	let candidate = (expected & ~mask) | x;
	if(candidate + half <= expected && candidate + window <= ((1n << 62n) - 1n)) candidate += window;
	else if(candidate > expected + half && candidate >= window) candidate -= window;
	return candidate;
}

function decryptLongPacket(packet, keys, largestReceived = -1n) {
	const raw = b(packet, 'packet');
	const h = parseLongHeaderUnprotected(raw);
	const hp = unprotectLong(raw, h.pnOffset, keys.headerProtectionKey);
	const p = hp.packet;
	const pnLen = hp.packetNumberLength;
	const pn = decodePnFull(p.subarray(h.pnOffset, h.pnOffset + pnLen), largestReceived);
	const header = p.subarray(0, h.pnOffset + pnLen);
	const ciphertext = p.subarray(h.pnOffset + pnLen, h.packetEnd);
	const plaintext = open({
		key: keys.key,
		iv: keys.iv,
		packetNumber: pn,
		aad: header,
		ciphertext
	});
	const out = {
		...h,
		packet: p,
		packetNumber: pn,
		packetNumberLength: pnLen,
		plaintext
	};
	if(PACKET_DETAILS) {
		out.details = {
			rawPacket: Buffer.from(raw),
			header: Buffer.from(header),
			packet: Buffer.from(p),
			packetNumber: pn,
			packetNumberLength: pnLen,
			ciphertext: Buffer.from(ciphertext),
			plaintext: Buffer.from(plaintext),
			headerProtection: hp.details || null,
			aead: plaintext.details || null
		};
	}
	return out;
}

function decryptShortPacket(packet, dcidLength, keys, largestReceived = -1n) {
	const raw = b(packet, 'packet');
	if(raw.length < 2 + dcidLength + 16) throw new QUICError('Short packet too short', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const pnOffset = 1 + dcidLength;
	const hp = unprotectShort(raw, pnOffset, keys.headerProtectionKey);
	const p = hp.packet;
	const pnLen = hp.packetNumberLength;
	const pn = decodePnFull(p.subarray(pnOffset, pnOffset + pnLen), largestReceived);
	const header = p.subarray(0, pnOffset + pnLen);
	const ciphertext = p.subarray(pnOffset + pnLen);
	const plaintext = open({
		key: keys.key,
		iv: keys.iv,
		packetNumber: pn,
		aad: header,
		ciphertext
	});
	const out = {
		packet: p,
		dcid: Buffer.from(p.subarray(1, 1 + dcidLength)),
		packetNumber: pn,
		packetNumberLength: pnLen,
		plaintext,
		keyPhase: !!(p[0] & 0x04),
		spin: !!(p[0] & 0x20)
	};
	if(PACKET_DETAILS) {
		out.details = {
			rawPacket: Buffer.from(raw),
			header: Buffer.from(header),
			packet: Buffer.from(p),
			packetNumber: pn,
			packetNumberLength: pnLen,
			ciphertext: Buffer.from(ciphertext),
			plaintext: Buffer.from(plaintext),
			headerProtection: hp.details || null,
			aead: plaintext.details || null
		};
	}
	return out;
}

function buildVersionNegotiationPacket({ dcid = Buffer.alloc(0), scid = Buffer.alloc(0), versions = [] } = {}) {
	dcid = b(dcid, 'dcid');
	scid = b(scid, 'scid');
	if(dcid.length > 20 || scid.length > 20) throw new QUICError('Invalid Version Negotiation CID length', {
		code: QUICError.ERR_INVALID_CONNECTION_ID
	});
	const list = [...new Set(versions.map(v => Number(v) >>> 0))];
	if(!list.length) throw new QUICError('Version Negotiation requires versions', {
		code: QUICError.ERR_INVALID_ARGUMENT
	});
	const out = [Buffer.from([0x80 | (crypto.randomBytes(1)[0] & 0x3f)]), Buffer.alloc(4), Buffer.from([dcid.length]), dcid, Buffer.from([scid.length]), scid];
	out[1].writeUInt32BE(0, 0);
	for(const v of list) {
		const x = Buffer.alloc(4);
		x.writeUInt32BE(v, 0);
		out.push(x);
	}
	return Buffer.concat(out);
}

function parseVersionNegotiationPacket(packet) {
	const p = b(packet, 'packet');
	if(p.length < 7 || !(p[0] & 0x80) || p.readUInt32BE(1) !== 0) throw new QUICError('Not a Version Negotiation packet', {
		code: QUICError.ERR_INVALID_PACKET
	});
	let o = 5;
	const dl = p[o++];
	if(o + dl > p.length) throw new QUICError('Truncated Version Negotiation DCID', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const dcid = Buffer.from(p.subarray(o, o + dl));
	o += dl;
	if(o >= p.length) throw new QUICError('Missing Version Negotiation SCID length', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const sl = p[o++];
	if(o + sl > p.length) throw new QUICError('Truncated Version Negotiation SCID', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const scid = Buffer.from(p.subarray(o, o + sl));
	o += sl;
	if(dcid.length > 20 || scid.length > 20) throw new QUICError('Invalid Version Negotiation CID length', {
		code: QUICError.ERR_INVALID_CONNECTION_ID
	});
	if((p.length - o) % 4 !== 0 || p.length === o) throw new QUICError('Malformed or empty Version Negotiation versions', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const versions = [];
	while(o < p.length) {
		versions.push(p.readUInt32BE(o));
		o += 4;
	}
	return {
		dcid,
		scid,
		versions
	};
}

function buildRetryPacket({ version = QUIC_VERSION.V1, dcid, scid, token = Buffer.alloc(0), originalDestinationConnectionId }) {
	dcid = b(dcid, 'dcid');
	scid = b(scid, 'scid');
	token = b(token, 'token');
	if(dcid.length > 20 || scid.length > 20) throw new QUICError('Invalid Retry CID length', {
		code: QUICError.ERR_INVALID_CONNECTION_ID
	});
	const typeBits = longType(version, 'retry');
	const first = 0x80 | 0x40 | ((typeBits & 3) << 4);
	const v = Buffer.alloc(4);
	v.writeUInt32BE(version >>> 0);
	const body = Buffer.concat([Buffer.from([first]), v, Buffer.from([dcid.length]), dcid, Buffer.from([scid.length]), scid, token]);
	return Buffer.concat([body, retryIntegrityTag({
		version,
		originalDestinationConnectionId,
		retryPacketWithoutTag: body
	})]);
}

function parseRetryPacket(packet) {
	const p = b(packet, 'packet');
	if(p.length < 7 + 16) throw new QUICError('Retry packet too short', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const first = p[0],
		version = p.readUInt32BE(1);
	let o = 5;
	const dl = p[o++];
	if(o + dl > p.length) throw new QUICError('Truncated Retry DCID', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const dcid = Buffer.from(p.subarray(o, o + dl));
	o += dl;
	const sl = p[o++];
	if(o + sl + 16 > p.length) throw new QUICError('Truncated Retry SCID', {
		code: QUICError.ERR_INVALID_PACKET
	});
	const scid = Buffer.from(p.subarray(o, o + sl));
	o += sl;
	const token = Buffer.from(p.subarray(o, p.length - 16));
	const integrityTag = Buffer.from(p.subarray(p.length - 16));
	return {
		first,
		version,
		dcid,
		scid,
		token,
		integrityTag
	};
}

function verifyRetryPacket(packet, originalDestinationConnectionId) {
	const p = b(packet, 'packet');
	if(p.length < 16) return false;
	const version = p.readUInt32BE(1);
	return verifyRetryIntegrity({
		version,
		originalDestinationConnectionId,
		retryPacket: p
	});
}

module.exports = {
	buildLongPacket,
	buildShortPacket,
	buildVersionNegotiationPacket,
	parseVersionNegotiationPacket,
	buildRetryPacket,
	parseRetryPacket,
	verifyRetryPacket,
	parseLongHeaderUnprotected,
	decryptLongPacket,
	decryptShortPacket,
	decodePnFull
};

module.exports.default = module.exports;