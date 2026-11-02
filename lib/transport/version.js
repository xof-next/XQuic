'use strict';

const { randomBytes } = require('node:crypto');
const { QUIC_VERSION } = require('../constants');

function normalizeVersions(input) {
	const versions = Array.isArray(input) && input.length ? input : [QUIC_VERSION.V1];
	return [...new Set(versions.map(v => Number(v) >>> 0))];
}

function isSupportedVersion(version, versions) {
	return normalizeVersions(versions).includes(Number(version) >>> 0);
}

function buildVersionNegotiation({ dcid = Buffer.alloc(0), scid = Buffer.alloc(0), versions } = {}) {
	dcid = Buffer.from(dcid);
	scid = Buffer.from(scid);
	const list = normalizeVersions(versions);
	if(dcid.length > 20 || scid.length > 20) throw new RangeError('Connection ID length must be <= 20 bytes');
	const out = Buffer.alloc(7 + dcid.length + scid.length + list.length * 4);
	out[0] = 0x80 | (randomBytes(1)[0] & 0x3f);
	out.writeUInt32BE(0, 1);
	let o = 5;
	out[o++] = dcid.length;
	dcid.copy(out, o);
	o += dcid.length;
	out[o++] = scid.length;
	scid.copy(out, o);
	o += scid.length;
	for(const v of list) {
		out.writeUInt32BE(v >>> 0, o);
		o += 4;
	}
	return out.subarray(0, o);
}

function parseVersionNegotiation(packet) {
	const p = Buffer.from(packet);
	if(p.length < 7 || !(p[0] & 0x80) || p.readUInt32BE(1) !== 0) throw new Error('Not a Version Negotiation packet');
	let o = 5;
	const dl = p[o++];
	if(o + dl > p.length) throw new Error('Truncated Version Negotiation DCID');
	const dcid = Buffer.from(p.subarray(o, o + dl));
	o += dl;
	if(o >= p.length) throw new Error('Missing Version Negotiation SCID length');
	const sl = p[o++];
	if(o + sl > p.length) throw new Error('Truncated Version Negotiation SCID');
	const scid = Buffer.from(p.subarray(o, o + sl));
	o += sl;
	if(dcid.length > 20 || scid.length > 20) throw new Error('Invalid Version Negotiation CID length');
	if((p.length - o) % 4 || p.length === o) throw new Error('Malformed or empty Version Negotiation versions');
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

module.exports = {
	normalizeVersions,
	isSupportedVersion,
	buildVersionNegotiation,
	parseVersionNegotiation
};

module.exports.default = module.exports;