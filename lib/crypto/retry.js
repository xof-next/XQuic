'use strict';

const crypto = require('node:crypto');
const { QUIC_VERSION } = require('../constants');
const { hkdfExpandLabel } = require('./hkdf');
	
const V1_SECRET = Buffer.from('d9c9943e6101fd200021506bcc02814c73030f25c79d71ce876eca876e6fca8e', 'hex');
const V2_SECRET = Buffer.from('c4dd2484d681aefa4ff4d69c2c20299984a765a5d3c31982f38fc74162155e9f', 'hex');

function material(version) {
	const secret = version === QUIC_VERSION.V2 ? V2_SECRET : V1_SECRET;
	const p = version === QUIC_VERSION.V2 ? 'quicv2 ' : 'quic ';
	return {
		key: hkdfExpandLabel(secret, p + 'key', Buffer.alloc(0), 16),
		iv: hkdfExpandLabel(secret, p + 'iv', Buffer.alloc(0), 12)
	};
}

function retryIntegrityTag({ version = QUIC_VERSION.V1, originalDestinationConnectionId, retryPacketWithoutTag }) {
	const odcid = Buffer.from(originalDestinationConnectionId || []);
	const rp = Buffer.from(retryPacketWithoutTag || []);
	const a = Buffer.concat([Buffer.from([odcid.length]), odcid, rp]);
	const m = material(version);
	const cipher = crypto.createCipheriv('aes-128-gcm', m.key, m.iv);
	cipher.setAAD(a);
	cipher.final();
	return cipher.getAuthTag();
}

function verifyRetryIntegrity({ version = QUIC_VERSION.V1, originalDestinationConnectionId, retryPacket }) {
	const p = Buffer.from(retryPacket);
	if(p.length < 16) return false;
	const body = p.subarray(0, p.length - 16),
		tag = p.subarray(p.length - 16);
	const odcid = Buffer.from(originalDestinationConnectionId || []);
	const aad = Buffer.concat([Buffer.from([odcid.length]), odcid, body]);
	const m = material(version);
	try {
		const d = crypto.createDecipheriv('aes-128-gcm', m.key, m.iv);
		d.setAAD(aad);
		d.setAuthTag(tag);
		d.final();
		return true;
	} catch {
		return false;
	}
}

module.exports = {
	retryIntegrityTag,
	verifyRetryIntegrity
};

module.exports.default = module.exports;