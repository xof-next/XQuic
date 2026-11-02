'use strict';

const crypto = require('node:crypto');
const { QUICError } = require('../errors');

function b(v, n) {
	if(Buffer.isBuffer(v)) return Buffer.from(v);
	if(v instanceof Uint8Array) return Buffer.from(v);
	throw new QUICError(n + ' must be Buffer or Uint8Array', {
		code: QUICError.ERR_INVALID_ARGUMENT
	})
}

function hkdfExtract(salt, ikm) {
	return crypto.createHmac('sha256', b(salt, 'salt')).update(b(ikm, 'ikm')).digest()
}

function hkdfExpand(prk, info, len) {
	if(!Number.isInteger(len) || len < 0 || len > 8160) throw new QUICError('Invalid HKDF length', {
		code: QUICError.ERR_INVALID_ARGUMENT
	});
	const p = b(prk, 'prk'),
		i = b(info, 'info');
	let t = Buffer.alloc(0),
		o = Buffer.alloc(0);
	for(let n = 1; o.length < len; n++) {
		t = crypto.createHmac('sha256', p).update(Buffer.concat([t, i, Buffer.from([n])])).digest();
		o = Buffer.concat([o, t])
	}
	return o.subarray(0, len)
}

function hkdfExpandLabel(secret, label, context, len) {
	if(typeof label !== 'string') throw new QUICError('Invalid HKDF label', {
		code: QUICError.ERR_INVALID_ARGUMENT
	});
	const c = b(context, 'context');
	const l = Buffer.from('tls13 ' + label, 'ascii');
	if(l.length > 255 || c.length > 255 || len > 65535) throw new QUICError('Invalid HKDF label parameters', {
		code: QUICError.ERR_INVALID_ARGUMENT
	});
	const info = Buffer.concat([Buffer.from([(len >>> 8) & 255, len & 255, l.length]), l, Buffer.from([c.length]), c]);
	return hkdfExpand(secret, info, len)
}

module.exports = {
	hkdfExtract,
	hkdfExpand,
	hkdfExpandLabel
};

module.exports.default = module.exports;