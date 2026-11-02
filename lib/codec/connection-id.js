'use strict';

const { CONNECTION_ID } = require('../constants');
const { QUICError } = require('../errors');

function b(v, n = 'value') {
	if(Buffer.isBuffer(v)) return Buffer.from(v);
	if(v instanceof Uint8Array) return Buffer.from(v);
	throw new QUICError(n + ' must be Buffer or Uint8Array', {
		code: QUICError.ERR_INVALID_ARGUMENT
	})
}

function validateLength(n) {
	if(!Number.isInteger(n) || n < 0 || n > CONNECTION_ID.MAX_LENGTH) throw new QUICError('Invalid Connection ID length', {
		code: QUICError.ERR_INVALID_CONNECTION_ID
	})
}

function encodeConnectionId(v) {
	const x = b(v, 'Connection ID');
	validateLength(x.length);
	return x
}

function decodeConnectionId(v, o = 0, n) {
	const x = b(v, 'packet');
	if(!Number.isSafeInteger(o) || o < 0) throw new QUICError('Invalid offset', {
		code: QUICError.ERR_INVALID_ARGUMENT
	});
	if(n === undefined) throw new QUICError('Connection ID length required', {
		code: QUICError.ERR_INVALID_ARGUMENT
	});
	validateLength(n);
	if(o + n > x.length) throw new QUICError('Truncated Connection ID', {
		code: QUICError.ERR_INVALID_PACKET
	});
	return {
		value: Buffer.from(x.subarray(o, o + n)),
		offset: o + n,
		length: n
	}
}

module.exports = {
	encodeConnectionId,
	decodeConnectionId,
	validateLength
};

module.exports.default = module.exports;