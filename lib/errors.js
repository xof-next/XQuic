'use strict';

class QUICError extends Error {
	constructor(message, options = {}) {
		super(message, {
			cause: options.cause
		});
		this.name = 'QUICError';
		if(options.code !== undefined) this.code = options.code;
		if(options.transportCode !== undefined) this.transportCode = options.transportCode;
		if(options.frameType !== undefined) this.frameType = options.frameType;
		Error.captureStackTrace?.(this, QUICError)
	}
}

QUICError.ERR_INVALID_ARGUMENT = 'ERR_QUIC_INVALID_ARGUMENT';
QUICError.ERR_INVALID_PACKET = 'ERR_QUIC_INVALID_PACKET';
QUICError.ERR_INVALID_VARINT = 'ERR_QUIC_INVALID_VARINT';
QUICError.ERR_INVALID_CONNECTION_ID = 'ERR_QUIC_INVALID_CONNECTION_ID';
QUICError.ERR_INVALID_PACKET_NUMBER = 'ERR_QUIC_INVALID_PACKET_NUMBER';
QUICError.ERR_INVALID_FRAME = 'ERR_QUIC_INVALID_FRAME';
QUICError.ERR_INVALID_LENGTH = 'ERR_QUIC_INVALID_LENGTH';
QUICError.ERR_CRYPTO = 'ERR_QUIC_CRYPTO';
QUICError.ERR_CRYPTO_BUFFER_EXCEEDED = 'ERR_QUIC_CRYPTO_BUFFER_EXCEEDED';
QUICError.ERR_PROTOCOL = 'ERR_QUIC_PROTOCOL';
QUICError.ERR_STATE = 'ERR_QUIC_STATE';
QUICError.ERR_FLOW_CONTROL = 'ERR_QUIC_FLOW_CONTROL';
QUICError.ERR_STREAM_LIMIT = 'ERR_QUIC_STREAM_LIMIT';
QUICError.ERR_STREAM_STATE = 'ERR_QUIC_STREAM_STATE';
QUICError.ERR_CONNECTION_ID_LIMIT = 'ERR_QUIC_CONNECTION_ID_LIMIT';
QUICError.ERR_INTERNAL = 'ERR_QUIC_INTERNAL';
QUICError.ERR_FINAL_SIZE = 'ERR_QUIC_FINAL_SIZE';
QUICError.ERR_TRANSPORT_PARAMETER = 'ERR_QUIC_TRANSPORT_PARAMETER';
QUICError.ERR_KEY_UPDATE = 'ERR_QUIC_KEY_UPDATE';
QUICError.ERR_CONNECTION_CLOSED = 'ERR_QUIC_CONNECTION_CLOSED';
QUICError.ERR_HANDSHAKE_TIMEOUT = 'ETIMEDOUT';
QUICError.ERR_DNS = 'ENOTFOUND';
QUICError.ERR_UNREACHABLE = 'ERR_QUIC_UNREACHABLE';
QUICError.ERR_CERTIFICATE_CHAIN = 'ERR_QUIC_CERTIFICATE_CHAIN';

class QUICTransportError extends QUICError {
	constructor(message, transportCode, options = {}) {
		super(message, {
			...options,
			transportCode
		});
		this.name = 'QUICTransportError'
	}
}

class QUICProtocolError extends QUICTransportError {
	constructor(message, transportCode, options = {}) {
		super(message, transportCode, options);
		this.name = 'QUICProtocolError'
	}
}

class QUICCryptoError extends QUICTransportError {
	constructor(message, cryptoErrorCode, options = {}) {
		super(message, 0x100 + cryptoErrorCode, options);
		this.name = 'QUICCryptoError';
		this.cryptoErrorCode = cryptoErrorCode
	}
}

module.exports = {
	QUICError,
	QUICTransportError,
	QUICProtocolError,
	QUICCryptoError
};

module.exports.default = module.exports;