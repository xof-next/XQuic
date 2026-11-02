'use strict';

// the HTTP/3 Datagram payload begins with a Quarter Stream ID.
const { encodeVarInt, decodeVarInt } = require('../codec/varint');
const H3_DATAGRAM_ERROR = 0x33;
const MAX_QUARTER_STREAM_ID = (1n << 60n) - 1n;
const MAX_STREAM_ID = (1n << 62n) - 1n;

function protocolError(message, cause) {
  const error = new Error(message, cause ? { cause } : undefined);
  error.h3Code = H3_DATAGRAM_ERROR;
  error.code = 'ERR_HTTP3_DATAGRAM';
  return error;
}
function normalizeStreamId(value) {
  let id;
  if (typeof value === 'bigint') id = value;
  else if (typeof value === 'number' && Number.isSafeInteger(value)) id = BigInt(value);
  else throw new TypeError('HTTP/3 Datagram stream ID must be a BigInt or safe integer');
  if (id < 0n || id > MAX_STREAM_ID || (id & 0x03n) !== 0n) throw new RangeError('HTTP/3 Datagram stream ID must identify a client-initiated bidirectional stream');
  if ((id >> 2n) > MAX_QUARTER_STREAM_ID) throw new RangeError('Quarter Stream ID exceeds RFC 9297 limit');
  return id;
}
function encodeHTTP3Datagram(streamId, payload = Buffer.alloc(0)) {
  const id = normalizeStreamId(streamId);
  if (!Buffer.isBuffer(payload) && !(payload instanceof Uint8Array)) throw new TypeError('HTTP Datagram payload must be a Buffer or Uint8Array');
  return Buffer.concat([encodeVarInt(id >> 2n), Buffer.from(payload)]);
}
function decodeHTTP3Datagram(input) {
  if (!Buffer.isBuffer(input) && !(input instanceof Uint8Array)) throw new TypeError('HTTP/3 Datagram input must be a Buffer or Uint8Array');
  const buffer = Buffer.from(input);
  let decoded;
  try { decoded = decodeVarInt(buffer, 0); }
  catch (cause) { throw protocolError('HTTP/3 Datagram is too short to contain a Quarter Stream ID', cause); }
  if (decoded.value > MAX_QUARTER_STREAM_ID) throw protocolError('HTTP/3 Datagram Quarter Stream ID exceeds RFC 9297 maximum');
  const streamId = decoded.value << 2n;
  if (streamId > MAX_STREAM_ID) throw protocolError('HTTP/3 Datagram maps to an invalid request stream ID');
  return {
    quarterStreamId: decoded.value,
    streamId,
    payload: Buffer.from(buffer.subarray(decoded.offset))
  };
}

module.exports = { H3_DATAGRAM_ERROR, MAX_QUARTER_STREAM_ID, encodeHTTP3Datagram, decodeHTTP3Datagram };
module.exports.default = module.exports;
