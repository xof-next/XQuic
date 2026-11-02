'use strict';

const { FRAME_TYPE, STREAM_FRAME } = require('../constants');
const { encodeVarInt, decodeVarInt, getEncodedLength } = require('../codec/varint');
const { QUICError } = require('../errors');

function fail(message, code = QUICError.ERR_INVALID_FRAME, extra = {}) {
  throw new QUICError(message, { code, ...extra });
}

function bytes(value, name = 'value') {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  fail(`${name} must be a Buffer or Uint8Array`, QUICError.ERR_INVALID_ARGUMENT);
}

function uint(value, name) {
  if (typeof value === 'bigint') {
    if (value < 0n || value > 0x3fffffffffffffffn) fail(`${name} out of range`, QUICError.ERR_INVALID_ARGUMENT);
    return value;
  }
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  fail(`${name} must be a non-negative safe integer or bigint`, QUICError.ERR_INVALID_ARGUMENT);
}

function typeOf(frame) {
  if (!frame || typeof frame !== 'object') fail('Frame must be an object', QUICError.ERR_INVALID_ARGUMENT);
  if (frame.type === undefined) fail('Frame type is required', QUICError.ERR_INVALID_ARGUMENT);
  return uint(frame.type, 'frame.type');
}

function readVar(buf, offset, what) {
  try { return decodeVarInt(buf, offset); }
  catch (e) { fail(`Malformed ${what}: ${e.message}`, e.code || QUICError.ERR_INVALID_FRAME); }
}

function readBytes(buf, offset, length, what) {
  const n = Number(length);
  if (!Number.isSafeInteger(n) || n < 0 || offset + n > buf.length) fail(`Truncated ${what}`);
  return { value: buf.subarray(offset, offset + n), offset: offset + n };
}

function encodeAck(frame, type) {
  const largest = uint(frame.largestAcked, 'largestAcked');
  const delay = uint(frame.ackDelay ?? 0, 'ackDelay');
  const ranges = Array.isArray(frame.ranges) ? frame.ranges : [];
  if (!ranges.length) fail('ACK requires at least one range');

  const first = normalizeAckRange(ranges[0]);
  if (first.end !== largest) fail('ACK largestAcked must equal the end of the first ACK range');
  const encoded = [encodeVarInt(type), encodeVarInt(largest), encodeVarInt(delay), encodeVarInt(ranges.length - 1), encodeVarInt(first.end - first.start)];
  let previousStart = first.start;
  for (let i = 1; i < ranges.length; i++) {
    const r = normalizeAckRange(ranges[i]);
    if (r.end >= previousStart) fail('ACK ranges must be strictly descending and non-overlapping');
    const gap = previousStart - r.end - 2n;
    if (gap < 0n) fail('Invalid ACK gap');
    encoded.push(encodeVarInt(gap), encodeVarInt(r.end - r.start));
    previousStart = r.start;
  }
  if (type === FRAME_TYPE.ACK_ECN) {
    encoded.push(encodeVarInt(uint(frame.ect0 ?? 0, 'ect0')), encodeVarInt(uint(frame.ect1 ?? 0, 'ect1')), encodeVarInt(uint(frame.ecnCe ?? 0, 'ecnCe')));
  }
  return Buffer.concat(encoded);
}

function normalizeAckRange(r) {
  if (!r || r.start === undefined || r.end === undefined) fail('ACK range requires start and end');
  const start = uint(r.start, 'ACK range start');
  const end = uint(r.end, 'ACK range end');
  if (end < start) fail('ACK range end must be >= start');
  return { start, end };
}

function encodeAckFrequency(frame, type) {
  const sequenceNumber = uint(frame.sequenceNumber ?? frame.sequence, 'sequenceNumber');
  const packetTolerance = uint(frame.packetTolerance, 'packetTolerance');
  const maxAckDelay = uint(frame.maxAckDelay, 'maxAckDelay');
  const reorderingThreshold = uint(frame.reorderingThreshold, 'reorderingThreshold');

  // ACK_FREQUENCY extension requires non-zero packet_tolerance. Timing bounds depend on the
  // negotiated ACK_FREQUENCY transport parameters and are not guessed here.
  if (packetTolerance === 0n) fail('ACK_FREQUENCY packetTolerance must be greater than zero');

  return Buffer.concat([
    encodeVarInt(type),
    encodeVarInt(sequenceNumber),
    encodeVarInt(packetTolerance),
    encodeVarInt(maxAckDelay),
    encodeVarInt(reorderingThreshold)
  ]);
}

function encodeStream(frame, type) {
  const id = encodeVarInt(uint(frame.streamId, 'streamId'));
  const off = (type & STREAM_FRAME.OFF) ? encodeVarInt(uint(frame.offset ?? 0, 'offset')) : Buffer.alloc(0);
  const data = bytes(frame.data ?? Buffer.alloc(0), 'data');
  const len = (type & STREAM_FRAME.LEN) ? encodeVarInt(data.length) : Buffer.alloc(0);
  return Buffer.concat([encodeVarInt(type), id, off, len, data]);
}

function encodeFrame(frame) {
  const type = typeOf(frame);
  const t = Number(type);
  if (t === FRAME_TYPE.PADDING) return Buffer.from([0]);
  if (t === FRAME_TYPE.PING) return Buffer.from([1]);
  if (t === FRAME_TYPE.ACK || t === FRAME_TYPE.ACK_ECN) return encodeAck(frame, t);
  if (t === FRAME_TYPE.IMMEDIATE_ACK) return encodeVarInt(type);
  if (t === FRAME_TYPE.ACK_FREQUENCY) return encodeAckFrequency(frame, type);
  if (t >= FRAME_TYPE.STREAM_BASE && t <= 0x0f) return encodeStream(frame, t);
  if (t === FRAME_TYPE.DATAGRAM || t === FRAME_TYPE.DATAGRAM_LEN) {
    const data = bytes(frame.data ?? Buffer.alloc(0), 'data');
    return t === FRAME_TYPE.DATAGRAM ? Buffer.concat([encodeVarInt(type), data]) : Buffer.concat([encodeVarInt(type), encodeVarInt(data.length), data]);
  }

  switch (t) {
    case FRAME_TYPE.RESET_STREAM:
      return Buffer.concat([encodeVarInt(type), encodeVarInt(uint(frame.streamId, 'streamId')), encodeVarInt(uint(frame.applicationProtocolErrorCode ?? frame.errorCode ?? 0, 'errorCode')), encodeVarInt(uint(frame.finalSize, 'finalSize'))]);
    case FRAME_TYPE.STOP_SENDING:
      return Buffer.concat([encodeVarInt(type), encodeVarInt(uint(frame.streamId, 'streamId')), encodeVarInt(uint(frame.applicationProtocolErrorCode ?? frame.errorCode ?? 0, 'errorCode'))]);
    case FRAME_TYPE.CRYPTO: {
      const data = bytes(frame.data ?? Buffer.alloc(0), 'data');
      return Buffer.concat([encodeVarInt(type), encodeVarInt(uint(frame.offset ?? 0, 'offset')), encodeVarInt(data.length), data]);
    }
    case FRAME_TYPE.NEW_TOKEN: {
      const token = bytes(frame.token ?? Buffer.alloc(0), 'token');
      if (!token.length) fail('NEW_TOKEN token must not be empty');
      return Buffer.concat([encodeVarInt(type), encodeVarInt(token.length), token]);
    }
    case FRAME_TYPE.MAX_DATA:
      return Buffer.concat([encodeVarInt(type), encodeVarInt(uint(frame.maximumData, 'maximumData'))]);
    case FRAME_TYPE.MAX_STREAM_DATA:
      return Buffer.concat([encodeVarInt(type), encodeVarInt(uint(frame.streamId, 'streamId')), encodeVarInt(uint(frame.maximumStreamData, 'maximumStreamData'))]);
    case FRAME_TYPE.MAX_STREAMS_BIDI:
    case FRAME_TYPE.MAX_STREAMS_UNI:
      return Buffer.concat([encodeVarInt(type), encodeVarInt(uint(frame.maximumStreams, 'maximumStreams'))]);
    case FRAME_TYPE.DATA_BLOCKED:
      return Buffer.concat([encodeVarInt(type), encodeVarInt(uint(frame.maximumData, 'maximumData'))]);
    case FRAME_TYPE.STREAM_DATA_BLOCKED:
      return Buffer.concat([encodeVarInt(type), encodeVarInt(uint(frame.streamId, 'streamId')), encodeVarInt(uint(frame.maximumStreamData, 'maximumStreamData'))]);
    case FRAME_TYPE.STREAMS_BLOCKED_BIDI:
    case FRAME_TYPE.STREAMS_BLOCKED_UNI:
      return Buffer.concat([encodeVarInt(type), encodeVarInt(uint(frame.maximumStreams, 'maximumStreams'))]);
    case FRAME_TYPE.NEW_CONNECTION_ID: {
      const cid = bytes(frame.connectionId, 'connectionId');
      const token = bytes(frame.statelessResetToken, 'statelessResetToken');
      if (cid.length < 1 || cid.length > 20) fail('NEW_CONNECTION_ID connectionId length must be between 1 and 20 bytes');
      if (token.length !== 16) fail('statelessResetToken must be 16 bytes');
      const sequence = uint(frame.sequence, 'sequence');
      const retirePriorTo = uint(frame.retirePriorTo ?? 0, 'retirePriorTo');
      if (retirePriorTo > sequence) fail('retirePriorTo exceeds sequence');
      return Buffer.concat([encodeVarInt(type), encodeVarInt(sequence), encodeVarInt(retirePriorTo), Buffer.from([cid.length]), cid, token]);
    }
    case FRAME_TYPE.RETIRE_CONNECTION_ID:
      return Buffer.concat([encodeVarInt(type), encodeVarInt(uint(frame.sequence, 'sequence'))]);
    case FRAME_TYPE.PATH_CHALLENGE: {
      const data = bytes(frame.data, 'data');
      if (data.length !== 8) fail('PATH_CHALLENGE data must be exactly 8 bytes');
      return Buffer.concat([encodeVarInt(type), data]);
    }
    case FRAME_TYPE.PATH_RESPONSE: {
      const data = bytes(frame.data, 'data');
      if (data.length !== 8) fail('PATH_RESPONSE data must be exactly 8 bytes');
      return Buffer.concat([encodeVarInt(type), data]);
    }
    case FRAME_TYPE.CONNECTION_CLOSE:
    case FRAME_TYPE.APPLICATION_CLOSE: {
      const reason = bytes(frame.reasonPhrase ?? Buffer.alloc(0), 'reasonPhrase');
      const errorCode = uint(frame.errorCode ?? 0, 'errorCode');
      const out = [encodeVarInt(type), encodeVarInt(errorCode)];
      if (t === FRAME_TYPE.CONNECTION_CLOSE) out.push(encodeVarInt(uint(frame.frameType ?? 0, 'frameType')));
      out.push(encodeVarInt(reason.length), reason);
      return Buffer.concat(out);
    }
    case FRAME_TYPE.HANDSHAKE_DONE:
      return Buffer.from([0x1e]);
    default:
      fail(`Unsupported frame type 0x${t.toString(16)}`);
  }
}

function decodeAck(buf, offset, type) {
  const largest = readVar(buf, offset, 'ACK largest acknowledged'); offset = largest.offset;
  const delay = readVar(buf, offset, 'ACK delay'); offset = delay.offset;
  const count = readVar(buf, offset, 'ACK range count'); offset = count.offset;
  const firstLen = readVar(buf, offset, 'ACK first range'); offset = firstLen.offset;
  if (firstLen.value > largest.value) fail('ACK first range exceeds largest acknowledged');
  const ranges = [{ start: largest.value - firstLen.value, end: largest.value }];
  let previousStart = ranges[0].start;
  for (let i = 0n; i < count.value; i++) {
    const gap = readVar(buf, offset, 'ACK gap'); offset = gap.offset;
    const len = readVar(buf, offset, 'ACK range length'); offset = len.offset;
    if (gap.value + 2n > previousStart) fail('ACK gap exceeds packet number space');
    const end = previousStart - gap.value - 2n;
    if (end < 0n || len.value > end) fail('Invalid ACK range');
    const start = end - len.value;
    ranges.push({ start, end });
    previousStart = start;
  }
  const frame = { type, largestAcked: largest.value, ackDelay: delay.value, ranges };
  if (type === FRAME_TYPE.ACK_ECN) {
    const ect0 = readVar(buf, offset, 'ACK ECN ect0'); offset = ect0.offset;
    const ect1 = readVar(buf, offset, 'ACK ECN ect1'); offset = ect1.offset;
    const ecnCe = readVar(buf, offset, 'ACK ECN ce'); offset = ecnCe.offset;
    Object.assign(frame, { ect0: ect0.value, ect1: ect1.value, ecnCe: ecnCe.value });
  }
  return { frame, offset };
}

function decodeFrame(buf, offset = 0) {
  buf = bytes(buf, 'input');
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > buf.length) fail('Invalid frame offset', QUICError.ERR_INVALID_ARGUMENT);
  if (offset === buf.length) return null;
  const tv = readVar(buf, offset, 'frame type'); offset = tv.offset;
  const type = Number(tv.value);
  if (type === FRAME_TYPE.PADDING) return { frame: { type }, offset };
  if (type === FRAME_TYPE.PING) return { frame: { type }, offset };
  if (type === FRAME_TYPE.ACK || type === FRAME_TYPE.ACK_ECN) return decodeAck(buf, offset, type);
  if (type === FRAME_TYPE.IMMEDIATE_ACK) return { frame: { type }, offset };
  if (type === FRAME_TYPE.ACK_FREQUENCY) {
    const sequenceNumber = readVar(buf, offset, 'ACK_FREQUENCY sequence number'); offset = sequenceNumber.offset;
    const packetTolerance = readVar(buf, offset, 'ACK_FREQUENCY packet tolerance'); offset = packetTolerance.offset;
    const maxAckDelay = readVar(buf, offset, 'ACK_FREQUENCY max ack delay'); offset = maxAckDelay.offset;
    const reorderingThreshold = readVar(buf, offset, 'ACK_FREQUENCY reordering threshold'); offset = reorderingThreshold.offset;
    if (packetTolerance.value === 0n) fail('ACK_FREQUENCY packetTolerance must be greater than zero');
    return { frame: { type, sequenceNumber: sequenceNumber.value, packetTolerance: packetTolerance.value, maxAckDelay: maxAckDelay.value, reorderingThreshold: reorderingThreshold.value }, offset };
  }
  if (type === FRAME_TYPE.DATAGRAM) {
    return { frame: { type, data: Buffer.from(buf.subarray(offset)) }, offset: buf.length };
  }
  if (type === FRAME_TYPE.DATAGRAM_LEN) {
    const l = readVar(buf, offset, 'DATAGRAM length'); offset = l.offset;
    const d = readBytes(buf, offset, l.value, 'DATAGRAM data'); offset = d.offset;
    return { frame: { type, data: Buffer.from(d.value) }, offset };
  }
  if (type >= FRAME_TYPE.STREAM_BASE && type <= 0x0f) {
    const sid = readVar(buf, offset, 'STREAM stream ID'); offset = sid.offset;
    let off = 0n;
    if (type & STREAM_FRAME.OFF) { const v = readVar(buf, offset, 'STREAM offset'); offset = v.offset; off = v.value; }
    let data;
    if (type & STREAM_FRAME.LEN) {
      const l = readVar(buf, offset, 'STREAM length'); offset = l.offset;
      const d = readBytes(buf, offset, l.value, 'STREAM data'); offset = d.offset; data = Buffer.from(d.value);
    } else {
      data = Buffer.from(buf.subarray(offset)); offset = buf.length;
    }
    return { frame: { type, streamId: sid.value, offset: off, fin: !!(type & STREAM_FRAME.FIN), data }, offset };
  }
  switch (type) {
    case FRAME_TYPE.RESET_STREAM: {
      const sid=readVar(buf,offset,'RESET_STREAM stream ID'); offset=sid.offset; const ec=readVar(buf,offset,'RESET_STREAM error code'); offset=ec.offset; const fs=readVar(buf,offset,'RESET_STREAM final size'); offset=fs.offset;
      return {frame:{type,streamId:sid.value,errorCode:ec.value,finalSize:fs.value},offset};
    }
    case FRAME_TYPE.STOP_SENDING: {
      const sid=readVar(buf,offset,'STOP_SENDING stream ID'); offset=sid.offset; const ec=readVar(buf,offset,'STOP_SENDING error code'); offset=ec.offset;
      return {frame:{type,streamId:sid.value,errorCode:ec.value},offset};
    }
    case FRAME_TYPE.CRYPTO: {
      const off=readVar(buf,offset,'CRYPTO offset'); offset=off.offset; const l=readVar(buf,offset,'CRYPTO length'); offset=l.offset; const d=readBytes(buf,offset,l.value,'CRYPTO data'); offset=d.offset;
      return {frame:{type,offset:off.value,data:Buffer.from(d.value)},offset};
    }
    case FRAME_TYPE.NEW_TOKEN: {
      const l=readVar(buf,offset,'NEW_TOKEN length'); offset=l.offset; if(l.value===0n) fail('NEW_TOKEN token must not be empty'); const d=readBytes(buf,offset,l.value,'NEW_TOKEN token'); offset=d.offset;
      return {frame:{type,token:Buffer.from(d.value)},offset};
    }
    case FRAME_TYPE.MAX_DATA: { const v=readVar(buf,offset,'MAX_DATA'); return {frame:{type,maximumData:v.value},offset:v.offset}; }
    case FRAME_TYPE.MAX_STREAM_DATA: { const s=readVar(buf,offset,'MAX_STREAM_DATA stream ID'); offset=s.offset; const v=readVar(buf,offset,'MAX_STREAM_DATA'); return {frame:{type,streamId:s.value,maximumStreamData:v.value},offset:v.offset}; }
    case FRAME_TYPE.MAX_STREAMS_BIDI:
    case FRAME_TYPE.MAX_STREAMS_UNI: { const v=readVar(buf,offset,'MAX_STREAMS'); return {frame:{type,maximumStreams:v.value},offset:v.offset}; }
    case FRAME_TYPE.DATA_BLOCKED: { const v=readVar(buf,offset,'DATA_BLOCKED'); return {frame:{type,maximumData:v.value},offset:v.offset}; }
    case FRAME_TYPE.STREAM_DATA_BLOCKED: { const s=readVar(buf,offset,'STREAM_DATA_BLOCKED stream ID'); offset=s.offset; const v=readVar(buf,offset,'STREAM_DATA_BLOCKED'); return {frame:{type,streamId:s.value,maximumStreamData:v.value},offset:v.offset}; }
    case FRAME_TYPE.STREAMS_BLOCKED_BIDI:
    case FRAME_TYPE.STREAMS_BLOCKED_UNI: { const v=readVar(buf,offset,'STREAMS_BLOCKED'); return {frame:{type,maximumStreams:v.value},offset:v.offset}; }
    case FRAME_TYPE.NEW_CONNECTION_ID: {
      const seq=readVar(buf,offset,'NEW_CONNECTION_ID sequence'); offset=seq.offset; const rp=readVar(buf,offset,'NEW_CONNECTION_ID retire_prior_to'); offset=rp.offset;
      if(offset>=buf.length) fail('Missing NEW_CONNECTION_ID CID length'); const len=buf[offset++]; if(len<1||len>20) fail('Invalid NEW_CONNECTION_ID CID length');
      const cid=readBytes(buf,offset,len,'NEW_CONNECTION_ID CID'); offset=cid.offset; const token=readBytes(buf,offset,16,'NEW_CONNECTION_ID reset token'); offset=token.offset;
      if(rp.value>seq.value) fail('retire_prior_to exceeds sequence');
      return {frame:{type,sequence:seq.value,retirePriorTo:rp.value,connectionId:Buffer.from(cid.value),statelessResetToken:Buffer.from(token.value)},offset};
    }
    case FRAME_TYPE.RETIRE_CONNECTION_ID: { const v=readVar(buf,offset,'RETIRE_CONNECTION_ID'); return {frame:{type,sequence:v.value},offset:v.offset}; }
    case FRAME_TYPE.PATH_CHALLENGE:
    case FRAME_TYPE.PATH_RESPONSE: { const d=readBytes(buf,offset,8,type===FRAME_TYPE.PATH_CHALLENGE?'PATH_CHALLENGE':'PATH_RESPONSE'); return {frame:{type,data:Buffer.from(d.value)},offset:d.offset}; }
    case FRAME_TYPE.CONNECTION_CLOSE:
    case FRAME_TYPE.APPLICATION_CLOSE: {
      const ec=readVar(buf,offset,'CONNECTION_CLOSE error code'); offset=ec.offset; let ft=0n;
      if(type===FRAME_TYPE.CONNECTION_CLOSE){const v=readVar(buf,offset,'CONNECTION_CLOSE frame type'); offset=v.offset; ft=v.value;}
      const l=readVar(buf,offset,'CONNECTION_CLOSE reason length'); offset=l.offset; const d=readBytes(buf,offset,l.value,'CONNECTION_CLOSE reason'); offset=d.offset;
      return {frame:{type,errorCode:ec.value,frameType:ft,reasonPhrase:Buffer.from(d.value)},offset};
    }
    case FRAME_TYPE.HANDSHAKE_DONE: return {frame:{type},offset};
    default: fail(`Unsupported frame type 0x${type.toString(16)}`);
  }
}

function encodeFrames(frames) {
  if (!Array.isArray(frames)) fail('frames must be an array', QUICError.ERR_INVALID_ARGUMENT);
  for (let i = 0; i < frames.length - 1; i++) {
    const type = Number(typeOf(frames[i]));
    // STREAM without LEN and DATAGRAM without LEN consume the rest of the packet.
    if ((type >= FRAME_TYPE.STREAM_BASE && type <= 0x0f && !(type & STREAM_FRAME.LEN)) || type === FRAME_TYPE.DATAGRAM) {
      fail(`Frame type 0x${type.toString(16)} without a length field must be last in the packet`);
    }
  }
  return Buffer.concat(frames.map(encodeFrame));
}

function decodeFrames(input, options = {}) {
  const buf = bytes(input, 'input');
  const frames = [];
  let offset = 0;
  while (offset < buf.length) {
    const result = decodeFrame(buf, offset);
    if (!result) break;
    frames.push(result.frame);
    if (result.offset <= offset) fail('Frame decoder made no progress');
    offset = result.offset;
    if (options.maxFrames !== undefined && frames.length > options.maxFrames) fail('Maximum frame count exceeded', QUICError.ERR_INVALID_LENGTH);
  }
  return { frames, offset };
}

module.exports = { encodeFrame, decodeFrame, encodeFrames, decodeFrames, normalizeAckRange };
module.exports.default = module.exports;
