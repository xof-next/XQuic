'use strict';

const { encodeVarInt, decodeVarInt } = require('../codec/varint');
const { QUICError } = require('../errors');

const TYPE = Object.freeze({ DATA:0x00, HEADERS:0x01, CANCEL_PUSH:0x03, SETTINGS:0x04, PUSH_PROMISE:0x05, GOAWAY:0x07, MAX_PUSH_ID:0x0d, PRIORITY_UPDATE_REQUEST:0xf0700, PRIORITY_UPDATE_PUSH:0xf0701 });
const SETTINGS = Object.freeze({ QPACK_MAX_TABLE_CAPACITY:0x01, MAX_FIELD_SECTION_SIZE:0x06, QPACK_BLOCKED_STREAMS:0x07, ENABLE_CONNECT_PROTOCOL:0x08, H3_DATAGRAM:0x33 });

function frame(type, payload=Buffer.alloc(0)) {
  payload = Buffer.from(payload);
  return Buffer.concat([encodeVarInt(type), encodeVarInt(payload.length), payload]);
}

function varintFrame(type, id) {
  return frame(type, encodeVarInt(id));
}

function cancelPush(pushId) {
  return varintFrame(TYPE.CANCEL_PUSH, pushId);
}

function goaway(id) {
  return varintFrame(TYPE.GOAWAY, id);
}

function maxPushId(pushId) {
  return varintFrame(TYPE.MAX_PUSH_ID, pushId);
}

function pushPromise(pushId, fieldSection) {
  return frame(TYPE.PUSH_PROMISE, Buffer.concat([encodeVarInt(pushId), Buffer.from(fieldSection)]));
}

function priorityUpdateRequest(streamId, priorityValue) {
  return frame(TYPE.PRIORITY_UPDATE_REQUEST, Buffer.concat([encodeVarInt(streamId), Buffer.from(String(priorityValue), 'ascii')]));
}

function priorityUpdatePush(pushId, priorityValue) {
  return frame(TYPE.PRIORITY_UPDATE_PUSH, Buffer.concat([encodeVarInt(pushId), Buffer.from(String(priorityValue), 'ascii')]));
}
function settings(values={}) { const p=[]; for(const [id,v] of Object.entries(values)) p.push(encodeVarInt(BigInt(id)),encodeVarInt(BigInt(v))); return frame(TYPE.SETTINGS,Buffer.concat(p)); }
function parseFrames(buf, final=false) {
  buf=Buffer.from(buf); let o=0; const out=[];
  while(o<buf.length){
    const frameStart=o;
    let t,l;
    try {
      const a=decodeVarInt(buf,o);
      t=a.value;
      o=a.offset;
      const b=decodeVarInt(buf,o);
      l=b.value;
      o=b.offset;
    } catch(e){
      if(!final) return {frames:out,remaining:Buffer.from(buf.subarray(frameStart))};
      throw new QUICError('Truncated HTTP/3 frame',{code:0x0106});
    }

    const n=Number(l);
    if(!Number.isSafeInteger(n)){
      throw new QUICError('Invalid HTTP/3 frame length',{code:0x0106});
    }
    if(o+n>buf.length){
      if(!final) return {frames:out,remaining:Buffer.from(buf.subarray(frameStart))};
      throw new QUICError('Truncated HTTP/3 frame',{code:0x0106});
    }

    const frameType = t <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(t) : t;
    out.push({type:frameType,payload:Buffer.from(buf.subarray(o,o+n))});
    o+=n;
  }
  return {frames:out,remaining:Buffer.from(buf.subarray(o))};
}

function parseSettings(payload){
  const out = new Map(); let o = 0;
  const seen = new Set();
  while(o < payload.length){
    let a,b; try { a=decodeVarInt(payload,o);o=a.offset;b=decodeVarInt(payload,o); o = b.offset;
    } catch {
       throw new QUICError('Malformed HTTP/3 SETTINGS', { code:0x0109 });
    }
    const idBig = a.value;
    const id = idBig <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(idBig) : idBig;
    const idKey = idBig.toString();
    if(seen.has(idKey))throw new QUICError('Duplicate HTTP/3 setting', { code:0x0109 });
    seen.add(idKey);
    if(idBig===0n)throw new QUICError('Reserved HTTP/3 setting 0', { code:0x0109 });
    if(idBig===2n)throw new QUICError('SETTINGS_ENABLE_PUSH is forbidden', { code:0x0109 });
    if(idBig===3n||idBig===4n||idBig===5n)throw new QUICError('HTTP/2 setting used in HTTP/3', { code:0x0109 });
    if(idBig===8n && b.value !== 0n && b.value !== 1n)throw new QUICError('SETTINGS_ENABLE_CONNECT_PROTOCOL must be 0 or 1', { code:0x0109 });
    if(idBig===0x33n && b.value !== 0n && b.value !== 1n)throw new QUICError('SETTINGS_H3_DATAGRAM must be 0 or 1', { code:0x0109 });
    if(idBig===9n)throw new QUICError('Reserved HTTP/2 setting used in HTTP/3', { code:0x0109 });
    out.set(id,b.value);
  }
  return out;
}

module.exports={ TYPE, SETTINGS, frame, settings, cancelPush, goaway, maxPushId, pushPromise, priorityUpdateRequest, priorityUpdatePush, parseFrames, parseSettings};
module.exports.default = module.exports;