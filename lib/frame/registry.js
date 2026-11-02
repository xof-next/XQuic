'use strict';

const { FRAME_TYPE } = require('../constants');
const { QUICError } = require('../errors');

const CONTEXTS = Object.freeze({
  INITIAL: 'initial',
  ZERO_RTT: '0rtt',
  HANDSHAKE: 'handshake',
  ONE_RTT: '1rtt'
});

const ALL = Object.freeze(['initial', '0rtt', 'handshake', '1rtt']);
const APP = Object.freeze(['0rtt', '1rtt']);
const ACK = Object.freeze(['initial', 'handshake', '1rtt']);
const ONE_RTT = Object.freeze(['1rtt']);
// ACK_FREQUENCY / IMMEDIATE_ACK are registered as an optional extension codepoint
// for codec testing only; its current publication/IANA status is not verified here.
const REGISTRY = new Map();
function add(type, name, packetTypes, { ackEliciting = true, extension = null } = {}) {
  REGISTRY.set(type, Object.freeze({
    type,
    name,
    packetTypes,
    ackEliciting,
    extension
  }));
}

add(FRAME_TYPE.PADDING, 'PADDING', ALL, { ackEliciting: false });
add(FRAME_TYPE.PING, 'PING', ALL);
add(FRAME_TYPE.ACK, 'ACK', ACK, { ackEliciting: false });
add(FRAME_TYPE.ACK_ECN, 'ACK_ECN', ACK, { ackEliciting: false });
add(FRAME_TYPE.RESET_STREAM, 'RESET_STREAM', APP);
add(FRAME_TYPE.STOP_SENDING, 'STOP_SENDING', APP);
add(FRAME_TYPE.CRYPTO, 'CRYPTO', ACK);
add(FRAME_TYPE.NEW_TOKEN, 'NEW_TOKEN', ONE_RTT);
for (let type = 0x08; type <= 0x0f; type++) add(type, 'STREAM', APP);
add(FRAME_TYPE.MAX_DATA, 'MAX_DATA', APP);
add(FRAME_TYPE.MAX_STREAM_DATA, 'MAX_STREAM_DATA', APP);
add(FRAME_TYPE.MAX_STREAMS_BIDI, 'MAX_STREAMS_BIDI', APP);
add(FRAME_TYPE.MAX_STREAMS_UNI, 'MAX_STREAMS_UNI', APP);
add(FRAME_TYPE.DATA_BLOCKED, 'DATA_BLOCKED', APP);
add(FRAME_TYPE.STREAM_DATA_BLOCKED, 'STREAM_DATA_BLOCKED', APP);
add(FRAME_TYPE.STREAMS_BLOCKED_BIDI, 'STREAMS_BLOCKED_BIDI', APP);
add(FRAME_TYPE.STREAMS_BLOCKED_UNI, 'STREAMS_BLOCKED_UNI', APP);
add(FRAME_TYPE.NEW_CONNECTION_ID, 'NEW_CONNECTION_ID', ONE_RTT);
add(FRAME_TYPE.RETIRE_CONNECTION_ID, 'RETIRE_CONNECTION_ID', ONE_RTT);
add(FRAME_TYPE.PATH_CHALLENGE, 'PATH_CHALLENGE', ONE_RTT);
add(FRAME_TYPE.PATH_RESPONSE, 'PATH_RESPONSE', ONE_RTT);
add(FRAME_TYPE.CONNECTION_CLOSE, 'CONNECTION_CLOSE', ACK, { ackEliciting: false });
add(FRAME_TYPE.APPLICATION_CLOSE, 'APPLICATION_CLOSE', APP, { ackEliciting: false });
add(FRAME_TYPE.HANDSHAKE_DONE, 'HANDSHAKE_DONE', ONE_RTT);
add(FRAME_TYPE.IMMEDIATE_ACK, 'IMMEDIATE_ACK', ONE_RTT, { extension: 'ACK_FREQUENCY extension (negotiation unavailable)' });
add(FRAME_TYPE.DATAGRAM, 'DATAGRAM', APP, { extension: 'RFC 9221' });
add(FRAME_TYPE.DATAGRAM_LEN, 'DATAGRAM_LEN', APP, { extension: 'RFC 9221' });
add(FRAME_TYPE.ACK_FREQUENCY, 'ACK_FREQUENCY', ONE_RTT, { extension: 'ACK_FREQUENCY extension (negotiation unavailable)' });

function normalizePacketType(packetType) {
  const v = String(packetType).toLowerCase().replace(/[ _-]/g, '');
  if (v === 'initial') return 'initial';
  if (v === '0rtt' || v === 'zerortt' || v === 'zeroroundtrip') return '0rtt';
  if (v === 'handshake') return 'handshake';
  if (v === '1rtt' || v === 'app' || v === 'application' || v === 'short') return '1rtt';
  return null;
}

function normalizeType(type) {
  if (typeof type === 'bigint') {
    if (type < 0n || type > 0x3fffffffffffffffn) return null;
    if (type > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    return Number(type);
  }
  if (typeof type !== 'number' || !Number.isSafeInteger(type) || type < 0) return null;
  return type;
}

function getFrameMetadata(type) {
  const n = normalizeType(type);
  if (n === null) return null;
  return REGISTRY.get(n) || null;
}

function isFrameAllowedInPacket(frameOrType, packetType) {
  const type = (frameOrType && typeof frameOrType === 'object') ? frameOrType.type : frameOrType;
  const metadata = getFrameMetadata(type);
  const packet = normalizePacketType(packetType);
  return !!metadata && !!packet && metadata.packetTypes.includes(packet);
}

function validateFrameContext(frameOrType, packetType) {
  const type = (frameOrType && typeof frameOrType === 'object') ? frameOrType.type : frameOrType;
  const metadata = getFrameMetadata(type);
  const packet = normalizePacketType(packetType);
  if (!metadata) {
    const label = type === undefined ? 'undefined' : String(type);
    throw new QUICError(`Unknown or unsupported QUIC frame type ${label}`, { code: QUICError.ERR_INVALID_FRAME });
  }
  if (!packet || !metadata.packetTypes.includes(packet)) {
    throw new QUICError(`${metadata.name} is not permitted in ${String(packetType)} packets`, {
      code: QUICError.ERR_PROTOCOL,
      frameType: metadata.type
    });
  }
  return true;
}

function listFrameMetadata() {
  return [...REGISTRY.values()].map((entry) => ({ ...entry, packetTypes: [...entry.packetTypes] }));
}

module.exports = {
  CONTEXTS,
  getFrameMetadata,
  isFrameAllowedInPacket,
  validateFrameContext,
  listFrameMetadata
};
module.exports.default = module.exports;
