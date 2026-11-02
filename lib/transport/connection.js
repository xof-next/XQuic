'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const tls = require('../crypto/tls13');
const { randomBytes } = crypto;
const { clone } = require('../crypto/diagnostics');
const { QLog } = require('./qlog');
const { Recovery } = require('./recovery');
const { QUICError } = require('../errors');
const { PathManager } = require('./path');
const { QUICPacer } = require('./pacer');
const { PathMtuDiscovery } = require('./path-mtu');
const { EventEmitter } = require('node:events');
const { FlowControl, StreamState } = require('./flow-control');
const { StatelessResetManager } = require('./stateless-reset');
const { QUIC_VERSION, FRAME_TYPE, STREAM_FRAME } = require('../constants');
const { encodeFrames, decodeFrames, validateFrameContext } = require('../frame');
const { deriveInitialSecrets, derivePacketKeys, deriveNextTrafficSecret } = require('../crypto/initial');
const { buildLongPacket, buildShortPacket, decryptLongPacket, decryptShortPacket, parseLongHeaderUnprotected, buildRetryPacket, parseRetryPacket, verifyRetryPacket } = require('../packet/protection');

const PT = Object.freeze({
	INITIAL: 'initial',
	HANDSHAKE: 'handshake',
	APP: 'app'
});

function validatePeerTransportParameters(tp, {
	isServer
}) {
	if(!tp || typeof tp !== 'object') throw new QUICError('Missing transport parameters', {
		code: QUICError.ERR_TRANSPORT_PARAMETER
	});
	if(isServer) {
		for(const id of [0, 2, 13, 16]) {
			if(tp[id] !== undefined) throw new QUICError('Client sent server-only transport parameter ' + id, {
				code: QUICError.ERR_TRANSPORT_PARAMETER
			});
		}
	} else {}
	return tp;
}

function arr(v) {
	return Buffer.from(v);
}

function wipeBufferTree(value, seen = new Set()) {
	if(Buffer.isBuffer(value)) {
		value.fill(0);
		return;
	}
	if(!value || typeof value !== 'object' || seen.has(value)) return;
	seen.add(value);
	for(const child of Object.values(value)) wipeBufferTree(child, seen);
}

function stripAttachedDetails(value, expose = false) {
	if(expose || !value || !value.details) return value;
	wipeBufferTree(value.details);
	try { delete value.details; } catch { value.details = undefined; }
	return value;
}

function frame(type, data = {}) {
	return {
		type,
		...data
	};
}

function transportErrorCode(err) {
	if(Number.isInteger(err?.transportCode) && err.transportCode >= 0 && err.transportCode <= 0x1fffffff) return err.transportCode;
	switch(err?.code) {
		case QUICError.ERR_INTERNAL: return 0x01; // INTERNAL_ERROR
		case QUICError.ERR_FLOW_CONTROL: return 0x03; // FLOW_CONTROL_ERROR
		case QUICError.ERR_STREAM_LIMIT: return 0x04; // STREAM_LIMIT_ERROR
		case QUICError.ERR_STREAM_STATE: return 0x05; // STREAM_STATE_ERROR
		case QUICError.ERR_CRYPTO_BUFFER_EXCEEDED: return 0x0d; // CRYPTO_BUFFER_EXCEEDED
		case QUICError.ERR_FINAL_SIZE: return 0x06; // FINAL_SIZE_ERROR
		case QUICError.ERR_INVALID_FRAME:
		case QUICError.ERR_INVALID_VARINT:
		case QUICError.ERR_INVALID_LENGTH:
		case QUICError.ERR_INVALID_ARGUMENT: return 0x07; // FRAME_ENCODING_ERROR
		case QUICError.ERR_TRANSPORT_PARAMETER: return 0x08; // TRANSPORT_PARAMETER_ERROR
		case QUICError.ERR_CONNECTION_ID_LIMIT: return 0x09; // CONNECTION_ID_LIMIT_ERROR
		case QUICError.ERR_KEY_UPDATE: return 0x0e; // KEY_UPDATE_ERROR
		case QUICError.ERR_CRYPTO: return 0x100 + (Number(err?.tlsAlert ?? err?.cryptoErrorCode ?? 80) & 0xff); // CRYPTO_ERROR(alert)
		case QUICError.ERR_STATE: return 0x01; // INTERNAL_ERROR unless a more specific error is supplied
		case QUICError.ERR_PROTOCOL:
		default: return 0x0a; // PROTOCOL_VIOLATION
	}
}

class CryptoReassembler {
	constructor(maxBufferedBytes = 1024 * 1024) {
		this.chunks = new Map();
		this.next = 0;
		this.bufferedBytes = 0;
		this.maxBufferedBytes = Math.max(4096, Number(maxBufferedBytes) || 1024 * 1024);
	}
	push(offset, data) {
		let b = Buffer.from(data);
		const oBig = typeof offset === 'bigint' ? offset : BigInt(offset);
		if (oBig < 0n || oBig > BigInt(Number.MAX_SAFE_INTEGER)) {
			throw new QUICError('Invalid CRYPTO offset', { code: QUICError.ERR_PROTOCOL });
		}
		let o = Number(oBig);
		if (!b.length) return Buffer.alloc(0);
		let end = o + b.length;
		if (!Number.isSafeInteger(end) || end < o) {
			throw new QUICError('CRYPTO offset overflow', { code: QUICError.ERR_PROTOCOL });
		}
		if (end <= this.next) return Buffer.alloc(0);
		// Already-delivered CRYPTO bytes need not be buffered again. Trim a
		// retransmission that starts in the delivered prefix before merging.
		if (o < this.next) {
			const trim = this.next - o;
			b = b.subarray(trim);
			o = this.next;
			end = o + b.length;
		}
		if (!b.length) return Buffer.alloc(0);

		let unionStart = o;
		let unionEnd = end;
		let overlapBytes = 0;
		const overlaps = [];
		for (const [key, existing] of this.chunks) {
			const a = Number(key);
			const z = a + existing.length;
			if (z <= o || a >= end) continue;
			const lo = Math.max(a, o);
			const hi = Math.min(z, end);
			const incoming = b.subarray(lo - o, hi - o);
			const prior = existing.subarray(lo - a, hi - a);
			if (!incoming.equals(prior)) {
				throw new QUICError('Conflicting CRYPTO overlap', { code: QUICError.ERR_PROTOCOL });
			}
			overlapBytes += hi - lo;
			overlaps.push([key, a, existing]);
			if (a < unionStart) unionStart = a;
			if (z > unionEnd) unionEnd = z;
		}

		const addedBytes = b.length - overlapBytes;
		if (this.bufferedBytes + addedBytes > this.maxBufferedBytes) {
			throw new QUICError('CRYPTO reassembly limit exceeded', { code: QUICError.ERR_CRYPTO_BUFFER_EXCEEDED });
		}
		if (overlaps.length) {
			const merged = Buffer.alloc(unionEnd - unionStart);
			for (const [key, a, existing] of overlaps) {
				existing.copy(merged, a - unionStart);
				this.chunks.delete(key);
			}
			b.copy(merged, o - unionStart);
			this.chunks.set(unionStart, merged);
		} else {
			this.chunks.set(o, b);
		}
		this.bufferedBytes += addedBytes;

		const out = [];
		while (this.chunks.has(this.next)) {
			const chunk = this.chunks.get(this.next);
			this.chunks.delete(this.next);
			this.bufferedBytes -= chunk.length;
			out.push(chunk);
			this.next += chunk.length;
		}
		return out.length ? Buffer.concat(out) : Buffer.alloc(0);
	}
}
class Space {
	constructor() {
		this.sendPN = 0n;
		this.largestRx = -1n;
		this.pendingAck = false;
		this.acked = new Set();
		this.received = new Set();
		this.sent = new Map();
	}
	recordReceived(packetNumber, maxHistory = 4096) {
		const pn = BigInt(packetNumber);
		if(this.received.has(pn)) return false;
		this.received.add(pn);
		if(pn > this.largestRx) this.largestRx = pn;
		// Keep a bounded duplicate-detection/ACK-range history. This is shared
		// by Initial, Handshake, and Application packet-number spaces so packet
		// reordering is not mistaken for a duplicate in any encryption level.
		if(this.received.size > maxHistory) {
			let oldest = null;
			for(const value of this.received) {
				if(oldest === null || value < oldest) oldest = value;
			}
			if(oldest !== null) this.received.delete(oldest);
		}
		return true;
	}
}
class QUICConnection extends EventEmitter {
	constructor(socket, opts = {}) {
		super();
		this.socket = socket;
		this.isServer = !!opts.isServer;
		this.address = opts.address;
		this.version = opts.version ?? QUIC_VERSION.V1;
		this.psk = opts.psk == null ? null : tls.normalizePsk(opts.psk);
		this.noPsk = opts.noPsk === true || (opts.noPsk === undefined && !this.psk && !!opts.cert);
		if(!this.noPsk && !this.psk) throw new QUICError('PSK mode requires an explicit PSK; certificate mode requires noPsk: true', { code: QUICError.ERR_INVALID_ARGUMENT });
		this.identity = opts.identity ?? 'xof';
		this.alpn = Array.isArray(opts.alpn) ? opts.alpn.map(String) : (opts.alpn ?? 'xof');
		this.serverName = opts.serverName ?? null;
		this.signatureAlgorithms = opts.signatureAlgorithms;
		this.rejectUnauthorized = opts.rejectUnauthorized !== false;
		this.exposeKeyMaterial = opts.exposeKeyMaterial === true || process.env.XOF_EXPOSE_KEY_MATERIAL === '1';
		this.ca = opts.ca;
		this.cert = opts.cert ? (Buffer.isBuffer(opts.cert) ? Buffer.from(opts.cert) : Buffer.from(String(opts.cert).includes('BEGIN') ? String(opts.cert) : fs.readFileSync(opts.cert))) : null;
		this.certChain = Array.isArray(opts.certChain) ? opts.certChain.map(x => Buffer.isBuffer(x) ? Buffer.from(x) : Buffer.from(String(x).includes('BEGIN') ? String(x) : fs.readFileSync(x))) : [];
		this.privateKey = opts.key ? (opts.key.type ? opts.key : crypto.createPrivateKey(String(opts.key).includes('BEGIN') ? opts.key : fs.readFileSync(opts.key))) : null;
		this.supportedVersions = Array.isArray(opts.supportedVersions) && opts.supportedVersions.length ? opts.supportedVersions.map(v => Number(v) >>> 0) : [QUIC_VERSION.V1];
		this.statelessResetManager = opts.statelessResetSecret ? new StatelessResetManager(opts.statelessResetSecret) : null;
		if(this.isServer && this.noPsk && (!this.cert || !this.privateKey)) throw new QUICError('Certificate mode requires cert and key', {
			code: QUICError.ERR_INVALID_ARGUMENT
		});
		this.peerResetTokens = new Map();
		this.retransmitQueue = {
			initial: [],
			handshake: [],
			app: []
		};
		this.addressValidated = !this.isServer || !!opts.addressValidated;
		this.localCID = Buffer.from(opts.localCID ?? randomBytes(8));
		this.peerCID = opts.peerCID ? Buffer.from(opts.peerCID) : null;
		this.initialDCID = opts.initialDCID ? Buffer.from(opts.initialDCID) : null;
		this.serverCID = this.isServer ? this.localCID : null;
		this.spaces = {
			initial: new Space(),
			handshake: new Space(),
			app: new Space()
		};
		this.cryptoRx = {
			initial: new CryptoReassembler(opts.maxCryptoBufferBytes),
			handshake: new CryptoReassembler(opts.maxCryptoBufferBytes)
		};
		this.cryptoTx = {
			initial: 0,
			handshake: 0
		};
		this.tlsRxBuffers = {
			initial: Buffer.alloc(0),
			handshake: Buffer.alloc(0)
		};
		this.streams = new Map();
		this.maxRemoteStreamId = -1n;
		this.handshakeState = 'idle';
		this.readyState = 'new';
		this.closed = false;
		this.draining = false;
		this.closeSent = false;
		this.closeReceived = false;
		this.closeCode = 0;
		this.closeReason = '';
		this.retryTimer = null;
		this.peerAckFrequency = null;
		this.recovery = new Recovery(this, {
			maxDatagramSize: 1200,
			maxAckDelay: 25
		});
		this.pacer = new QUICPacer({
			enabled: opts.pacing !== false,
			gain: opts.pacingGain ?? 1.25,
			getCongestionWindow: () => this.recovery?.cwnd ?? 12000,
			getSmoothedRtt: () => this.recovery?.rtt?.smoothedRtt || 333
		});
		this.idleTimer = null;
		this.handshakeTimer = null;
		this.handshakeTimeout = Math.max(1000, Number(opts.handshakeTimeout ?? 15000));
		this.clientHello = null;
		this.serverHello = null;
		this.ee = null;
		this.serverFinished = null;
		this.keys = {
			initialTx: null,
			initialRx: null,
			handshakeTx: null,
			handshakeRx: null,
			appTx: null,
			appRx: null
		};
		this.appSecrets = {
			tx: null,
			rx: null
		};
		this.diagnostics = {
			version: this.version,
			role: this.isServer ? 'server' : 'client',
			tls: {
				local: null,
				peer: null,
				handshake: null
			},
			quic: {
				localTransportParameters: null,
				peerTransportParameters: null
			},
			crypto: {
				initial: null,
				handshake: null,
				application: null,
				keyUpdates: [],
				keyMaterialExposed: this.exposeKeyMaterial,
				lastAEAD: null,
				lastHeaderProtection: null
			},
			packets: {
				lastTx: null,
				lastRx: null
			}
		};
		this.keyPhase = 0;
		this.rxKeyPhase = 0;
		this.txKeyUpdates = 0;
		this.rxKeyUpdates = 0;
		this.maxKeyUpdates = 1 << 20;
		this.maxStreamBufferBytes = Math.max(64 * 1024, Number(opts.maxStreamBufferBytes ?? 16 * 1024 * 1024));
		this.qlog = opts.qlog ? (opts.qlog instanceof QLog ? opts.qlog : new QLog(typeof opts.qlog === 'object' ? opts.qlog : {})) : null;
		this.transportParameters = {
			maxData: Number(opts.maxData ?? 1048576),
			maxStreamData: Number(opts.maxStreamData ?? 1048576),
			maxStreamDataBidiLocal: Number(opts.maxStreamDataBidiLocal ?? opts.maxStreamData ?? 1048576),
			maxStreamDataBidiRemote: Number(opts.maxStreamDataBidiRemote ?? opts.maxStreamData ?? 1048576),
			maxStreamDataUni: Number(opts.maxStreamDataUni ?? opts.maxStreamData ?? 1048576),
			maxStreams: Number(opts.maxStreams ?? 16),
			maxStreamsUni: Number(opts.maxStreamsUni ?? 16),
			idleTimeout: Number(opts.idleTimeout ?? 30_000),
			maxUdpPayloadSize: Number(opts.maxUdpPayloadSize ?? 65527),
			ackDelayExponent: Number(opts.ackDelayExponent ?? 3),
			maxAckDelay: Number(opts.maxAckDelay ?? 25),
			disableActiveMigration: !!opts.disableActiveMigration,
			maxDatagramFrameSize: Number(opts.maxDatagramFrameSize ?? 0),
			activeConnectionIdLimit: Number(opts.activeConnectionIdLimit ?? 8)
		};
		this.peerTransportParameters = null;
		this.remoteMaxDatagramFrameSize = 0;
		this.flow = new FlowControl({
			...this.transportParameters,
			localMaxStreamDataBidiLocal: this.transportParameters.maxStreamDataBidiLocal,
			localMaxStreamDataBidiRemote: this.transportParameters.maxStreamDataBidiRemote,
			localMaxStreamDataUni: this.transportParameters.maxStreamDataUni,
			remoteMaxStreams: 0n,
			remoteMaxStreamsUni: 0n,
			isServer: this.isServer,
			maxStreamsUni: this.transportParameters.maxStreamsUni
		});
		this.path = new PathManager(this);
		this.pathMtu = new PathMtuDiscovery(this, {
			maxSize: opts.maxPathMtu ?? 1452,
			probeTimeoutMs: opts.pathMtuProbeTimeoutMs ?? 16000,
			maxProbes: opts.pathMtuMaxProbes ?? 3
		});
		this.retryToken = opts.retryToken ? Buffer.from(opts.retryToken) : null;
		this.retryReceived = false;
		if(this.retryToken) this.addressValidated = true;
		this.originalServerCID = this.initialDCID ? Buffer.from(this.initialDCID) : null;
		this.originalDestinationConnectionId = opts.originalDestinationConnectionId ? Buffer.from(opts.originalDestinationConnectionId) : (this.initialDCID ? Buffer.from(this.initialDCID) : null);
		this.retrySourceConnectionId = opts.retrySourceConnectionId ? Buffer.from(opts.retrySourceConnectionId) : null;
		const initialResetToken = this.statelessResetManager ? this.statelessResetManager.token(this.localCID) : randomBytes(16);
		const initialLocalCid = { sequence: 0n, cid: Buffer.from(this.localCID), token: initialResetToken, retired: false };
		this.activeConnectionIds = new Map([[0n, initialLocalCid]]);
		this.issuedConnectionIds = new Map([[0n, { ...initialLocalCid, cid: Buffer.from(initialLocalCid.cid), token: Buffer.from(initialLocalCid.token) }]]);
		this.peerConnectionIds = new Map();
		this.nextCidSequence = 1n;
		this.maxActiveConnectionIdLimit = BigInt(opts.activeConnectionIdLimit ?? 8);
		if (this.maxActiveConnectionIdLimit < 2n || this.maxActiveConnectionIdLimit > 0x3fffffffffffffffn) throw new QUICError('activeConnectionIdLimit must be at least 2', { code: QUICError.ERR_INVALID_ARGUMENT });
		this.peerMaxActiveConnectionIdLimit = 2n;
		this.peerRetirePriorTo = 0n;
		this.peerActiveCidSequence = 0n;
		// ACK_FREQUENCY is an optional extension: codec support does not mean it was negotiated.
		this.ackFrequencyNegotiated = false;
		this.bytesRx = 0;
		this.bytesTx = 0;
		this.pathBytes = new Map();
		this._onMessage = this._onMessage.bind(this);
		this._processingDatagram = false;
		this._pendingHandshakeCoalesce = null;
		this._handshakeCoalesceScheduled = false;
		this._pendingFlightPackets = null;
		this._flightCoalesceScheduled = false;
		this._maxCoalescedDatagram = 1200;
		this.on('error', () => {});
		if(!opts.managedSocket) {
			socket.on('message', this._onMessage);
			socket.on('error', err => this.emit('error', err));
		}
		this.recovery.on('loss', e => {
			this.emit('loss', e);
			this.emit('writable', { reason: 'loss' });
		});
		this.recovery.on('pto', e => this.emit('pto', e));
		this.recovery.on('ack', e => {
			this.emit('ack', e);
			this.emit('writable', { reason: 'ack' });
		});
		this.recovery.on('congestion', e => this.emit('congestion', e));
		this.touchIdle();
	}
	armHandshakeTimeout() {
		clearTimeout(this.handshakeTimer);
		if(this.closed || this.readyState === 'open') return;
		this.handshakeTimer = setTimeout(() => {
			if(this.closed || this.readyState === 'open') return;
			const err = new QUICError('QUIC handshake timeout', {
				code: QUICError.ERR_HANDSHAKE_TIMEOUT
			});
			this.emit('timeout', err);
			this.close(0, 'handshake timeout');
		}, this.handshakeTimeout);
	}
	clearHandshakeTimeout() {
		if(this.handshakeTimer) {
			clearTimeout(this.handshakeTimer);
			this.handshakeTimer = null;
		}
	}
	touchIdle() {
		clearTimeout(this.idleTimer);
		const local = Number(this.transportParameters.idleTimeout ?? 30_000);
		const remote = Number(this.peerTransportParameters?.idleTimeout ?? local);
		const timeout = Math.max(1_000, Math.min(local, remote));
		this.idleTimer = setTimeout(() => this.close(0, 'idle timeout'), timeout);
	}
	_pathBytesKey(address) {
		return JSON.stringify([String(address?.address ?? ''), Number(address?.port)]);
	}
	setPeerAddress(address, validated = false) {
		if(!address) return;
		const a = {
			address: address.address,
			port: Number(address.port)
		};
		this.address = a;
		if(validated) {
			const key = this._pathBytesKey(a);
			const counters = this.pathBytes.get(key) || { rx: 0, tx: 0, validated: false };
			counters.validated = true;
			this.pathBytes.set(key, counters);
		}
	}
	_activeLocalCids() {
		return [...this.activeConnectionIds.values()].filter(x => !x.retired).sort((a, b) => a.sequence < b.sequence ? -1 : a.sequence > b.sequence ? 1 : 0);
	}
	_activePeerCids() {
		return [...this.peerConnectionIds.values()].filter(x => !x.retired && Buffer.isBuffer(x.cid)).sort((a, b) => a.sequence < b.sequence ? -1 : a.sequence > b.sequence ? 1 : 0);
	}
	selectPeerConnectionId(sequence) {
		const entry = this.peerConnectionIds.get(BigInt(sequence));
		if (!entry || entry.retired) throw new QUICError('Peer connection ID is not active', { code: QUICError.ERR_STATE });
		this.peerCID = Buffer.from(entry.cid);
		this.peerActiveCidSequence = BigInt(entry.sequence);
		return this.peerActiveCidSequence;
	}
	onPathValidated(address, previousAddress) {
		const active = this._activePeerCids();
		const replacement = active.find(x => x.sequence !== this.peerActiveCidSequence);
		if (!replacement) return false;
		const oldSequence = this.peerActiveCidSequence;
		this.selectPeerConnectionId(replacement.sequence);
		if (oldSequence !== replacement.sequence && this.readyState === 'open') {
			try {
				this.sendFrames('app', 'app', [frame(FRAME_TYPE.RETIRE_CONNECTION_ID, { sequence: oldSequence })]);
				const oldEntry = this.peerConnectionIds.get(oldSequence);
				if (oldEntry) oldEntry.retired = true;
				if (oldEntry) this.peerResetTokens.delete(oldEntry.cid.toString('hex'));
			} catch (err) { this.emit('error', err); }
		}
		this.emit('peerConnectionIdChanged', { sequence: replacement.sequence, cid: Buffer.from(replacement.cid), address: { ...address }, previousAddress: previousAddress ? { ...previousAddress } : null });
		return true;
	}
	_retirePeerIdsBefore(retirePriorTo) {
		const rp = BigInt(retirePriorTo);
		if (rp <= this.peerRetirePriorTo) return;
		const retire = [];
		for (const [seq, entry] of this.peerConnectionIds) {
			if (seq < rp && !entry.retired) {
				entry.retired = true;
				this.peerResetTokens.delete(entry.cid.toString('hex'));
				retire.push(seq);
			}
		}
		this.peerRetirePriorTo = rp;
		const current = this.peerConnectionIds.get(this.peerActiveCidSequence);
		if (!current || current.retired || this.peerActiveCidSequence < rp) {
			const replacement = this._activePeerCids().find(x => x.sequence >= rp);
			if (!replacement) throw new QUICError('Peer retired all available connection IDs', { code: QUICError.ERR_CONNECTION_ID_LIMIT });
			this.selectPeerConnectionId(replacement.sequence);
		}
		if (retire.length && this.readyState === 'open') {
			const frames = retire.map(sequence => frame(FRAME_TYPE.RETIRE_CONNECTION_ID, { sequence }));
			this.sendFrames('app', 'app', frames);
		}
	}
	sendRaw(packet, address = this.address) {
		if(this.closed) return;
		if(!address || address.port == null || !address.address) throw new QUICError('Peer address unavailable', {
			code: QUICError.ERR_STATE
		});
		const size = Buffer.byteLength(packet);
		const key = this._pathBytesKey(address);
		const st = this.pathBytes.get(key) || {
			rx: 0,
			tx: 0,
			validated: this.path.isValidated(address) || (this.addressValidated && this.path.isCurrent(address))
		};
		if(this.isServer && !st.validated && st.tx + size > 3 * Math.max(st.rx, 1)) throw new QUICError('Server anti-amplification limit', {
			code: QUICError.ERR_STATE
		});
		st.tx += size;
		this.pathBytes.set(key, st);
		this.bytesTx += size;
		this.socket.send(packet, address.port, address.address);
	}
	_isClientFinishedFrames(space, frames) {
		if(this.isServer || space !== 'handshake') return false;
		for(const f of frames) {
			if(Number(f.type) !== FRAME_TYPE.CRYPTO) continue;
			const data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data || []);
			if(data.length && data[0] === tls.HS_FINISHED) return true;
		}
		return false;
	}
	_flushHandshakeCoalesce() {
		const p = this._pendingHandshakeCoalesce;
		if(!p) return;
		this._pendingHandshakeCoalesce = null;
		try {
			this.sendRaw(p.packet, p.address);
			this.markSent(p.space, p.pn, p.entry);
		} catch {}
	}
	_sameAddress(a, b) {
		return !!(a && b && `${a.address}:${Number(a.port)}` === `${b.address}:${Number(b.port)}`);
	}
	_flushFlightCoalesce() {
		const q = this._pendingFlightPackets;
		if(!q || !q.length) return;
		this._pendingFlightPackets = null;
		const address = q[0].address;
		try {
			this.sendRaw(Buffer.concat(q.map(x => x.packet)), address);
			for(const x of q) this.markSent(x.space, x.pn, x.entry);
		} catch {}
	}
	_queueFlightPacket(item) {
		const q = this._pendingFlightPackets || [];
		const address = item.address;
		const total = q.reduce((n, x) => n + x.packet.length, 0) + item.packet.length;
		if(q.length && (!this._sameAddress(q[0].address, address) || total > this._maxCoalescedDatagram)) {
			this._flushFlightCoalesce();
			return this._queueFlightPacket(item);
		}
		q.push(item);
		this._pendingFlightPackets = q;
		if(!this._flightCoalesceScheduled) {
			this._flightCoalesceScheduled = true;
			setImmediate(() => {
				this._flightCoalesceScheduled = false;
				this._flushFlightCoalesce();
			});
		}
	}
	derivePacketKeys(secret) {
		return stripAttachedDetails(derivePacketKeys(secret, this.version), this.exposeKeyMaterial);
	}
	clearHandshakeSecrets() {
		if(!this.handshakeSecrets) return;
		for(const name of ['early', 'binder', 'handshake', 'cHs', 'sHs', 'master', 'cApp', 'sApp']) {
			const value = this.handshakeSecrets[name];
			if(Buffer.isBuffer(value)) value.fill(0);
		}
		stripAttachedDetails(this.handshakeSecrets, false);
		this.handshakeSecrets = null;
		if(Buffer.isBuffer(this.psk)) this.psk.fill(0);
		this.psk = null;
	}
	zeroizeSecrets() {
		for(const name of ['initialTx', 'initialRx', 'handshakeTx', 'handshakeRx', 'appTx', 'appRx']) {
			const keys = this.keys[name];
			if(!keys) continue;
			for(const field of ['key', 'iv', 'headerProtectionKey']) if(Buffer.isBuffer(keys[field])) keys[field].fill(0);
			stripAttachedDetails(keys, false);
			this.keys[name] = null;
		}
		for(const direction of ['tx', 'rx']) {
			const secret = this.appSecrets[direction];
			if(Buffer.isBuffer(secret)) {
				if(secret.details) stripAttachedDetails(secret, false);
				secret.fill(0);
			}
			this.appSecrets[direction] = null;
		}
		this.clearHandshakeSecrets();
		if(this.clientHello?.keyShare) this.clientHello.keyShare.privateKey = null;
		if(this.clientKeyShare) this.clientKeyShare.privateKey = null;
		if(this.serverKeyShare) this.serverKeyShare.privateKey = null;
		this.clientKeyShare = null;
		this.privateKey = null;
	}
	setInitialKeys() {
		if(!this.initialDCID) throw new QUICError('Initial DCID missing', {
			code: QUICError.ERR_STATE
		});
		const s = deriveInitialSecrets({
			version: this.version,
			destinationConnectionId: this.initialDCID
		});
		if(this.isServer) {
			this.keys.initialTx = this.derivePacketKeys(s.serverInitialSecret);
			this.keys.initialRx = this.derivePacketKeys(s.clientInitialSecret);
		} else {
			this.keys.initialTx = this.derivePacketKeys(s.clientInitialSecret);
			this.keys.initialRx = this.derivePacketKeys(s.serverInitialSecret);
		}
		this.diagnostics.crypto.initial = this.exposeKeyMaterial ? {
			derivation: clone(s.details || {
				version: this.version,
				initialSecret: s.initialSecret,
				clientInitialSecret: s.clientInitialSecret,
				serverInitialSecret: s.serverInitialSecret
			}),
			tx: clone(this.keys.initialTx.details || this.keys.initialTx),
			rx: clone(this.keys.initialRx.details || this.keys.initialRx)
		} : {
			version: this.version,
			cipher: 'AES-128-GCM',
			headerProtection: 'AES-128-ECB',
			keyMaterialExposed: false,
			tx: { keyLength: this.keys.initialTx.key.length, ivLength: this.keys.initialTx.iv.length, headerProtectionKeyLength: this.keys.initialTx.headerProtectionKey.length },
			rx: { keyLength: this.keys.initialRx.key.length, ivLength: this.keys.initialRx.iv.length, headerProtectionKeyLength: this.keys.initialRx.headerProtectionKey.length }
		};
		if(!this.exposeKeyMaterial) {
			for(const name of ['initialSecret', 'clientInitialSecret', 'serverInitialSecret']) if(Buffer.isBuffer(s[name])) s[name].fill(0);
			if(s.details) wipeBufferTree(s.details);
			delete s.details;
		}
	}
	nextPN(space) {
		const s = this.spaces[space];
		const pn = s.sendPN;
		s.sendPN++;
		return pn;
	}
	markSent(space, pn, entry) {
		this.recovery.onPacketSent(space, {
			...entry,
			pn,
			bytes: entry.bytes ?? 0,
			sentAt: Date.now(),
			ackEliciting: entry.ackEliciting !== false,
			inFlight: true
		});
	}
	acknowledge(space, largest) {
		return this.recovery.onAck(space, {
			largestAcked: BigInt(largest),
			ackDelay: 0n,
			ranges: [{
				start: 0n,
				end: BigInt(largest)
			}]
		});
	}
	retransmit(space, packet) {
		if(this.closed || !packet.frames?.length) return;
		// QUIC retransmits lost information in new packets, not unreliable DATAGRAMs or ACKs.
		const nonRetransmittable = new Set([FRAME_TYPE.PADDING, FRAME_TYPE.ACK, FRAME_TYPE.ACK_ECN, FRAME_TYPE.DATAGRAM, FRAME_TYPE.DATAGRAM_LEN]);
		const retransmittable = packet.frames.filter(f => !nonRetransmittable.has(Number(f.type)));
		if (!retransmittable.length) return;
		try {
			this.sendFrames(space, packet.packetType, retransmittable, { retransmit: true, probe: false });
		} catch (err) {
			if(err instanceof QUICError && err.code === QUICError.ERR_STATE && /Congestion window exhausted/.test(err.message)) {
				const q = this.retransmitQueue[space] || [];
				if(q.length < 256) q.push({ packetType: packet.packetType, frames: retransmittable });
				return;
			}
		}
	}
	flushRetransmissions(space) {
		const q = this.retransmitQueue[space];
		if(!q?.length || this.closed) return;
		while(q.length) {
			const item = q[0];
			try {
				this.sendFrames(space, item.packetType, item.frames, {
					retransmit: true,
					probe: false
				});
				q.shift();
			} catch (err) {
				if(err instanceof QUICError && err.code === QUICError.ERR_STATE) break;
				q.shift();
			}
		}
	}
	sendFrames(space, packetType, frames, {
		retransmit = false,
		probe = false,
		address = null,
		coalesceFlight = false,
		pmtuProbeSize = null,
		pmtuProbeId = null
	} = {}) {
		if(this.closed) return;
		for(const f of frames) validateFrameContext(f, packetType);
		let encoded = encodeFrames(frames);
		if(pmtuProbeSize !== null) {
			const size = Number(pmtuProbeSize);
			if(space !== 'app' || packetType !== 'app' || !Number.isSafeInteger(size) || size < 1200 || size > 65527 || !Number.isSafeInteger(Number(pmtuProbeId)) || Number(pmtuProbeId) < 1 || frames.length !== 1 || Number(frames[0].type) !== FRAME_TYPE.PING) {
				throw new QUICError('PMTU probes must be application packets containing only PING plus PADDING and a valid UDP payload size', { code: QUICError.ERR_INVALID_ARGUMENT });
			}
			// Short header (1 byte) + Destination CID + 4-byte packet number + AEAD tag.
			// Appending zero bytes creates legal PADDING frames and targets UDP payload size exactly.
			const overhead = 1 + Buffer.from(this.peerCID || []).length + 4 + 16;
			const paddingLength = size - overhead - encoded.length;
			if(paddingLength < 0) throw new QUICError('PMTU probe target is smaller than its encoded packet overhead', { code: QUICError.ERR_INVALID_LENGTH });
			encoded = Buffer.concat([encoded, Buffer.alloc(paddingLength)]);
		}
		const s = this.spaces[space];
		const pn = this.nextPN(space);
		const ackEliciting = frames.some(f => Number(f.type) !== FRAME_TYPE.PADDING && Number(f.type) !== FRAME_TYPE.ACK && Number(f.type) !== FRAME_TYPE.ACK_ECN && Number(f.type) !== FRAME_TYPE.CONNECTION_CLOSE && Number(f.type) !== FRAME_TYPE.APPLICATION_CLOSE);
		let packet;
		if(space === 'app') {
			if(!this.keys.appTx) throw new QUICError('Application keys unavailable', {
				code: QUICError.ERR_STATE
			});
			packet = buildShortPacket({
				dcid: this.peerCID,
				packetNumber: pn,
				packetNumberLength: 4,
				keyPhase: this.keyPhase,
				frames: encoded,
				keys: this.keys.appTx
			});
			if(process.env.XOF_DEBUG) console.error('SENDAPP', this.isServer, this.keyPhase, pn.toString(), this.appSecrets.tx && this.appSecrets.tx.toString('hex').slice(0, 8));
		} else {
			const keys = space === 'initial' ? this.keys.initialTx : this.keys.handshakeTx;
			if(!keys) throw new QUICError(space + ' keys unavailable', {
				code: QUICError.ERR_STATE
			});
			packet = buildLongPacket({
				version: this.version,
				type: space,
				dcid: this.peerCID,
				scid: this.localCID,
				token: space === 'initial' ? (this.retryToken || Buffer.alloc(0)) : Buffer.alloc(0),
				packetNumber: pn,
				packetNumberLength: 4,
				frames: encoded,
				keys,
				minSize: space === 'initial' ? 1200 : 0
			});
		}
		if(pmtuProbeSize !== null && packet.length !== Number(pmtuProbeSize)) {
			throw new QUICError('Internal PMTU probe size mismatch', { code: QUICError.ERR_INTERNAL });
		}
		if(ackEliciting && !probe && !this.recovery.canSend(packet.length)) {
			throw new QUICError('Congestion window exhausted', {
				code: QUICError.ERR_STATE
			});
		}
		if(packet?.details && this.exposeKeyMaterial) {
			this.diagnostics.packets.lastTx = clone(packet.details);
			this.diagnostics.crypto.lastAEAD = packet.details.aead || this.diagnostics.crypto.lastAEAD;
			this.diagnostics.crypto.lastHeaderProtection = packet.details.headerProtection || this.diagnostics.crypto.lastHeaderProtection;
		}
		this.qlog?.packet('tx', packetType, pn, {
			length: packet.length
		});
		const targetAddress = address || this.address;
		const entry = {
			packetType,
			frames,
			attempts: 0,
			retransmit,
			bytes: packet.length,
			ackEliciting: true,
			isPmtuProbe: pmtuProbeSize !== null,
			pmtuProbeId: pmtuProbeId === null ? null : Number(pmtuProbeId),
			pmtuProbeSize: pmtuProbeSize === null ? null : Number(pmtuProbeSize)
		};
		if(ackEliciting && !probe && this._isClientFinishedFrames(space, frames)) {
			if(this._pendingHandshakeCoalesce) this._flushHandshakeCoalesce();
			this._pendingHandshakeCoalesce = {
				packet,
				pn,
				space,
				entry,
				address: targetAddress
			};
			if(!this._handshakeCoalesceScheduled) {
				this._handshakeCoalesceScheduled = true;
				setImmediate(() => {
					this._handshakeCoalesceScheduled = false;
					this._flushHandshakeCoalesce();
				});
			}
			return pn;
		}
		const pending = this._pendingHandshakeCoalesce;
		if(pending && space === 'app' && targetAddress && pending.address && `${targetAddress.address}:${Number(targetAddress.port)}` === `${pending.address.address}:${Number(pending.address.port)}`) {
			this._pendingHandshakeCoalesce = null;
			this.sendRaw(Buffer.concat([pending.packet, packet]), targetAddress);
			this.markSent(pending.space, pending.pn, pending.entry);
			if(ackEliciting) this.markSent(space, pn, entry);
			return pn;
		}
		if(pending) this._flushHandshakeCoalesce();
		if(coalesceFlight && !retransmit && !probe) {
			this._queueFlightPacket({
				packet,
				pn,
				space,
				entry,
				address: targetAddress
			});
			return pn;
		}
		this.sendRaw(packet, targetAddress);
		if(ackEliciting) this.markSent(space, pn, entry);
		return pn;
	}
	_ackRanges(space, maxRanges = 32) {
		const s = this.spaces[space];
		const nums = [...s.received].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
		if(!nums.length) return [];
		const limit = Math.max(1, Math.min(256, Number(maxRanges) || 32));
		const ranges = [];
		let start = nums[nums.length - 1],
			end = start;
		for(let i = nums.length - 2; i >= 0; i--) {
			const n = nums[i];
			if(n + 1n === start) start = n;
			else {
				ranges.push({ start, end });
				if(ranges.length >= limit) return ranges;
				start = end = n;
			}
		}
		ranges.push({ start, end });
		return ranges.slice(0, limit);
	}
	sendAck(space) {
		const s = this.spaces[space];
		if(s.largestRx < 0n) return;
		s.pendingAck = false;
		const ranges = this._ackRanges(space);
		if(ranges.length) this.sendFrames(space, space, [frame(FRAME_TYPE.ACK, {
			largestAcked: s.largestRx,
			ackDelay: 0n,
			ranges
		})]);
	}
	start() {
		if(this.isServer) return this;
		this.readyState = 'handshaking';
		this.armHandshakeTimeout();
		this.handshakeState = 'client_initial';
		this.initialDCID = this.initialDCID || Buffer.from(this.peerCID || randomBytes(8));
		if(!this.peerCID) this.peerCID = Buffer.from(this.initialDCID);
		this.setInitialKeys();
		const tp = tls.makeTransportParameters({
			initialSourceConnectionId: this.localCID,
			activeConnectionIdLimit: this.transportParameters.activeConnectionIdLimit,
			maxData: this.transportParameters.maxData,
			maxUdpPayloadSize: this.transportParameters.maxUdpPayloadSize,
			idleTimeout: this.transportParameters.idleTimeout,
			ackDelayExponent: this.transportParameters.ackDelayExponent,
			maxAckDelay: this.transportParameters.maxAckDelay,
			disableActiveMigration: this.transportParameters.disableActiveMigration,
			maxStreamData: this.transportParameters.maxStreamData,
			maxStreamDataBidiLocal: this.transportParameters.maxStreamDataBidiLocal,
			maxStreamDataBidiRemote: this.transportParameters.maxStreamDataBidiRemote,
			maxStreamDataUni: this.transportParameters.maxStreamDataUni,
			maxStreams: this.transportParameters.maxStreams,
			maxStreamsUni: this.transportParameters.maxStreamsUni,
			maxDatagramFrameSize: this.transportParameters.maxDatagramFrameSize
		});
		this.clientHello = tls.buildClientHello({
			psk: this.psk,
			identity: this.identity,
			alpn: this.alpn,
			serverName: this.serverName,
			signatureAlgorithms: this.signatureAlgorithms,
			transportParameters: tp,
			noPsk: this.noPsk
		});
		this.diagnostics.quic.localTransportParameters = clone(tp.details || {
			raw: tp
		});
		this.diagnostics.tls.local = clone({
			raw: this.clientHello.raw || this.clientHello.message,
			details: this.clientHello.details,
			fingerprint: this.clientHello.fingerprint
		});
		this.clientKeyShare = this.clientHello.keyShare;
		this.sendFrames('initial', 'initial', [frame(FRAME_TYPE.CRYPTO, {
			offset: 0n,
			data: this.clientHello.message
		})]);
		return this;
	}
	handleInitialPayload(plaintext, hdr) {
		const r = this.cryptoRx.initial.push(BigInt(hdr?.offset ?? 0n), plaintext);
		if(!r.length) return;
		this.tlsRxBuffers.initial = Buffer.concat([this.tlsRxBuffers.initial, r]);
		const b = this.tlsRxBuffers.initial;
		let o = 0;
		while(o + 4 <= b.length) {
			const len = b.readUIntBE(o + 1, 3);
			if(o + 4 + len > b.length) break;
			const msg = Buffer.from(b.subarray(o, o + 4 + len));
			o += 4 + len;
			this.handleTLSInitial(msg, hdr);
		}
		this.tlsRxBuffers.initial = b.subarray(o).length ? Buffer.from(b.subarray(o)) : Buffer.alloc(0);
	}
	handleHandshakePayload(plaintext, offset = 0n) {
		const r = this.cryptoRx.handshake.push(BigInt(offset), plaintext);
		if(!r.length) return;
		this.tlsRxBuffers.handshake = Buffer.concat([this.tlsRxBuffers.handshake, r]);
		const b = this.tlsRxBuffers.handshake;
		let o = 0;
		while(o + 4 <= b.length) {
			const len = b.readUIntBE(o + 1, 3);
			if(o + 4 + len > b.length) break;
			const msg = Buffer.from(b.subarray(o, o + 4 + len));
			o += 4 + len;
			this.handleTLSHandshake(msg);
		}
		this.tlsRxBuffers.handshake = b.subarray(o).length ? Buffer.from(b.subarray(o)) : Buffer.alloc(0);
	}
	handleTLSInitial(msg, hdr) {
		if(this.isServer) {
			if(msg[0] !== tls.HS_CLIENT_HELLO) return;
			this.processClientHello(msg, hdr);
		} else {
			if(msg[0] !== tls.HS_SERVER_HELLO) return;
			this.processServerHello(msg, hdr);
		}
	}
	processClientHello(msg, hdr) {
		if(this.handshakeState !== 'idle' && this.handshakeState !== 'server_wait_ch') return;
		if(this.clientHello && Buffer.from(this.clientHello).equals(Buffer.from(msg))) return;
		if(hdr && hdr.dcid) this.initialDCID = Buffer.from(hdr.dcid);
		if(hdr && hdr.scid) {
			this.peerCID = Buffer.from(hdr.scid);
			this.peerConnectionIds.set(0n, {
				sequence: 0n,
				cid: Buffer.from(hdr.scid),
				token: null,
				retired: false
			});
			this.peerActiveCidSequence = 0n;
		}
		this.setInitialKeys();
		const ch = tls.parseClientHello(msg);
		this.diagnostics.tls.peer = clone({
			raw: ch.raw || msg,
			details: ch.details || null,
			fingerprint: ch.fingerprint || null
		});
		let clientTP;
		try {
			clientTP = validatePeerTransportParameters(tls.parseTransportParameters(ch.transportParameters), {
				isServer: true
			});
		} catch (err) {
			throw new QUICError('Invalid client transport parameters', {
				code: QUICError.ERR_PROTOCOL,
				cause: err
			});
		}
		this.diagnostics.quic.peerTransportParameters = clone(clientTP.details || clientTP);
		this.peerMaxActiveConnectionIdLimit = BigInt(clientTP[14] ?? 2n);
		if(clientTP[15] === undefined) throw new QUICError('Client initial_source_connection_id transport parameter is required', { code: QUICError.ERR_TRANSPORT_PARAMETER });
		if(!Buffer.from(clientTP[15]).equals(this.peerCID || Buffer.alloc(0))) throw new QUICError('initial_source_connection_id mismatch', {
			code: QUICError.ERR_PROTOCOL
		});
		if(ch.serverName) this.serverName = ch.serverName;
		this.peerTransportParameters = {
			idleTimeout: clientTP[1] !== undefined ? Number(clientTP[1]) : 30_000,
			maxUdpPayloadSize: clientTP[3] !== undefined ? Number(clientTP[3]) : 65527,
			maxData: clientTP[4],
			maxStreamData: clientTP[6] ?? 0n,
			maxStreamDataBidiLocal: clientTP[5] ?? 0n,
			maxStreamDataBidiRemote: clientTP[6] ?? 0n,
			maxStreamDataUni: clientTP[7] ?? 0n,
			maxStreams: clientTP[8],
			maxStreamsUni: clientTP[9],
			ackDelayExponent: clientTP[10] !== undefined ? Number(clientTP[10]) : 3,
			maxAckDelay: clientTP[11] !== undefined ? Number(clientTP[11]) : 25,
			maxDatagramFrameSize: clientTP[0x20] !== undefined ? clientTP[0x20] : 0n
		};
		this.remoteMaxDatagramFrameSize = BigInt(this.peerTransportParameters.maxDatagramFrameSize || 0n);
		this.touchIdle();
		this.flow.remoteMaxStreams = clientTP[8] ?? 0n;
		this.flow.remoteMaxStreamsUni = clientTP[9] ?? 0n;
		if(clientTP[4] !== undefined) this.flow.remoteMaxData = clientTP[4];
		this.flow.remoteMaxStreamDataBidiLocal = clientTP[5] ?? 0n;
		this.flow.remoteMaxStreamDataBidiRemote = clientTP[6] ?? 0n;
		this.flow.remoteMaxStreamDataUni = clientTP[7] ?? 0n;
		this.flow.remoteMaxStreamData = clientTP[6] ?? 0n;
		this.recovery.maxAckDelay = this.peerTransportParameters.maxAckDelay;
		const clientAlpn = Array.isArray(ch.alpn) ? ch.alpn : (ch.alpn ? [ch.alpn] : []);
		const localAlpn = Array.isArray(this.alpn) ? this.alpn : [this.alpn];
		const selectedALPN = localAlpn.find(x => clientAlpn.includes(x));
		if(!selectedALPN) throw new QUICError('ALPN negotiation failed', {
			code: QUICError.ERR_PROTOCOL
		});
		this.selectedALPN = selectedALPN;
		const usePsk = !this.noPsk && this.psk.length > 0 && !!ch.identity && !!ch.binder;
		if(this.noPsk && usePsk) throw new QUICError('PSK not accepted in certificate mode', {
			code: QUICError.ERR_PROTOCOL
		});
		if(!this.noPsk) {
			const early = crypto.createHash('sha256').update(Buffer.from([])).digest();
			const earlySecret = require('../crypto/hkdf').hkdfExtract(Buffer.alloc(32), this.psk);
			const binderKey = tls.deriveSecret(earlySecret, 'res binder', early);
			const expectedBinder = tls.computeFinished(binderKey, crypto.createHash('sha256').update(ch.truncatedClientHello).digest());
			if(!ch.binder || !crypto.timingSafeEqual(Buffer.from(ch.binder), Buffer.from(expectedBinder))) throw new QUICError('TLS PSK binder verification failed', {
				code: QUICError.ERR_PROTOCOL
			});
		}
		this.clientHello = msg;
		this.clientKeyShareRaw = ch.rawKeyShare;
		this.serverKeyShare = tls.generateX25519();
		const shared = crypto.diffieHellman({
			privateKey: this.serverKeyShare.privateKey,
			publicKey: tls.x25519Public(ch.rawKeyShare)
		});
		this.serverKeyShare.privateKey = null;
		this.serverHello = tls.buildServerHello({
			sessionId: ch.sessionId || Buffer.alloc(0),
			serverKeyShare: this.serverKeyShare,
			selectedPsk: !this.noPsk
		});
		this.diagnostics.tls.handshake = this.diagnostics.tls.handshake || {};
		this.diagnostics.tls.handshake.serverHello = clone({
			raw: this.serverHello,
			details: this.serverHello.details || null
		});
		const secrets = tls.tls13Secrets(this.noPsk ? Buffer.alloc(0) : this.psk, shared, this.clientHello, this.serverHello, Buffer.alloc(0));
		shared.fill(0);
		this.handshakeSecrets = secrets;
		this.diagnostics.crypto.handshake = this.exposeKeyMaterial ? {
			secrets: clone(secrets.details || secrets),
			tx: clone(derivePacketKeys(secrets.sHs, this.version).details),
			rx: clone(derivePacketKeys(secrets.cHs, this.version).details)
		} : { cipher: 'TLS_AES_128_GCM_SHA256', keyMaterialExposed: false };
		stripAttachedDetails(secrets, this.exposeKeyMaterial);
		this.keys.handshakeTx = this.derivePacketKeys(secrets.sHs);
		this.keys.handshakeRx = this.derivePacketKeys(secrets.cHs);
		const tp = tls.makeTransportParameters({
			originalDestinationConnectionId: this.originalDestinationConnectionId,
			retrySourceConnectionId: this.retrySourceConnectionId,
			initialSourceConnectionId: this.localCID,
			statelessResetToken: this.statelessResetManager ? this.activeConnectionIds.get(0n).token : undefined,
			activeConnectionIdLimit: this.transportParameters.activeConnectionIdLimit,
			maxData: this.transportParameters.maxData,
			maxUdpPayloadSize: this.transportParameters.maxUdpPayloadSize,
			idleTimeout: this.transportParameters.idleTimeout,
			ackDelayExponent: this.transportParameters.ackDelayExponent,
			maxAckDelay: this.transportParameters.maxAckDelay,
			disableActiveMigration: this.transportParameters.disableActiveMigration,
			maxStreamData: this.transportParameters.maxStreamData,
			maxStreamDataBidiLocal: this.transportParameters.maxStreamDataBidiLocal,
			maxStreamDataBidiRemote: this.transportParameters.maxStreamDataBidiRemote,
			maxStreamDataUni: this.transportParameters.maxStreamDataUni,
			maxStreams: this.transportParameters.maxStreams,
			maxStreamsUni: this.transportParameters.maxStreamsUni,
			maxDatagramFrameSize: this.transportParameters.maxDatagramFrameSize
		});
		this.diagnostics.quic.localTransportParameters = clone(tp.details || {
			raw: tp
		});
		this.ee = tls.buildEncryptedExtensions({
			alpn: selectedALPN,
			transportParameters: tp
		});
		this.serverFinished = null;
		this.serverCertificate = null;
		this.serverCertificateVerify = null;
		const handshakeParts = [this.ee];
		if(this.noPsk) {
			const certs = [this.cert, ...this.certChain];
			this.serverCertificate = tls.buildCertificate(certs);
			const certTranscript = tls.transcriptHash(this.clientHello, this.serverHello, ...handshakeParts, this.serverCertificate);
			const scheme = tls.selectSignatureScheme(this.privateKey, ch.signatureAlgorithms || []);
			const sig = tls.signCertificateVerify(this.privateKey, scheme, certTranscript);
			this.serverCertificateVerify = tls.buildCertificateVerify(scheme, sig);
			this.privateKey = null;
			handshakeParts.push(this.serverCertificate, this.serverCertificateVerify);
			this.serverSignatureScheme = scheme;
		}
		const beforeFinished = tls.transcriptHash(this.clientHello, this.serverHello, ...handshakeParts);
		this.serverFinished = tls.buildFinished(secrets.sHs, beforeFinished);
		handshakeParts.push(this.serverFinished);
		this.serverFlight = Buffer.concat(handshakeParts);
		const coalesceFlight = true;
		// Piggyback the Initial ACK on the server's already-required 1200-byte
		// Initial response. Sending a separate padded ACK-only Initial can consume
		// the server's 3x anti-amplification budget and starve the remaining flight.
		const initialAckRanges = this.spaces.initial.pendingAck ? this._ackRanges('initial') : [];
		const initialFrames = [];
		if(initialAckRanges.length) initialFrames.push(frame(FRAME_TYPE.ACK, {
			largestAcked: this.spaces.initial.largestRx,
			ackDelay: 0n,
			ranges: initialAckRanges
		}));
		initialFrames.push(frame(FRAME_TYPE.CRYPTO, {
			offset: 0n,
			data: this.serverHello
		}));
		this.sendFrames('initial', 'initial', initialFrames, { coalesceFlight });
		if(initialAckRanges.length) this.spaces.initial.pendingAck = false;
		const handshakeChunkSize = 700;
		for(let off = 0; off < this.serverFlight.length; off += handshakeChunkSize) {
			const chunk = this.serverFlight.subarray(off, Math.min(this.serverFlight.length, off + handshakeChunkSize));
			this.sendFrames('handshake', 'handshake', [frame(FRAME_TYPE.CRYPTO, {
				offset: BigInt(off),
				data: chunk
			})], {
				coalesceFlight
			});
		}
		this.handshakeState = 'server_wait_client_finished';
		this.readyState = 'handshaking';
	}
	processServerHello(msg, hdr) {
		if(this.handshakeState !== 'client_initial') return;
		this.serverHello = msg;
		const sh = tls.parseServerHello(msg);
		this.diagnostics.tls.peer = this.diagnostics.tls.peer || {};
		this.diagnostics.tls.peer.serverHello = clone({
			raw: sh.raw || msg,
			details: sh.details || null
		});
		if(hdr && hdr.scid) {
			this.peerCID = Buffer.from(hdr.scid);
			this.serverCID = Buffer.from(this.peerCID);
			this.peerConnectionIds.set(0n, {
				sequence: 0n,
				cid: Buffer.from(hdr.scid),
				token: null,
				retired: false
			});
			this.peerActiveCidSequence = 0n;
		}
		const shared = crypto.diffieHellman({
			privateKey: this.clientKeyShare.privateKey,
			publicKey: tls.x25519Public(sh.rawKeyShare)
		});
		if(this.clientHello?.keyShare) this.clientHello.keyShare.privateKey = null;
		if(this.clientKeyShare) this.clientKeyShare.privateKey = null;
		this.clientKeyShare = null;
		this.handshakeSecrets = tls.tls13Secrets(this.noPsk ? Buffer.alloc(0) : this.psk, shared, this.clientHello.message, msg, Buffer.alloc(0));
		shared.fill(0);
		this.keys.handshakeTx = this.derivePacketKeys(this.handshakeSecrets.cHs);
		this.keys.handshakeRx = this.derivePacketKeys(this.handshakeSecrets.sHs);
		this.diagnostics.crypto.handshake = this.exposeKeyMaterial ? {
			secrets: clone(this.handshakeSecrets.details || this.handshakeSecrets),
			tx: clone(this.keys.handshakeTx.details || this.keys.handshakeTx),
			rx: clone(this.keys.handshakeRx.details || this.keys.handshakeRx)
		} : { cipher: 'TLS_AES_128_GCM_SHA256', keyMaterialExposed: false };
		stripAttachedDetails(this.handshakeSecrets, this.exposeKeyMaterial);
		this.handshakeState = 'client_wait_server_flight';
	}
	handleTLSHandshake(msg) {
		if(this.isServer) {
			if(msg[0] !== tls.HS_FINISHED) return;
			const verify = tls.parseFinished(msg);
			const th = crypto.createHash('sha256').update(Buffer.concat([this.clientHello, this.serverHello, this.serverFlight])).digest();
			const exp = tls.computeFinished(this.handshakeSecrets.cHs, th);
			if(!crypto.timingSafeEqual(verify, exp)) throw new QUICError('TLS client Finished verification failed', {
				code: QUICError.ERR_PROTOCOL
			});
			const appHash = th;
			this.appSecrets.tx = tls.deriveSecret(this.handshakeSecrets.master, 's ap traffic', appHash);
			this.appSecrets.rx = tls.deriveSecret(this.handshakeSecrets.master, 'c ap traffic', appHash);
			this.keys.appTx = this.derivePacketKeys(this.appSecrets.tx);
			this.keys.appRx = this.derivePacketKeys(this.appSecrets.rx);
			this.diagnostics.crypto.application = this.exposeKeyMaterial ? {
				txSecret: Buffer.from(this.appSecrets.tx),
				rxSecret: Buffer.from(this.appSecrets.rx),
				tx: clone(this.keys.appTx.details || this.keys.appTx),
				rx: clone(this.keys.appRx.details || this.keys.appRx)
			} : { cipher: 'TLS_AES_128_GCM_SHA256', keyMaterialExposed: false };
			this.clearHandshakeSecrets();
			this.handshakeState = 'connected';
			this.readyState = 'open';
			this.clearHandshakeTimeout();
			this.issueConnectionIds();
			this.emit('ready', this);
			this.sendFrames('app', 'app', [frame(FRAME_TYPE.HANDSHAKE_DONE)]);
			return;
		}
		if(!this.serverFlightMessages) this.serverFlightMessages = [];
		this.serverFlightMessages.push(msg);
		if(msg[0] === tls.HS_ENCRYPTED_EXTENSIONS) {
			this.ee = msg;
			const ee = tls.parseEncryptedExtensions(msg);
			const offered = Array.isArray(this.alpn) ? this.alpn : [this.alpn];
			const peerAlpn = Array.isArray(ee.alpn) ? ee.alpn : (ee.alpn ? [ee.alpn] : []);
			if(peerAlpn.length !== 1 || !offered.includes(peerAlpn[0])) throw new QUICError('ALPN negotiation failed', {
				code: QUICError.ERR_PROTOCOL
			});
			this.selectedALPN = peerAlpn[0] || null;
			if(ee.transportParameters) {
				const tp = validatePeerTransportParameters(tls.parseTransportParameters(ee.transportParameters), {
					isServer: false
				});
				if(!tp[0] || !tp[15]) throw new QUICError('Server transport parameters missing authenticated connection IDs', {
					code: QUICError.ERR_TRANSPORT_PARAMETER
				});
				if(this.originalDestinationConnectionId && !Buffer.from(tp[0]).equals(this.originalDestinationConnectionId)) throw new QUICError('server original_destination_connection_id mismatch', {
					code: QUICError.ERR_PROTOCOL
				});
				if(tp[15] && this.peerCID && !Buffer.from(tp[15]).equals(this.peerCID)) throw new QUICError('server initial_source_connection_id mismatch', {
					code: QUICError.ERR_PROTOCOL
				});
				if (tp[2] !== undefined) {
					const resetToken = Buffer.from(tp[2]);
					if (resetToken.length !== 16) throw new QUICError('Invalid server stateless_reset_token', { code: QUICError.ERR_TRANSPORT_PARAMETER });
					this.peerResetTokens.set(Buffer.from(tp[15]).toString('hex'), resetToken);
					this.peerConnectionIds.set(0n, { sequence: 0n, cid: Buffer.from(tp[15]), token: resetToken, retired: false });
				}
				if(this.retrySourceConnectionId && (!tp[16] || !Buffer.from(tp[16]).equals(this.retrySourceConnectionId))) throw new QUICError('server retry_source_connection_id mismatch', {
					code: QUICError.ERR_PROTOCOL
				});
				if(!this.retrySourceConnectionId && tp[16]) throw new QUICError('Unexpected retry_source_connection_id without Retry', { code: QUICError.ERR_PROTOCOL });
				this.peerAdvertisedActiveConnectionIdLimit = BigInt(tp[14] ?? 2n);
				this.peerMaxActiveConnectionIdLimit = this.peerAdvertisedActiveConnectionIdLimit;
				this.peerTransportParameters = {
					idleTimeout: tp[1] !== undefined ? Number(tp[1]) : 30_000,
					maxUdpPayloadSize: tp[3] !== undefined ? Number(tp[3]) : 65527,
					maxData: tp[4],
					maxStreamData: tp[6] ?? 0n,
					maxStreamDataBidiLocal: tp[5] ?? 0n,
					maxStreamDataBidiRemote: tp[6] ?? 0n,
					maxStreamDataUni: tp[7] ?? 0n,
					maxStreams: tp[8],
					maxStreamsUni: tp[9],
					ackDelayExponent: tp[10] !== undefined ? Number(tp[10]) : 3,
					maxAckDelay: tp[11] !== undefined ? Number(tp[11]) : 25,
					maxDatagramFrameSize: tp[0x20] !== undefined ? tp[0x20] : 0n
				};
				this.remoteMaxDatagramFrameSize = BigInt(this.peerTransportParameters.maxDatagramFrameSize || 0n);
				this.touchIdle();
				if(tp[4] !== undefined) this.flow.remoteMaxData = tp[4];
				this.flow.remoteMaxStreamDataBidiLocal = tp[5] ?? 0n;
				this.flow.remoteMaxStreamDataBidiRemote = tp[6] ?? 0n;
				this.flow.remoteMaxStreamDataUni = tp[7] ?? 0n;
				this.flow.remoteMaxStreamData = tp[6] ?? 0n;
				this.flow.remoteMaxStreams = tp[8] ?? 0n;
				this.flow.remoteMaxStreamsUni = tp[9] ?? 0n;
				this.recovery.maxAckDelay = this.peerTransportParameters.maxAckDelay;
			}
			return;
		}
		if(msg[0] === tls.HS_CERTIFICATE) {
			this.serverCertificate = msg;
			return;
		}
		if(msg[0] === tls.HS_CERTIFICATE_VERIFY) {
			if(!this.serverCertificate) throw new QUICError('CertificateVerify before Certificate', {
				code: QUICError.ERR_PROTOCOL
			});
			const certs = tls.parseCertificate(this.serverCertificate);
			if(!certs.length) throw new QUICError('Empty server certificate', {
				code: QUICError.ERR_CRYPTO
			});
			const leaf = new crypto.X509Certificate(certs[0]);
			const ca = this.ca;
			const certificateValidation = tls.verifyCertificateChain(certs[0], certs.slice(1), {
				servername: this.serverName,
				ca,
				rejectUnauthorized: this.rejectUnauthorized
			});
			// Keep a deliberately small, non-secret certificate summary for client diagnostics.
			// Never copy DER, private key material, or handshake secrets into this summary.
			this.diagnostics.tls.peer = this.diagnostics.tls.peer || {};
			this.diagnostics.tls.peer.certificate = {
				servername: this.serverName || null,
				subject: leaf.subject || null,
				issuer: leaf.issuer || null,
				subjectAltName: leaf.subjectAltName || null,
				validFrom: leaf.validFrom || null,
				validTo: leaf.validTo || null,
				fingerprint256: leaf.fingerprint256 || null,
				serialNumber: leaf.serialNumber || null,
				hostnameMatched: true,
				trustValidated: this.rejectUnauthorized === true,
				chainLength: Array.isArray(certificateValidation?.chain) ? certificateValidation.chain.length : null
			};
			const cv = tls.parseCertificateVerify(msg);
			const offered = this.signatureAlgorithms || [tls.SIG_ECDSA_SECP256R1_SHA256, tls.SIG_RSA_PSS_RSAE_SHA256, tls.SIG_RSA_PSS_PSS_SHA256, tls.SIG_ED25519];
			if(!offered.includes(cv.scheme)) throw new QUICError('Server signature scheme not offered', {
				code: QUICError.ERR_CRYPTO
			});
			const transcript = tls.transcriptHash(this.clientHello.message, this.serverHello, this.ee, this.serverCertificate);
			if(!tls.verifyCertificateVerify(leaf.publicKey, cv.scheme, cv.signature, transcript, 'server')) throw new QUICError('CertificateVerify signature invalid', {
				code: QUICError.ERR_CRYPTO
			});
			this.serverCertificateVerify = msg;
			return;
		}
		if(msg[0] === tls.HS_FINISHED) {
			this.serverFinished = msg;
			const prior = [this.clientHello.message, this.serverHello, ...this.serverFlightMessages.filter(x => x !== msg)];
			const th = crypto.createHash('sha256').update(Buffer.concat(prior)).digest();
			const verify = tls.parseFinished(msg);
			const exp = tls.computeFinished(this.handshakeSecrets.sHs, th);
			if(!crypto.timingSafeEqual(verify, exp)) throw new QUICError('TLS server Finished verification failed', {
				code: QUICError.ERR_PROTOCOL
			});
			const sfHash = crypto.createHash('sha256').update(Buffer.concat([...prior, msg])).digest();
			this.appSecrets.tx = tls.deriveSecret(this.handshakeSecrets.master, 'c ap traffic', sfHash);
			this.appSecrets.rx = tls.deriveSecret(this.handshakeSecrets.master, 's ap traffic', sfHash);
			this.keys.appTx = this.derivePacketKeys(this.appSecrets.tx);
			this.keys.appRx = this.derivePacketKeys(this.appSecrets.rx);
			this.diagnostics.crypto.application = this.exposeKeyMaterial ? {
				txSecret: Buffer.from(this.appSecrets.tx),
				rxSecret: Buffer.from(this.appSecrets.rx),
				tx: clone(this.keys.appTx.details || this.keys.appTx),
				rx: clone(this.keys.appRx.details || this.keys.appRx)
			} : { cipher: 'TLS_AES_128_GCM_SHA256', keyMaterialExposed: false };
			const fin = tls.buildFinished(this.handshakeSecrets.cHs, sfHash);
			this.sendFrames('handshake', 'handshake', [frame(FRAME_TYPE.CRYPTO, {
				offset: 0n,
				data: fin
			})]);
			this.clearHandshakeSecrets();
			this.handshakeState = 'connected';
			this.readyState = 'open';
			this.clearHandshakeTimeout();
			this.issueConnectionIds();
			this.emit('ready', this);
			return;
		}
	}
	handleFrames(space, frames) {
		const s = this.spaces[space];
		for(const f of frames) {
			validateFrameContext(f, space);
			const t = Number(f.type);
			if(t === FRAME_TYPE.PADDING) continue;
			if((t === FRAME_TYPE.IMMEDIATE_ACK || t === FRAME_TYPE.ACK_FREQUENCY) && !this.ackFrequencyNegotiated) {
				throw new QUICError('ACK_FREQUENCY extension received without negotiated support', { code: QUICError.ERR_PROTOCOL, frameType: t });
			}
			if(t === FRAME_TYPE.IMMEDIATE_ACK) {
				// The packet was marked ACK-pending before its frames were dispatched.
				// Send promptly rather than waiting for the end-of-datagram flush.
				this.sendAck('app');
				continue;
			}
			if(t === FRAME_TYPE.ACK_FREQUENCY) {
				const sequenceNumber = BigInt(f.sequenceNumber);
				if(!this.peerAckFrequency || sequenceNumber > this.peerAckFrequency.sequenceNumber) {
					this.peerAckFrequency = {
						sequenceNumber,
						packetTolerance: BigInt(f.packetTolerance),
						maxAckDelay: BigInt(f.maxAckDelay),
						reorderingThreshold: BigInt(f.reorderingThreshold)
					};
					this.emit('ackFrequency', { ...this.peerAckFrequency });
				}
				// ACKs are currently sent more frequently than any requested tolerance.
				// The metadata is retained for applications; delayed-ACK scheduling is not yet implemented.
				continue;
			}
			if(t === FRAME_TYPE.ACK || t === FRAME_TYPE.ACK_ECN) {
				const exponent = space === 'app' ? Number(this.peerTransportParameters?.ackDelayExponent ?? 3) : 0;
				const maxDelay = space === 'app' ? Number(this.peerTransportParameters?.maxAckDelay ?? 25) : 0;
				const encodedDelay = BigInt(f.ackDelay ?? 0n);
				const safeExponent = Math.max(0, Math.min(20, Number.isInteger(exponent) ? exponent : 3));
				// QUIC ACK Delay is encoded in microseconds divided by 2^ack_delay_exponent.
				// Recovery stores RTTs in milliseconds, so scale back to milliseconds here.
				const delayMicros = encodedDelay << BigInt(safeExponent);
				const maxDelayMillis = Math.max(0, Number.isFinite(maxDelay) ? maxDelay : 25);
				const decodedDelay = Math.min(maxDelayMillis, Number(delayMicros) / 1000);
				this.recovery.onAck(space, {
					...f,
					ackDelay: decodedDelay,
					applyAckDelay: space === 'app' && this.handshakeState === 'connected'
				});
				continue;
			}
			if(t === FRAME_TYPE.NEW_TOKEN) {
				if(this.isServer) throw new QUICError('Client sent server-only NEW_TOKEN frame', { code: QUICError.ERR_PROTOCOL, frameType: t });
				const token = Buffer.from(f.token || []);
				if(!token.length) throw new QUICError('NEW_TOKEN token must not be empty', { code: QUICError.ERR_PROTOCOL, frameType: t });
				this.newToken = Buffer.from(token);
				this.emit('newToken', Buffer.from(token), this);
				continue;
			}
			if(t === FRAME_TYPE.CRYPTO) {
				if(space === 'initial') this.handleInitialPayload(f.data, {
					...(this.lastInitialHeader || {}),
					offset: f.offset ?? 0n
				});
				else this.handleHandshakePayload(f.data, f.offset ?? 0n);
				continue;
			}
			if(t >= FRAME_TYPE.STREAM_BASE && t <= 0x0f) {
				const id = BigInt(f.streamId);
				const localInitiated = this.flow.isLocalInitiated(id, this.isServer);
				const bidirectional = this.flow.isBidirectional(id);
				let st = this.streams.get(String(id));
				if(localInitiated) {
					if(!bidirectional) throw new QUICError('Peer sent STREAM data on a locally initiated unidirectional stream', { code: QUICError.ERR_STREAM_STATE });
					if((id >> 2n) >= this.flow.wireOpenedLocalBidi) throw new QUICError('Peer sent STREAM data before the locally initiated stream was opened on the wire', { code: QUICError.ERR_STREAM_STATE });
					if(!st) {
						st = this.flow.stream(id, true, { ...this.flow.streamLimits(id, this.isServer), maxBufferedBytes: this.maxStreamBufferBytes });
						this.streams.set(String(id), st);
					}
				} else {
					if(bidirectional) this.flow.checkNewRemoteStream(id, this.isServer);
					else this.flow.checkNewRemoteUni(id, this.isServer);
					if(!st) {
						st = this.flow.stream(id, true, {
							...this.flow.streamLimits(id, this.isServer),
							maxBufferedBytes: this.maxStreamBufferBytes
						});
						this.streams.set(String(id), st);
						this.flow.noteRemoteStream(id, this.isServer);
						if(!bidirectional) this.flow.noteRemoteUni(id, this.isServer);
					}
				}
				const before = st.recvHighestOffset;
				const delivered = st.receive(BigInt(f.offset || 0n), Buffer.from(f.data), !!f.fin);
				const delta = st.recvHighestOffset - before;
				if(delta > 0n) this.flow.noteReceived(delta);
				if(delivered.length) {
					this.emit('data', delivered, this, id);
					st.consume(BigInt(delivered.length));
					this.flow.consume(BigInt(delivered.length));
					const nextConn = this.flow.maybeMaxData();
					const nextStream = this.flow.maybeMaxStreamData(st);
					const updates = [];
					if(nextConn !== null) updates.push(frame(FRAME_TYPE.MAX_DATA, {
						maximumData: nextConn
					}));
					if(nextStream !== null) updates.push(frame(FRAME_TYPE.MAX_STREAM_DATA, {
						streamId: id,
						maximumStreamData: nextStream
					}));
					if(updates.length) {
						try {
							this.sendFrames('app', 'app', updates);
						} catch {}
					}
				}
				if(st.isReadableFinished()) this.emit('streamEnd', this, id);
				continue;
			}
			if(t === FRAME_TYPE.MAX_DATA) {
				const v = BigInt(f.maximumData);
				if(v <= this.flow.remoteMaxData) continue;
				this.flow.remoteMaxData = v;
				this.emit('flowControlUpdate', { scope: 'connection', maximumData: v });
				this.emit('writable', { reason: 'max-data' });
				continue;
			}
			if(t === FRAME_TYPE.STREAM_DATA_BLOCKED) {
				const id = BigInt(f.streamId);
				const localInitiated = this.flow.isLocalInitiated(id, this.isServer);
				const bidirectional = this.flow.isBidirectional(id);
				const key = String(id);
				let st = this.streams.get(key);
				// The peer cannot send STREAM_DATA_BLOCKED on a locally initiated
				// unidirectional stream: its direction only permits us to send.
				if(localInitiated) {
					if(!bidirectional) throw new QUICError('STREAM_DATA_BLOCKED for a locally initiated unidirectional send-only stream', { code: QUICError.ERR_STREAM_STATE });
					if((id >> 2n) >= this.flow.wireOpenedLocalBidi) throw new QUICError('STREAM_DATA_BLOCKED for a locally initiated stream that is not open on the wire', { code: QUICError.ERR_STREAM_STATE });
					if(!st) {
						st = this.flow.stream(id, true, { ...this.flow.streamLimits(id, this.isServer), maxBufferedBytes: this.maxStreamBufferBytes });
						this.streams.set(key, st);
					}
				} else {
					// this frame can create the receive side of a
					// peer-initiated stream, even when it arrives before STREAM data.
					if(bidirectional) this.flow.checkNewRemoteStream(id, this.isServer);
					else this.flow.checkNewRemoteUni(id, this.isServer);
					if(!st) {
						st = this.flow.stream(id, true, {
							...this.flow.streamLimits(id, this.isServer),
							maxBufferedBytes: this.maxStreamBufferBytes
						});
						this.streams.set(key, st);
						if(bidirectional) this.flow.noteRemoteStream(id, this.isServer);
						else this.flow.noteRemoteUni(id, this.isServer);
					}
				}
				this.emit('streamDataBlocked', {
					streamId: id,
					maximumStreamData: BigInt(f.maximumStreamData)
				});
				continue;
			}
			if(t === FRAME_TYPE.MAX_STREAM_DATA) {
				const id = BigInt(f.streamId);
				const localInitiated = this.flow.isLocalInitiated(id, this.isServer);
				const bidirectional = this.flow.isBidirectional(id);
				// MAX_STREAM_DATA is only useful where this endpoint can send data:
				// bidirectional streams, or a unidirectional stream initiated locally.
				if(!bidirectional && !localInitiated) throw new QUICError('MAX_STREAM_DATA for peer-initiated unidirectional receive-only stream', { code: QUICError.ERR_STREAM_STATE });
				const key = String(id);
				let st = this.streams.get(key);
				if(localInitiated) {
					const opened = bidirectional ? this.flow.wireOpenedLocalBidi : this.flow.wireOpenedLocalUni;
					if((id >> 2n) >= opened) throw new QUICError('MAX_STREAM_DATA for a locally initiated stream that is not open on the wire', { code: QUICError.ERR_STREAM_STATE });
					if(!st) {
						st = this.flow.stream(id, true, { ...this.flow.streamLimits(id, this.isServer), maxBufferedBytes: this.maxStreamBufferBytes });
						this.streams.set(key, st);
					}
				} else {
					// MAX_STREAM_DATA can open the sending part
					// of a peer-initiated bidirectional stream. It can arrive before
					// STREAM data when packets are reordered.
					this.flow.checkNewRemoteStream(id, this.isServer);
					if(!st) {
						st = this.flow.stream(id, true, {
							...this.flow.streamLimits(id, this.isServer),
							maxBufferedBytes: this.maxStreamBufferBytes
						});
						this.streams.set(key, st);
						this.flow.noteRemoteStream(id, this.isServer);
					}
				}
				const v = BigInt(f.maximumStreamData);
				if(v > st.sendMax) {
					st.sendMax = v;
					this.emit('flowControlUpdate', { scope: 'stream', streamId: id, maximumStreamData: v });
					this.emit('writable', { reason: 'max-stream-data', streamId: id });
				}
				continue;
			}
			if(t === FRAME_TYPE.MAX_STREAMS_UNI) {
				const v = BigInt(f.maximumStreams);
				if(v > this.flow.remoteMaxStreamsUni) this.flow.remoteMaxStreamsUni = v;
				continue;
			}
			if(t === FRAME_TYPE.MAX_STREAMS_BIDI) {
				const v = BigInt(f.maximumStreams);
				if(v > this.flow.remoteMaxStreams) this.flow.remoteMaxStreams = v;
				continue;
			}
			if(t === FRAME_TYPE.RESET_STREAM) {
				const id = BigInt(f.streamId);
				const local = this.flow.isLocalInitiated(id, this.isServer);
				const bidirectional = this.flow.isBidirectional(id);
				const existing = this.streams.get(String(id));
				if(local && !bidirectional) throw new QUICError('Peer sent RESET_STREAM on a locally initiated unidirectional stream', { code: QUICError.ERR_STREAM_STATE });
				if(local && (id >> 2n) >= this.flow.wireOpenedLocalBidi) throw new QUICError('RESET_STREAM for a locally initiated stream that is not open on the wire', { code: QUICError.ERR_STREAM_STATE });
				if(!local) {
					this.flow.checkNewRemoteStream(id, this.isServer);
					if((id & 2n) !== 0n) this.flow.checkNewRemoteUni(id, this.isServer);
					this.flow.noteRemoteStream(id, this.isServer);
					if((id & 2n) !== 0n) this.flow.noteRemoteUni(id, this.isServer);
				}
				const st = this.streams.get(String(id)) || this.flow.stream(id, true, {
					...this.flow.streamLimits(id, this.isServer),
					maxBufferedBytes: this.maxStreamBufferBytes
				});
				this.streams.set(String(id), st);
				if(st.recvFinalSize !== null && st.recvFinalSize !== BigInt(f.finalSize)) throw new QUICError('Conflicting RESET_STREAM final size', {
					code: QUICError.ERR_FINAL_SIZE
				});
				const finalSize = BigInt(f.finalSize);
				if(finalSize > st.recvMax) throw new QUICError('RESET_STREAM final size exceeds stream limit', {
					code: QUICError.ERR_FLOW_CONTROL
				});
				if(finalSize < st.recvHighestOffset) throw new QUICError('RESET_STREAM final size is smaller than previously received data', { code: QUICError.ERR_FINAL_SIZE });
				const finalDelta = finalSize - st.recvHighestOffset;
				if(finalDelta > 0n) this.flow.noteReceived(finalDelta);
				st.recvHighestOffset = finalSize;
				st.recvFinalSize = finalSize;
				st.recvOpened = true;
				st.resetReceived = true;
				this.emit('streamReset', f.errorCode, this, id);
				continue;
			}
			if(t === FRAME_TYPE.STOP_SENDING) {
				const id = BigInt(f.streamId);
				const localInitiated = this.flow.isLocalInitiated(id, this.isServer);
				const bidirectional = this.flow.isBidirectional(id);
				let st = this.streams.get(String(id));
				if(!bidirectional && !localInitiated) throw new QUICError('STOP_SENDING for peer-initiated unidirectional receive-only stream', { code: QUICError.ERR_STREAM_STATE });
				if(localInitiated) {
					const opened = bidirectional ? this.flow.wireOpenedLocalBidi : this.flow.wireOpenedLocalUni;
					if((id >> 2n) >= opened) throw new QUICError('STOP_SENDING for a locally initiated stream that is not open on the wire', { code: QUICError.ERR_STREAM_STATE });
					if(!st) {
						st = this.flow.stream(id, true, { ...this.flow.streamLimits(id, this.isServer), maxBufferedBytes: this.maxStreamBufferBytes });
						this.streams.set(String(id), st);
					}
				} else {
					// allows STOP_SENDING to open the
					// sending part of a peer-initiated bidirectional stream.
					this.flow.checkNewRemoteStream(id, this.isServer);
					if(!st) {
						st = this.flow.stream(id, true, {
							...this.flow.streamLimits(id, this.isServer),
							maxBufferedBytes: this.maxStreamBufferBytes
						});
						this.streams.set(String(id), st);
						this.flow.noteRemoteStream(id, this.isServer);
					}
				}
				st.stopped = true;
				// requires the sender to answer STOP_SENDING with RESET_STREAM
				// unless sending has already completed or a reset was already sent.
				if(!st.finSent && !st.resetSent) {
					this.sendFrames('app', 'app', [frame(FRAME_TYPE.RESET_STREAM, { streamId: id, errorCode: BigInt(f.errorCode), finalSize: st.sendOffset })]);
					st.sendOpened = true;
					st.resetSent = true;
				}
				this.emit('stopSending', f.errorCode, this, id);
				continue;
			}
			if(t === FRAME_TYPE.PATH_CHALLENGE) {
				try {
					this.sendFrames('app', 'app', [frame(FRAME_TYPE.PATH_RESPONSE, {
						data: f.data
					})], {
						probe: true,
						address: this._lastReceiveAddress
					});
				} catch {}
				continue;
			}
			if(t === FRAME_TYPE.PATH_RESPONSE) {
				this.path.response(f.data, this._lastReceiveAddress);
				continue;
			}
			if(t === FRAME_TYPE.NEW_CONNECTION_ID) {
				const seq = BigInt(f.sequence);
				const rp = BigInt(f.retirePriorTo || 0n);
				if(rp > seq) throw new QUICError('retire_prior_to exceeds sequence', { code: QUICError.ERR_PROTOCOL });
				const cid = Buffer.from(f.connectionId);
				const token = Buffer.from(f.statelessResetToken);
				if(seq === 0n) throw new QUICError('NEW_CONNECTION_ID sequence 0 duplicates initial_source_connection_id', { code: QUICError.ERR_PROTOCOL });
				if(cid.length < 1 || cid.length > 20 || token.length !== 16) throw new QUICError('Invalid NEW_CONNECTION_ID', { code: QUICError.ERR_PROTOCOL });
				const prior = this.peerConnectionIds.get(seq);
				let arrivedAlreadyRetired = false;
				if(prior) {
					if(!prior.cid.equals(cid) || !prior.token || !prior.token.equals(token)) throw new QUICError('Conflicting NEW_CONNECTION_ID', { code: QUICError.ERR_PROTOCOL });
				} else {
					for (const [otherSequence, existing] of this.peerConnectionIds) {
						if (otherSequence !== seq && existing.cid.equals(cid)) throw new QUICError('Connection ID reused with a different sequence number', { code: QUICError.ERR_PROTOCOL });
					}
					arrivedAlreadyRetired = seq < this.peerRetirePriorTo;
					this.peerConnectionIds.set(seq, { sequence: seq, cid, token, retired: arrivedAlreadyRetired });
					if (!arrivedAlreadyRetired) this.peerResetTokens.set(cid.toString('hex'), token);
				}
				if (arrivedAlreadyRetired && this.readyState === 'open') {
					this.sendFrames('app', 'app', [frame(FRAME_TYPE.RETIRE_CONNECTION_ID, { sequence: seq })]);
				} else {
					this._retirePeerIdsBefore(rp);
				}
				const activePeerCount = this._activePeerCids().length;
				if(BigInt(activePeerCount) > this.maxActiveConnectionIdLimit) throw new QUICError('Peer active connection ID limit exceeded', { code: QUICError.ERR_CONNECTION_ID_LIMIT });
				continue;
			}
			if(t === FRAME_TYPE.RETIRE_CONNECTION_ID) {
				const seq = BigInt(f.sequence);
				const issued = this.issuedConnectionIds.get(seq);
				if(!issued) throw new QUICError('RETIRE_CONNECTION_ID for an unissued sequence', { code: QUICError.ERR_PROTOCOL });
				if(issued.retired) continue;
				issued.retired = true;
				const active = this.activeConnectionIds.get(seq);
				if(active) {
					active.retired = true;
					this.activeConnectionIds.delete(seq);
				}
				this.issueConnectionIds(1);
				continue;
			}
			if(t === FRAME_TYPE.DATAGRAM || t === FRAME_TYPE.DATAGRAM_LEN) {
				const limit = BigInt(this.transportParameters.maxDatagramFrameSize || 0);
				if(limit <= 0n) throw new QUICError('DATAGRAM frame received without negotiated support', { code: QUICError.ERR_PROTOCOL });
				const wireSize = BigInt(encodeFrames([f]).length);
				if(wireSize > limit) throw new QUICError('DATAGRAM frame exceeds max_datagram_frame_size including frame overhead', { code: QUICError.ERR_PROTOCOL });
				this.qlog?.add('transport:datagram_received', {
					length: Buffer.from(f.data).length
				});
				this.emit('datagram', Buffer.from(f.data), this);
				continue;
			}
			if(t === FRAME_TYPE.HANDSHAKE_DONE) {
				if(this.isServer) throw new QUICError('Client sent server-only HANDSHAKE_DONE frame', { code: QUICError.ERR_PROTOCOL, frameType: t });
				this.handshakeConfirmed = true;
				if(this.readyState !== 'open') {
					this.readyState = 'open';
					this.emit('ready', this);
				}
				continue;
			}
			if(t === FRAME_TYPE.CONNECTION_CLOSE || t === FRAME_TYPE.APPLICATION_CLOSE) {
				this._receiveConnectionClose(Number(f.errorCode || 0), Buffer.from(f.reasonPhrase || '').toString());
				return;
			}
		}
	}
	_flushPendingAcks() {
		for(const space of ['initial', 'handshake', 'app']) {
			const s = this.spaces[space];
			if(!s?.pendingAck || s.largestRx < 0n) continue;
			// Until the client's address is validated, a separate server Initial ACK
			// would itself require a 1200-byte datagram. Leave it pending; the normal
			// ServerHello response piggybacks the first ACK, and later ACKs can wait
			// until an authenticated Handshake packet validates the path.
			if(space === 'initial' && this.isServer && !this.addressValidated) continue;
			try {
				this.sendAck(space);
			} catch {}
		}
	}
	_onMessage(msg, rinfo) {
		if(this.closed) return;
		const packet = Buffer.isBuffer(msg) ? msg : Buffer.from(msg || []);
		if(!packet.length) return;
		this.bytesRx += packet.length;
		if(rinfo) {
			const k = this._pathBytesKey(rinfo);
			const st = this.pathBytes.get(k) || {
				rx: 0,
				tx: 0,
				validated: this.path.isValidated(rinfo) || (this.addressValidated && this.path.isCurrent(rinfo))
			};
			st.rx += packet.length;
			this.pathBytes.set(k, st);
			this.path.failExpired();
		}
		let offset = 0;
		let processed = 0;
		this._processingDatagram = true;
		try {
			while(offset < packet.length && !this.closed) {
				const slice = packet.subarray(offset);
				let currentIsLong = !!(slice[0] & 0x80);
				let currentPacketLen = null;
				try {
					const first = slice[0];
					if(first & 0x80) {
						const h = parseLongHeaderUnprotected(slice);
						const packetLen = h.packetType === 'retry' || h.version === 0 ? slice.length : h.packetEnd;
						if(packetLen <= 0 || packetLen > slice.length) throw new QUICError('Invalid coalesced packet length', {
							code: QUICError.ERR_INVALID_PACKET
						});
						currentPacketLen = packetLen;
						const one = slice.subarray(0, packetLen);
						this._onPacket(one, rinfo, h);
						offset += packetLen;
						processed++;
						continue;
					}
					currentIsLong = false;
					this._onPacket(slice, rinfo, null);
					processed++;
					break;
				} catch (err) {
					// Header parsing and failed AEAD authentication happen before a peer is
					// authenticated. QUIC requires these packets to be discarded, not to
					// tear down a live connection (or crash an application).
					if(err?.authenticatedPacket === true) {
						this.emit('error', err);
						if(!this.closed) this.close(transportErrorCode(err), err.message || 'Authenticated packet protocol error');
					} else {
						this.qlog?.add('transport:packet_dropped', { reason: String(err?.message || 'unauthenticated packet error') });
					}
					// A valid long-header length lets us skip just the undecryptable packet
					// and continue processing any coalesced packets in the same UDP datagram.
					if(err?.authenticatedPacket !== true && currentIsLong && currentPacketLen !== null) {
						offset += currentPacketLen;
						processed++;
						continue;
					}
					break;
				}
			}
		} finally {
			this._processingDatagram = false;
			if(!this.closed) this._flushPendingAcks();
		}
		this.qlog?.add('transport:datagram_received', {
			length: packet.length,
			packets: processed
		});
	}
	_onPacket(msg, rinfo, parsedLong = null) {
		if(this.closed) return;
		let packetAuthenticated = false;
		let decryptedCidLength = null;
		try {
			const first = msg[0];
			if(first & 0x80) {
				const h = parsedLong || parseLongHeaderUnprotected(msg);
				if(h.packetType === 'retry' && !this.isServer) {
					// Retry integrity protects packet integrity, not sender identity: the public
					// key means CID binding and accepting at most one Retry are essential.
					if(this.retryReceived || h.version !== this.version || !this.originalDestinationConnectionId) return;
					let rp;
					try {
						rp = parseRetryPacket(msg);
					} catch {
						return;
					}
					if(!rp.dcid.equals(this.localCID) || !verifyRetryPacket(msg, this.originalDestinationConnectionId)) return;
					this.retryReceived = true;
					this.peerCID = Buffer.from(rp.scid);
					this.retryToken = Buffer.from(rp.token);
					this.retrySourceConnectionId = Buffer.from(rp.scid);
					this.initialDCID = Buffer.from(rp.scid);
					// Retry creates a new Initial protection context.
					// Discard the previous Initial packet-number/recovery/CRYPTO state so
					// the first Initial after Retry starts again at packet number zero.
					this.spaces.initial = new Space();
					this.cryptoRx.initial = new CryptoReassembler(this.cryptoRx.initial.maxBufferedBytes);
					this.cryptoTx.initial = 0;
					this.tlsRxBuffers.initial = Buffer.alloc(0);
					this.retransmitQueue.initial = [];
					const previousInitialSent = this.recovery.spaces.initial;
					for(const packet of previousInitialSent.sent.values()) {
						if(packet.inFlight) this.recovery.bytesInFlight = Math.max(0, this.recovery.bytesInFlight - packet.bytes);
						if(packet.timer) clearTimeout(packet.timer);
						packet.inFlight = false;
					}
					this.recovery.spaces.initial = { sent: new Map(), largestAcked: -1n, lossTime: 0, ptoTime: 0 };
					this.recovery._rearmTimer();
					this.setInitialKeys();
					this.clientHello = tls.buildClientHello({
						psk: this.psk,
						identity: this.identity,
						alpn: this.alpn,
						serverName: this.serverName,
						signatureAlgorithms: this.signatureAlgorithms,
						transportParameters: tls.makeTransportParameters({
							initialSourceConnectionId: this.localCID,
							activeConnectionIdLimit: this.transportParameters.activeConnectionIdLimit,
							maxData: this.transportParameters.maxData,
			maxUdpPayloadSize: this.transportParameters.maxUdpPayloadSize,
			idleTimeout: this.transportParameters.idleTimeout,
			ackDelayExponent: this.transportParameters.ackDelayExponent,
			maxAckDelay: this.transportParameters.maxAckDelay,
			disableActiveMigration: this.transportParameters.disableActiveMigration,
							maxStreamData: this.transportParameters.maxStreamData,
							maxStreamDataBidiLocal: this.transportParameters.maxStreamDataBidiLocal,
							maxStreamDataBidiRemote: this.transportParameters.maxStreamDataBidiRemote,
							maxStreamDataUni: this.transportParameters.maxStreamDataUni,
							maxStreams: this.transportParameters.maxStreams,
			maxStreamsUni: this.transportParameters.maxStreamsUni,
							maxDatagramFrameSize: this.transportParameters.maxDatagramFrameSize
						}),
						noPsk: this.noPsk
					});
					this.diagnostics.tls.local = clone({
						raw: this.clientHello.raw || this.clientHello.message,
						details: this.clientHello.details,
						fingerprint: this.clientHello.fingerprint
					});
					this.clientKeyShare = this.clientHello.keyShare;
					this.handshakeState = 'client_initial';
					this.sendFrames('initial', 'initial', [frame(FRAME_TYPE.CRYPTO, {
						offset: 0n,
						data: this.clientHello.message
					})]);
					return;
				}
				let space = h.packetType === 'initial' ? 'initial' : h.packetType === 'handshake' ? 'handshake' : null;
				if(!space) return;
				if(this.isServer && this.peerCID === null) this.peerCID = Buffer.from(h.scid);
				this.lastInitialHeader = h;
				if(!this.initialDCID) this.initialDCID = Buffer.from(h.dcid);
				if(space === 'initial' && !this.keys.initialRx) this.setInitialKeys();
				const keys = space === 'initial' ? this.keys.initialRx : this.keys.handshakeRx;
				if(!keys) return;
				const d = decryptLongPacket(msg, keys, this.spaces[space].largestRx);
				packetAuthenticated = true;
				if (this.isServer && space === 'handshake' && rinfo) {
					// Receipt of an authenticated Handshake packet proves reachability of this peer address.
					this.addressValidated = true;
					this.path.markValidated(rinfo, { makeCurrent: false });
				}
				if(d?.details && this.exposeKeyMaterial) {
					this.diagnostics.packets.lastRx = clone(d.details);
					this.diagnostics.crypto.lastAEAD = d.details.aead || this.diagnostics.crypto.lastAEAD;
					this.diagnostics.crypto.lastHeaderProtection = d.details.headerProtection || this.diagnostics.crypto.lastHeaderProtection;
				}
				this.touchIdle();
				if(rinfo) this._lastReceiveAddress = {
					address: rinfo.address,
					port: Number(rinfo.port)
				};
				if(this.isServer && space === 'initial' && this.retryToken) this.addressValidated = true;
				const s = this.spaces[space];
				// Packet numbers are not required to arrive in increasing order.
				// Track exact receipt history and discard only actual duplicates; using
				// largestRx as a replay filter incorrectly drops reordered CRYPTO data.
				if(!s.recordReceived(d.packetNumber)) return;
				const decodedLong = decodeFrames(d.plaintext).frames;
				if(decodedLong.some(f => {
						const t = Number(f.type);
						return t !== FRAME_TYPE.PADDING && t !== FRAME_TYPE.ACK && t !== FRAME_TYPE.ACK_ECN && t !== FRAME_TYPE.CONNECTION_CLOSE && t !== FRAME_TYPE.APPLICATION_CLOSE;
					})) s.pendingAck = true;
				if(space === 'initial' || space === 'handshake') this.touchIdle();
				this.handleFrames(space, decodedLong);
				return;
			}
			for(const token of this.peerResetTokens.values()) {
				if(this.statelessResetManager && this.statelessResetManager.matches(msg, token)) {
					this._receiveConnectionClose(0x1, 'stateless reset');
					return;
				}
				if(msg.length >= 21 && Buffer.from(msg.subarray(msg.length - 16)).equals(token)) {
					this._receiveConnectionClose(0x1, 'stateless reset');
					return;
				}
			}
			if(this.readyState !== 'open') return;
			if(!this.keys.appRx || !this.peerCID) return;
			let d;
			try {
				const cidLengths = [];
				for (const local of this._activeLocalCids()) {
					const cid = Buffer.from(local.cid);
					if (cid.length === 0) {
						if (!cidLengths.includes(0)) cidLengths.push(0);
					} else if (msg.length >= 1 + cid.length && msg.subarray(1, 1 + cid.length).equals(cid)) {
						if (!cidLengths.includes(cid.length)) cidLengths.push(cid.length);
					}
				}
				// Never try decrypting a short-header packet for a CID this endpoint has retired or never issued.
				if (!cidLengths.length) return;
				let firstErr = null;
				for(const len of cidLengths) {
					try {
						d = decryptShortPacket(msg, len, this.keys.appRx, this.spaces.app.largestRx);
						decryptedCidLength = len;
						packetAuthenticated = true;
						break;
					} catch (err) {
						firstErr = firstErr || err;
					}
				}
				if(!d) {
					if(this.rxKeyUpdates >= this.maxKeyUpdates || !this.appSecrets.rx) throw firstErr || new QUICError('Unable to decode application packet', {
						code: QUICError.ERR_CRYPTO
					});
					const nextSecret = stripAttachedDetails(deriveNextTrafficSecret(this.appSecrets.rx, this.version), this.exposeKeyMaterial);
					const nextKeys = this.derivePacketKeys(nextSecret);
					let next = null;
					for(const len of cidLengths) {
						try {
							next = decryptShortPacket(msg, len, nextKeys, this.spaces.app.largestRx);
							decryptedCidLength = len;
							packetAuthenticated = true;
							break;
						} catch {}
					}
					if(!next) throw firstErr || new QUICError('Unable to decode application packet', {
						code: QUICError.ERR_CRYPTO
					});
					this.appSecrets.rx = nextSecret;
					this.keys.appRx = nextKeys;
					this.rxKeyPhase = next.keyPhase ? 1 : 0;
					this.rxKeyUpdates++;
					d = next;
					this.diagnostics.crypto.keyUpdates.push(this.exposeKeyMaterial ? {
						direction: 'rx', phase: this.rxKeyPhase, secret: Buffer.from(nextSecret), keys: clone(nextKeys.details || nextKeys)
					} : { direction: 'rx', phase: this.rxKeyPhase, keyMaterialExposed: false });
					this.emit('keyUpdate', {
						direction: 'rx',
						phase: this.rxKeyPhase,
						count: this.rxKeyUpdates
					});
				}
				if((d.keyPhase ? 1 : 0) !== this.rxKeyPhase) {
					if(this.rxKeyUpdates >= this.maxKeyUpdates || !this.appSecrets.rx) throw new QUICError('Invalid application key phase', {
						code: QUICError.ERR_KEY_UPDATE
					});
					const nextSecret = stripAttachedDetails(deriveNextTrafficSecret(this.appSecrets.rx, this.version), this.exposeKeyMaterial);
					const nextKeys = this.derivePacketKeys(nextSecret);
					const next = decryptShortPacket(msg, decryptedCidLength ?? this.localCID.length, nextKeys, this.spaces.app.largestRx);
					packetAuthenticated = true;
					if(next.keyPhase === d.keyPhase) {
						this.appSecrets.rx = nextSecret;
						this.keys.appRx = nextKeys;
						this.rxKeyPhase = next.keyPhase ? 1 : 0;
						this.rxKeyUpdates++;
						d = next;
						this.diagnostics.crypto.keyUpdates.push(this.exposeKeyMaterial ? {
							direction: 'rx', phase: this.rxKeyPhase, secret: Buffer.from(nextSecret), keys: clone(nextKeys.details || nextKeys)
						} : { direction: 'rx', phase: this.rxKeyPhase, keyMaterialExposed: false });
						this.emit('keyUpdate', {
							direction: 'rx',
							phase: this.rxKeyPhase,
							count: this.rxKeyUpdates
						});
					}
				}
			} catch (err) {
				for(const token of this.peerResetTokens.values())
					if(msg.length >= 21 && Buffer.from(msg.subarray(msg.length - 16)).equals(token)) {
						this._receiveConnectionClose(0x1, 'stateless reset');
						return;
					}
				throw err;
			}
			if(d?.details && this.exposeKeyMaterial) {
				this.diagnostics.packets.lastRx = clone(d.details);
				this.diagnostics.crypto.lastAEAD = d.details.aead || this.diagnostics.crypto.lastAEAD;
				this.diagnostics.crypto.lastHeaderProtection = d.details.headerProtection || this.diagnostics.crypto.lastHeaderProtection;
			}
			this.touchIdle();
			if(rinfo) this._lastReceiveAddress = {
				address: rinfo.address,
				port: Number(rinfo.port)
			};
			const s = this.spaces.app;
			if(!s.recordReceived(d.packetNumber)) return;
			const decodedApp = decodeFrames(d.plaintext).frames;
			if(decodedApp.some(f => {
					const t = Number(f.type);
					return t !== FRAME_TYPE.PADDING && t !== FRAME_TYPE.ACK && t !== FRAME_TYPE.ACK_ECN && t !== FRAME_TYPE.CONNECTION_CLOSE && t !== FRAME_TYPE.APPLICATION_CLOSE;
				})) s.pendingAck = true;
			this.touchIdle();
			this.path.observe(rinfo);
			this.handleFrames('app', decodedApp);
		} catch (err) {
			if(packetAuthenticated && err && typeof err === 'object') err.authenticatedPacket = true;
			throw err;
		}
	}
	issueConnectionIds(count = 3) {
		count = Math.max(0, Math.min(7, Number(count) || 0));
		if(this.closed || !this.peerCID || this.readyState !== 'open' || this.peerCID.length === 0) return;
		const frames = [];
		while(frames.length < count && BigInt(this.activeConnectionIds.size) < BigInt(this.peerMaxActiveConnectionIdLimit)) {
			const seq = this.nextCidSequence++;
			let cid;
			let attempts = 0;
			do {
				cid = randomBytes(this.localCID.length || 8);
				attempts++;
			} while (attempts < 8 && [...this.issuedConnectionIds.values()].some(v => v.cid.equals(cid)));
			if ([...this.issuedConnectionIds.values()].some(v => v.cid.equals(cid))) throw new QUICError('Unable to allocate a unique connection ID', { code: QUICError.ERR_INTERNAL });
			const token = this.statelessResetManager ? this.statelessResetManager.token(cid) : randomBytes(16);
			const entry = { sequence: seq, cid: Buffer.from(cid), token: Buffer.from(token), retired: false };
			this.activeConnectionIds.set(seq, entry);
			this.issuedConnectionIds.set(seq, { ...entry, cid: Buffer.from(cid), token: Buffer.from(token) });
			frames.push(frame(FRAME_TYPE.NEW_CONNECTION_ID, {
				sequence: seq,
				retirePriorTo: 0n,
				connectionId: cid,
				statelessResetToken: token
			}));
		}
		if(frames.length) {
			try {
				this.sendFrames('app', 'app', frames);
			} catch (err) {
				for(const f of frames) {
					const seq = BigInt(f.sequence);
					this.activeConnectionIds.delete(seq);
					this.issuedConnectionIds.delete(seq);
				}
				throw err;
			}
		}
	}

	_getOrCreateLocalStream(id) {
		id = BigInt(id);
		let st = this.streams.get(String(id));
		if(st) return st;
		const local = this.flow.isLocalInitiated(id, this.isServer);
		if(!local) throw new QUICError('Cannot write to remotely initiated stream before creation', {
			code: QUICError.ERR_STREAM_LIMIT
		});
		this.flow.noteLocalStream(id, this.isServer, false);
		st = this.flow.stream(id, true, {
			...this.flow.streamLimits(id, this.isServer),
			maxBufferedBytes: this.maxStreamBufferBytes
		});
		this.streams.set(String(id), st);
		return st;
	}
	openUnidirectionalStream() {
		if(this.readyState !== 'open') throw new QUICError('Connection is not open', {
			code: QUICError.ERR_STATE
		});
		const id = this.flow.allocUni();
		const st = this.flow.stream(id, true, {
			...this.flow.streamLimits(id, this.isServer),
			maxBufferedBytes: this.maxStreamBufferBytes
		});
		this.streams.set(String(id), st);
		const conn = this;
		return {
			id,
			write(data) {
				conn.write(data, { streamId: id });
				return this;
			},
			writeAsync(data, opts = {}) {
				return conn.writeAsync(data, { ...opts, streamId: id }).then(() => this);
			},
			end(data = Buffer.alloc(0)) {
				if(data.length) conn.write(data, {
					streamId: id,
					fin: true
				});
				else conn.write(Buffer.alloc(0), { streamId: id, fin: true });
				return this;
			},
			endAsync(data = Buffer.alloc(0), opts = {}) {
				return conn.writeAsync(data, { ...opts, streamId: id, fin: true }).then(() => this);
			},
			reset(errorCode = 0) {
				conn.resetStream(id, errorCode);
				return this;
			}
		};
	}
	openStream() {
		if(this.readyState !== 'open') throw new QUICError('Connection is not open', {
			code: QUICError.ERR_STATE
		});
		const id = this.flow.allocBidi();
		const st = this._getOrCreateLocalStream(id);
		const conn = this;
		return {
			id,
			write(data) {
				conn.write(data, { streamId: id });
				return this;
			},
			writeAsync(data, opts = {}) {
				return conn.writeAsync(data, { ...opts, streamId: id }).then(() => this);
			},
			end(data = Buffer.alloc(0)) {
				if(data.length) conn.write(data, {
					streamId: id,
					fin: true
				});
				else conn.write(Buffer.alloc(0), { streamId: id, fin: true });
				return this;
			},
			endAsync(data = Buffer.alloc(0), opts = {}) {
				return conn.writeAsync(data, { ...opts, streamId: id, fin: true }).then(() => this);
			},
			reset(errorCode = 0) {
				conn.resetStream(id, errorCode);
				return this;
			},
			on(event, fn) {
				conn.on(`stream:${id}:${event}`, fn);
				return this;
			}
		};
	}
	write(data, opts = {}) {
		if(this.readyState !== 'open') throw new QUICError('Connection is not open', {
			code: QUICError.ERR_STATE
		});
		const b = Buffer.isBuffer(data) ? data : Buffer.from(data);
		const id = BigInt(opts.streamId ?? 0);
		const st = this._getOrCreateLocalStream(id);
		const off = opts.offset === undefined ? st.sendOffset : BigInt(opts.offset);
		const fin = !!opts.fin;
		const end = st.checkSend(off, b.length, fin);
		// Connection-level flow control counts the increase in this stream's
		// highest offset, not the number of bytes in each retransmitted/overlapping frame.
		const newBytes = end > st._highestSent ? end - st._highestSent : 0n;
		this.flow.checkSendData(this.flow.sentData, newBytes);
		const type = FRAME_TYPE.STREAM_BASE | STREAM_FRAME.LEN | (off !== 0n ? STREAM_FRAME.OFF : 0) | (fin ? STREAM_FRAME.FIN : 0);
		const pn = this.sendFrames('app', 'app', [frame(type, {
			streamId: id,
			offset: off,
			fin,
			data: b
		})]);
		st.noteSent(off, b.length, fin);
		if(this.flow.isLocalInitiated(id, this.isServer)) this.flow.noteLocalStream(id, this.isServer, true);
		if(newBytes > 0n) this.flow.noteSent(this.flow.sentData, newBytes);
		this.emit('streamWrite', id, b);
		return pn;
	}
	async writeAsync(data, opts = {}) {
		const id = BigInt(opts.streamId ?? 0);
		if(opts.offset !== undefined) throw new QUICError('writeAsync appends to the current stream offset; offset is not supported', { code: QUICError.ERR_INVALID_ARGUMENT });
		const key = String(id);
		if(!this._asyncWriteTails) this._asyncWriteTails = new Map();
		const previous = this._asyncWriteTails.get(key) || Promise.resolve();
		const task = previous.catch(() => {}).then(() => this._writeAsyncUnlocked(data, { ...opts, streamId: id }));
		this._asyncWriteTails.set(key, task);
		const clear = () => { if(this._asyncWriteTails.get(key) === task) this._asyncWriteTails.delete(key); };
		task.then(clear, clear);
		return task;
	}
	async _writeAsyncUnlocked(data, opts = {}) {
		if(this.readyState !== 'open' || this.closed) throw new QUICError('Connection is not open', { code: QUICError.ERR_STATE });
		const id = BigInt(opts.streamId ?? 0);
		const b = Buffer.isBuffer(data) ? Buffer.from(data) : Buffer.from(data, opts.encoding);
		const fin = !!opts.fin;
		const signal = opts.signal;
		if(signal !== undefined && (!signal || typeof signal.addEventListener !== 'function' || typeof signal.removeEventListener !== 'function' || typeof signal.aborted !== 'boolean')) {
			throw new QUICError('signal must be an AbortSignal', { code: QUICError.ERR_INVALID_ARGUMENT });
		}
		if(opts.timeout !== undefined && (!Number.isFinite(Number(opts.timeout)) || Number(opts.timeout) < 0)) {
			throw new QUICError('timeout must be a non-negative finite number', { code: QUICError.ERR_INVALID_ARGUMENT });
		}
		if(signal?.aborted) throw signal.reason || new QUICError('writeAsync was aborted', { code: QUICError.ERR_STATE });
		if(!b.length && !fin) return { streamId: id, bytesWritten: 0, packetsSent: 0, fin: false };
		const datagramSize = Math.max(256, Number(this.recovery?.maxDatagramSize ?? 1200));
		const safePayload = Math.max(1, datagramSize - 96); // reserve room for QUIC, STREAM-frame, CID, PN and AEAD overhead
		const requestedChunk = opts.maxChunkSize === undefined ? safePayload : Number(opts.maxChunkSize);
		if(!Number.isSafeInteger(requestedChunk) || requestedChunk < 1) throw new QUICError('maxChunkSize must be a positive safe integer', { code: QUICError.ERR_INVALID_ARGUMENT });
		const chunkSize = Math.min(requestedChunk, safePayload);
		const waitOpts = { signal, timeout: opts.timeout };
		const st = this._getOrCreateLocalStream(id);
		let written = 0;
		let packetsSent = 0;
		if(!b.length && fin) {
			while(true) {
				if(signal?.aborted) throw signal.reason || new QUICError('writeAsync was aborted', { code: QUICError.ERR_STATE });
				try { this.write(Buffer.alloc(0), { streamId: id, fin: true }); packetsSent++; break; }
				catch(err) {
					if(err?.code === QUICError.ERR_STATE && /Congestion window exhausted/.test(err.message)) { await this._waitForWriteSignal(id, 'congestion', waitOpts); continue; }
					throw err;
				}
			}
			return { streamId: id, bytesWritten: 0, packetsSent, fin: true };
		}
		while(written < b.length) {
			if(this.readyState !== 'open' || this.closed) throw new QUICError('Connection closed while writeAsync was waiting', { code: QUICError.ERR_CONNECTION_CLOSED });
			if(signal?.aborted) throw signal.reason || new QUICError('writeAsync was aborted', { code: QUICError.ERR_STATE });
			const offset = st.sendOffset;
			const streamCredit = st.sendMax > offset ? st.sendMax - offset : 0n;
			const connCredit = this.flow.remoteMaxData > this.flow.sentData ? this.flow.remoteMaxData - this.flow.sentData : 0n;
			const credit = streamCredit < connCredit ? streamCredit : connCredit;
			if(credit <= 0n) { await this._waitForWriteSignal(id, 'flow', waitOpts); continue; }
			const length = Math.min(chunkSize, b.length - written, Number(credit > BigInt(Number.MAX_SAFE_INTEGER) ? BigInt(Number.MAX_SAFE_INTEGER) : credit));
			if(length < 1) { await this._waitForWriteSignal(id, 'flow', waitOpts); continue; }
			const finalChunk = fin && written + length === b.length;
			if(this.pacer && opts.pacing !== false) {
				// Include conservative QUIC + STREAM framing/AEAD overhead in the pacing budget.
				await this.pacer.wait(Math.min(datagramSize, length + 96), { signal });
			}
			try {
				this.write(b.subarray(written, written + length), { streamId: id, fin: finalChunk });
				written += length;
				packetsSent++;
			} catch(err) {
				if(err?.code === QUICError.ERR_FLOW_CONTROL) { await this._waitForWriteSignal(id, 'flow', waitOpts); continue; }
				if(err?.code === QUICError.ERR_STATE && /Congestion window exhausted/.test(err.message)) { await this._waitForWriteSignal(id, 'congestion', waitOpts); continue; }
				throw err;
			}
		}
		return { streamId: id, bytesWritten: written, packetsSent, fin };
	}
	_waitForWriteSignal(streamId, reason, opts = {}) {
		if(this.closed || this.readyState !== 'open') return Promise.reject(new QUICError('Connection closed while writeAsync was waiting', { code: QUICError.ERR_CONNECTION_CLOSED }));
		const signal = opts.signal;
		if(signal?.aborted) return Promise.reject(signal.reason || new QUICError('writeAsync was aborted', { code: QUICError.ERR_STATE }));
		const timeout = opts.timeout === undefined ? 0 : Number(opts.timeout);
		if(!Number.isFinite(timeout) || timeout < 0) return Promise.reject(new QUICError('timeout must be a non-negative finite number', { code: QUICError.ERR_INVALID_ARGUMENT }));
		return new Promise((resolve, reject) => {
			let timer = null;
			const cleanup = () => {
				this.removeListener('writable', onWritable);
				this.removeListener('close', onClose);
				if(signal) signal.removeEventListener('abort', onAbort);
				if(timer) clearTimeout(timer);
			};
			const finish = (err) => { cleanup(); err ? reject(err) : resolve(); };
			const onWritable = () => finish();
			const onClose = () => finish(new QUICError('Connection closed while writeAsync was waiting', { code: QUICError.ERR_CONNECTION_CLOSED }));
			const onAbort = () => finish(signal.reason || new QUICError('writeAsync was aborted', { code: QUICError.ERR_STATE }));
			this.on('writable', onWritable);
			this.once('close', onClose);
			if(signal) signal.addEventListener('abort', onAbort, { once: true });
			if(timeout > 0) timer = setTimeout(() => finish(new QUICError('writeAsync timed out waiting for flow control or congestion window', { code: 'ETIMEDOUT' })), timeout);
		});
	}
	probePathMtu(address = this.address) {
		if(this.closed || this.readyState !== 'open' || !this.keys?.appTx) throw new QUICError('PMTU probing requires an open QUIC application connection', { code: QUICError.ERR_STATE });
		if(!address || !address.address || !Number.isInteger(Number(address.port))) throw new QUICError('A valid path address is required for PMTU probing', { code: QUICError.ERR_INVALID_ARGUMENT });
		const validated = this.path?.isValidated(address) || (this.addressValidated && this.path?.isCurrent(address));
		if(!validated) throw new QUICError('PMTU probing is not allowed on an unvalidated path', { code: QUICError.ERR_STATE });
		const candidate = this.pathMtu.startProbe(address);
		if(!candidate) return null;
		try {
			this.sendFrames('app', 'app', [frame(FRAME_TYPE.PING)], { address, pmtuProbeSize: candidate.size, pmtuProbeId: candidate.id });
			this.qlog?.add('transport:pmtu_probe_sent', { id: candidate.id, size: candidate.size });
			return candidate;
		} catch (err) {
			this.pathMtu.cancelProbe(candidate.id);
			throw err;
		}
	}
	getPathMtuState(address = this.address) {
		return this.pathMtu.snapshot(address);
	}
	sendDatagram(data) {
		if(this.readyState !== 'open') throw new QUICError('Connection is not open', {
			code: QUICError.ERR_STATE
		});
		const b = Buffer.isBuffer(data) ? Buffer.from(data) : Buffer.from(data);
		const limit = BigInt(this.remoteMaxDatagramFrameSize || 0);
		if(limit <= 0n) throw new QUICError('Peer did not negotiate DATAGRAM support', { code: QUICError.ERR_STATE });
		const outgoingFrame = frame(FRAME_TYPE.DATAGRAM_LEN, { data: b });
		const wireSize = BigInt(encodeFrames([outgoingFrame]).length);
		if(wireSize > limit) throw new QUICError('DATAGRAM frame exceeds peer max_datagram_frame_size including frame overhead', { code: QUICError.ERR_INVALID_LENGTH });
		this.sendFrames('app', 'app', [outgoingFrame]);
		this.qlog?.add('transport:datagram_sent', {
			length: b.length
		});
		return this;
	}
	stopSending(id, errorCode = 0) {
		if(this.readyState !== 'open') throw new QUICError('Connection is not open', { code: QUICError.ERR_STATE });
		id = BigInt(id);
		if(id < 0n || id > 0x3fffffffffffffffn) throw new QUICError('Invalid QUIC stream ID', { code: QUICError.ERR_INVALID_ARGUMENT });
		const key = String(id);
		const localInitiated = this.flow.isLocalInitiated(id, this.isServer);
		const bidirectional = this.flow.isBidirectional(id);
		if(localInitiated && !bidirectional) throw new QUICError('Cannot STOP_SENDING on a locally initiated unidirectional stream', { code: QUICError.ERR_STREAM_STATE });
		if(localInitiated) {
			if((id >> 2n) >= this.flow.wireOpenedLocalBidi) throw new QUICError('STOP_SENDING for a locally initiated stream that is not open on the wire', { code: QUICError.ERR_STREAM_STATE });
		} else {
			const opened = bidirectional ? this.flow.openedRemoteBidi : this.flow.openedRemoteUni;
			if((id >> 2n) >= opened) throw new QUICError('STOP_SENDING cannot open a peer-initiated stream that has not been opened', { code: QUICError.ERR_STREAM_STATE });
		}
		// A higher stream ID implicitly opens lower IDs of the same type. The
		// per-stream object can stay lazy, but STOP_SENDING on such a stream is
		// still valid and must not fail merely because its object was never made.
		let st = this.streams.get(key);
		if(!st) {
			st = this.flow.stream(id, true, {
				...this.flow.streamLimits(id, this.isServer),
				maxBufferedBytes: this.maxStreamBufferBytes
			});
			this.streams.set(key, st);
		}
		if(st.recvFinalSize !== null || st.resetReceived || st.stopSendingSent) return this;
		this.sendFrames('app', 'app', [frame(FRAME_TYPE.STOP_SENDING, { streamId: id, errorCode: BigInt(errorCode) })]);
		st.stopSendingSent = true;
		return this;
	}
	resetStream(id, errorCode = 0) {
		const st = this._getOrCreateLocalStream(BigInt(id));
		if(st.resetSent || st.finSent) return this;
		this.sendFrames('app', 'app', [frame(FRAME_TYPE.RESET_STREAM, {
			streamId: BigInt(id),
			errorCode: BigInt(errorCode),
			finalSize: st._highestSent
		})]);
		st.sendOpened = true;
		st.resetSent = true;
		if(this.flow.isLocalInitiated(BigInt(id), this.isServer)) this.flow.noteLocalStream(BigInt(id), this.isServer, true);
		return this;
	}
	updateKeys() {
		if(this.readyState !== 'open' || !this.appSecrets.tx) throw new QUICError('Application key update unavailable', {
			code: QUICError.ERR_STATE
		});
		if(this.txKeyUpdates >= this.maxKeyUpdates) throw new QUICError('Too many key updates', {
			code: QUICError.ERR_KEY_UPDATE
		});
		this.appSecrets.tx = stripAttachedDetails(deriveNextTrafficSecret(this.appSecrets.tx, this.version), this.exposeKeyMaterial);
		this.keys.appTx = this.derivePacketKeys(this.appSecrets.tx);
		this.diagnostics.crypto.keyUpdates.push(this.exposeKeyMaterial ? {
			direction: 'tx', phase: this.keyPhase, secret: Buffer.from(this.appSecrets.tx), keys: clone(this.keys.appTx.details || this.keys.appTx)
		} : { direction: 'tx', phase: this.keyPhase, keyMaterialExposed: false });
		this.keyPhase ^= 1;
		this.txKeyUpdates++;
		this.emit('keyUpdate', {
			direction: 'tx',
			phase: this.keyPhase,
			count: this.txKeyUpdates
		});
		return this.keyPhase;
	}
	sendProbe(space, packets) {
		if(this.closed) return;
		const candidates = Array.isArray(packets) ? packets.slice(0, 2) : [];
		const nonRetransmittable = new Set([FRAME_TYPE.PADDING, FRAME_TYPE.ACK, FRAME_TYPE.ACK_ECN, FRAME_TYPE.DATAGRAM, FRAME_TYPE.DATAGRAM_LEN]);
		// PTO sends two ack-eliciting probe packets. Re-send useful
		// frames from distinct outstanding packets where available; otherwise
		// send PING probes. DATAGRAM and ACK frames are never retransmitted.
		for(let i = 0; i < 2; i++) {
			const p = candidates[i];
			const probeFrames = p?.frames?.length
				? p.frames.filter(f => !nonRetransmittable.has(Number(f.type)))
				: [];
			const frames = probeFrames.length ? probeFrames : [frame(FRAME_TYPE.PING)];
			const packetType = p?.packetType || space;
			try {
				this.sendFrames(space, packetType, frames, { retransmit: Boolean(probeFrames.length), probe: true });
			} catch (err) {
				this.emit('probeError', err);
			}
		}
	}
	getDiagnostics() {
		return clone(this.diagnostics);
	}
	getFingerprint() {
		const local = this.diagnostics.tls.local || null;
		const peer = this.diagnostics.tls.peer || null;
		return {
			local: local ? {
				raw: local.raw ? Buffer.from(local.raw) : null,
				details: clone(local.details || null),
				ja3: local.fingerprint?.ja3 ? clone(local.fingerprint.ja3) : null
			} : null,
			peer: peer ? {
				raw: peer.raw ? Buffer.from(peer.raw) : null,
				details: clone(peer.details || null),
				ja3: peer.fingerprint?.ja3 ? clone(peer.fingerprint.ja3) : null,
				serverHello: clone(peer.serverHello || null)
			} : null
		};
	}
	enableQLog(options = {}) {
		if(!this.qlog) this.qlog = new QLog(options);
		return this.qlog;
	}
	getPath() {
		return this.path.current ? {
			...this.path.current
		} : null;
	}
	getPeerTransportParameters() {
		return this.peerTransportParameters ? {
			...this.peerTransportParameters
		} : null;
	}
	_receiveConnectionClose(code = 0, reason = '') {
		if(this.closed) return;
		this.closeReceived = true;
		this.closeCode = Number(code) || 0;
		this.closeReason = String(reason || '');
		clearTimeout(this.idleTimer);
		this.clearHandshakeTimeout();
		if(this.retryTimer) clearTimeout(this.retryTimer);
		this.path.close();
		this.pathMtu?.close();
		this.recovery.close();
		this.draining = true;
		this.closed = true;
		this.readyState = 'closed';
		this.zeroizeSecrets();
		this.emit('close', {
			code: this.closeCode,
			reason: this.closeReason,
			remote: true
		});
	}
	close(code = 0, reason = '') {
		if(this.closed) {
			// A remotely closed/draining connection may still be held by the application.
			// Re-run idempotent cleanup so retained references are sanitized as well.
			this.zeroizeSecrets();
			return;
		}
		this._flushHandshakeCoalesce();
		this._flushFlightCoalesce();
		code = Number(code);
		if(!Number.isSafeInteger(code) || code < 0 || code > 0x1fffffff) throw new QUICError('Invalid application/transport error code', {
			code: QUICError.ERR_INVALID_ARGUMENT
		});
		clearTimeout(this.idleTimer);
		this.clearHandshakeTimeout();
		if(this.retryTimer) clearTimeout(this.retryTimer);
		const safeReason = Buffer.from(String(reason)).subarray(0, 1024);
		try {
			if(!this.closeSent && !this.closeReceived && this.peerCID) {
				// Send CONNECTION_CLOSE at the highest encryption level whose keys are
				// available. A protocol error during Initial/Handshake must not be
				// silently reduced to a local timeout merely because 1-RTT keys do not exist.
				const space = this.keys.appTx ? 'app' : this.keys.handshakeTx ? 'handshake' : this.keys.initialTx ? 'initial' : null;
				if(space) {
					const f = frame(FRAME_TYPE.CONNECTION_CLOSE, {
						errorCode: BigInt(code),
						frameType: 0n,
						reasonPhrase: safeReason
					});
					this.closeSent = true;
					this.draining = true;
					this.sendFrames(space, space, [f]);
				}
			}
		} catch {}
		this.recovery.close();
		this.path.close();
		this.pathMtu?.close();
		this.closed = true;
		this.readyState = 'closed';
		this.zeroizeSecrets();
		this.emit('close', {
			code: Number(code) || 0,
			reason: String(reason || ''),
			remote: false
		});
	}
}

module.exports = {
	QUICConnection,
	CryptoReassembler,
	Space,
	PT
};

module.exports.default = module.exports;