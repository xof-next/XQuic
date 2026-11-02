'use strict';

const dgram = require('node:dgram');
const { EventEmitter } = require('node:events');
const { QUIC_VERSION } = require('../constants');
const { QUICConnection } = require('./connection');
const { buildRetryPacket, parseLongHeaderUnprotected, buildVersionNegotiationPacket } = require('../packet/protection');
const { RetryTokenManager } = require('./token');
const { StatelessResetManager } = require('./stateless-reset');
const { normalizeVersions, isSupportedVersion } = require('./version');
const { randomBytes } = require('node:crypto');

class QUICServer extends EventEmitter {
	constructor(options = {}) {
		super();
		this.host = options.host || '127.0.0.1';
		this.port = options.port ?? 4433;
		this.version = options.version ?? QUIC_VERSION.V1;
		this.supportedVersions = normalizeVersions(options.supportedVersions || [this.version, ...(this.version === QUIC_VERSION.V1 ? [QUIC_VERSION.V2] : [])]);
		this.psk = options.psk == null ? null : options.psk;
		this.noPsk = options.noPsk === undefined ? (!this.psk && !!(options.cert || options.key)) : !!options.noPsk;
		if(!this.noPsk && !this.psk) throw new TypeError('QUICServer requires an explicit per-deployment psk or noPsk: true with cert and key');
		if(this.noPsk && (!options.cert || !options.key)) throw new TypeError('Certificate mode requires both cert and key');
		this.cert = options.cert;
		this.key = options.key;
		this.certChain = options.certChain;
		this.identity = options.identity ?? 'xof';
		this.alpn = options.alpn ?? 'xof';
		this.requireRetry = !!options.requireRetry;
		this.qlog = options.qlog || false;
		this.exposeKeyMaterial = options.exposeKeyMaterial === true;
		this.handshakeTimeout = Math.max(1000, Number(options.handshakeTimeout ?? 15000));
		this.retryTokens = new RetryTokenManager(options.retrySecret || this.psk);
		this.statelessReset = new StatelessResetManager(options.statelessResetSecret || options.retrySecret || this.psk);
		this.maxDatagramFrameSize = Number(options.maxDatagramFrameSize ?? 0);
		this.activeConnectionIdLimit = Number(options.activeConnectionIdLimit ?? 8);
		this.ipv6 = !!options.ipv6;
		this.socket = dgram.createSocket(this.ipv6 ? 'udp6' : 'udp4');
		this.connections = new Map();
		this.socket.on('error', e => this.emit('error', e));
		this.socket.on('message', (msg, rinfo) => this._message(msg, rinfo));
		this.socket.on('close', () => this.emit('close'));
	}
	listen(port = this.port, host = this.host) {
		this.port = port;
		this.host = host;
		return new Promise((resolve, reject) => {
			const onErr = e => {
				this.socket.off('listening', onListen);
				reject(e)
			};
			const onListen = () => {
				this.socket.off('error', onErr);
				this.addressInfo = this.socket.address();
				this.emit('listening', this.addressInfo);
				resolve(this)
			};
			this.socket.once('listening', onListen);
			this.socket.once('error', onErr);
			this.socket.bind(port, host);
		});
	}
	_endpoint(rinfo) {
		return rinfo.address + ':' + rinfo.port;
	}
	_extractDcid(msg) {
		try {
			if(msg[0] & 0x80) {
				const dl = msg[5];
				if(msg.length >= 6 + dl) return Buffer.from(msg.subarray(6, 6 + dl));
			} else if(msg.length >= 9) return Buffer.from(msg.subarray(1, 9));
		} catch {}
		return Buffer.alloc(0);
	}
	_key(rinfo, dcid) {
		return this._endpoint(rinfo) + ':' + Buffer.from(dcid || '').toString('hex');
	}
	_sendVersionNegotiation(msg, rinfo) {
		try {
			const h = parseLongHeaderUnprotected(msg);
			const vn = buildVersionNegotiationPacket({
				dcid: h.scid,
				scid: h.dcid,
				versions: this.supportedVersions
			});
			this.socket.send(vn, rinfo.port, rinfo.address);
			this.emit('versionNegotiation', {
				address: rinfo,
				versions: this.supportedVersions
			});
		} catch (e) {
			this.emit('clientError', e);
		}
	}
	_sendStatelessReset(dcid, msg, rinfo) {
		if(!dcid.length || msg.length < 21) return;
		const reset = this.statelessReset.packet({
			length: Math.min(1200, Math.max(21, msg.length)),
			token: this.statelessReset.token(dcid)
		});
		try {
			this.socket.send(reset, rinfo.port, rinfo.address);
		} catch {}
	}
	_message(msg, rinfo) {
		if(!msg.length) return;
		const isLongHeader = !!(msg[0] & 0x80);
		const dcid = isLongHeader ? this._extractDcid(msg) : Buffer.alloc(0);
		const endpoint = this._endpoint(rinfo);
		if(isLongHeader) {
			let h;
			try {
				h = parseLongHeaderUnprotected(msg);
			} catch {
				return;
			}
			if(h.version === 0) return;
			if(!isSupportedVersion(h.version, this.supportedVersions)) {
				this._sendVersionNegotiation(msg, rinfo);
				return;
			}
		}
		if (!isLongHeader) {
			// A short header carries no DCID length. Route only by exact match against active local CIDs.
			let target = null;
			for (const candidate of this.connections.values()) {
				for (const entry of candidate._activeLocalCids()) {
					const cid = Buffer.from(entry.cid);
					if (cid.length && msg.length >= 1 + cid.length && msg.subarray(1, 1 + cid.length).equals(cid)) {
						target = candidate;
						break;
					}
				}
				if (target) break;
				const a = candidate.address || candidate._lastReceiveAddress;
				if (candidate.localCID?.length === 0 && a && a.address === rinfo.address && Number(a.port) === Number(rinfo.port)) {
					target = candidate;
					break;
				}
			}
			if (target) {
				target._onMessage(msg, rinfo);
				return;
			}
			// An otherwise-unroutable short packet may be a Stateless Reset for a live connection.
			if (msg.length >= 21) {
				const suffix = msg.subarray(msg.length - 16);
				for (const candidate of this.connections.values()) {
					for (const token of candidate.peerResetTokens.values()) {
						if (Buffer.from(token).equals(suffix)) {
							candidate._receiveConnectionClose(0x1, 'stateless reset');
							return;
						}
					}
			}
			}
			return;
		}
		let c = this.connections.get(this._key(rinfo, dcid));
		if(!c && !(msg[0] & 0x80)) {
			for(const v of this.connections.values()) {
				const a = v.address || v._lastReceiveAddress;
				if(v.peerCID && v.peerCID.length === 0 && a && a.address === rinfo.address && Number(a.port) === Number(rinfo.port)) {
					c = v;
					break;
				}
			}
		}
		if(!c) {
			for(const v of this.connections.values()) {
				const hasActiveLocalCid = v._activeLocalCids().some(entry => Buffer.from(entry.cid).equals(dcid));
				if(hasActiveLocalCid || (v.initialDCID && v.initialDCID.equals(dcid))) {
					c = v;
					break;
				}
			}
		}
		if(!c) {
			if(!(msg[0] & 0x80)) {
				this._sendStatelessReset(dcid, msg, rinfo);
				return;
			}
			let h;
			try {
				h = parseLongHeaderUnprotected(msg);
			} catch {
				return;
			}
			if(h.packetType !== 'initial') return;
			let validatedToken = null,
				originalDcid = h.dcid;
			if(this.requireRetry) {
				let token = Buffer.alloc(0),
					valid = false;
				try {
					let o = 5 + 1 + h.dcid.length + 1 + h.scid.length;
					const { decodeVarInt } = require('../codec/varint');
					const tv = decodeVarInt(msg, o);
					o = tv.offset;
					const n = Number(tv.value);
					token = Buffer.from(msg.subarray(o, o + n));
					valid = this.retryTokens.verify(token, {
						address: rinfo.address,
						port: rinfo.port,
						version: h.version
					});
					if(valid) {
						const d = this.retryTokens.decode(token);
						if(d) originalDcid = d.odcid;
					}
				} catch {}
				if(!valid) {
					const retryScid = randomBytes(8);
					const rt = this.retryTokens.issue({
						address: rinfo.address,
						port: rinfo.port,
						odcid: h.dcid,
						version: h.version
					});
					const retry = buildRetryPacket({
						version: h.version,
						dcid: h.scid,
						scid: retryScid,
						token: rt,
						originalDestinationConnectionId: h.dcid
					});
					if(retry.length <= Math.max(1200, msg.length * 3)) this.socket.send(retry, rinfo.port, rinfo.address);
					return;
				}
				validatedToken = token;
			}
			c = new QUICConnection(this.socket, {
				isServer: true,
				version: h.version,
				psk: this.psk,
				identity: this.identity,
				alpn: this.alpn,
				cert: this.cert,
				key: this.key,
				certChain: this.certChain,
				noPsk: this.noPsk,
				address: {
					address: rinfo.address,
					port: rinfo.port
				},
				localCID: randomBytes(8),
				managedSocket: true,
				retryToken: validatedToken,
				addressValidated: !!validatedToken,
				supportedVersions: this.supportedVersions,
				qlog: this.qlog,
				exposeKeyMaterial: this.exposeKeyMaterial,
				maxDatagramFrameSize: this.maxDatagramFrameSize,
				activeConnectionIdLimit: this.activeConnectionIdLimit,
				handshakeTimeout: this.handshakeTimeout,
				statelessResetSecret: this.statelessReset.secret,
				originalDestinationConnectionId: originalDcid
			});
			if(validatedToken) {
				const d = this.retryTokens.decode(validatedToken);
				c.originalDestinationConnectionId = d ? d.odcid : originalDcid;
				c.retrySourceConnectionId = h.dcid;
			}
			this.connections.set(this._key(rinfo, c.localCID), c);
			c.armHandshakeTimeout();
			c.once('ready', () => this.emit('connection', c));
			c.on('data', (data, conn, streamId) => this.emit('stream', data, conn, streamId));
			c.on('close', () => {
				for(const [k, v] of this.connections)
					if(v === c) this.connections.delete(k);
			});
			c.on('error', e => this.emit('clientError', e, c));
		} else {
			c._lastReceiveAddress = {
				address: rinfo.address,
				port: rinfo.port
			};
		}
		c._onMessage(msg, rinfo);
	}
	close() {
		return new Promise(resolve => {
			for(const c of this.connections.values()) c.close();
			this.connections.clear();
			if(this.socket) {
				try {
					this.socket.close(() => resolve())
				} catch {
					resolve()
				}
			} else resolve()
		})
	}
}

module.exports = {
	QUICServer
};

module.exports.default = module.exports;