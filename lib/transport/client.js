'use strict';

const net = require('node:net');
const dgram = require('node:dgram');
const { EventEmitter } = require('node:events');
const { randomBytes } = require('node:crypto');
const {QUIC_VERSION } = require('../constants');
const { normalizeVersions } = require('./version');
const { QUICConnection } = require('./connection');
const { Recovery } = require('./recovery');
const { parseVersionNegotiationPacket } = require('../packet/protection');

function lookup(host, port) {
	return new Promise((resolve, reject) => {
		const dns = require('node:dns');
		dns.lookup(host, {
			all: true,
			verbatim: true
		}, (err, addresses) => {
			if(err) return reject(err);
			const a = (addresses || []).find(x => x.family === 4) || addresses?.[0];
			if(!a) return reject(Object.assign(new Error('No address found'), {
				code: 'ENODATA'
			}));
			resolve({
				address: a.address,
				port,
				family: a.family
			});
		})
	})
}

function tcpProbe(host, port, timeout = 3000) {
	return new Promise(resolve => {
		const socket = net.connect({ host, port }, () => {
			socket.destroy();
			resolve({
				reachable: true,
				error: null
			})
		});
		socket.setTimeout(timeout, () => {
			socket.destroy();
			resolve({
				reachable: false,
				error: 'ETIMEDOUT'
			})
		});
		socket.once('error', err => {
			socket.destroy();
			resolve({
				reachable: false,
				error: err.code || err.message
			})
		})
	})
}

class QUICClient extends EventEmitter {
	constructor(options = {}) {
		super();
		this.on('error', () => {});
		this.host = options.host || '127.0.0.1';
		this.port = options.port ?? 4433;
		this.version = options.version ?? QUIC_VERSION.V1;
		this.supportedVersions = normalizeVersions(options.supportedVersions || [this.version, ...(this.version === QUIC_VERSION.V1 ? [QUIC_VERSION.V2] : [])]);
		this.psk = options.psk == null ? null : options.psk;
		this.noPsk = options.noPsk === undefined ? !this.psk : !!options.noPsk;
		if(!this.noPsk && !this.psk) throw new TypeError('PSK mode requires an explicit per-deployment psk; use noPsk: true for TLS certificate mode');
		this.identity = options.identity ?? 'xof';
		this.alpn = options.alpn ?? 'xof';
		this.servername = options.servername ?? this.host;
		this.ca = options.ca;
		this.rejectUnauthorized = options.rejectUnauthorized !== false;
		this.signatureAlgorithms = options.signatureAlgorithms;
		this.qlog = options.qlog || false;
		this.exposeKeyMaterial = options.exposeKeyMaterial === true;
		this.handshakeTimeout = Math.max(1000, Number(options.handshakeTimeout ?? 15000));
		this.autoCloseOnHandshakeTimeout = options.autoCloseOnHandshakeTimeout !== false;
		this.maxDatagramFrameSize = Number(options.maxDatagramFrameSize ?? 0);
		this.activeConnectionIdLimit = Number(options.activeConnectionIdLimit ?? 8);
		this.socket = dgram.createSocket(options.ipv6 ? 'udp6' : 'udp4');
		this.connection = null;
		this._bound = false;
		this.socket.on('error', e => this.emit('error', e));
		this.socket.on('close', () => this.emit('close'));
		this.socket.on('message', (msg, rinfo) => {
			if(!this.connection) return;
			if((msg[0] & 0x80) && msg.length >= 5 && msg.readUInt32BE(1) === 0) {
				try {
					const vn = parseVersionNegotiationPacket(msg);
					const conn = this.connection;
					// ignore spoofed/misbound VN packets and any VN list
					// containing the version we actually attempted.
					if(!vn.dcid.equals(conn.localCID) || !vn.scid.equals(conn.initialDCID || conn.peerCID)) return;
					if(vn.versions.includes(conn.version)) return;
					this.emit('versionNegotiation', vn);
					const next = this.supportedVersions.find(v => vn.versions.includes(v));
					if(next && next !== conn.version && conn.readyState !== 'open') this._restartVersion(next);
				} catch (e) {
					this.emit('error', e);
				}
				return;
			}
			this.connection._onMessage(msg, rinfo)
		});
	}
	async _restartVersion(version) {
		const old = this.connection;
		if(!old) return;
		old.clearHandshakeTimeout?.();
		if(old.idleTimer) clearTimeout(old.idleTimer);
		old.idleTimer = null;
		old.recovery?.close();
		this.version = version;
		old.version = version;
		old.handshakeState = 'idle';
		old.readyState = 'new';
		old.closed = false;
		old.keys = {
			initialTx: null,
			initialRx: null,
			handshakeTx: null,
			handshakeRx: null,
			appTx: null,
			appRx: null
		};
		old.spaces = {
			initial: new old.spaces.initial.constructor(),
			handshake: new old.spaces.handshake.constructor(),
			app: new old.spaces.app.constructor()
		};
		old.recovery = new Recovery(old, { maxDatagramSize: 1200, maxAckDelay: 25 });
		old.recovery.on('loss', () => old.emit('loss'));
		old.recovery.on('pto', event => old.emit('pto', event));
		old.retransmitQueue = { initial: [], handshake: [], app: [] };
		old.appSecrets = { tx: null, rx: null };
		old.handshakeSecrets = null;
		old.serverFlightMessages = null;
		old.keyPhase = 0;
		old.rxKeyPhase = 0;
		old.txKeyUpdates = 0;
		old.rxKeyUpdates = 0;
		old.cryptoRx = {
			initial: new old.cryptoRx.initial.constructor(),
			handshake: new old.cryptoRx.handshake.constructor()
		};
		old.cryptoTx = {
			initial: 0,
			handshake: 0
		};
		// A VN restart uses fresh CIDs so packets from the abandoned attempt cannot
		// be confused with the new version attempt.
		old.localCID = randomBytes(8);
		old.peerCID = randomBytes(8);
		old.initialDCID = Buffer.from(old.peerCID);
		old.originalDestinationConnectionId = Buffer.from(old.peerCID);
		old.originalServerCID = Buffer.from(old.peerCID);
		old.retrySourceConnectionId = null;
		old.retryReceived = false;
		old.retryToken = null;
		old.activeConnectionIds = new Map([[0n, { sequence: 0n, cid: Buffer.from(old.localCID), token: randomBytes(16), retired: false }]]);
		old.peerConnectionIds = new Map();
		old.start();
	}
	async connect(host = this.host, port = this.port) {
		let addr;
		try {
			addr = await lookup(host, port);
		} catch (cause) {
			const err = new(require('../errors').QUICError)('DNS lookup failed: ' + host, {
				code: require('../errors').QUICError.ERR_DNS,
				cause
			});
			err.diagnosis = {
				state: 'down',
				reason: 'DNS_FAILURE',
				host,
				port
			};
			throw err;
		}
		this.host = addr.address;
		this.port = addr.port;
		if(!this._bound) {
			await new Promise((resolve, reject) => {
				this.socket.bind(0, err => err ? reject(err) : resolve())
			});
			this._bound = true;
		}
		const dcid = randomBytes(8),
			scid = randomBytes(8);
		const c = new QUICConnection(this.socket, {
			isServer: false,
			version: this.version,
			supportedVersions: this.supportedVersions,
			psk: this.psk,
			identity: this.identity,
			alpn: this.alpn,
			serverName: this.servername,
			ca: this.ca,
			rejectUnauthorized: this.rejectUnauthorized,
			signatureAlgorithms: this.signatureAlgorithms,
			noPsk: this.noPsk,
			qlog: this.qlog,
			exposeKeyMaterial: this.exposeKeyMaterial,
			handshakeTimeout: this.handshakeTimeout,
			maxDatagramFrameSize: this.maxDatagramFrameSize,
			activeConnectionIdLimit: this.activeConnectionIdLimit,
			address: addr,
			localCID: scid,
			peerCID: dcid,
			initialDCID: dcid,
			managedSocket: true
		});
		this.connection = c;
		c.once('ready', () => this.emit('connect', c));
		c.once('timeout', async err => {
			err.diagnosis = {
				state: 'unknown',
				reason: 'QUIC_HANDSHAKE_TIMEOUT',
				host,
				port,
				udpReachable: false
			};
			try {
				const probe = await tcpProbe(host, port, Math.min(3000, this.handshakeTimeout));
				err.diagnosis.tcp443 = probe;
				if(probe.reachable) err.diagnosis = {
					...err.diagnosis,
					state: 'web-up-quic-unavailable'
				};
				else err.diagnosis = {
					...err.diagnosis,
					state: 'down-or-unreachable'
				};
			} catch {}
			this.emit('timeout', err);
			if(this.listenerCount('error')) this.emit('error', err);
			if(this.autoCloseOnHandshakeTimeout && this.connection === c) this.close();
		});
		c.on('data', (d, conn, sid) => this.emit('data', d, conn, sid));
		c.on('close', x => this.emit('connectionClose', x));
		c.on('error', e => this.emit('error', e));
		c.start();
		return c;
	}
	close() {
		try {
			if(this.connection) this.connection.close();
		} catch {}
		if(this.socket && this.socket.readyState !== 'closed') {
			try {
				this.socket.close();
			} catch {}
		}
	}
}

module.exports = {
	QUICClient
};

module.exports.default = module.exports;