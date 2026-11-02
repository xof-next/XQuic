'use strict';

const crypto = require('node:crypto');
const { hkdfExtract, hkdfExpandLabel } = require('./hkdf');
const { QUICError } = require('../errors');
const { attachDetails, computeJA3 } = require('./diagnostics');
const { validateLeafCertificate, validateIssuerCertificate, countNonSelfIssuedCAs } = require('./rfc-policy');

const HASH_LEN = 32;
const TLS_AES_128_GCM_SHA256 = 0x1301;
const GROUP_X25519 = 0x001d;
const EXT_SERVER_NAME = 0x0000;
const EXT_SUPPORTED_GROUPS = 0x000a;
const EXT_SIGNATURE_ALGORITHMS = 0x000d;
const EXT_ALPN = 0x0010;
const EXT_SUPPORTED_VERSIONS = 0x002b;
const EXT_PSK_MODES = 0x002d;
const EXT_KEY_SHARE = 0x0033;
const EXT_QUIC_TP = 0x0039;
const EXT_PRE_SHARED_KEY = 0x0029;
const HS_CLIENT_HELLO = 1;
const HS_SERVER_HELLO = 2;
const HS_ENCRYPTED_EXTENSIONS = 8;
const HS_CERTIFICATE = 11;
const HS_CERTIFICATE_VERIFY = 15;
const HS_FINISHED = 20;
const SIG_ECDSA_SECP256R1_SHA256 = 0x0403;
const SIG_ECDSA_SECP384R1_SHA384 = 0x0503;
const SIG_ECDSA_SECP521R1_SHA512 = 0x0603;
const SIG_RSA_PSS_RSAE_SHA256 = 0x0804;
const SIG_RSA_PSS_PSS_SHA256 = 0x0809;
const SIG_ED25519 = 0x0807;
const ZERO_HASH = crypto.createHash('sha256').update(Buffer.alloc(0)).digest();
const ZERO = Buffer.alloc(HASH_LEN);

function u16(n) {
	const b = Buffer.alloc(2);
	b.writeUInt16BE(Number(n));
	return b;
}

function u24(n) {
	const b = Buffer.alloc(3);
	b[0] = (Number(n) >>> 16) & 255;
	b[1] = (Number(n) >>> 8) & 255;
	b[2] = Number(n) & 255;
	return b;
}

function u32(n) {
	const b = Buffer.alloc(4);
	b.writeUInt32BE(Number(n) >>> 0);
	return b;
}

function vector8(x) {
	x = Buffer.from(x || []);
	if(x.length > 255) throw new RangeError('vector8 too long');
	return Buffer.concat([Buffer.from([x.length]), x]);
}

function vector16(x) {
	x = Buffer.from(x || []);
	if(x.length > 65535) throw new RangeError('vector16 too long');
	return Buffer.concat([u16(x.length), x]);
}

function vector24(x) {
	x = Buffer.from(x || []);
	if(x.length > 0xffffff) throw new RangeError('vector24 too long');
	return Buffer.concat([u24(x.length), x]);
}

function hs(type, body) {
	body = Buffer.from(body || []);
	return Buffer.concat([Buffer.from([type]), u24(body.length), body]);
}

function ext(type, data) {
	data = Buffer.from(data || []);
	return Buffer.concat([u16(type), u16(data.length), data]);
}

function deriveSecret(secret, label, transcript) {
	return hkdfExpandLabel(secret, label, Buffer.from(transcript || []), HASH_LEN);
}

function finishedKey(baseKey) {
	return hkdfExpandLabel(baseKey, 'finished', Buffer.alloc(0), HASH_LEN);
}

function transcriptHash(...messages) {
	return crypto.createHash('sha256').update(Buffer.concat(messages.map(Buffer.from))).digest();
}

function computeFinished(baseKey, transcript) {
	return crypto.createHmac('sha256', finishedKey(baseKey)).update(transcript).digest();
}

function uvar(v) {
	v = typeof v === 'bigint' ? v : BigInt(v);
	if(v < 0n || v > 0x3fffffffffffffffn) throw new QUICError('QUIC varint out of range', {
		code: QUICError.ERR_INVALID_ARGUMENT
	});
	if(v <= 63n) return Buffer.from([Number(v)]);
	if(v <= 16383n) return Buffer.from([0x40 | Number(v >> 8n), Number(v & 255n)]);
	if(v <= 1073741823n) {
		const b = Buffer.alloc(4);
		b.writeUInt32BE((0x80000000 | Number(v)) >>> 0);
		return b;
	}
	const b = Buffer.alloc(8);
	b.writeBigUInt64BE(0xc000000000000000n | v);
	return b;
}

function readVar(buf, offset) {
	if(offset >= buf.length) throw new QUICError('Truncated QUIC transport parameter', {
		code: QUICError.ERR_TRANSPORT_PARAMETER
	});
	const first = buf[offset],
		len = 1 << ((first >>> 6) & 3);
	if(offset + len > buf.length) throw new QUICError('Truncated QUIC transport parameter', {
		code: QUICError.ERR_TRANSPORT_PARAMETER
	});
	let value = BigInt(first & 0x3f);
	for(let i = 1; i < len; i++) value = (value << 8n) | BigInt(buf[offset + i]);
	return {
		value,
		offset: offset + len
	};
}

function makeTransportParameters({
	originalDestinationConnectionId,
	retrySourceConnectionId,
	maxData = 1048576,
	maxStreamData = 1048576,
	maxStreamDataBidiLocal = maxStreamData,
	maxStreamDataBidiRemote = maxStreamData,
	maxStreamDataUni = maxStreamData,
	maxStreams = 16,
	maxStreamsUni = 16,
	maxUdpPayloadSize = 65527,
	idleTimeout = 30_000,
	ackDelayExponent = 3,
	maxAckDelay = 25,
	activeConnectionIdLimit = 8,
	initialSourceConnectionId,
	statelessResetToken,
	disableActiveMigration = false,
	maxDatagramFrameSize = 0,
	enableWebTransport = false
} = {}) {
	const asBigInt = (value, name) => {
		try { return typeof value === 'bigint' ? value : BigInt(value); }
		catch { throw new QUICError('Invalid ' + name, { code: QUICError.ERR_TRANSPORT_PARAMETER }); }
	};
	const udpSize = asBigInt(maxUdpPayloadSize, 'max_udp_payload_size');
	const ackExponent = asBigInt(ackDelayExponent, 'ack_delay_exponent');
	const ackDelay = asBigInt(maxAckDelay, 'max_ack_delay');
	const cidLimit = asBigInt(activeConnectionIdLimit, 'active_connection_id_limit');
	if(udpSize < 1200n || udpSize > 65527n) throw new QUICError('max_udp_payload_size must be between 1200 and 65527', { code: QUICError.ERR_TRANSPORT_PARAMETER });
	if(ackExponent < 0n || ackExponent > 20n) throw new QUICError('ack_delay_exponent must be between 0 and 20', { code: QUICError.ERR_TRANSPORT_PARAMETER });
	if(ackDelay < 0n || ackDelay >= 16384n) throw new QUICError('max_ack_delay must be less than 16384', { code: QUICError.ERR_TRANSPORT_PARAMETER });
	if(cidLimit < 2n) throw new QUICError('active_connection_id_limit must be at least 2', { code: QUICError.ERR_TRANSPORT_PARAMETER });
	for(const [name, value] of [['original_destination_connection_id', originalDestinationConnectionId], ['retry_source_connection_id', retrySourceConnectionId], ['initial_source_connection_id', initialSourceConnectionId]]) {
		if(value != null && Buffer.from(value).length > 20) throw new QUICError(name + ' exceeds 20 bytes', { code: QUICError.ERR_TRANSPORT_PARAMETER });
	}
	if(statelessResetToken != null && Buffer.from(statelessResetToken).length !== 16) throw new QUICError('stateless_reset_token must be exactly 16 bytes', { code: QUICError.ERR_TRANSPORT_PARAMETER });
	const parts = [];
	const put = (id, val) => {
		const x = uvar(val);
		parts.push(Buffer.concat([uvar(id), uvar(x.length), x]));
	};
	const putBytes = (id, x) => {
		x = Buffer.from(x || []);
		parts.push(Buffer.concat([uvar(id), uvar(x.length), x]));
	};
	if(originalDestinationConnectionId) putBytes(0x00, originalDestinationConnectionId);
	if(statelessResetToken != null) putBytes(0x02, statelessResetToken);
	put(0x01, Math.max(0, Math.min(0x3fffffffffffffff, Math.floor(Number(idleTimeout)))));
	put(0x03, maxUdpPayloadSize);
	put(0x04, maxData);
	put(0x05, maxStreamDataBidiLocal);
	put(0x06, maxStreamDataBidiRemote);
	put(0x07, maxStreamDataUni);
	put(0x08, maxStreams);
	put(0x09, maxStreamsUni);
	put(0x0a, ackDelayExponent);
	put(0x0b, maxAckDelay);
	if(disableActiveMigration) parts.push(Buffer.from([0x0c, 0x00]));
	put(0x0e, activeConnectionIdLimit);
	if(initialSourceConnectionId) putBytes(0x0f, initialSourceConnectionId);
	if(retrySourceConnectionId) putBytes(0x10, retrySourceConnectionId);
	if(maxDatagramFrameSize > 0) put(0x20, maxDatagramFrameSize);
	if(enableWebTransport) put(0x2b, 1);
	const raw = Buffer.concat(parts);
	return attachDetails(raw, {
		raw: Buffer.from(raw),
		parameters: parts.map((part) => Buffer.from(part)),
		parameterCount: parts.length
	});
}

function parseTransportParameters(data) {
	const b = Buffer.from(data || []);
	let o = 0;
	const out = {
		raw: b,
	details: {
		raw: Buffer.from(b),
		parameters: []
	}
	};
	const seen = new Set();
	const integerIds = new Set([1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 32, 0x2b]);
	const bytesIds = new Set([0, 2, 12, 13, 15, 16, 17, 18, 19]);
	while(o < b.length) {
		const idv = readVar(b, o);
		o = idv.offset;
		const id = Number(idv.value);
		if(seen.has(id)) throw new QUICError('Duplicate transport parameter ' + id, {
			code: QUICError.ERR_TRANSPORT_PARAMETER
		});
		seen.add(id);
		const lv = readVar(b, o);
		o = lv.offset;
		const n = Number(lv.value);
		if(!Number.isSafeInteger(n) || o + n > b.length) throw new QUICError('Invalid transport parameter length', {
			code: QUICError.ERR_TRANSPORT_PARAMETER
		});
		const value = b.subarray(o, o + n);
		o += n;
		out.details.parameters.push({
		id,
		length: n,
		value: Buffer.from(value),
		raw: Buffer.concat([uvar(id), uvar(n), Buffer.from(value)])
	});
		if(integerIds.has(id)) {
			if(![1, 2, 4, 8].includes(n)) throw new QUICError('Invalid integer transport parameter', {
				code: QUICError.ERR_TRANSPORT_PARAMETER
			});
			const vv = readVar(value, 0);
			if(vv.offset !== value.length) throw new QUICError('Invalid integer transport parameter encoding', {
				code: QUICError.ERR_TRANSPORT_PARAMETER
			});
			out[id] = vv.value;
		} else if(bytesIds.has(id)) out[id] = Buffer.from(value);
		else {
			out.unknown = out.unknown || new Map();
			out.unknown.set(id, Buffer.from(value));
		}
	}
	if(out[3] !== undefined && (out[3] < 1200n || out[3] > 65527n)) throw new QUICError('Invalid max_udp_payload_size', {
		code: QUICError.ERR_TRANSPORT_PARAMETER
	});
	if(out[10] !== undefined && out[10] > 20n) throw new QUICError('Invalid ack_delay_exponent', {
		code: QUICError.ERR_TRANSPORT_PARAMETER
	});
	if(out[11] !== undefined && out[11] >= 16384n) throw new QUICError('Invalid max_ack_delay', {
		code: QUICError.ERR_TRANSPORT_PARAMETER
	});
	if(out[14] !== undefined && out[14] < 2n) throw new QUICError('active_connection_id_limit must be >= 2', {
		code: QUICError.ERR_TRANSPORT_PARAMETER
	});
	if(out[2] !== undefined && Buffer.from(out[2]).length !== 16) throw new QUICError('stateless_reset_token must be exactly 16 bytes', { code: QUICError.ERR_TRANSPORT_PARAMETER });
	for(const id of [0, 15, 16]) {
		if(out[id] !== undefined && Buffer.from(out[id]).length > 20) throw new QUICError('Connection ID transport parameter exceeds 20 bytes', { code: QUICError.ERR_TRANSPORT_PARAMETER });
	}
	if(out[12] !== undefined && Buffer.from(out[12]).length !== 0) throw new QUICError('disable_active_migration must be empty', { code: QUICError.ERR_TRANSPORT_PARAMETER });
	if(out[13] !== undefined && (Buffer.from(out[13]).length < 41 || Buffer.from(out[13]).length > 61)) throw new QUICError('Invalid preferred_address length', { code: QUICError.ERR_TRANSPORT_PARAMETER });
	return out;
}

function rawX25519Public(key) {
	const der = key.export({
		format: 'der',
		type: 'spki'
	});
	return Buffer.from(der.subarray(der.length - 32));
}

function x25519Public(raw) {
	const r = Buffer.from(raw);
	if(r.length !== 32) throw new Error('X25519 public key must be 32 bytes');
	return crypto.createPublicKey({
		key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), r]),
		format: 'der',
		type: 'spki'
	});
}

function generateX25519() {
	const kp = crypto.generateKeyPairSync('x25519');
	return {
		privateKey: kp.privateKey,
		publicKey: kp.publicKey,
		rawPublic: rawX25519Public(kp.publicKey)
	};
}

function normalizePsk(psk) {
	if(psk === undefined || psk === null) return Buffer.alloc(0);
	if(Buffer.isBuffer(psk)) return Buffer.from(psk);
	if(typeof psk === 'string') return Buffer.from(psk, 'utf8');
	throw new QUICError('PSK must be Buffer or string', {
		code: QUICError.ERR_INVALID_ARGUMENT
	});
}

function tls13Secrets(psk, shared, ch, sh, transcriptAfterServerFinished = null) {
	psk = normalizePsk(psk);
	const effectivePsk = psk.length ? psk : ZERO;
	const early = hkdfExtract(ZERO, effectivePsk);
	// normalizePsk() made a private working copy; discard it as soon as HKDF has consumed it.
	if(psk.length) psk.fill(0);
	const earlyBinder = deriveSecret(early, 'res binder', ZERO_HASH);
	const derivedEarly = deriveSecret(early, 'derived', ZERO_HASH);
	const handshake = hkdfExtract(derivedEarly, shared);
	const chsh = transcriptHash(ch, sh);
	const cHs = deriveSecret(handshake, 'c hs traffic', chsh);
	const sHs = deriveSecret(handshake, 's hs traffic', chsh);
	const derivedHs = deriveSecret(handshake, 'derived', ZERO_HASH);
	const master = hkdfExtract(derivedHs, ZERO);
	const result = {
		early,
		binder: earlyBinder,
		handshake,
		cHs,
		sHs,
		master,
		cApp: null,
		sApp: null
	};
	if(transcriptAfterServerFinished && Buffer.from(transcriptAfterServerFinished).length) {
		const appHash = crypto.createHash('sha256').update(Buffer.from(transcriptAfterServerFinished)).digest();
		result.cApp = deriveSecret(master, 'c ap traffic', appHash);
		result.sApp = deriveSecret(master, 's ap traffic', appHash);
	}
	result.details = {
		early: Buffer.from(early),
		binder: Buffer.from(earlyBinder),
		handshake: Buffer.from(handshake),
		cHs: Buffer.from(cHs),
		sHs: Buffer.from(sHs),
		master: Buffer.from(master),
		cApp: result.cApp ? Buffer.from(result.cApp) : null,
		sApp: result.sApp ? Buffer.from(result.sApp) : null,
		transcriptClientHello: Buffer.from(ch || []),
		transcriptServerHello: Buffer.from(sh || []),
		transcriptAfterServerFinished: Buffer.from(transcriptAfterServerFinished || [])
	};
	return result;
}

function tls13CertificateSecrets(shared, ch, sh, afterServerFinished) {
	return tls13Secrets(Buffer.alloc(0), shared, ch, sh, afterServerFinished);
}

function encodeServerName(name) {
	const host = Buffer.from(String(name), 'utf8');
	const entry = Buffer.concat([Buffer.from([0x00]), u16(host.length), host]);
	return vector16(entry);
}

function parseServerName(data) {
	const b = Buffer.from(data || []);
	if(b.length < 2) throw new Error('Bad server_name');
	const n = b.readUInt16BE(0);
	if(2 + n !== b.length) throw new Error('Bad server_name length');
	if(n < 3) return null;
	let o = 2;
	const type = b[o++];
	const l = b.readUInt16BE(o);
	o += 2;
	if(type !== 0 || o + l > b.length) return null;
	return b.subarray(o, o + l).toString('utf8');
}

function encodeSignatureAlgorithms(list) {
	const a = Buffer.alloc(list.length * 2);
	list.forEach((v, i) => a.writeUInt16BE(v, i * 2));
	return vector16(a);
}

function parseSignatureAlgorithms(data) {
	if(data.length < 2) throw new Error('Bad signature_algorithms');
	const n = data.readUInt16BE(0);
	if(n % 2 || n + 2 !== data.length) throw new Error('Bad signature_algorithms length');
	const out = [];
	for(let i = 0; i < n; i += 2) out.push(data.readUInt16BE(i + 2));
	return out;
}

function buildClientHello({ psk, identity = 'xof', alpn = 'h3', transportParameters, keyShare, serverName, signatureAlgorithms, noPsk = false } = {}) {
	psk = normalizePsk(psk);
	const usePsk = !noPsk && psk.length > 0;
	const ks = keyShare || generateX25519();
	const legacySession = Buffer.alloc(0);
	const random = crypto.randomBytes(32);
	const exts = [];
	if(serverName) exts.push(ext(EXT_SERVER_NAME, encodeServerName(serverName)));
	exts.push(ext(EXT_SUPPORTED_VERSIONS, Buffer.from([2, 0x03, 0x04])));
	exts.push(ext(EXT_SUPPORTED_GROUPS, encodeSignatureAlgorithms([GROUP_X25519])));
	exts.push(ext(EXT_KEY_SHARE, vector16(Buffer.concat([u16(GROUP_X25519), vector16(ks.rawPublic)]))));
	exts.push(ext(EXT_SIGNATURE_ALGORITHMS, encodeSignatureAlgorithms(signatureAlgorithms || [SIG_ECDSA_SECP256R1_SHA256, SIG_ECDSA_SECP384R1_SHA384, SIG_ECDSA_SECP521R1_SHA512, SIG_RSA_PSS_RSAE_SHA256, SIG_RSA_PSS_PSS_SHA256, SIG_ED25519])));
	if(alpn) {
		const protos = Array.isArray(alpn) ? alpn.map(String) : [String(alpn)];
		if(!protos.length || protos.some(x => !x || Buffer.byteLength(x) > 255)) throw new QUICError('Invalid ALPN list', {
			code: QUICError.ERR_INVALID_ARGUMENT
		});
		const encoded = Buffer.concat(protos.map(x => vector8(Buffer.from(x, 'ascii'))));
		exts.push(ext(EXT_ALPN, vector16(encoded)));
	}
	exts.push(ext(EXT_QUIC_TP, Buffer.from(transportParameters || Buffer.alloc(0))));
	if(usePsk) {
		exts.push(ext(EXT_PSK_MODES, Buffer.from([1, 1])));
		const id = Buffer.from(identity);
		const identities = Buffer.concat([vector16(id), u32(0)]);
		const binders = Buffer.concat([Buffer.from([32]), Buffer.alloc(32)]);
		const pskData = Buffer.concat([vector16(identities), vector16(binders)]);
		exts.push(ext(EXT_PRE_SHARED_KEY, pskData));
	}
	const body = Buffer.concat([Buffer.from([0x03, 0x03]), random, vector8(legacySession), vector16(u16(TLS_AES_128_GCM_SHA256)), Buffer.from([1, 0]), vector16(Buffer.concat(exts))]);
	const msg = hs(HS_CLIENT_HELLO, body);
	const buildDetails = (finalMessage, binderValue) => ({
		raw: Buffer.from(finalMessage),
		legacyVersion: 0x0303,
		random: Buffer.from(random),
		sessionId: Buffer.from(legacySession),
		cipherSuites: [TLS_AES_128_GCM_SHA256],
		compressionMethods: [0],
		extensions: exts.map((x) => ({
			type: x.readUInt16BE(0),
			length: x.readUInt16BE(2),
			data: Buffer.from(x.subarray(4)),
			raw: Buffer.from(x)
		})),
		supportedVersions: [0x0304],
		supportedGroups: [GROUP_X25519],
		signatureAlgorithms: [
			...(signatureAlgorithms || [
				SIG_ECDSA_SECP256R1_SHA256,
				SIG_ECDSA_SECP384R1_SHA384,
				SIG_ECDSA_SECP521R1_SHA512,
				SIG_RSA_PSS_RSAE_SHA256,
				SIG_RSA_PSS_PSS_SHA256,
				SIG_ED25519
			])
		],
		keyShares: [{ group: GROUP_X25519, keyExchange: Buffer.from(ks.rawPublic) }],
		serverName: serverName || null,
		alpn: Array.isArray(alpn) ? alpn.map(String) : alpn ? [String(alpn)] : [],
		transportParameters: Buffer.from(transportParameters || []),
		psk: usePsk ? { identity: Buffer.from(identity), binder: binderValue ? Buffer.from(binderValue) : null } : null
	});
	if(!usePsk) return {
		message: msg,
		keyShare: ks,
		binder: null,
		identity: null,
		raw: Buffer.from(msg),
		details: buildDetails(msg, null),
		fingerprint: {
			ja3: computeJA3({ version: 771, cipherSuites: [TLS_AES_128_GCM_SHA256], extensions: exts.map(x => x.readUInt16BE(0)), supportedGroups: [GROUP_X25519] })
		}
	};
	const binder = Buffer.alloc(32);
	const early = hkdfExtract(ZERO, psk);
	const binderKey = deriveSecret(early, 'res binder', ZERO_HASH);
	const full = Buffer.from(msg);
	const zeroStart = full.length - 32;
	const truncated = Buffer.from(full);
	truncated.fill(0, zeroStart);
	computeFinished(binderKey, crypto.createHash('sha256').update(truncated).digest()).copy(binder);
	binder.copy(full, zeroStart);
	const result = {
		message: full,
		keyShare: ks,
		binder: Buffer.from(binder),
		identity: Buffer.from(identity),
		raw: Buffer.from(full),
		details: buildDetails(full, binder),
		fingerprint: {
			ja3: computeJA3({ version: 771, cipherSuites: [TLS_AES_128_GCM_SHA256], extensions: exts.map(x => x.readUInt16BE(0)), supportedGroups: [GROUP_X25519] })
		}
	};
	// These are temporary PSK-derived values, not part of the returned ClientHello.
	psk.fill(0);
	early.fill(0);
	binderKey.fill(0);
	truncated.fill(0);
	return result;
}

function parseExtensions(buf) {
	const out = [];
	let o = 0;
	if(buf.length < 2) throw new QUICError('Malformed TLS extensions', {
		code: QUICError.ERR_PROTOCOL
	});
	const total = buf.readUInt16BE(o);
	o += 2;
	if(o + total !== buf.length) throw new QUICError('Malformed TLS extension block', {
		code: QUICError.ERR_PROTOCOL
	});
	const end = o + total;
	while(o < end) {
		if(o + 4 > end) throw new QUICError('Truncated TLS extension', {
			code: QUICError.ERR_PROTOCOL
		});
		const t = buf.readUInt16BE(o),
			l = buf.readUInt16BE(o + 2);
		o += 4;
		if(o + l > end) throw new QUICError('Truncated TLS extension data', {
			code: QUICError.ERR_PROTOCOL
		});
		out.push({
			type: t,
			data: Buffer.from(buf.subarray(o, o + l))
		});
		o += l;
	}
	return out;
}

function parseALPN(data) {
	const b = Buffer.from(data || []);
	if(b.length < 2) throw new Error('Bad ALPN');
	const total = b.readUInt16BE(0);
	if(total + 2 !== b.length) throw new Error('Bad ALPN length');
	let o = 2;
	const out = [];
	while(o < b.length) {
		const l = b[o++];
		if(l === 0 || o + l > b.length) throw new Error('Bad ALPN protocol');
		out.push(b.subarray(o, o + l).toString('ascii'));
		o += l;
	}
	if(!out.length) throw new Error('Empty ALPN');
	return out.length === 1 ? out[0] : out;
}

function parseClientHello(msg) {
	const b = Buffer.from(msg);
	if(b[0] !== HS_CLIENT_HELLO) throw new Error('Expected ClientHello');
	const len = b.readUIntBE(1, 3);
	if(len !== b.length - 4) throw new Error('ClientHello length mismatch');
	let o = 4;
	if(b.readUInt16BE(o) !== 0x0303) throw new Error('TLS legacy version mismatch');
	o += 2;
	const random = Buffer.from(b.subarray(o, o + 32));
	o += 32;
	const sidLen = b[o++];
	const sessionId = Buffer.from(b.subarray(o, o + sidLen));
	o += sidLen;
	const csLen = b.readUInt16BE(o);
	o += 2;
	const ciphers = [];
	for(let i = 0; i < csLen; i += 2) ciphers.push(b.readUInt16BE(o + i));
	o += csLen;
	const cmLen = b[o++];
	if(cmLen !== 1 || o >= b.length || b[o] !== 0) throw new Error('Invalid TLS compression methods');
	o += cmLen;
	const exts = parseExtensions(b.subarray(o));
	const get = t => exts.find(e => e.type === t);
	const pskIndex = exts.findIndex(e => e.type === EXT_PRE_SHARED_KEY);
	if(pskIndex >= 0 && pskIndex !== exts.length - 1) throw new Error('pre_shared_key extension must be last');
	const ks = get(EXT_KEY_SHARE),
		sv = get(EXT_SUPPORTED_VERSIONS),
		tp = get(EXT_QUIC_TP),
		alpn = get(EXT_ALPN),
		sn = get(EXT_SERVER_NAME),
		sig = get(EXT_SIGNATURE_ALGORITHMS),
		psk = get(EXT_PRE_SHARED_KEY);
	if(!ks || !sv || !tp) throw new Error('Missing required ClientHello extension');
	if(!Array.isArray(ciphers) || !ciphers.includes(TLS_AES_128_GCM_SHA256)) throw new Error('No supported TLS 1.3 cipher suite offered');
	if(sv.data.length < 3 || sv.data[0] < 2 || !((sv.data[1] === 0x03 && sv.data[2] === 0x04))) throw new Error('TLS 1.3 not offered');
	const kd = ks.data;
	if(kd.length < 2) throw new Error('Bad key_share');
	const kvLen = kd.readUInt16BE(0);
	let ko = 2,
		raw = null;
	while(ko < 2 + kvLen) {
		if(ko + 4 > kd.length) throw new Error('Truncated key_share');
		const g = kd.readUInt16BE(ko),
			l = kd.readUInt16BE(ko + 2);
		ko += 4;
		if(ko + l > kd.length) throw new Error('Truncated key_share');
		const x = kd.subarray(ko, ko + l);
		ko += l;
		if(g === GROUP_X25519) raw = Buffer.from(x);
	}
	if(!raw) throw new Error('No X25519 key share');
	let identity = null,
		binder = null,
		truncated = null;
	if(psk) {
		const pd = psk.data;
		if(pd.length < 2) throw new Error('Bad pre_shared_key');
		const idsLen = pd.readUInt16BE(0);
		let po = 2;
		if(po + idsLen + 2 > pd.length) throw new Error('Bad PSK identities');
		if(idsLen >= 2) {
			const il = pd.readUInt16BE(po);
			po += 2;
			if(po + il + 4 > pd.length) throw new Error('Bad PSK identity');
			identity = Buffer.from(pd.subarray(po, po + il));
			po += il;
			po += 4;
		}
		const bindersOffset = 2 + idsLen;
		if(bindersOffset + 2 > pd.length) throw new Error('Bad PSK binders');
		const blen = pd.readUInt16BE(bindersOffset);
		if(blen < 33 || bindersOffset + 2 + blen > pd.length) throw new Error('Invalid PSK binder');
		binder = Buffer.from(pd.subarray(bindersOffset + 3, bindersOffset + 3 + 32));
		truncated = Buffer.from(b);
		truncated.fill(0, truncated.length - 32);
	}
	const parsed = {
		random,
		sessionId,
		ciphers,
		rawKeyShare: raw,
		identity,
		binder,
		truncatedClientHello: truncated,
		alpn: alpn ? parseALPN(alpn.data) : null,
		serverName: sn ? parseServerName(sn.data) : null,
		signatureAlgorithms: sig ? parseSignatureAlgorithms(sig.data) : [],
		transportParameters: Buffer.from(tp.data),
		extensions: exts,
		raw: Buffer.from(b)
	};
	parsed.supportedGroups = (() => {
		const e = get(EXT_SUPPORTED_GROUPS);
		if(!e || e.data.length < 2) return [];
		const n = e.data.readUInt16BE(0);
		if(n + 2 > e.data.length || n % 2) return [];
		const a = [];
		for(let i = 0; i < n; i += 2) a.push(e.data.readUInt16BE(i + 2));
		return a;
	})();
	parsed.supportedVersions = (() => {
		if(!sv || sv.data.length < 1) return [];
		const n = sv.data[0];
		if(n % 2 || n + 1 > sv.data.length) return [];
		const a = [];
		for(let i = 0; i < n; i += 2) a.push(sv.data.readUInt16BE(i + 1));
		return a;
	})();
	parsed.keyShares = [{ group: GROUP_X25519, keyExchange: Buffer.from(raw) }];
	parsed.ecPointFormats = [];
	parsed.details = {
		raw: Buffer.from(b),
		legacyVersion: 0x0303,
		random: Buffer.from(random),
		sessionId: Buffer.from(sessionId),
		cipherSuites: [...ciphers],
		supportedGroups: [...parsed.supportedGroups],
		supportedVersions: [...parsed.supportedVersions],
		signatureAlgorithms: [...parsed.signatureAlgorithms],
		keyShares: parsed.keyShares.map(x => ({ group: x.group, keyExchange: Buffer.from(x.keyExchange) })),
		alpn: parsed.alpn,
		serverName: parsed.serverName,
		transportParameters: Buffer.from(parsed.transportParameters),
		extensions: exts.map(e => ({ type: e.type, length: e.data.length, data: Buffer.from(e.data) }))
	};
	parsed.fingerprint = {
		ja3: computeJA3({ version: 771, cipherSuites: ciphers, extensions: exts, supportedGroups: parsed.supportedGroups, ecPointFormats: parsed.ecPointFormats })
	};
	return parsed;
}

function buildServerHello({ sessionId = Buffer.alloc(0), serverKeyShare, selectedPsk = false }) {
	const extensions = [ext(EXT_SUPPORTED_VERSIONS, Buffer.from([0x03, 0x04])), ext(EXT_KEY_SHARE, Buffer.concat([u16(GROUP_X25519), vector16(serverKeyShare.rawPublic)]))];
	if(selectedPsk) extensions.push(ext(EXT_PRE_SHARED_KEY, u16(0)));
	const body = Buffer.concat([Buffer.from([0x03, 0x03]), crypto.randomBytes(32), vector8(sessionId), u16(TLS_AES_128_GCM_SHA256), Buffer.from([0]), vector16(Buffer.concat(extensions))]);
	const out = hs(HS_SERVER_HELLO, body);
	return attachDetails(out, {
		raw: Buffer.from(out),
		sessionId: Buffer.from(sessionId),
		cipherSuite: TLS_AES_128_GCM_SHA256,
		selectedPsk: !!selectedPsk,
		keyShare: Buffer.from(serverKeyShare.rawPublic),
		extensions: extensions.map(x => ({ type: x.readUInt16BE(0), length: x.readUInt16BE(2), data: Buffer.from(x.subarray(4)) }))
	});
}

function parseServerHello(msg) {
	const b = Buffer.from(msg);
	if(b[0] !== HS_SERVER_HELLO) throw new Error('Expected ServerHello');
	let o = 4;
	if(b.readUInt16BE(o) !== 0x0303) throw new Error('Bad ServerHello version');
	o += 2;
	const random = Buffer.from(b.subarray(o, o + 32));
	o += 32;
	const sl = b[o++];
	const sid = Buffer.from(b.subarray(o, o + sl));
	o += sl;
	const cs = b.readUInt16BE(o);
	o += 2;
	o++;
	const ex = parseExtensions(b.subarray(o));
	const k = ex.find(e => e.type === EXT_KEY_SHARE),
		p = ex.find(e => e.type === EXT_PRE_SHARED_KEY);
	if(cs !== TLS_AES_128_GCM_SHA256 || !k) throw new Error('Invalid ServerHello');
	const result = {
		random,
		sessionId: sid,
		rawKeyShare: Buffer.from(k.data.subarray(4)),
		selectedIdentity: p ? p.data.readUInt16BE(0) : null,
		raw: Buffer.from(b)
	};
	result.details = {
		raw: Buffer.from(b),
		random: Buffer.from(random),
		sessionId: Buffer.from(sid),
		cipherSuite: cs,
		extensions: ex.map(e => ({ type: e.type, length: e.data.length, data: Buffer.from(e.data) })),
		keyShare: Buffer.from(result.rawKeyShare),
		selectedIdentity: result.selectedIdentity
	};
	return result;
}

function buildEncryptedExtensions({ alpn = 'h3', transportParameters }) {
	const ex = [];
	if(alpn) {
		const p = Buffer.from(alpn);
		ex.push(ext(EXT_ALPN, vector16(Buffer.concat([vector8(p)]))));
	}
	ex.push(ext(EXT_QUIC_TP, transportParameters || Buffer.alloc(0)));
	const out = hs(HS_ENCRYPTED_EXTENSIONS, vector16(Buffer.concat(ex)));
	return attachDetails(out, {
		raw: Buffer.from(out),
		alpn: Array.isArray(alpn) ? alpn.map(String) : alpn ? [String(alpn)] : [],
		transportParameters: Buffer.from(transportParameters || []),
		extensions: ex.map(x => ({ type: x.readUInt16BE(0), length: x.readUInt16BE(2), data: Buffer.from(x.subarray(4)) }))
	});
}

function parseEncryptedExtensions(msg) {
	const b = Buffer.from(msg);
	if(b[0] !== HS_ENCRYPTED_EXTENSIONS) throw new Error('Expected EncryptedExtensions');
	const ex = parseExtensions(b.subarray(4));
	const a = ex.find(e => e.type === EXT_ALPN),
		tp = ex.find(e => e.type === EXT_QUIC_TP);
	const result = {
		alpn: a ? parseALPN(a.data) : null,
		transportParameters: tp ? Buffer.from(tp.data) : null,
		raw: Buffer.from(b)
	};
	result.details = {
		raw: Buffer.from(b),
		alpn: result.alpn,
		transportParameters: result.transportParameters ? Buffer.from(result.transportParameters) : null,
		extensions: ex.map(e => ({ type: e.type, length: e.data.length, data: Buffer.from(e.data) }))
	};
	return result;
}

function buildCertificate(certs) {
	const entries = [];
	for(const cert of certs) {
		let der;
		try {
			der = Buffer.from(new crypto.X509Certificate(cert).raw);
		} catch (cause) {
			throw new QUICError('Invalid X.509 certificate input', {
				code: QUICError.ERR_CRYPTO,
				cause
			});
		}
		entries.push(Buffer.concat([vector24(der), u16(0)]));
	}
	const out = hs(HS_CERTIFICATE, Buffer.concat([Buffer.from([0]), vector24(Buffer.concat(entries))]));
	return attachDetails(out, { raw: Buffer.from(out), certificateCount: entries.length });
}

function parseCertificate(msg) {
	const b = Buffer.from(msg);
	if(b[0] !== HS_CERTIFICATE) throw new Error('Expected Certificate');
	if(b.length < 5) throw new Error('Bad Certificate');
	const ctxLen = b[4];
	let o = 5 + ctxLen;
	if(o + 3 > b.length) throw new Error('Bad Certificate list');
	const total = b.readUIntBE(o, 3);
	o += 3;
	if(o + total !== b.length) throw new Error('Bad Certificate list length');
	const end = o + total;
	const certs = [];
	while(o < end) {
		if(o + 3 > end) throw new Error('Truncated certificate');
		const n = b.readUIntBE(o, 3);
		o += 3;
		if(o + n + 2 > end) throw new Error('Truncated certificate data');
		certs.push(Buffer.from(b.subarray(o, o + n)));
		o += n;
		const el = b.readUInt16BE(o);
		o += 2;
		if(o + el > end) throw new Error('Truncated certificate extensions');
		o += el;
	}
	return certs;
}

function certificatePublicKey(certPemOrDer) {
	return new crypto.X509Certificate(Buffer.isBuffer(certPemOrDer) ? certPemOrDer : certPemOrDer).publicKey;
}

function selectSignatureScheme(privateKey, offered = []) {
	const type = privateKey.asymmetricKeyType;
	if(type === 'ed25519' && offered.includes(SIG_ED25519)) return SIG_ED25519;
	if(type === 'ec' || type === 'id-ecPublicKey') {
		const curve = privateKey.asymmetricKeyDetails?.namedCurve;
		const scheme = curve === 'prime256v1' || curve === 'P-256'
			? SIG_ECDSA_SECP256R1_SHA256
			: curve === 'secp384r1' || curve === 'P-384'
				? SIG_ECDSA_SECP384R1_SHA384
				: curve === 'secp521r1' || curve === 'P-521'
					? SIG_ECDSA_SECP521R1_SHA512
					: null;
		if(scheme !== null && offered.includes(scheme)) return scheme;
	}
	if(type === 'rsa-pss') {
		if(offered.includes(SIG_RSA_PSS_PSS_SHA256)) return SIG_RSA_PSS_PSS_SHA256;
		if(offered.includes(SIG_RSA_PSS_RSAE_SHA256)) return SIG_RSA_PSS_RSAE_SHA256;
	}
	if(type === 'rsa' && offered.includes(SIG_RSA_PSS_RSAE_SHA256)) return SIG_RSA_PSS_RSAE_SHA256;
	if(type === 'rsa' && offered.includes(SIG_RSA_PSS_PSS_SHA256)) return SIG_RSA_PSS_PSS_SHA256;
	throw new QUICError('No mutually supported TLS 1.3 CertificateVerify signature scheme', {
		code: QUICError.ERR_CRYPTO
	});
}

function certificateVerifyInput(side, transcript) {
	const prefix = side === 'server' ? 'TLS 1.3, server CertificateVerify' : 'TLS 1.3, client CertificateVerify';
	return Buffer.concat([Buffer.alloc(64, 0x20), Buffer.from(prefix, 'ascii'), Buffer.from([0]), Buffer.from(transcript)]);
}

function signCertificateVerify(privateKey, scheme, transcript) {
	const input = certificateVerifyInput('server', transcript);
	if(scheme === SIG_ED25519) return crypto.sign(null, input, privateKey);
	if(scheme === SIG_ECDSA_SECP256R1_SHA256) return crypto.sign('sha256', input, privateKey);
	if(scheme === SIG_ECDSA_SECP384R1_SHA384) return crypto.sign('sha384', input, privateKey);
	if(scheme === SIG_ECDSA_SECP521R1_SHA512) return crypto.sign('sha512', input, privateKey);
	if(scheme === SIG_RSA_PSS_RSAE_SHA256 || scheme === SIG_RSA_PSS_PSS_SHA256) return crypto.sign('sha256', input, {
		key: privateKey,
		padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
		saltLength: 32
	});
	throw new Error('Unsupported signature scheme');
}

function buildCertificateVerify(scheme, signature) {
	const out = hs(HS_CERTIFICATE_VERIFY, Buffer.concat([u16(scheme), vector16(signature)]));
	return attachDetails(out, { raw: Buffer.from(out), scheme, signature: Buffer.from(signature) });
}

function parseCertificateVerify(msg) {
	const b = Buffer.from(msg);
	if(b[0] !== HS_CERTIFICATE_VERIFY || b.length < 8) throw new Error('Invalid CertificateVerify');
	const scheme = b.readUInt16BE(4),
		n = b.readUInt16BE(6);
	if(8 + n !== b.length) throw new Error('Invalid CertificateVerify length');
	const result = {
		scheme,
		signature: Buffer.from(b.subarray(8)),
		raw: Buffer.from(b)
	};
	result.details = { raw: Buffer.from(b), scheme, signature: Buffer.from(result.signature) };
	return result;
}

function verifyCertificateVerify(publicKey, scheme, signature, transcript, side = 'server') {
	const input = certificateVerifyInput(side, transcript);
	if(scheme === SIG_ED25519) return crypto.verify(null, input, publicKey, signature);
	if(scheme === SIG_ECDSA_SECP256R1_SHA256) return crypto.verify('sha256', input, publicKey, signature);
	if(scheme === SIG_ECDSA_SECP384R1_SHA384) return crypto.verify('sha384', input, publicKey, signature);
	if(scheme === SIG_ECDSA_SECP521R1_SHA512) return crypto.verify('sha512', input, publicKey, signature);
	if(scheme === SIG_RSA_PSS_RSAE_SHA256 || scheme === SIG_RSA_PSS_PSS_SHA256) return crypto.verify('sha256', input, {
		key: publicKey,
		padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
		saltLength: 32
	}, signature);
	return false;
}

function buildFinished(baseKey, transcript) {
	const verifyData = computeFinished(baseKey, transcript);
	const out = hs(HS_FINISHED, verifyData);
	return attachDetails(out, { raw: Buffer.from(out), verifyData: Buffer.from(verifyData) });
}

function parseFinished(msg) {
	if(msg[0] !== HS_FINISHED || msg.length !== 36) throw new Error('Invalid Finished');
	const out = Buffer.from(msg.subarray(4));
	return attachDetails(out, { raw: Buffer.from(msg), verifyData: Buffer.from(out) });
}

function splitCertificates(value) {
	if(value === undefined || value === null) return [];
	if(Array.isArray(value)) return value.flatMap(splitCertificates);
	if(Buffer.isBuffer(value)) {
		const text = value.toString('utf8');
		if(text.includes('-----BEGIN CERTIFICATE-----')) return splitCertificates(text);
		return [Buffer.from(value)];
	}
	if(typeof value === 'string') {
		if(require('node:fs').existsSync(value)) {
			try {
				return splitCertificates(require('node:fs').readFileSync(value));
			} catch {}
		}
		if(value.includes('-----BEGIN CERTIFICATE-----')) {
			return value.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
		}
		return [value];
	}
	return [value];
}

let DEFAULT_CA_CACHE = null;
let DEFAULT_TRUST_ANCHORS = null;

function certificateObjects(values) {
	const out = [];
	for(const value of splitCertificates(values)) {
		try {
			out.push(new crypto.X509Certificate(value));
		} catch (cause) {
			throw new QUICError('Invalid X.509 certificate input', {
				code: QUICError.ERR_CRYPTO,
				cause
			});
		}
	}
	return out;
}

function defaultCertificateObjects() {
	if(DEFAULT_CA_CACHE) return DEFAULT_CA_CACHE;
	const tls = require('node:tls');
	const defaults = typeof tls.getCACertificates === 'function' ? tls.getCACertificates('default') : tls.rootCertificates;
	DEFAULT_CA_CACHE = certificateObjects(defaults);
	return DEFAULT_CA_CACHE;
}

function trustAnchors(caItems) {
	if(caItems === DEFAULT_CA_CACHE && DEFAULT_TRUST_ANCHORS) return DEFAULT_TRUST_ANCHORS;
	const bySubject = new Map();
	for(const cert of caItems) {
		if(!cert.ca || cert.issuer !== cert.subject) continue;
		let selfSigned = false;
		try { selfSigned = cert.verify(cert.publicKey); } catch {}
		if(!selfSigned) continue;
		let key = null;
		try { key = cert.publicKey.export({type:'spki',format:'der'}); } catch {}
		if(!key) continue;
		const list = bySubject.get(cert.subject);
		const entry = { cert, key };
		if(list) list.push(entry); else bySubject.set(cert.subject,[entry]);
	}
	const result = { bySubject };
	if(caItems === DEFAULT_CA_CACHE) DEFAULT_TRUST_ANCHORS = result;
	return result;
}

function verifyCertificateChain(leaf, chain, { servername, ca, rejectUnauthorized = true } = {}) {
	let leafX;
	try {
		leafX = new crypto.X509Certificate(leaf);
	} catch (cause) {
		throw new QUICError('Invalid server certificate', {
			code: QUICError.ERR_CRYPTO,
			cause
		});
	}
	// service identity plus the local TLS 1.3 certificate profile.
	// checkHost() is configured with partialWildcards=false because Node's
	// default otherwise permits wildcard characters inside a DNS label.
	validateLeafCertificate(leafX, servername);

	const peerChain = certificateObjects(chain || []);
	if(!rejectUnauthorized) return {
		leaf: leafX,
		chain: [leafX, ...peerChain]
	};

	let caItems = [];
	if(ca !== undefined && ca !== null) caItems = certificateObjects(ca);
	if(!caItems.length) {
		try {
			caItems = defaultCertificateObjects();
		} catch {}
	}
	if(!caItems.length) throw new QUICError('No CA configured for certificate verification', {
		code: QUICError.ERR_CRYPTO,
		transportCode: 'CERTIFICATE_UNTRUSTED'
	});

	const pool = [...peerChain, ...caItems];
	const spkiDer = (cert) => {
		try {
			return cert.publicKey.export({ type: 'spki', format: 'der' });
		} catch {
			return null;
		}
	};
	const anchors = trustAnchors(caItems);
	const equivalentTrustAnchor = (cert) => {
		const key = spkiDer(cert);
		if(!key) return null;
		const candidates = anchors.bySubject.get(cert.subject) || [];
		for(const candidate of candidates) {
			if(candidate.key.equals(key)) return candidate.cert;
		}
		return null;
	};

	let current = leafX;
	const builtChain = [leafX];
	const visited = new Set([current.fingerprint256]);
	const now = Date.now();
	for(let depth = 0; depth < 10; depth++) {
		const equivalent = equivalentTrustAnchor(current);
		if(equivalent) {
			// A trust anchor is an input to path validation rather than an ordinary
			// path certificate, but when it is represented by X.509 we still apply
			// its CA and path-length constraints as an explicit local policy.
			const below = builtChain.length > 1 ? builtChain.slice(0, -1) : builtChain;
			validateIssuerCertificate(equivalent, {
				caCertificatesBelow: countNonSelfIssuedCAs(below),
				now
			});
			if(equivalent.fingerprint256 !== current.fingerprint256) builtChain.push(equivalent);
			return { leaf: leafX, chain: builtChain.slice() };
		}

		if(current.issuer === current.subject) {
			let selfSigned = false;
			try { selfSigned = current.verify(current.publicKey); } catch {}
			if(!selfSigned) throw new QUICError('Invalid self-signed certificate', {
				code: QUICError.ERR_CRYPTO,
				transportCode: 'CERTIFICATE_SIGNATURE_INVALID'
			});
			throw new QUICError('Untrusted root certificate', {
				code: QUICError.ERR_CRYPTO,
				transportCode: 'CERTIFICATE_UNTRUSTED'
			});
		}

		const subjectCandidates = pool.filter(cert => cert.subject === current.issuer);
		let issuer = null;
		let lastCandidateError = null;
		for(const candidate of subjectCandidates) {
			try {
				validateIssuerCertificate(candidate, {
					caCertificatesBelow: countNonSelfIssuedCAs(builtChain),
					now
				});
			} catch (err) {
				lastCandidateError = err;
				continue;
			}
			let metadataMatches = false;
			let signatureMatches = false;
			try {
				metadataMatches = typeof current.checkIssued === 'function'
					? current.checkIssued(candidate)
					: current.issuer === candidate.subject;
				if(!metadataMatches) continue;
				signatureMatches = current.verify(candidate.publicKey);
			} catch {}
			if(!signatureMatches) continue;
			issuer = candidate;
			break;
		}

		if(!issuer) {
			if(lastCandidateError) throw lastCandidateError;
			if(!subjectCandidates.length) {
				const err = new QUICError('Incomplete certificate chain: server did not provide the issuer certificate for ' + current.subject, {
					code: QUICError.ERR_CERTIFICATE_CHAIN,
					transportCode: 'CERTIFICATE_CHAIN_INCOMPLETE'
				});
				err.certificate = {
					subject: current.subject,
					issuer: current.issuer,
					fingerprint256: current.fingerprint256,
					peerChainLength: peerChain.length
				};
				throw err;
			}
			throw new QUICError('No issuer candidate satisfies certificate issuer and signature checks', {
				code: QUICError.ERR_CERTIFICATE_CHAIN,
				transportCode: 'CERTIFICATE_SIGNATURE_INVALID'
			});
		}

		if(visited.has(issuer.fingerprint256)) throw new QUICError('Certificate chain loop', {
			code: QUICError.ERR_CERTIFICATE_CHAIN,
			transportCode: 'CERTIFICATE_CHAIN_LOOP'
		});
		visited.add(issuer.fingerprint256);
		current = issuer;
		builtChain.push(issuer);
	}
	throw new QUICError('Certificate chain too long', {
		code: QUICError.ERR_CERTIFICATE_CHAIN,
		transportCode: 'CERTIFICATE_CHAIN_TOO_LONG'
	});
}

module.exports = {
	HASH_LEN,
	TLS_AES_128_GCM_SHA256,
	GROUP_X25519,
	EXT_SERVER_NAME,
	EXT_SIGNATURE_ALGORITHMS,
	EXT_ALPN,
	EXT_SUPPORTED_VERSIONS,
	EXT_QUIC_TP,
	SIG_ECDSA_SECP256R1_SHA256,
	SIG_ECDSA_SECP384R1_SHA384,
	SIG_ECDSA_SECP521R1_SHA512,
	SIG_RSA_PSS_RSAE_SHA256,
	SIG_RSA_PSS_PSS_SHA256,
	SIG_ED25519,
	generateX25519,
	x25519Public,
	normalizePsk,
	makeTransportParameters,
	parseTransportParameters,
	buildClientHello,
	parseClientHello,
	buildServerHello,
	parseServerHello,
	buildEncryptedExtensions,
	parseEncryptedExtensions,
	buildCertificate,
	parseCertificate,
	certificatePublicKey,
	selectSignatureScheme,
	signCertificateVerify,
	buildCertificateVerify,
	parseCertificateVerify,
	verifyCertificateVerify,
	verifyCertificateChain,
	buildFinished,
	parseFinished,
	transcriptHash,
	computeFinished,
	tls13Secrets,
	tls13CertificateSecrets,
	deriveSecret,
	finishedKey,
	HS_CLIENT_HELLO,
	HS_SERVER_HELLO,
	HS_ENCRYPTED_EXTENSIONS,
	HS_CERTIFICATE,
	HS_CERTIFICATE_VERIFY,
	HS_FINISHED
};

module.exports.default = module.exports;