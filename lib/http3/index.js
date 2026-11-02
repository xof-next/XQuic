'use strict';

const qpack = require('./qpack');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { decodeVarInt, encodeVarInt } = require('../codec/varint');
const { TYPE, frame, settings, cancelPush, goaway: goawayFrame, maxPushId, pushPromise, priorityUpdateRequest, priorityUpdatePush, parseFrames, parseSettings } = require('./codec');
const { DEFAULT_PRIORITY, parsePriority, encodePriority } = require('./priority');
const structuredFields = require('./structured-fields');
const capsule = require('./capsule');
const datagram = require('./datagram');
const { headersObject, normalizeOutgoingHeaders, validateHeaders, parseContentLength } = require('./headers');
const { H3, h3Name } = require('./errors');
const STREAM_CONTROL = 0x00, STREAM_PUSH = 0x01, STREAM_QPACK_ENCODER = 0x02, STREAM_QPACK_DECODER = 0x03;
const RESERVED_HTTP2_FRAME_TYPES = new Set([2n, 6n, 8n, 9n]);

const STREAM_SCOPED_EVENTS = new Set([
	'informational', 'headers', 'trailers', 'data', 'end',
	'streamError', 'datagram', 'datagramDrop', 'priority', 'unknownFrame', 'priorityUpdate'
]);

function h3EventAlias(connection, event, listener, streamId) {
	if(typeof listener !== 'function') throw new TypeError('Event listener must be a function');
	const name = String(event);
	const target = String(BigInt(streamId));
	const wrapped = (...args) => {
		if(STREAM_SCOPED_EVENTS.has(name)) {
			let candidate;
			switch(name) {
				case 'informational':
				case 'headers':
				case 'trailers':
				case 'data': candidate = args[2]; break;
				case 'end': candidate = args[1]; break;
				case 'streamError': candidate = args[0]?.id; break;
				default: candidate = args[0]?.streamId; break;
			}
			if(candidate === undefined || String(candidate) !== target) return;
		}
		listener(...args);
	};
	connection.on(name, wrapped);
	return wrapped;
}

function isSuccessfulConnectTunnel(connection, state) {
	if(state?.method !== 'CONNECT') return false;
	if(connection.isServer) return state.connectResponseAccepted === true;
	const status = Number(state.headers?.[':status']);
	return Number.isInteger(status) && status >= 200 && status < 300;
}

function hasExtendedConnect(list) {
	return list.some(([name]) => String(name).toLowerCase() === ':protocol');
}

function validateExtendedConnectSetting(connection, list, { outbound = false } = {}) {
	if(!hasExtendedConnect(list)) return;
	// outbound requests, the server's setting is authoritative;
	// for inbound requests, validate against the setting this endpoint advertised.
	const value = outbound ? connection.peerSettings.get(0x08) : BigInt(connection.localSettings?.[0x08] ?? 0);
	if(value !== 1n) {
		throw new Error('Extended CONNECT requires SETTINGS_ENABLE_CONNECT_PROTOCOL=1');
	}
}

function responseForbidsContent(st) {
	const status = Number(st.headers?.[':status']);
	if(!Number.isInteger(status)) return false;
	return (status >= 100 && status < 200) || status === 204 || status === 205 || status === 304 ||
		st.method === 'HEAD' || (st.method === 'CONNECT' && status >= 200 && status < 300);
}

function responseForbidsContentLength(method, status) {
	return (status >= 100 && status < 200) || status === 204 ||
		(method === 'CONNECT' && status >= 200 && status < 300);
}

class HTTP3Connection extends EventEmitter {
	constructor(conn, options = {}) {
		super();
		this.on('error', () => {});
		this.conn = conn;
		this.isServer = !!conn.isServer;
		this.settingsSent = false;
		this.controlStream = null;
		this.priorities = new Map();
		this.settingsReceived = false;
		this.controlFrameSeen = new Map();
		this.closed = false;
		this.goawayReceived = false;
		this.goawayId = null;
		this.localGoawayId = null;
		this.buffers = new Map();
		this.streamKinds = new Map();
		this.peerCriticalStreams = new Set();
		this.requests = new Map();
		this.datagramStreams = new Set();
		this.peerSettings = new Map();
		this.localSettings = options.settings || {};
		this.maxFieldSectionSize = options.maxFieldSectionSize ?? Number(this.localSettings[0x06] ?? 65536);
		// The encoder is constrained by the peer's QPACK settings, not our own.
		// Keep the active sending table at zero until an application explicitly
		// enables dynamic references; literal/static field sections remain interoperable.
		this.encoder = new qpack.QPACKEncoder({
			capacity: 0,
			maxCapacity: 0,
			useHuffman: options.useHuffman !== false
		});
		this.decoder = new qpack.QPACKDecoder({
			capacity: Number(this.localSettings[1] ?? 0)
		});
		this.qpackEncoderStream = null;
		this.qpackDecoderStream = null;
		this.qpackBlockedStreams = Number(this.localSettings[0x07] ?? 0);
		this.blockedFieldSections = new Map();
		this.blockedFieldSectionBytes = 0;
		this.maxBlockedFieldSectionBytes = options.maxBlockedFieldSectionBytes ?? (8 * 1024 * 1024);
		this.maxStreamBufferBytes = options.maxStreamBufferBytes ?? (16 * 1024 * 1024);
		this.maxCapsuleSize = options.maxCapsuleSize ?? capsule.DEFAULT_MAX_CAPSULE_SIZE;
		this.knownCapsuleTypes = new Set(['0']);
		for(const value of options.knownCapsuleTypes || []) this.knownCapsuleTypes.add(BigInt(value).toString());
		if(!Number.isSafeInteger(this.maxCapsuleSize) || this.maxCapsuleSize < 0) throw new RangeError('maxCapsuleSize must be a non-negative safe integer');
		this._bind();
		if(this.conn.readyState === 'open') queueMicrotask(() => this._ready());
	}
	_ready() {
		try {
			this._openControl();
			this.emit('ready', this);
		} catch (e) {
			this._fail(e);
		}
	}
	_bind() {
		this.conn.on('data', (data, c, id) => this._data(Buffer.from(data), BigInt(id)));
		this.conn.on('streamEnd', (c, id) => this._end(BigInt(id)));
		this.conn.on('close', (...a) => {
			const error = new Error('HTTP/3 connection closed');
			for(const st of this.requests.values()) {
				if(st.req && !st.req.destroyed && !st.req.readableEnded) st.req.destroy(error);
				if(st.rejectResponse && !st.response && !st.streamError) { st.streamError = error; st.rejectResponse(error); }
			}
			this.emit('close', ...a);
		});
		this.conn.on('datagram', (payload) => this._handleDatagram(Buffer.from(payload)));
		this.conn.once('ready', () => this._ready());
	}
	_fail(err, code = err?.h3Code ?? H3.INTERNAL_ERROR) {
		if(this.listenerCount('error')) this.emit('error', err);
		try {
			this.conn.close(Number(code), String(err.message || err).slice(0, 1024));
		} catch {}
	}
	_openControl() {
		if(this.settingsSent) return;
		const s = this.conn.openUnidirectionalStream();
		this.controlStream = s;
		this.streamKinds.set(String(s.id), STREAM_CONTROL);
		s.write(Buffer.concat([encodeVarInt(STREAM_CONTROL), settings(this.localSettings)]));
		this.settingsSent = true;
		// HTTP/3 requires one encoder and one decoder critical stream per endpoint,
		// even when QPACK dynamic-table capacity is zero.
		this.qpackEncoderStream = this.conn.openUnidirectionalStream();
		this.streamKinds.set(String(this.qpackEncoderStream.id), STREAM_QPACK_ENCODER);
		this.qpackEncoderStream.write(encodeVarInt(STREAM_QPACK_ENCODER));
		this.qpackDecoderStream = this.conn.openUnidirectionalStream();
		this.streamKinds.set(String(this.qpackDecoderStream.id), STREAM_QPACK_DECODER);
		this.qpackDecoderStream.write(encodeVarInt(STREAM_QPACK_DECODER));
	}
	_data(data, id) {
		const key = String(id);
		const unidirectional = (BigInt(id) & 2n) !== 0n;
		const knownKind = this.streamKinds.get(key);
		if(unidirectional && this.streamKinds.has(key) && ![STREAM_CONTROL, STREAM_PUSH, STREAM_QPACK_ENCODER, STREAM_QPACK_DECODER].includes(knownKind)) return;
		const incoming = Buffer.isBuffer(data) ? data : Buffer.from(data);
		const prev = this.buffers.get(key) || Buffer.alloc(0);
		if(prev.length + incoming.length > this.maxStreamBufferBytes) {
			this._fail(new Error('HTTP/3 stream buffer limit exceeded'));
			return;
		}
		let b = prev.length ? Buffer.concat([prev, incoming]) : incoming;
		this.buffers.set(key, b);
		const bidi = !unidirectional;
		if(unidirectional && !this.streamKinds.has(key)) {
			let x;
			try {
				x = decodeVarInt(b, 0);
			} catch(e) {
				if(/Truncated|Missing QUIC varint/.test(String(e?.message))) return;
				this._fail(Object.assign(new Error('Invalid unidirectional stream type'), { cause: e, h3Code: H3.STREAM_CREATION_ERROR }));
				return;
			}
			const kind = x.value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(x.value) : x.value;
			if([STREAM_CONTROL, STREAM_QPACK_ENCODER, STREAM_QPACK_DECODER].includes(kind)) {
				if(this.peerCriticalStreams.has(kind)) {
					this._fail(Object.assign(new Error('Duplicate HTTP/3 critical stream'), { h3Code: H3.STREAM_CREATION_ERROR }));
					return;
				}
				this.peerCriticalStreams.add(kind);
			} else if(kind === STREAM_PUSH) {
				// This implementation never advertises MAX_PUSH_ID, so peer push streams are not permitted.
				this._fail(Object.assign(new Error('Unsolicited HTTP/3 push stream'), { h3Code: H3.ID_ERROR }));
				return;
			}
			this.streamKinds.set(key, kind);
			b = b.subarray(x.offset);
			this.buffers.set(key, b);
			if(![STREAM_CONTROL, STREAM_QPACK_ENCODER, STREAM_QPACK_DECODER].includes(kind)) {
				this.buffers.delete(key);
				return;
			}
		}
		const kind = bidi ? undefined : this.streamKinds.get(key);
		if(kind === STREAM_CONTROL) {
			try {
				const p = parseFrames(b, false);
				this.buffers.set(key, p.remaining);
				for(const f of p.frames) this._controlFrame(f);
			} catch (e) {
				this._fail(e, e.h3Code ?? H3.FRAME_ERROR);
			}
			return;
		}
		if(kind === STREAM_QPACK_ENCODER) {
			try {
				const consumed = this.decoder.applyEncoderInstructions(b);
				this.buffers.set(key, b.subarray(consumed));
				this._flushQpackDecoderInstructions();
				this._retryBlocked();
			} catch (e) {
				this._fail(Object.assign(e, { h3Code: e.h3Code ?? 0x0201 }));
			}
			return;
		}
		if(kind === STREAM_QPACK_DECODER) {
			try {
				const consumed = this._qpackDecoderInstructions(b);
				this.buffers.set(key, b.subarray(consumed));
			} catch (e) {
				this._fail(Object.assign(e, { h3Code: e.h3Code ?? 0x0202 }));
			}
			return;
		}
		if(kind === undefined) {
			this._requestData(id, b);
		}
	}
	_flushQpackDecoderInstructions() {
		const instructions = this.decoder.takeDecoderInstructions();
		if(instructions.length && this.qpackDecoderStream) this.qpackDecoderStream.write(instructions);
	}
	_flushQpackEncoderInstructions() {
		const instructions = this.encoder.encodeInstructions();
		if(instructions.length && this.qpackEncoderStream) this.qpackEncoderStream.write(instructions);
	}
	_qpackDecoderInstructions(b) {
		let o = 0;
		while(o < b.length) {
			const start = o;
			const first = b[o];
			try {
				if(first & 0x80) {
					const x = qpack.readPrefixedInt(b, o, 7);
					o = x.offset;
					this.encoder.acknowledgeSection(x.value);
					continue;
				}
				if((first & 0xc0) === 0x40) {
					const x = qpack.readPrefixedInt(b, o, 6);
					o = x.offset;
					// Stream ID zero is valid; unlike Insert Count Increment, cancellation has no non-zero constraint.
					this.encoder.cancelStream(x.value);
					continue;
				}
				if((first & 0xc0) === 0x00) {
					const x = qpack.readPrefixedInt(b, o, 6);
					if(x.value === 0n) throw Object.assign(new Error('QPACK Insert Count Increment must be non-zero'), { h3Code: 0x0202 });
					const next = this.encoder.knownReceivedCount + x.value;
					if(next > BigInt(this.encoder.table.insertCount)) throw Object.assign(new Error('QPACK insert count exceeds sent count'), { h3Code: 0x0202 });
					this.encoder.knownReceivedCount = next;
					o = x.offset;
					continue;
				}
				throw Object.assign(new Error('Unknown QPACK decoder instruction'), { h3Code: 0x0202 });
			} catch(e) {
				if(e?.incomplete) return start;
				throw e;
			}
		}
		return o;
	}

	_controlFrame(f) {
		// RFC 9114 §6.2.1: SETTINGS MUST be the first frame on the
		// control stream and MUST NOT appear more than once.
		if(!this.settingsReceived && f.type !== TYPE.SETTINGS) {
			throw Object.assign(new Error('HTTP/3 control stream must begin with SETTINGS'), { h3Code: H3.MISSING_SETTINGS });
		}
		if(RESERVED_HTTP2_FRAME_TYPES.has(BigInt(f.type))) {
			throw Object.assign(new Error('Reserved HTTP/2 frame type is forbidden in HTTP/3'), { h3Code: H3.FRAME_UNEXPECTED });
		}
		if(f.type === TYPE.SETTINGS) {
			if(this.settingsReceived) throw Object.assign(new Error('Duplicate HTTP/3 SETTINGS'), { h3Code: H3.FRAME_UNEXPECTED });
			this.peerSettings = parseSettings(f.payload);
			const peerQpackCapacity = this.peerSettings.get(0x01) ?? 0n;
			if(peerQpackCapacity > BigInt(Number.MAX_SAFE_INTEGER)) throw Object.assign(new Error('Peer QPACK table capacity exceeds implementation limit'), { h3Code: H3.SETTINGS_ERROR });
			this.encoder.maxCapacity = Number(peerQpackCapacity);
			const peerBlockedStreams = this.peerSettings.get(0x07) ?? 0n;
			if(peerBlockedStreams > BigInt(Number.MAX_SAFE_INTEGER)) throw Object.assign(new Error('Peer QPACK blocked-stream limit exceeds implementation limit'), { h3Code: H3.SETTINGS_ERROR });
			this.encoder.maxBlockedStreams = Number(peerBlockedStreams);
			this.peerMaxFieldSectionSize = Number(this.peerSettings.get(0x06) ?? Infinity);
			this.settingsReceived = true;
			this.emit('settings', this.peerSettings);
			return;
		}
		if(f.type === TYPE.GOAWAY) {
			const x = decodeVarInt(f.payload, 0);
			if(x.offset !== f.payload.length) throw Object.assign(new Error('Invalid HTTP/3 GOAWAY'), { h3Code: H3.FRAME_ERROR });
			if(!this.isServer && (x.value & 0x03n) !== 0n) throw Object.assign(new Error('Server GOAWAY ID must be a client-initiated bidirectional stream ID'), { h3Code: H3.ID_ERROR });
			if(this.goawayReceived && x.value > this.goawayId) throw Object.assign(new Error('GOAWAY ID increased'), { h3Code: H3.ID_ERROR });
			this.goawayReceived = true;
			this.goawayId = x.value;
			this.emit('goaway', x.value);
			return;
		}
		if(f.type === TYPE.PRIORITY_UPDATE_REQUEST || f.type === TYPE.PRIORITY_UPDATE_PUSH) {
			if(!this.isServer) throw Object.assign(new Error('A server must not send PRIORITY_UPDATE frames'), { h3Code: H3.FRAME_UNEXPECTED });
			// This stack has no Server Push implementation, so it cannot have
			// promised a push ID that a PRIORITY_UPDATE_PUSH could reference.
			if(f.type === TYPE.PRIORITY_UPDATE_PUSH) throw Object.assign(new Error('Push priority update references an unsupported or unpromised push'), { h3Code: H3.ID_ERROR });
		}
		if(f.type === TYPE.PRIORITY_UPDATE_REQUEST) {
			let id;
			try { id = decodeVarInt(f.payload, 0); }
			catch (cause) { throw Object.assign(new Error('Malformed PRIORITY_UPDATE request stream ID', { cause }), { h3Code: H3.FRAME_ERROR }); }
			if((id.value & 0x03n) !== 0n) throw Object.assign(new Error('PRIORITY_UPDATE ID is not a client-initiated bidirectional stream'), { h3Code: H3.ID_ERROR });
			const valueBytes = f.payload.subarray(id.offset);
			const value = [...valueBytes].some(byte => byte < 0x20 || byte > 0x7e) ? '' : valueBytes.toString('ascii');
			const priority = parsePriority(value);
			const key = String(id.value);
			this.priorities.set(key, priority);
			const st = this.requests.get(key);
			if(st) {
				st.priority = priority;
				if(st.req) st.req.priority = priority;
			}
			this.emit('priorityUpdate', { streamId: id.value, priority, value, source: 'PRIORITY_UPDATE' });
			return;
		}
		if(f.type === TYPE.MAX_PUSH_ID) {
			if(!this.isServer) throw Object.assign(new Error('A server must not send MAX_PUSH_ID'), { h3Code: H3.FRAME_UNEXPECTED });
			// Server Push is not implemented; the client-advertised limit is not used.
			return;
		}
		if(f.type === TYPE.CANCEL_PUSH) {
			// No PUSH_PROMISE can be created by this stack, so there is no valid
			// push ID that CANCEL_PUSH could reference.
			throw Object.assign(new Error('CANCEL_PUSH references an unsupported or unpromised push'), { h3Code: H3.ID_ERROR });
		}
		if([TYPE.DATA, TYPE.HEADERS, TYPE.PUSH_PROMISE].includes(f.type)) {
			throw Object.assign(new Error('HTTP/3 frame on control stream'), { h3Code: H3.FRAME_UNEXPECTED });
		}
		// Unknown frame types are ignored per RFC 9114 §7.2.
	}

	_requestData(id, b, final = false) {
		const key = String(id);
		let st = this.requests.get(key);
		if(!st) {
			let resolveResponse, rejectResponse, responsePromise = null;
			if(!this.isServer) {
				responsePromise = new Promise((resolve, reject) => {
					resolveResponse = resolve;
					rejectResponse = reject;
				});
				// Preserve normal rejection for callers while avoiding process-level
				// unhandled-rejection noise if a client intentionally ignores the promise.
				responsePromise.catch(() => {});
			}
			st = {
				priority: this.priorities.get(key) || { ...DEFAULT_PRIORITY },
				headers: null,
				data: [],
				ended: false,
				contentLength: null,
				bytes: 0,
				trailers: false,
				responsePromise,
				resolveResponse,
				rejectResponse,
				streamError: null
			};
			this.requests.set(key, st);
		}
		// `headers` means the final request/response field section is available.
		// It must not also stand in for whether the stream's first frame was
		// HEADERS: a client can receive informational HEADERS (e.g. 103) before
		// the final response, and unknown extension frames after that first
		if(st.receivedInitialHeaders === undefined) st.receivedInitialHeaders = false;
		let p;
		try {
			p = parseFrames(b, final);
			for(const f of p.frames) {
				if(RESERVED_HTTP2_FRAME_TYPES.has(BigInt(f.type))) {
					throw Object.assign(new Error('Reserved HTTP/2 frame type is forbidden in HTTP/3'), { h3Code: H3.FRAME_UNEXPECTED, connectionError: true });
				}
				if([TYPE.SETTINGS, TYPE.GOAWAY, TYPE.CANCEL_PUSH, TYPE.MAX_PUSH_ID, TYPE.PRIORITY_UPDATE_REQUEST, TYPE.PRIORITY_UPDATE_PUSH].includes(f.type)) {
					throw Object.assign(new Error('HTTP/3 connection-level frame received on a request stream'), { h3Code: H3.FRAME_UNEXPECTED, connectionError: true });
				}
				if(f.type === TYPE.PUSH_PROMISE) {
					const code = this.isServer ? H3.FRAME_UNEXPECTED : H3.ID_ERROR;
					const message = this.isServer
						? 'A client must not send PUSH_PROMISE'
						: 'PUSH_PROMISE received without any advertised push ID limit';
					throw Object.assign(new Error(message), { h3Code: code, connectionError: true });
				}
				if(!st.receivedInitialHeaders) {
					if(f.type === TYPE.DATA) {
						throw Object.assign(new Error('DATA received before the initial HEADERS frame'), { h3Code: H3.FRAME_UNEXPECTED, connectionError: true });
					}
					if(f.type !== TYPE.HEADERS) {
						// permits unknown extension frames before, after,
						// or interleaved with message frames. They do not start the
						// HTTP message, so ignore them and keep waiting for HEADERS.
						this.emit('unknownFrame', { streamId: id, type: f.type, payload: f.payload });
						continue;
					}
					st.receivedInitialHeaders = true;
				}
				if(f.type === TYPE.HEADERS) {
					if(isSuccessfulConnectTunnel(this, st)) throw Object.assign(new Error('HEADERS is not permitted after a successful CONNECT tunnel is established'), { h3Code: H3.FRAME_UNEXPECTED, connectionError: true });
					if(st.trailers) throw Object.assign(new Error('HEADERS after trailing HEADERS'), { h3Code: H3.FRAME_UNEXPECTED, connectionError: true });
					let list;
					try {
						list = this.decoder.decodeFieldSection(f.payload, {
							streamId: id
						});
						this._flushQpackDecoderInstructions();
					} catch (e) {
						if(e && e.message === 'QPACK blocked field section') {
							const payload = Buffer.from(f.payload);
							if(this.qpackBlockedStreams <= 0) {
								e.h3Code = H3.QPACK_DECOMPRESSION_FAILED; e.connectionError = true; throw e;
							}
							const streamAlreadyBlocked = this.blockedFieldSections.has(key);
							if(!streamAlreadyBlocked && this.blockedFieldSections.size >= this.qpackBlockedStreams) {
								e.h3Code = H3.QPACK_DECOMPRESSION_FAILED; e.connectionError = true; throw e;
							}
							if(this.blockedFieldSectionBytes + payload.length > this.maxBlockedFieldSectionBytes) throw Object.assign(new Error('QPACK blocked section memory limit exceeded'), { h3Code: H3.EXCESSIVE_LOAD, connectionError: true });
							const arr = this.blockedFieldSections.get(key) || [];
							arr.push({
								payload,
								response: !this.isServer
							});
							this.blockedFieldSections.set(key, arr);
							this.blockedFieldSectionBytes += payload.length;
							continue;
						}
						 e.h3Code = H3.QPACK_DECOMPRESSION_FAILED;
						 e.connectionError = true;
						 throw e;
					}
					const validation = validateHeaders(list, {
						response: !this.isServer,
						trailers: !!st.headers
					});
					const parsedLength = parseContentLength(list);
					if(st.headers && parsedLength !== null) throw new Error('Content-Length is forbidden in trailers');
					if(!this.isServer && responseForbidsContentLength(st.method, Number(list.find(([name]) => name === ':status')?.[1])) && parsedLength !== null) {
						throw new Error('Content-Length is forbidden for this HTTP response');
					}
					if(!this.isServer && !st.headers) {
						const status = Number(list.find(([name]) => name === ':status')?.[1]);
						if(status >= 100 && status < 200 && status !== 101) {
							this.emit('informational', headersObject(list), this, id);
							continue;
						}
					}
					if(!st.headers) validateExtendedConnectSetting(this, list);
					if(validation.size > this.maxFieldSectionSize) throw new Error('HTTP/3 field section exceeds local limit');
					const decodedHeaders = headersObject(list);
					if(this.isServer && !st.method) st.method = decodedHeaders[':method'];
					if(!st.headers) this._negotiateCapsules(id, st, decodedHeaders);
					if(!st.headers) {
						if(decodedHeaders.priority !== undefined) {
							const rawPriority = Array.isArray(decodedHeaders.priority) ? decodedHeaders.priority.join(', ') : String(decodedHeaders.priority);
							st.priority = parsePriority(rawPriority);
							this.priorities.set(key, st.priority);
							this.emit('priority', { streamId: id, priority: st.priority, value: rawPriority, source: 'Priority field' });
						}
						st.headers = decodedHeaders;
						st.contentLength = parsedLength;
						if(!this.isServer && st.method === 'CONNECT' && Number(st.headers[':status']) >= 200 && Number(st.headers[':status']) < 300) {
							// A CONNECT response is complete at its successful header section;
							// the stream intentionally remains open for tunnel/Capsule data.
							const empty = Buffer.alloc(0);
							st.response = { id: BigInt(id), status: Number(st.headers[':status']), headers: st.headers, trailers: Object.create(null), body: empty, bodyBytes: 0, text(encoding = 'utf8') { return empty.toString(encoding); }, json() { return JSON.parse(empty.toString('utf8')); } };
							st.resolveResponse?.(st.response);
						}
						this.emit('headers', st.headers, this, id);
						if(this.isServer) {
							const req = this._requestObject(id, st);
							this.emit('request', req);
						}
					} else {
						st.trailers = true;
						st.trailersHeaders = decodedHeaders;
						if(st.req) st.req.trailers = decodedHeaders;
						this.emit('trailers', decodedHeaders, this, id);
					}
				} else if(f.type === TYPE.DATA) {
					if(!st.headers) throw Object.assign(new Error('DATA before HEADERS'), { h3Code: H3.FRAME_UNEXPECTED, connectionError: true });
					if(st.trailers) throw Object.assign(new Error('DATA after trailing HEADERS'), { h3Code: H3.FRAME_UNEXPECTED, connectionError: true });
					const connectTunnel = isSuccessfulConnectTunnel(this, st);
					if(!connectTunnel && !this.isServer && responseForbidsContent(st)) throw new Error('DATA is forbidden for this HTTP response');
					if(st.capsulesEnabled && st.capsuleParser) {
						// once Capsule Protocol is negotiated, DATA payloads
						// are a streaming sequence of Capsules, not HTTP content.
						try { st.capsuleParser.push(f.payload); }
						catch(error) { error.h3Code = H3.DATAGRAM_ERROR; throw error; }
					} else {
						// Successful CONNECT DATA is opaque tunnel payload, not HTTP content.
						if(!connectTunnel) {
							st.data.push(f.payload);
							st.bytes += f.payload.length;
							if(st.contentLength !== null && st.bytes > st.contentLength) throw new Error('HTTP message exceeds Content-Length');
						}
						if(st.req && !st.req.destroyed && !st.req.readableEnded) st.req.write(f.payload);
						this.emit('data', f.payload, this, id);
					}
				} else {
					// Unknown frame types are permitted and ignored.
					this.emit('unknownFrame', {
						streamId: id,
						type: f.type,
						payload: f.payload
					});
				}
			}
			this.buffers.set(key, p.remaining);
		} catch (e) {
			if(e?.connectionError) {
				this._fail(e, e.h3Code ?? H3.QPACK_DECOMPRESSION_FAILED);
				return false;
			}
			const streamErrorCode = e?.h3Code ?? (e?.code === H3.FRAME_ERROR ? H3.FRAME_ERROR : H3.MESSAGE_ERROR);
			try {
				this.conn.resetStream(BigInt(id), streamErrorCode);
			} catch {}
			st.streamError = e;
			st.req?.destroy(e);
			st.rejectResponse?.(e);
			const errorCode = streamErrorCode;
			this.emit('streamError', {
				id,
				errorCode,
				error: e,
				message: h3Name(errorCode)
			});
			return false;
		}
		return true;
	}
	_retryBlocked() {
		if(!this.blockedFieldSections.size) return;
		for(const [key, items] of this.blockedFieldSections) {
			const id = BigInt(key);
			const st = this.requests.get(key);
			if(!st) continue;
			const remaining = [];
			for(const item of items) {
				try {
					let list;
					try {
						list = this.decoder.decodeFieldSection(item.payload, { streamId: id });
					} catch(e) {
						if(e && e.message === 'QPACK blocked field section') throw e;
						e.h3Code = H3.QPACK_DECOMPRESSION_FAILED;
						e.connectionError = true;
						throw e;
					}
					this._flushQpackDecoderInstructions();
					const validation = validateHeaders(list, {
						response: item.response,
						trailers: !!st.headers
					});
					const parsedLength = parseContentLength(list);
					if(st.headers && parsedLength !== null) throw new Error('Content-Length is forbidden in trailers');
					if(item.response && responseForbidsContentLength(st.method, Number(list.find(([name]) => name === ':status')?.[1])) && parsedLength !== null) {
						throw new Error('Content-Length is forbidden for this HTTP response');
					}
					if(item.response && !st.headers) {
						const status = Number(list.find(([name]) => name === ':status')?.[1]);
						if(status >= 100 && status < 200 && status !== 101) {
							this.emit('informational', headersObject(list), this, id);
							continue;
						}
					}
					if(!st.headers) validateExtendedConnectSetting(this, list);
					if(validation.size > this.maxFieldSectionSize) throw new Error('HTTP/3 field section exceeds local limit');
					const decodedHeaders = headersObject(list);
					if(this.isServer && !st.method) st.method = decodedHeaders[':method'];
					if(!st.headers) this._negotiateCapsules(id, st, decodedHeaders);
					if(!st.headers) {
						if(decodedHeaders.priority !== undefined) {
							const rawPriority = Array.isArray(decodedHeaders.priority) ? decodedHeaders.priority.join(', ') : String(decodedHeaders.priority);
							st.priority = parsePriority(rawPriority);
							this.priorities.set(key, st.priority);
							this.emit('priority', { streamId: id, priority: st.priority, value: rawPriority, source: 'Priority field' });
						}
						st.headers = decodedHeaders;
						st.contentLength = parsedLength;
						if(!this.isServer && st.method === 'CONNECT' && Number(st.headers[':status']) >= 200 && Number(st.headers[':status']) < 300) {
							const empty = Buffer.alloc(0);
							st.response = { id, status: Number(st.headers[':status']), headers: st.headers, trailers: Object.create(null), body: empty, bodyBytes: 0, text(encoding = 'utf8') { return empty.toString(encoding); }, json() { return JSON.parse(empty.toString('utf8')); } };
							st.resolveResponse?.(st.response);
						}
						this.emit('headers', st.headers, this, id);
						if(this.isServer) this.emit('request', this._requestObject(id, st));
					} else {
						st.trailers = true;
						st.trailersHeaders = decodedHeaders;
						if(st.req) st.req.trailers = decodedHeaders;
						this.emit('trailers', decodedHeaders, this, id);
					}
				} catch (e) {
					if(e && e.message === 'QPACK blocked field section') {
						remaining.push(item);
						continue;
					}
					if(e?.connectionError) {
						this._fail(e, e.h3Code ?? H3.QPACK_DECOMPRESSION_FAILED);
						return;
					}
					this.blockedFieldSectionBytes = Math.max(0, this.blockedFieldSectionBytes - item.payload.length);
					try {
						this.conn.resetStream(id, e?.h3Code ?? H3.MESSAGE_ERROR);
					} catch {}
					st.streamError = e;
					st.req?.destroy(e);
					st.rejectResponse?.(e);
					const errorCode = e?.h3Code ?? H3.MESSAGE_ERROR;
					this.emit('streamError', {
						id,
						errorCode,
						error: e,
						message: h3Name(errorCode)
					});
					this.blockedFieldSections.delete(key);
					return;
				}
			}
			if(remaining.length) this.blockedFieldSections.set(key, remaining);
			else {
				this.blockedFieldSections.delete(key);
				for(const item of items) this.blockedFieldSectionBytes = Math.max(0, this.blockedFieldSectionBytes - item.payload.length);
			}
		}
	}
	_end(id) {
		const key = String(id);
		const kind = this.streamKinds.get(key);
		if(kind === STREAM_CONTROL || kind === STREAM_QPACK_ENCODER || kind === STREAM_QPACK_DECODER) {
			const err = Object.assign(new Error('HTTP/3 critical stream closed'), { h3Code: H3.CLOSED_CRITICAL_STREAM });
			this._fail(err, H3.CLOSED_CRITICAL_STREAM);
			return;
		}
		const st = this.requests.get(key);
		if(!st) return;
		if(st.ended) return;
		const pending = this.buffers.get(key);
		if(pending && pending.length) {
			const ok = this._requestData(id, pending, true);
			if(ok === false) return;
		}
		if(!st.receivedInitialHeaders) {
			this._fail(Object.assign(new Error('HTTP/3 message stream ended before initial HEADERS'), { h3Code: H3.FRAME_UNEXPECTED }), H3.FRAME_UNEXPECTED);
			return;
		}
		if(st.capsulesEnabled && st.capsuleParser) {
			try { st.capsuleParser.finish(); }
			catch(error) {
				st.ended = true;
				error.h3Code = H3.DATAGRAM_ERROR;
				try { this.conn.resetStream(BigInt(id), H3.DATAGRAM_ERROR); } catch {}
				st.streamError = error;
				st.req?.destroy(error);
				st.rejectResponse?.(error);
				this.emit('streamError', { id: BigInt(id), errorCode: H3.DATAGRAM_ERROR, error, message: h3Name(H3.DATAGRAM_ERROR) });
				return;
			}
		}
		st.ended = true;
		if(st.headers && st.contentLength !== null && !(!this.isServer && responseForbidsContent(st)) && st.bytes !== st.contentLength) {
			const error = new Error(`HTTP message body length mismatch: expected ${st.contentLength}, received ${st.bytes}`);
			try {
				this.conn.resetStream(BigInt(id), H3.MESSAGE_ERROR);
			} catch {}
			st.streamError = error;
			st.req?.destroy(error);
			st.rejectResponse?.(error);
			this.emit('streamError', {
				id,
				errorCode: H3.MESSAGE_ERROR,
				error,
				message: h3Name(H3.MESSAGE_ERROR)
			});
			return;
		}
		const body = st.data.length === 0 ? Buffer.alloc(0) : Buffer.concat(st.data, st.bytes);
		const response = {
			id: BigInt(id),
			status: st.headers?.[':status'] !== undefined ? Number(st.headers[':status']) : undefined,
			headers: st.headers || Object.create(null),
			trailers: st.trailersHeaders || Object.create(null),
			body,
			bodyBytes: body.length,
			text(encoding = 'utf8') {
				return body.toString(encoding);
			},
			json() {
				return JSON.parse(body.toString('utf8'));
			}
		};
		const successfulConnectResponse = !this.isServer && st.method === 'CONNECT' && response.status >= 200 && response.status < 300;
		if(!successfulConnectResponse || !st.response) {
			st.response = response;
			st.resolveResponse?.(response);
		}
		if(st.req && !st.req.destroyed) {
			st.req.complete = true;
			if(!st.req.readableEnded) st.req.end();
		}
		this.emit('end', this, id, st);
	}
	_requestObject(id, st) {
		const h = st.headers || {};
		if(st.req) return st.req;
		const req = new PassThrough({
			autoDestroy: true
		});
		Object.assign(req, {
			id: BigInt(id),
			headers: h,
			method: h[':method'] || 'GET',
			path: h[':path'] || '/',
			authority: h[':authority'] || '',
			scheme: h[':scheme'] || 'https',
			protocol: h[':protocol'],
			priority: st.priority || { ...DEFAULT_PRIORITY },
			httpVersion: '3.0',
			httpVersionMajor: 3,
			httpVersionMinor: 0,
			complete: false,
			aborted: false,
			trailers: Object.create(null),
			respond: (status = 200, headers = {}, body = null) => this.respond(id, status, headers, body),
			enableDatagrams: () => this.enableDatagrams(id),
			sendDatagram: (payload) => this.sendDatagram(id, payload),
			enableCapsules: () => this.enableCapsules(id),
			sendCapsule: (type, payload) => this.sendCapsule(id, type, payload),
			sendCapsuleAsync: (type, payload, opts) => this.sendCapsuleAsync(id, type, payload, opts),
			sendDatagramCapsule: (payload) => this.sendDatagramCapsule(id, payload),
			sendDatagramCapsuleAsync: (payload, opts) => this.sendDatagramCapsuleAsync(id, payload, opts)
		});
		req.on('error', () => {});
		req.on('close', () => {
			if(!req.readableEnded) req.aborted = true;
		});
		st.req = req;
		return req;
	}
	_capsuleHeaderEnabled(headers) {
		return capsule.parseCapsuleProtocol(headers?.['capsule-protocol']);
	}
	_negotiateCapsules(id, st, headers) {
		const enabled = this._capsuleHeaderEnabled(headers);
		if(this.isServer) {
			if(!enabled) return false;
			capsule.validateCapsuleProtocolUse({ method: headers[':method'], headers });
			if(!headers[':protocol']) throw Object.assign(new Error('Capsule Protocol over HTTP/3 requires Extended CONNECT'), { h3Code: H3.MESSAGE_ERROR });
			st.capsuleProtocolOffered = true;
			return true;
		}
		if(!enabled) return false;
		const status = Number(headers[':status']);
		capsule.validateCapsuleProtocolUse({ method: st.method, statusCode: status, headers });
		if(st.capsuleProtocolRequested && st.requestHeaders?.[':protocol'] && status >= 200 && status < 300) {
			this._activateCapsules(id, st);
			return true;
		}
		return false;
	}
	_activateCapsules(streamId, st) {
		if(st.capsulesEnabled) return st.capsuleParser;
		const id = BigInt(streamId);
		const parser = new capsule.CapsuleParser({
			maxCapsuleSize: this.maxCapsuleSize,
			knownTypes: [...this.knownCapsuleTypes].map((v) => BigInt(v)),
			dropUnknown: true
		});
		parser.on('capsule', (item) => {
			const event = { streamId: id, type: item.type, payload: Buffer.from(item.payload), source: 'capsule' };
			this.emit('capsule', event);
			if(BigInt(item.type) === capsule.CAPSULE_TYPE.DATAGRAM) this.emit('datagram', { streamId: id, payload: Buffer.from(item.payload), source: 'capsule' });
		});
		st.capsulesEnabled = true;
		st.capsuleParser = parser;
		return parser;
	}
	enableCapsules(streamId) {
		const id = BigInt(streamId);
		const st = this.requests.get(String(id));
		if(!st) throw new Error('Cannot enable Capsules before the request stream is registered');
		if(st.method !== 'CONNECT') throw new Error('Capsule Protocol requires CONNECT');
		if(!st.capsuleProtocolOffered && !st.capsuleProtocolRequested) throw new Error('Capsule Protocol must be negotiated with Capsule-Protocol: ?1');
		if(!isSuccessfulConnectTunnel(this, st)) throw new Error('Capsules require a successful CONNECT response');
		return this._activateCapsules(id, st);
	}
	_prepareOutgoingCapsule(streamId, type, payload = Buffer.alloc(0)) {
		const id = BigInt(streamId);
		const key = String(id);
		const st = this.requests.get(key);
		if(!st || !st.capsulesEnabled || !st.capsuleParser) throw new Error('Capsule Protocol is not active for this request stream');
		if(!isSuccessfulConnectTunnel(this, st)) throw new Error('Capsules require a successful CONNECT response');
		const transportStream = this.conn.streams?.get?.(key);
		if(transportStream && (transportStream.finSent || transportStream.resetSent)) throw new Error('Cannot send a Capsule after the stream send side is closed');
		const value = BigInt(type).toString();
		if(!this.knownCapsuleTypes.has(value)) throw new Error(`Capsule type ${value} is not registered as supported by this connection`);
		return { id, encoded: capsule.encodeCapsule(type, payload, { maxCapsuleSize: this.maxCapsuleSize }) };
	}
	sendCapsule(streamId, type, payload = Buffer.alloc(0)) {
		const { id, encoded } = this._prepareOutgoingCapsule(streamId, type, payload);
		this.conn.write(frame(TYPE.DATA, encoded), { streamId: id, fin: false });
		return this;
	}
	async sendCapsuleAsync(streamId, type, payload = Buffer.alloc(0), opts = {}) {
		const { id, encoded } = this._prepareOutgoingCapsule(streamId, type, payload);
		if(typeof this.conn.writeAsync !== 'function') throw new Error('The underlying QUIC connection does not support writeAsync');
		await this.conn.writeAsync(frame(TYPE.DATA, encoded), { ...opts, streamId: id, fin: false });
		return this;
	}
	sendDatagramCapsule(streamId, payload = Buffer.alloc(0)) {
		return this.sendCapsule(streamId, capsule.CAPSULE_TYPE.DATAGRAM, payload);
	}
	sendDatagramCapsuleAsync(streamId, payload = Buffer.alloc(0), opts = {}) {
		return this.sendCapsuleAsync(streamId, capsule.CAPSULE_TYPE.DATAGRAM, payload, opts);
	}
	_enableDatagramSettings() {
		const local = Number(this.localSettings[0x33] ?? 0) === 1;
		const peer = this.peerSettings.get(0x33) === 1n;
		if(!local || !peer) throw Object.assign(new Error('HTTP Datagrams require SETTINGS_H3_DATAGRAM=1 from both endpoints'), { h3Code: H3.DATAGRAM_ERROR });
	}
	enableDatagrams(streamId) {
		const id = BigInt(streamId);
		if(id < 0n || (id & 0x03n) !== 0n) throw new RangeError('HTTP Datagram association must use a client-initiated bidirectional request stream');
		this._enableDatagramSettings();
		const st = this.requests.get(String(id));
		if(!st) throw new Error('Cannot enable HTTP Datagrams before the request stream is registered');
		// The caller opts the request into the extension-defined datagram semantics.
		// Base HTTP methods alone do not define HTTP Datagram
		st.datagramsEnabled = true;
		this.datagramStreams.add(String(id));
		return id;
	}
	sendDatagram(streamId, payload = Buffer.alloc(0)) {
		const id = BigInt(streamId);
		const key = String(id);
		const st = this.requests.get(key);
		if(!st || !st.datagramsEnabled || !this.datagramStreams.has(key)) throw new Error('HTTP Datagrams are not enabled for this request stream');
		this._enableDatagramSettings();
		if(st.method === 'CONNECT') {
			if(this.isServer && !st.datagramResponseAccepted) throw new Error('Server must establish a successful CONNECT response before sending datagrams');
			if(!this.isServer) {
				const status = Number(st.headers?.[':status']);
				if(!Number.isInteger(status) || status < 200 || status >= 300) throw new Error('Client must receive a successful CONNECT response before sending datagrams');
			}
		}
		const transportStream = this.conn.streams?.get?.(key);
		if(!transportStream) throw new Error('Underlying QUIC request stream is not available for HTTP Datagrams');
		if(transportStream.finSent || transportStream.resetSent) throw new Error('Cannot send HTTP Datagrams after the request stream send side is closed');
		if(typeof this.conn.sendDatagram !== 'function') throw new Error('The underlying QUIC connection does not support DATAGRAM frames');
		const encoded = datagram.encodeHTTP3Datagram(id, payload);
		this.conn.sendDatagram(encoded);
		return this;
	}
	_handleDatagram(payload) {
		let parsed;
		try { parsed = datagram.decodeHTTP3Datagram(payload); }
		catch(error) { this._fail(error, H3.DATAGRAM_ERROR); return; }
		try { this._enableDatagramSettings(); }
		catch(error) { this._fail(error, H3.DATAGRAM_ERROR); return; }
		const key = String(parsed.streamId);
		const st = this.requests.get(key);
		// RFC 9297 §2.1 allows datagrams for not-yet-created streams to be dropped.
		if(!st) { this.emit('datagramDrop', { ...parsed, reason: 'request stream not yet available' }); return; }
		if(!st.datagramsEnabled || !this.datagramStreams.has(key)) {
			const error = Object.assign(new Error('Request has no registered HTTP Datagram semantics'), { h3Code: H3.DATAGRAM_ERROR });
			try { this.conn.resetStream(parsed.streamId, H3.DATAGRAM_ERROR); } catch {}
			try { this.conn.stopSending?.(parsed.streamId, H3.DATAGRAM_ERROR); } catch {}
			st.streamError = error;
			st.req?.destroy(error);
			st.rejectResponse?.(error);
			this.emit('streamError', { id: parsed.streamId, errorCode: H3.DATAGRAM_ERROR, error, message: 'H3_DATAGRAM_ERROR' });
			return;
		}
		const transportStream = this.conn.streams?.get?.(key);
		if(transportStream?.finReceived || transportStream?.resetReceived) {
			this.emit('datagramDrop', { ...parsed, reason: 'request stream receive side is closed' });
			return;
		}
		this.emit('datagram', { streamId: parsed.streamId, payload: parsed.payload });
	}
	createCapsuleParser(options = {}) { return new capsule.CapsuleParser(options); }
	getPriority(streamId) {
		const value = this.priorities.get(String(BigInt(streamId))) || DEFAULT_PRIORITY;
		return { urgency: value.urgency, incremental: value.incremental };
	}
	updatePriority(streamId, priority) {
		if(this.isServer) throw new Error('Only an HTTP/3 client can send PRIORITY_UPDATE frames');
		if(!this.controlStream || this.closed) throw new Error('HTTP/3 control stream is not available');
		const id = BigInt(streamId);
		if(id < 0n || (id & 0x03n) !== 0n) throw new RangeError('Request stream ID must be a client-initiated bidirectional stream ID');
		const value = encodePriority(priority);
		this.controlStream.write(priorityUpdateRequest(id, value));
		const parsed = parsePriority(value);
		this.priorities.set(String(id), parsed);
		this.emit('priority', { streamId: id, priority: parsed, value, source: 'local PRIORITY_UPDATE' });
		return parsed;
	}
	request({
		method = 'GET',
		scheme = 'https',
		authority = 'localhost',
		path = '/',
		headers = {},
		body = null,
		datagrams = false,
		capsules = false
	} = {}) {
		if(this.goawayReceived) throw new Error('HTTP/3 connection is draining');
		const methodValue = String(method);
		if(typeof datagrams !== 'boolean') throw new TypeError('datagrams must be a boolean');
		if(typeof capsules !== 'boolean') throw new TypeError('capsules must be a boolean');
		const extraHeaders = normalizeOutgoingHeaders(headers);
		if(capsules && !extraHeaders.some(([name]) => String(name).toLowerCase() === 'capsule-protocol')) extraHeaders.push(['capsule-protocol', '?1']);
		const extendedConnect = methodValue === 'CONNECT' && extraHeaders.some(([name]) => name === ':protocol');
		const classicConnect = methodValue === 'CONNECT' && !extendedConnect;
		const list = classicConnect ? [
			[':method', 'CONNECT'],
			[':authority', authority], ...extraHeaders
		] : [
			[':method', methodValue],
			[':scheme', scheme],
			[':authority', authority],
			[':path', path], ...extraHeaders
		];
		const validation = validateHeaders(list);
		const capsuleRequestEnabled = capsule.validateCapsuleProtocolUse({ method: methodValue, headers: list }).enabled;
		if(capsuleRequestEnabled && !extendedConnect) throw new Error('Capsule Protocol requires Extended CONNECT over HTTP/3');
		if(capsules && !extendedConnect) throw new Error('request({ capsules: true }) requires Extended CONNECT with an explicit :protocol');
		if(extendedConnect) validateExtendedConnectSetting(this, list, { outbound: true });
		if(datagrams) {
			if(!extendedConnect) throw new Error('request({ datagrams: true }) requires Extended CONNECT with an explicit :protocol');
			this._enableDatagramSettings();
		}
		if(this.peerMaxFieldSectionSize !== undefined && validation.size > this.peerMaxFieldSectionSize) throw new Error('Request headers exceed peer field-section limit');
		const requestContentLength = parseContentLength(list);
		if(methodValue === 'CONNECT' && requestContentLength !== null) throw new Error('Content-Length is forbidden in a CONNECT request');
		const bodyBuffer = body === null || body === undefined ? Buffer.alloc(0) : Buffer.isBuffer(body) ? body : Buffer.from(String(body));
		if(requestContentLength !== null && bodyBuffer.length !== requestContentLength) {
			throw new Error(`Request body length ${bodyBuffer.length} does not match Content-Length ${requestContentLength}`);
		}
		if(methodValue === 'CONNECT' && bodyBuffer.length) throw new Error('CONNECT cannot include an HTTP request body; tunnel DATA can be sent after a successful 2xx response');
		const s = this.conn.openStream();
		const id = s.id;
		const block = this.encoder.encodeFieldSection(list, {
			useDynamic: false,
			streamId: id
		});
		this._flushQpackEncoderInstructions();
		let resolve, reject;
		const response = new Promise((res, rej) => {
			resolve = res;
			reject = rej;
		});
		response.catch(() => {});
		const key = String(id);
		const st = this.requests.get(key) || {
			priority: this.priorities.get(key) || { ...DEFAULT_PRIORITY },
			headers: null,
			data: [],
			ended: false,
			contentLength: null,
			bytes: 0,
			trailers: false
		};
		st.method = methodValue;
		st.requestHeaders = Object.fromEntries(list);
		st.capsuleProtocolRequested = capsuleRequestEnabled;
		if(!st.responsePromise) {
			st.responsePromise = response;
			st.resolveResponse = resolve;
			st.rejectResponse = reject;
			this.requests.set(key, st);
		}
		const requestListeners = new Map();
		const req = {
			id,
			response,
			write: (d) => {
				if(st.requestEnded) throw new Error('HTTP/3 request stream is already ended');
				if(methodValue === 'CONNECT' && !isSuccessfulConnectTunnel(this, st)) throw new Error('CONNECT tunnel DATA requires a successful 2xx response first');
				s.write(frame(TYPE.DATA, Buffer.isBuffer(d) ? d : Buffer.from(d)));
				return req;
			},
			writeAsync: async (d, opts = {}) => {
				if(st.requestEnded) throw new Error('HTTP/3 request stream is already ended');
				if(methodValue === 'CONNECT' && !isSuccessfulConnectTunnel(this, st)) throw new Error('CONNECT tunnel DATA requires a successful 2xx response first');
				if(typeof s.writeAsync !== 'function') throw new Error('The underlying QUIC stream does not support writeAsync');
				await s.writeAsync(frame(TYPE.DATA, Buffer.isBuffer(d) ? d : Buffer.from(d)), opts);
				return req;
			},
			end: (d = null) => {
				if(st.requestEnded) return req;
				if(methodValue === 'CONNECT' && !isSuccessfulConnectTunnel(this, st)) throw new Error('CONNECT request stream must remain open until a successful 2xx response');
				if(d !== null && d !== undefined) {
					s.end(frame(TYPE.DATA, Buffer.isBuffer(d) ? d : Buffer.from(d)));
				} else {
					s.end();
				}
				st.requestEnded = true;
				return req;
			},
			endAsync: async (d = null, opts = {}) => {
				if(st.requestEnded) return req;
				if(methodValue === 'CONNECT' && !isSuccessfulConnectTunnel(this, st)) throw new Error('CONNECT request stream must remain open until a successful 2xx response');
				if(typeof s.endAsync !== 'function') throw new Error('The underlying QUIC stream does not support endAsync');
				if(d !== null && d !== undefined) await s.endAsync(frame(TYPE.DATA, Buffer.isBuffer(d) ? d : Buffer.from(d)), opts);
				else await s.endAsync(Buffer.alloc(0), opts);
				st.requestEnded = true;
				return req;
			},
			cancel: () => this.cancelRequest(id),
			on: (event, fn) => {
				const wrapped = h3EventAlias(this, event, fn, id);
				const items = requestListeners.get(String(event)) || [];
				items.push({ fn, wrapped }); requestListeners.set(String(event), items);
				return req;
			},
			once: (event, fn) => {
				if(typeof fn !== 'function') throw new TypeError('Event listener must be a function');
				const onceFn = (...args) => { req.off(event, onceFn); fn(...args); };
				return req.on(event, onceFn);
			},
			off: (event, fn) => {
				const name = String(event), items = requestListeners.get(name) || [];
				const keep = [];
				for(const item of items) {
					if(fn === undefined || item.fn === fn) this.off(name, item.wrapped);
					else keep.push(item);
				}
				if(keep.length) requestListeners.set(name, keep); else requestListeners.delete(name);
				return req;
			},
			removeListener: (event, fn) => req.off(event, fn)
		};
		if(methodValue === 'CONNECT') {
			if(datagrams) this.enableDatagrams(id);
			s.write(frame(TYPE.HEADERS, block));
			// request stream remains open while CONNECT is
			// negotiated; after 2xx, DATA carries tunnel bytes.
			st.requestEnded = false;
		} else if(body !== null && body !== undefined) {
			s.write(frame(TYPE.HEADERS, block));
			req.end(bodyBuffer);
		} else {
			s.end(frame(TYPE.HEADERS, block));
			st.requestEnded = true;
		}
		req.enableDatagrams = () => this.enableDatagrams(id);
		req.sendDatagram = (payload) => this.sendDatagram(id, payload);
		req.enableCapsules = () => this.enableCapsules(id);
		req.sendCapsule = (type, payload) => this.sendCapsule(id, type, payload);
		req.sendCapsuleAsync = (type, payload, opts) => this.sendCapsuleAsync(id, type, payload, opts);
		req.sendDatagramCapsule = (payload) => this.sendDatagramCapsule(id, payload);
		req.sendDatagramCapsuleAsync = (payload, opts) => this.sendDatagramCapsuleAsync(id, payload, opts);
		return req;
	}
	cancelRequest(id, errorCode = H3.REQUEST_CANCELLED) {
		const streamId = BigInt(id);
		const key = String(streamId);
		const blocked = this.blockedFieldSections.get(key) || [];
		if(blocked.length) {
			this.blockedFieldSectionBytes = Math.max(0, this.blockedFieldSectionBytes - blocked.reduce((n, item) => n + item.payload.length, 0));
			this.blockedFieldSections.delete(key);
		}
		if(this.decoder.cancelStream(streamId, { force: blocked.length > 0 })) this._flushQpackDecoderInstructions();
		this.conn.resetStream(streamId, Number(errorCode));
		if(typeof this.conn.stopSending === 'function') this.conn.stopSending(streamId, Number(errorCode));
		return true;
	}
	sendInformational(id, status = 103, headers = {}) {
		if(!this.isServer) throw new Error('Only an HTTP/3 server can send informational responses');
		const statusCode = Number(status);
		if(!Number.isInteger(statusCode) || statusCode < 100 || statusCode >= 200 || statusCode === 101) {
			throw new RangeError('Informational status must be an HTTP/3 status from 100 to 199, excluding 101');
		}
		const list = [[':status', String(statusCode)], ...normalizeOutgoingHeaders(headers)];
		const validation = validateHeaders(list, { response: true });
		if(parseContentLength(list) !== null) throw new Error('Content-Length is forbidden in an informational response');
		if(this.peerMaxFieldSectionSize !== undefined && validation.size > this.peerMaxFieldSectionSize) {
			throw new Error('Informational headers exceed peer field-section limit');
		}
		const section = this.encoder.encodeFieldSection(list, { streamId: BigInt(id) });
		this._flushQpackEncoderInstructions();
		this.conn.write(frame(TYPE.HEADERS, section), { streamId: BigInt(id), fin: false });
		return statusCode;
	}
	respond(id, status = 200, headers = {}, body = null) {
		const list = [
			[':status', String(status)], ...normalizeOutgoingHeaders(headers)
		];
		const validation = validateHeaders(list, {
			response: true
		});
		const responseContentLength = parseContentLength(list);
		const statusCode = Number(status);
		if(statusCode >= 100 && statusCode < 200) throw new Error('Use sendInformational() for informational responses; respond() sends the final response');
		const requestState = this.requests.get(String(BigInt(id)));
		const requestMethod = requestState?.headers?.[':method'] || requestState?.method;
		const capsuleResponseEnabled = capsule.validateCapsuleProtocolUse({ method: requestMethod, statusCode, headers: list }).enabled;
		if(capsuleResponseEnabled && (!requestState?.capsuleProtocolOffered || !requestState?.headers?.[':protocol'])) throw new Error('Capsule Protocol response requires an Extended CONNECT request that offered Capsule-Protocol: ?1');
		if(responseForbidsContentLength(requestMethod, statusCode) && responseContentLength !== null) {
			throw new Error('Content-Length is forbidden for this HTTP response');
		}
		const noResponseContent = (statusCode >= 100 && statusCode < 200) || statusCode === 204 || statusCode === 205 || statusCode === 304 ||
			requestMethod === 'HEAD' || (requestMethod === 'CONNECT' && statusCode >= 200 && statusCode < 300);
		const bodyBuffer = body === null || body === undefined ? Buffer.alloc(0) : Buffer.isBuffer(body) ? body : Buffer.from(String(body));
		if(noResponseContent && bodyBuffer.length > 0) throw new Error('Response body is forbidden for this HTTP response');
		if(responseContentLength !== null && !noResponseContent && bodyBuffer.length !== responseContentLength) {
			throw new Error(`Response body length ${bodyBuffer.length} does not match Content-Length ${responseContentLength}`);
		}
		if(this.peerMaxFieldSectionSize !== undefined && validation.size > this.peerMaxFieldSectionSize) throw new Error('Response headers exceed peer field-section limit');
		const keepConnectOpen = requestMethod === 'CONNECT' && statusCode >= 200 && statusCode < 300;
		const parts = [frame(TYPE.HEADERS, this.encoder.encodeFieldSection(list, { streamId: BigInt(id) }))];
		this._flushQpackEncoderInstructions();
		if(bodyBuffer.length) parts.push(frame(TYPE.DATA, bodyBuffer));
		this.conn.write(Buffer.concat(parts), {
			streamId: BigInt(id),
			fin: !keepConnectOpen
		});
		if(requestState && keepConnectOpen) {
			requestState.connectResponseAccepted = true;
			if(requestState.datagramsEnabled) requestState.datagramResponseAccepted = true;
			if(capsuleResponseEnabled) this._activateCapsules(BigInt(id), requestState);
		}
	}
	goaway(id = 0n) {
		const next = BigInt(id);
		if(next < 0n) throw new RangeError('GOAWAY identifier must be non-negative');
		if(this.isServer && (next & 0x03n) !== 0n) throw Object.assign(new Error('Server GOAWAY ID must be a client-initiated bidirectional stream ID'), { h3Code: H3.ID_ERROR });
		if(this.localGoawayId !== null && next > this.localGoawayId) throw Object.assign(new Error('GOAWAY identifier must not increase'), { h3Code: H3.ID_ERROR });
		if(!this.controlStream || this.closed) throw new Error('HTTP/3 control stream is not available');
		this.localGoawayId = next;
		this.controlStream.write(goawayFrame(next));
		return this.localGoawayId;
	}
	close(code = H3.NO_ERROR, reason = '') {
		this.closed = true;
		try {
			this.conn.close(code, reason);
		} catch {}
	}
}

function attachHTTP3(conn, options) {
	const h = new HTTP3Connection(conn, options);
	conn.http3 = h;
	return h;
}

module.exports = {
	HTTP3Connection,
	attachHTTP3,
	TYPE,
	frame,
	settings,
	cancelPush,
	goaway: goawayFrame,
	maxPushId,
	pushPromise,
	priorityUpdateRequest,
	priorityUpdatePush,
	qpack,
	STREAM_CONTROL,
	STREAM_PUSH,
	STREAM_QPACK_ENCODER,
	STREAM_QPACK_DECODER,
	H3,
	DEFAULT_PRIORITY,
	parsePriority,
	encodePriority,
	structuredFields,
	...structuredFields,
	...capsule,
	...datagram
};