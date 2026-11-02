'use strict';

const { QUICError } = require('../errors');
const huffman = require('./qpack-huffman');

function prefixedInt(value, prefixBits, prefixMask = 0) {
	value = BigInt(value);
	const max = (1n << BigInt(prefixBits)) - 1n;
	if(value < max) return Buffer.from([prefixMask | Number(value)]);
	const out = [prefixMask | Number(max)];
	value -= max;
	while(value >= 128n) {
		out.push(Number((value & 127n) | 128n));
		value >>= 7n;
	}
	out.push(Number(value));
	return Buffer.from(out);
}

function incomplete(message, code = 0x0200) {
	const err = new QUICError(message, { code });
	err.incomplete = true;
	return err;
}

function readPrefixedInt(buf, off, prefixBits) {
	if(off >= buf.length) throw incomplete('Truncated QPACK integer');
	const mask = (1 << prefixBits) - 1;
	const first = buf[off++];
	let value = BigInt(first & mask);
	if(value !== BigInt(mask)) return {
		value,
		offset: off
	};
	let shift = 0n;
	for(;;) {
		if(off >= buf.length) throw incomplete('Truncated QPACK integer');
		if(shift > 56n) throw new QUICError('Invalid QPACK integer', { code: 0x0200 });
		const b = buf[off++];
		value += BigInt(b & 127) << shift;
		if(!(b & 128)) return {
			value,
			offset: off
		};
		shift += 7n;
	}
}

function str(s, prefixBits = 7, mask = 0, { useHuffman = true } = {}) {
	const raw = Buffer.from(String(s), 'utf8');
	const encoded = useHuffman ? huffman.encode(raw) : raw;
	const useH = useHuffman && encoded.length < raw.length;
	const flag = useH ? (1 << prefixBits) : 0;
	const prefix = prefixedInt(useH ? encoded.length : raw.length, prefixBits, mask | flag);
	return Buffer.concat([prefix, useH ? encoded : raw]);
}

function readStr(buf, off) {
	if(off >= buf.length) throw incomplete('Truncated QPACK string');
	const h = !!(buf[off] & 0x80);
	const x = readPrefixedInt(buf, off, 7);
	off = x.offset;
	const n = Number(x.value);
	if(!Number.isSafeInteger(n)) throw new QUICError('Invalid QPACK string length', { code: 0x0200 });
	if(off + n > buf.length) throw incomplete('Truncated QPACK string');
	const raw = buf.subarray(off, off + n);
	return {
		value: (h ? huffman.decode(raw) : Buffer.from(raw)).toString('utf8'),
		offset: off + n,
		huffman: h
	};
}

const STATIC_TABLE = Object.freeze([
	[':authority', ''],
	[':path', '/'],
	['age', '0'],
	['content-disposition', ''],
	['content-length', '0'],
	['cookie', ''],
	['date', ''],
	['etag', ''],
	['if-modified-since', ''],
	['if-none-match', ''],
	['last-modified', ''],
	['link', ''],
	['location', ''],
	['referer', ''],
	['set-cookie', ''],
	[':method', 'CONNECT'],
	[':method', 'DELETE'],
	[':method', 'GET'],
	[':method', 'HEAD'],
	[':method', 'OPTIONS'],
	[':method', 'POST'],
	[':method', 'PUT'],
	[':scheme', 'http'],
	[':scheme', 'https'],
	[':status', '103'],
	[':status', '200'],
	[':status', '304'],
	[':status', '404'],
	[':status', '503'],
	['accept', '*/*'],
	['accept', 'application/dns-message'],
	['accept-encoding', 'gzip, deflate, br'],
	['accept-ranges', 'bytes'],
	['access-control-allow-headers', 'cache-control'],
	['access-control-allow-headers', 'content-type'],
	['access-control-allow-origin', '*'],
	['cache-control', 'max-age=0'],
	['cache-control', 'max-age=2592000'],
	['cache-control', 'max-age=604800'],
	['cache-control', 'no-cache'],
	['cache-control', 'no-store'],
	['cache-control', 'public, max-age=31536000'],
	['content-encoding', 'br'],
	['content-encoding', 'gzip'],
	['content-type', 'application/dns-message'],
	['content-type', 'application/javascript'],
	['content-type', 'application/json'],
	['content-type', 'application/x-www-form-urlencoded'],
	['content-type', 'image/gif'],
	['content-type', 'image/jpeg'],
	['content-type', 'image/png'],
	['content-type', 'text/css'],
	['content-type', 'text/html; charset=utf-8'],
	['content-type', 'text/plain'],
	['content-type', 'text/plain;charset=utf-8'],
	['range', 'bytes=0-'],
	['strict-transport-security', 'max-age=31536000'],
	['strict-transport-security', 'max-age=31536000; includesubdomains'],
	['strict-transport-security', 'max-age=31536000; includesubdomains; preload'],
	['vary', 'accept-encoding'],
	['vary', 'origin'],
	['x-content-type-options', 'nosniff'],
	['x-xss-protection', '1; mode=block'],
	[':status', '100'],
	[':status', '204'],
	[':status', '206'],
	[':status', '302'],
	[':status', '400'],
	[':status', '403'],
	[':status', '421'],
	[':status', '425'],
	[':status', '500'],
	['accept-language', ''],
	['access-control-allow-credentials', 'FALSE'],
	['access-control-allow-credentials', 'TRUE'],
	['access-control-allow-headers', '*'],
	['access-control-allow-methods', 'get'],
	['access-control-allow-methods', 'get, post, options'],
	['access-control-allow-methods', 'options'],
	['access-control-expose-headers', 'content-length'],
	['access-control-request-headers', 'content-type'],
	['access-control-request-method', 'get'],
	['access-control-request-method', 'post'],
	['alt-svc', 'clear'],
	['authorization', ''],
	['content-security-policy', "script-src 'none'; object-src 'none'; base-uri 'none'"],
	['early-data', '1'],
	['expect-ct', ''],
	['forwarded', ''],
	['if-range', ''],
	['origin', ''],
	['purpose', 'prefetch'],
	['server', ''],
	['timing-allow-origin', '*'],
	['upgrade-insecure-requests', '1'],
	['user-agent', ''],
	['x-forwarded-for', ''],
	['x-frame-options', 'deny'],
	['x-frame-options', 'sameorigin']
]);

function staticExact(name, value) {
	for(let i = 0; i < STATIC_TABLE.length; i++)
		if(STATIC_TABLE[i][0] === name && STATIC_TABLE[i][1] === value) return i;
	return -1;
}

function staticName(name) {
	for(let i = 0; i < STATIC_TABLE.length; i++)
		if(STATIC_TABLE[i][0] === name) return i;
	return -1;
}

function staticAt(index) {
	if(!Number.isSafeInteger(index) || index < 0 || index >= STATIC_TABLE.length) throw new QUICError('Invalid QPACK static table index', {
		code: 0x0200
	});
	return STATIC_TABLE[index];
}
class DynamicTable {
	constructor(capacity = 0) {
		capacity = Number(capacity);
		if(!Number.isSafeInteger(capacity) || capacity < 0) throw new QUICError('Invalid QPACK dynamic table capacity', { code: 0x0200 });
		this.capacity = capacity;
		this.entries = [];
		this.insertCount = 0;
		this.base = 0;
	}
	setCapacity(capacity) {
		capacity = Number(capacity);
		if(!Number.isSafeInteger(capacity) || capacity < 0) throw new QUICError('Invalid QPACK dynamic table capacity', {
			code: 0x0200
		});
		this.capacity = capacity;
		this.evict();
	}
	sizeOf([name, value]) {
		return Buffer.byteLength(name) + Buffer.byteLength(value) + 32;
	}
	evict() {
		while(this.entries.reduce((n, e) => n + e.size, 0) > this.capacity && this.entries.length) this.entries.pop();
	}
	insert(name, value) {
		// Preserve wire casing in the decoder table so HTTP/3 can reject an
		// illegal uppercase field name instead of silently normalizing it.
		name = String(name);
		value = String(value);
		const entry = {
			name,
			value,
			size: this.sizeOf([name, value]),
			abs: this.insertCount
		};
		if(entry.size > this.capacity) {
			this.entries = [];
			this.insertCount++;
			return entry;
		}
		this.entries.unshift(entry);
		this.insertCount++;
		this.evict();
		return entry;
	}
	getRelative(index) {
		const i = Number(index);
		if(!Number.isSafeInteger(i) || i < 0 || i >= this.entries.length) throw new QUICError('Invalid QPACK dynamic index', {
			code: 0x0200
		});
		return this.entries[i];
	}
	findExact(name, value) {
		for(let i = 0; i < this.entries.length; i++)
			if(this.entries[i].name === name && this.entries[i].value === value) return i;
		return -1;
	}
	findName(name) {
		for(let i = 0; i < this.entries.length; i++)
			if(this.entries[i].name === name) return i;
		return -1;
	}
}
class QPACKEncoder {
	constructor({ capacity = 0, maxCapacity = capacity, useHuffman = true } = {}) {
		capacity = Number(capacity);
		maxCapacity = Number(maxCapacity);
		if(!Number.isSafeInteger(maxCapacity) || maxCapacity < 0 || capacity > maxCapacity) throw new QUICError('Invalid QPACK encoder maximum capacity', { code: 0x0201 });
		this.table = new DynamicTable(capacity);
		this.capacity = capacity;
		this.maxCapacity = maxCapacity;
		this.instructions = [];
		this.useHuffman = !!useHuffman;
		this.knownReceivedCount = 0n;
		this.streamSections = new Map();
		this.references = new Map();
		this.maxBlockedStreams = 0;
	}
	_entryRefCount(abs) {
		return this.references.get(String(BigInt(abs))) || 0;
	}
	_releaseRefs(refs) {
		for(const abs of refs || []) {
			const key = String(BigInt(abs));
			const count = this.references.get(key) || 0;
			if(count <= 1) this.references.delete(key);
			else this.references.set(key, count - 1);
		}
	}
	_assertEvictionsAllowed(extraSize = 0, newCapacity = this.capacity) {
		let size = this.table.entries.reduce((n, e) => n + e.size, 0) + extraSize;
		for(let i = this.table.entries.length - 1; size > newCapacity && i >= 0; i--) {
			const entry = this.table.entries[i];
			if(this._entryRefCount(entry.abs) > 0) throw new QUICError('QPACK encoder cannot evict a dynamic entry referenced by an outstanding field section', { code: 0x0201 });
			size -= entry.size;
		}
		if(size > newCapacity) throw new QUICError('QPACK dynamic entry exceeds table capacity', { code: 0x0201 });
	}
	setCapacity(capacity) {
		capacity = Number(capacity);
		if(!Number.isSafeInteger(capacity) || capacity < 0 || capacity > this.maxCapacity) throw new QUICError('QPACK encoder capacity exceeds peer SETTINGS_QPACK_MAX_TABLE_CAPACITY', { code: 0x0201 });
		this._assertEvictionsAllowed(0, capacity);
		this.capacity = capacity;
		this.table.setCapacity(this.capacity);
		this.instructions.push(prefixedInt(this.capacity, 5, 0x20));
	}
	insert(name, value) {
		if(this.capacity <= 0) throw new QUICError('QPACK dynamic table capacity is zero', {
			code: 0x0201
		});
		name = String(name).toLowerCase();
		value = String(value);
		const size = this.table.sizeOf([name, value]);
		if(size > this.capacity) throw new QUICError('QPACK encoder entry exceeds dynamic table capacity', { code: 0x0201 });
		this._assertEvictionsAllowed(size, this.capacity);
		const ni = staticName(name);
		let entry;
		if(ni >= 0) {
			this.instructions.push(prefixedInt(ni, 6, 0xc0), str(value, 7, 0, {
				useHuffman: this.useHuffman
			}));
			entry = this.table.insert(name, value);
		} else {
			this.instructions.push(str(name, 5, 0x40, {
				useHuffman: this.useHuffman
			}), str(value, 7, 0, {
				useHuffman: this.useHuffman
			}));
			entry = this.table.insert(name, value);
		}
		return entry;
	}
	encodeInstructions() {
		return Buffer.concat(this.instructions.splice(0));
	}
	acknowledgeSection(streamId) {
		const key = String(BigInt(streamId));
		const queue = this.streamSections.get(key);
		if(!queue || !queue.length) throw new QUICError('QPACK Section Acknowledgement has no outstanding dynamic field section', { code: 0x0202 });
		const section = queue.shift();
		this.knownReceivedCount = this.knownReceivedCount > section.required ? this.knownReceivedCount : section.required;
		this._releaseRefs(section.refs);
		if(!queue.length) this.streamSections.delete(key);
	}
	cancelStream(streamId) {
		const key = String(BigInt(streamId));
		const queue = this.streamSections.get(key);
		if(!queue || !queue.length) throw new QUICError('QPACK Stream Cancellation has no outstanding dynamic field section', { code: 0x0202 });
		for(const section of queue) this._releaseRefs(section.refs);
		this.streamSections.delete(key);
	}
	_encodeRic(required) {
		required = BigInt(required);
		if(required === 0n) return 0n;
		const maxEntries = Math.floor(this.maxCapacity / 32);
		if(maxEntries <= 0) throw new QUICError('QPACK dynamic reference requires at least one table entry', {
			code: 0x0201
		});
		const full = BigInt(2 * maxEntries);
		return (required % full) + 1n;
	}
	encodeFieldSection(headers, { useDynamic = false, streamId = 0n } = {}) {
		const lines = Array.isArray(headers) ? headers : Object.entries(headers || {});
		const refs = [];
		const planned = [];
		for(const [n0, v0] of lines) {
			const name = String(n0).toLowerCase(),
				value = String(v0 ?? '');
			const ex = staticExact(name, value);
			if(ex >= 0) {
				planned.push(['si', ex]);
				continue;
			}
			const ni = staticName(name);
			if(ni >= 0) {
				planned.push(['sn', ni, value]);
				continue;
			}
			if(useDynamic && this.capacity > 0) {
				const di = this.table.findExact(name, value);
				if(di >= 0) {
					const e = this.table.getRelative(di);
					planned.push(['di', e.abs]);
					refs.push(e.abs + 1);
					continue;
				}
				const dn = this.table.findName(name);
				if(dn >= 0) {
					const e = this.table.getRelative(dn);
					planned.push(['dn', e.abs, value]);
					refs.push(e.abs + 1);
					continue;
				}
			}
			planned.push(['ln', name, value]);
		}
		let required = refs.length ? Math.max(...refs.map(Number)) : 0;
		const key = String(BigInt(streamId));
		if(required > Number(this.knownReceivedCount)) {
			const blocked = [...this.streamSections.entries()].filter(([, sections]) => sections.some(section => section.required > this.knownReceivedCount)).map(([id]) => id);
			if(!blocked.includes(key) && blocked.length >= Math.max(0, Number(this.maxBlockedStreams) || 0)) {
				for(let i = 0; i < planned.length; i++) {
					const item = planned[i];
					if(item[0] === 'di') {
						const entry = this.table.entries.find(e => e.abs === item[1]);
						planned[i] = ['ln', entry.name, entry.value];
					} else if(item[0] === 'dn') {
						const entry = this.table.entries.find(e => e.abs === item[1]);
						planned[i] = ['ln', entry.name, item[2]];
					}
				}
				refs.length = 0;
				required = 0;
			}
		}
		if(required > 0) {
			const queue = this.streamSections.get(key) || [];
			const uniqueRefs = [...new Set(refs.map(x => BigInt(x - 1).toString()))].map(BigInt);
			queue.push({ required: BigInt(required), refs: uniqueRefs });
			this.streamSections.set(key, queue);
			for(const abs of uniqueRefs) this.references.set(String(abs), this._entryRefCount(abs) + 1);
		}
		const base = BigInt(required);
		const out = [prefixedInt(this._encodeRic(required), 8, 0), prefixedInt(0, 7, (base === required ? 0 : 0))];
		for(const p of planned) {
			if(p[0] === 'si') {
				out.push(prefixedInt(p[1], 6, 0xc0));
				continue;
			}
			if(p[0] === 'sn') {
				out.push(prefixedInt(p[1], 4, 0x50), str(p[2], 7, 0, {
					useHuffman: this.useHuffman
				}));
				continue;
			}
			if(p[0] === 'di') {
				const abs = BigInt(p[1]);
				const rel = base - abs - 1n;
				if(rel < 0n) out.push(prefixedInt(Number(abs - base), 4, 0x10));
				else out.push(prefixedInt(rel, 6, 0x80));
				continue;
			}
			if(p[0] === 'dn') {
				const abs = BigInt(p[1]);
				const rel = base - abs - 1n;
				if(rel < 0n) throw new QUICError('Post-base dynamic name reference unavailable', {
					code: 0x0200
				});
				out.push(prefixedInt(rel, 4, 0x40), str(p[2], 7, 0, {
					useHuffman: this.useHuffman
				}));
				continue;
			}
			const nb = Buffer.from(p[1]);
			const ne = this.useHuffman ? huffman.encode(nb) : nb;
			const nh = this.useHuffman && ne.length < nb.length;
			out.push(prefixedInt(nh ? ne.length : nb.length, 3, 0x20 | (nh ? 0x08 : 0)), nh ? ne : nb, str(p[2], 7, 0, {
				useHuffman: this.useHuffman
			}));
		}
		return Buffer.concat(out);
	}
}
class QPACKDecoder {
	constructor({ capacity = 0} = {}) {
		// A decoder's advertised capacity is only a ceiling. The active table
		// starts at zero and changes only after SET_DYNAMIC_TABLE_CAPACITY.
		capacity = Number(capacity);
		if(!Number.isSafeInteger(capacity) || capacity < 0) throw new QUICError('Invalid QPACK decoder maximum capacity', { code: 0x0200 });
		this.table = new DynamicTable(0);
		this.maxCapacity = capacity;
		this.knownInsertCount = 0;
		this.encoderCount = 0;
		this.pendingInsertCountIncrement = 0n;
		this.pendingSectionAcks = [];
		this.pendingStreamCancellations = [];
		this.streamSections = new Map();
	}
	acknowledgeSection(streamId) {
		const key = String(BigInt(streamId));
		const queue = this.streamSections.get(key) || [];
		if(queue.length) {
			queue.shift();
			if(queue.length) this.streamSections.set(key, queue);
			else this.streamSections.delete(key);
		}
	}
	cancelStream(streamId, { force = false } = {}) {
		const id = BigInt(streamId);
		const key = String(id);
		const hadSections = this.streamSections.has(key) || this.pendingSectionAcks.some(x => x === id);
		if(!hadSections && !force) return false;
		this.streamSections.delete(key);
		this.pendingSectionAcks = this.pendingSectionAcks.filter(x => x !== id);
		this.pendingStreamCancellations.push(id);
		return true;
	}
	takeDecoderInstructions() {
		const out = [];
		if(this.pendingInsertCountIncrement > 0n) {
			out.push(prefixedInt(this.pendingInsertCountIncrement, 6, 0));
			this.pendingInsertCountIncrement = 0n;
		}
		for(const id of this.pendingSectionAcks.splice(0)) {
			out.push(prefixedInt(id, 7, 0x80));
			this.acknowledgeSection(id);
		}
		for(const id of this.pendingStreamCancellations.splice(0)) out.push(prefixedInt(id, 6, 0x40));
		return Buffer.concat(out);
	}
	_insert(name, value) {
		const before = this.table.insertCount;
		const entry = this.table.insert(name, value);
		if(entry.size > this.table.capacity) throw new QUICError('QPACK insertion exceeds dynamic table capacity', {
			code: 0x0201
		});
		this.knownInsertCount = this.table.insertCount;
		this.pendingInsertCountIncrement += 1n;
		return entry;
	}
	applyEncoderInstructions(buf) {
		buf = Buffer.from(buf || []);
		let o = 0;
		while(o < buf.length) {
			const start = o;
			const b = buf[o];
			try {
				if(b & 0x80) {
					const t = !!(b & 0x40);
					const x = readPrefixedInt(buf, o, 6);
					let cursor = x.offset;
					const name = t ? staticAt(Number(x.value))[0] : this.table.getRelative(Number(x.value)).name;
					const v = readStr(buf, cursor);
					cursor = v.offset;
					this._insert(name, v.value);
					o = cursor;
					continue;
				}
				if((b & 0xc0) === 0x40) {
					const x = readPrefixedInt(buf, o, 5);
					let cursor = x.offset;
					const nameLen = Number(x.value);
					if(!Number.isSafeInteger(nameLen)) throw new QUICError('Invalid QPACK literal name length', { code: 0x0201 });
					if(cursor + nameLen > buf.length) throw incomplete('Truncated QPACK literal name', 0x0201);
					const nameBuf = buf.subarray(cursor, cursor + nameLen);
					cursor += nameLen;
					const name = (b & 0x20) ? huffman.decode(nameBuf).toString('utf8') : nameBuf.toString('utf8');
					const v = readStr(buf, cursor);
					cursor = v.offset;
					this._insert(name, v.value);
					o = cursor;
					continue;
				}
				if((b & 0xe0) === 0x20) {
					const x = readPrefixedInt(buf, o, 5);
					if(x.value > BigInt(this.maxCapacity)) throw new QUICError('QPACK dynamic table capacity exceeds limit', { code: 0x0201 });
					this.table.setCapacity(Number(x.value));
					o = x.offset;
					continue;
				}
				if((b & 0xe0) === 0x00) {
					const x = readPrefixedInt(buf, o, 5);
					const e = this.table.getRelative(Number(x.value));
					this._insert(e.name, e.value);
					o = x.offset;
					continue;
				}
				throw new QUICError('Unknown QPACK encoder instruction', { code: 0x0201 });
			} catch(e) {
				if(e?.incomplete) return start;
				if(e instanceof QUICError) throw e;
				throw new QUICError(e.message || 'Invalid QPACK encoder instruction', { code: 0x0201 });
			}
		}
		return o;
	}

	_abs(abs) {
		abs = BigInt(abs);
		for(const e of this.table.entries)
			if(BigInt(e.abs) === abs) return e;
		throw new QUICError('Invalid QPACK dynamic absolute index', {
			code: 0x0200
		});
	}
	_decodeRic(encoded) {
		encoded = BigInt(encoded);
		if(encoded === 0n) return 0n;
		const maxEntries = Math.floor(this.maxCapacity / 32);
		if(maxEntries <= 0) throw new QUICError('Non-zero QPACK Required Insert Count with zero capacity', {
			code: 0x0200
		});
		const full = BigInt(2 * maxEntries);
		if(encoded > full) throw new QUICError('Invalid QPACK required insert count', {
			code: 0x0200
		});
		const maxValue = BigInt(this.knownInsertCount) + BigInt(maxEntries);
		let candidate = (maxValue / full) * full + encoded - 1n;
		if(candidate > maxValue) {
			if(candidate < full) throw new QUICError('Invalid QPACK wrapped insert count', {
				code: 0x0200
			});
			candidate -= full;
		}
		if(candidate === 0n) throw new QUICError('Invalid QPACK zero required insert count', {
			code: 0x0200
		});
		if(candidate > BigInt(this.knownInsertCount) + BigInt(maxEntries)) throw new QUICError('QPACK required insert count too far ahead', {
			code: 0x0200
		});
		return candidate;
	}
	decodeFieldSection(buf, { streamId = 0n } = {}) {
		buf = Buffer.from(buf);
		let o = 0;
		const ricEnc = readPrefixedInt(buf, o, 8);
		o = ricEnc.offset;
		const second = buf[o] ?? 0;
		const db = readPrefixedInt(buf, o, 7);
		o = db.offset;
		const s = !!(second & 0x80);
		const required = this._decodeRic(ricEnc.value);
		const delta = db.value;
		const base = s ? (required <= delta ? throwQpack() : required - delta - 1n) : required + delta;
		if(base < 0n) throw new QUICError('Negative QPACK base', {
			code: 0x0200
		});
		if(required > BigInt(this.knownInsertCount)) throw new QUICError('QPACK blocked field section', {
			code: 0x0200
		});
		const headers = [];
		const dyn = (abs) => this._abs(abs);
		while(o < buf.length) {
			const b = buf[o];
			if(b & 0x80) {
				const t = !!(b & 0x40);
				const x = readPrefixedInt(buf, o, 6);
				o = x.offset;
				if(t) {
					const e = staticAt(Number(x.value));
					headers.push(e.slice());
				} else {
					const abs = base - BigInt(x.value) - 1n;
					const e = dyn(abs);
					if(abs >= required) throw new QUICError('QPACK dynamic reference exceeds Required Insert Count', {
						code: 0x0200
					});
					headers.push([e.name, e.value]);
				}
				continue;
			}
			if((b & 0xf0) === 0x10) {
				const x = readPrefixedInt(buf, o, 4);
				o = x.offset;
				const abs = base + BigInt(x.value);
				const e = dyn(abs);
				if(abs >= required) throw new QUICError('QPACK post-base reference exceeds Required Insert Count', {
					code: 0x0200
				});
				headers.push([e.name, e.value]);
				continue;
			}
			if((b & 0xc0) === 0x40) {
				const n = !!(b & 0x20),
					t = !!(b & 0x10);
				const x = readPrefixedInt(buf, o, 4);
				o = x.offset;
				let name;
				if(t) name = staticAt(Number(x.value))[0];
				else {
					const abs = base - BigInt(x.value) - 1n;
					const e = dyn(abs);
					if(abs >= required) throw new QUICError('QPACK dynamic name reference exceeds Required Insert Count', {
						code: 0x0200
					});
					name = e.name;
				}
				const v = readStr(buf, o);
				o = v.offset;
				headers.push([name, v.value]);
				continue;
			}
			if((b & 0xe0) === 0x20) {
				const h = !!(b & 0x08);
				const x = readPrefixedInt(buf, o, 3);
				o = x.offset;
				const n = Number(x.value);
				if(!Number.isSafeInteger(n) || o + n > buf.length) throw new QUICError('Truncated QPACK field name', {
					code: 0x0200
				});
				const nb = buf.subarray(o, o + n);
				o += n;
				const name = (h ? huffman.decode(nb) : nb).toString('utf8');
				const v = readStr(buf, o);
				o = v.offset;
				headers.push([name, v.value]);
				continue;
			}
			if((b & 0xe0) === 0x00) {
				const x = readPrefixedInt(buf, o, 3);
				o = x.offset;
				const abs = base + BigInt(x.value);
				const e = dyn(abs);
				if(abs >= required) throw new QUICError('QPACK post-base name reference exceeds Required Insert Count', {
					code: 0x0200
				});
				const v = readStr(buf, o);
				o = v.offset;
				headers.push([e.name, v.value]);
				continue;
			}
			if((b & 0xe0) === 0x20) {
				const h = !!(b & 0x08);
				const x = readPrefixedInt(buf, o, 3);
				o = x.offset;
				const n = Number(x.value);
				if(!Number.isSafeInteger(n) || o + n > buf.length) throw new QUICError('Truncated QPACK field name', {
					code: 0x0200
				});
				const nb = buf.subarray(o, o + n);
				o += n;
				const name = (h ? huffman.decode(nb) : nb).toString('utf8');
				const v = readStr(buf, o);
				o = v.offset;
				headers.push([name, v.value]);
				continue;
			}
			throw new QUICError('Unsupported QPACK field representation', {
				code: 0x0200
			});
		}
		if(required > 0n) {
			const key = String(BigInt(streamId));
			const queue = this.streamSections.get(key) || [];
			queue.push(required);
			this.streamSections.set(key, queue);
			this.pendingSectionAcks.push(BigInt(streamId));
		}
		return headers;
	}
}

function throwQpack() {
	throw new QUICError('Invalid QPACK base', {
		code: 0x0200
	});
}
const defaultEncoder = new QPACKEncoder();
const defaultDecoder = new QPACKDecoder();

function encodeHeaders(headers, options) {
	return defaultEncoder.encodeFieldSection(headers, options);
}

function decodeHeaders(buf) {
	return defaultDecoder.decodeFieldSection(buf);
}

module.exports = {
	encodeHeaders,
	decodeHeaders,
	STATIC_TABLE,
	DynamicTable,
	QPACKEncoder,
	QPACKDecoder,
	prefixedInt,
	readPrefixedInt
};

module.exports.default = module.exports;