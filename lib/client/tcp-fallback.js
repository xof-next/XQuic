'use strict';

const https = require('node:https');
const http2 = require('node:http2');
const net = require('node:net');

const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;

function peerCertificate(socket) {
    if (!socket || typeof socket.getPeerCertificate !== 'function') return null;
    let cert;
    try { cert = socket.getPeerCertificate(); } catch { return null; }
    if (!cert || Object.keys(cert).length === 0) return null;
    return {
        subject: cert.subject || null,
        issuer: cert.issuer || null,
        subjectAltName: cert.subjectaltname || null,
        validFrom: cert.valid_from || null,
        validTo: cert.valid_to || null,
        fingerprint256: cert.fingerprint256 || null,
        serialNumber: cert.serialNumber || null
    };
}

function getTLSMetadata(socket) {
    if (!socket) return null;
    let cipher = null;
    try { cipher = socket.getCipher?.() || null; } catch {}
    return {
        tlsVersion: socket.getProtocol?.() || null,
        cipher: cipher?.name || null,
        alpnProtocol: socket.alpnProtocol || null,
        authorized: socket.authorized === true,
        authorizationError: socket.authorizationError || null,
        servername: socket.servername || null,
        remoteAddress: socket.remoteAddress || null,
        remotePort: socket.remotePort || null,
        certificate: peerCertificate(socket)
    };
}

function bodyCollector(maxBodyBytes = DEFAULT_MAX_BODY_BYTES) {
    const chunks = [];
    let storedBytes = 0;
    let totalBytes = 0;
    let truncated = false;

    return {
        add(chunk) {
            const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            totalBytes += buffer.length;
            const remaining = Math.max(0, maxBodyBytes - storedBytes);
            if (remaining > 0) {
                const part = buffer.length > remaining ? buffer.subarray(0, remaining) : buffer;
                chunks.push(part);
                storedBytes += part.length;
            }
            if (storedBytes < totalBytes) truncated = true;
        },
        result() {
            return {
                body: Buffer.concat(chunks, storedBytes),
                bodyBytes: totalBytes,
                bodyTruncated: truncated
            };
        }
    };
}

function requestHttp2({
    host,
    port = 443,
    path = '/',
    timeout,
    connectTimeout = timeout ?? 5000,
    responseTimeout = timeout ?? 10000,
    ca,
    maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
    onEvent = () => {}
}) {
    if (!host || typeof host !== 'string') return Promise.reject(new TypeError('host is required'));
    if (!Number.isInteger(Number(port)) || Number(port) < 1 || Number(port) > 65535) return Promise.reject(new RangeError('port must be 1-65535'));
    if (typeof path !== 'string' || !path.startsWith('/') || /[\r\n]/.test(path)) return Promise.reject(new TypeError('path must be an origin-form path'));

    return new Promise((resolve, reject) => {
        const authorityHost = net.isIP(host) === 6 && !host.startsWith('[') ? `[${host}]` : host;
        const authority = Number(port) === 443 ? authorityHost : `${authorityHost}:${Number(port)}`;
        let session;
        let stream;
        let timer;
        let settled = false;
        let responseReceived = false;
        let responseHeaders = null;
        let tls = null;
        const collector = bodyCollector(maxBodyBytes);

        const armTimer = (ms, phase) => {
            clearTimeout(timer);
            timer = setTimeout(() => {
                const error = new Error(`HTTP/2 ${phase} timeout (${ms}ms)`);
                error.code = 'ETIMEDOUT';
                error.timeoutPhase = phase;
                fail(error);
            }, ms);
            timer.unref?.();
        };
        const cleanup = () => {
            clearTimeout(timer);
            if (session) {
                session.removeListener('error', onSessionError);
                session.removeListener('close', onSessionClose);
            }
            if (stream) {
                stream.removeListener('error', onStreamError);
                stream.removeListener('aborted', onStreamAborted);
            }
        };
        const fail = err => {
            if (settled) return;
            settled = true;
            cleanup();
            if (err && typeof err === 'object') err.responseReceived = responseReceived;
            try { session?.destroy(); } catch {}
            reject(err instanceof Error ? err : new Error(String(err)));
        };
        const finish = () => {
            if (settled) return;
            settled = true;
            cleanup();
            const body = collector.result();
            const result = {
                protocol: 'HTTP/2',
                status: Number(responseHeaders?.[':status'] || 0),
                headers: responseHeaders || Object.create(null),
                ...body,
                tls,
                remoteAddress: tls?.remoteAddress || null,
                durationMs: 0
            };
            try { session?.close(); } catch {}
            resolve(result);
        };
        const onSessionError = err => fail(err);
        const onSessionClose = () => {
            if (!settled) fail(new Error('HTTP/2 session closed before a complete response'));
        };
        const onStreamError = err => fail(err);
        const onStreamAborted = () => fail(new Error('HTTP/2 response stream was aborted'));

        timer = setTimeout(() => {
            const error = new Error(`HTTP/2 connect timeout (${connectTimeout}ms)`);
            error.code = 'ETIMEDOUT';
            error.timeoutPhase = 'connect';
            fail(error);
        }, connectTimeout);
        timer.unref?.();

        try {
            session = http2.connect(`https://${authority}`, {
                ...(net.isIP(host.replace(/^\[|\]$/g, '')) ? {} : { servername: host }),
                rejectUnauthorized: true,
                minVersion: 'TLSv1.2',
                ALPNProtocols: ['h2'],
                ...(ca ? { ca } : {})
            });
        } catch (err) {
            fail(err);
            return;
        }

        session.on('error', onSessionError);
        session.on('close', onSessionClose);
        session.once('connect', () => {
            armTimer(responseTimeout, 'response');
            const socket = session.socket;
            const alpn = session.alpnProtocol || socket?.alpnProtocol || null;
            tls = getTLSMetadata(socket);
            onEvent('TLS', `HTTP/2 TLS connected; ALPN=${alpn || '(none)'}`);
            if (alpn !== 'h2') {
                const error = new Error(`HTTP/2 requires ALPN h2; negotiated ${alpn || 'no protocol'}`);
                error.code = 'ERR_HTTP2_ALPN';
                fail(error);
                return;
            }

            try {
                stream = session.request({
                    ':method': 'GET',
                    ':scheme': 'https',
                    ':authority': authority,
                    ':path': path,
                    'user-agent': 'xof-quic-diagnostic',
                    'accept': '*/*'
                });
            } catch (err) {
                fail(err);
                return;
            }

            stream.on('response', headers => {
                responseReceived = true;
                responseHeaders = headers;
                tls = getTLSMetadata(session.socket) || tls;
                onEvent('HEADERS', `HTTP/2 status ${headers[':status'] || 'unknown'}`);
                for (const [name, value] of Object.entries(headers)) {
                    onEvent('HEADER', `${name}: ${Array.isArray(value) ? value.join(', ') : String(value)}`);
                }
            });
            stream.on('data', chunk => collector.add(chunk));
            stream.once('error', onStreamError);
            stream.once('aborted', onStreamAborted);
            stream.once('end', finish);
            stream.end();
        });
    });
}

function requestHttp1({
    host,
    port = 443,
    path = '/',
    timeout,
    connectTimeout = timeout ?? 5000,
    responseTimeout = timeout ?? 10000,
    ca,
    maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
    onEvent = () => {}
}) {
    if (!host || typeof host !== 'string') return Promise.reject(new TypeError('host is required'));
    if (!Number.isInteger(Number(port)) || Number(port) < 1 || Number(port) > 65535) return Promise.reject(new RangeError('port must be 1-65535'));
    if (typeof path !== 'string' || !path.startsWith('/') || /[\r\n]/.test(path)) return Promise.reject(new TypeError('path must be an origin-form path'));

    return new Promise((resolve, reject) => {
        const collector = bodyCollector(maxBodyBytes);
        let settled = false;
        let responseReceived = false;
        let timer;
        const started = process.hrtime.bigint();
        const requestOptions = {
            protocol: 'https:',
            hostname: host.replace(/^\[|\]$/g, ''),
            port: Number(port),
            path,
            method: 'GET',
            headers: {
                'user-agent': 'xof-quic-diagnostic',
                'accept': '*/*'
            },
            ...(net.isIP(host.replace(/^\[|\]$/g, '')) ? {} : { servername: host }),
            rejectUnauthorized: true,
            minVersion: 'TLSv1.2',
            ALPNProtocols: ['http/1.1'],
            agent: false,
            ...(ca ? { ca } : {})
        };
        let request;

        const armTimer = (ms, phase) => {
            clearTimeout(timer);
            timer = setTimeout(() => {
                const error = new Error(`HTTP/1.1 ${phase} timeout (${ms}ms)`);
                error.code = 'ETIMEDOUT';
                error.timeoutPhase = phase;
                fail(error);
            }, ms);
            timer.unref?.();
        };
        const cleanup = () => clearTimeout(timer);
        const fail = err => {
            if (settled) return;
            settled = true;
            cleanup();
            if (err && typeof err === 'object') err.responseReceived = responseReceived;
            try { request?.destroy(); } catch {}
            reject(err instanceof Error ? err : new Error(String(err)));
        };

        timer = setTimeout(() => {
            const error = new Error(`HTTP/1.1 connect timeout (${connectTimeout}ms)`);
            error.code = 'ETIMEDOUT';
            error.timeoutPhase = 'connect';
            fail(error);
        }, connectTimeout);
        timer.unref?.();

        try {
            request = https.request(requestOptions, response => {
                armTimer(responseTimeout, 'response');
                responseReceived = true;
                const tls = getTLSMetadata(response.socket);
                const headers = response.headers;
                onEvent('TLS', `HTTP/1.1 TLS connected; ALPN=${tls?.alpnProtocol || '(none; HTTP/1.1 client)'}`);
                onEvent('HEADERS', `HTTP/1.1 status ${response.statusCode || 'unknown'}`);
                for (const [name, value] of Object.entries(headers)) {
                    onEvent('HEADER', `${name}: ${Array.isArray(value) ? value.join(', ') : String(value)}`);
                }
                response.on('data', chunk => collector.add(chunk));
                response.once('error', err => fail(err));
                response.once('aborted', () => fail(new Error('HTTP/1.1 response was aborted')));
                response.once('end', () => {
                    if (settled) return;
                    settled = true;
                    cleanup();
                    resolve({
                        protocol: 'HTTP/1.1',
                        status: response.statusCode || 0,
                        headers,
                        ...collector.result(),
                        tls,
                        remoteAddress: response.socket?.remoteAddress || tls?.remoteAddress || null,
                        durationMs: Number(process.hrtime.bigint() - started) / 1e6
                    });
                });
            });
        } catch (err) {
            fail(err);
            return;
        }

        request.once('error', err => fail(err));
        request.once('socket', socket => {
            const onSecureConnect = () => armTimer(responseTimeout, 'response');
            if (socket.encrypted && socket.connecting) socket.once('secureConnect', onSecureConnect);
            else if (socket.encrypted && socket.authorized !== undefined) onSecureConnect();
        });
        request.end();
    });
}

module.exports = {
    DEFAULT_MAX_BODY_BYTES,
    getTLSMetadata,
    requestHttp2,
    requestHttp1
};
