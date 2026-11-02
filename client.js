'use strict';

const fs = require('node:fs');
const { X509Certificate } = require('node:crypto');
const dns = require('node:dns').promises;
const { QUICClient, attachHTTP3 } = require('./lib');
const { requestHttp2, requestHttp1 } = require('./lib/client/tcp-fallback');

const DEFAULT_CONNECT_TIMEOUT = 5000;
const DEFAULT_RESPONSE_TIMEOUT = 10000;
const MAX_BODY_PREVIEW = 512;
const SAVE_DIAGNOSTICS = process.env.XOF_SAVE_DIAGNOSTICS === '1';
const DIAGNOSTIC_FILE = process.env.XOF_DIAGNOSTIC_FILE || './xquic-client.log';

function parseArgs(argv) {
    if (argv.length === 1 && (argv[0] === '--help' || argv[0] === '-h')) return { help: true };
    const args = [...argv];
    const host = args.shift();
    let port = 443;
    if (args.length && /^\d+$/.test(args[0])) port = Number(args.shift());
    let timeout = DEFAULT_CONNECT_TIMEOUT;
    let responseTimeout = DEFAULT_RESPONSE_TIMEOUT;
    let fallback = true;
    let path = '/';
    let caPath = null;

    while (args.length) {
        const arg = args.shift();
        if (arg === '--no-fallback') fallback = false;
        else if (arg === '--connect-timeout') timeout = Number(args.shift());
        else if (arg.startsWith('--connect-timeout=')) timeout = Number(arg.slice('--connect-timeout='.length));
        else if (arg === '--response-timeout') responseTimeout = Number(args.shift());
        else if (arg.startsWith('--response-timeout=')) responseTimeout = Number(arg.slice('--response-timeout='.length));
        else if (arg === '--path') path = String(args.shift() || '');
        else if (arg.startsWith('--path=')) path = arg.slice('--path='.length);
        else if (arg === '--ca') caPath = String(args.shift() || '');
        else if (arg.startsWith('--ca=')) caPath = arg.slice('--ca='.length);
        else if (arg === '--help' || arg === '-h') return { help: true };
        else throw new Error(`Unknown option: ${arg}`);
    }

    if (!host || typeof host !== 'string') throw new Error('host is required');
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('port must be an integer from 1 to 65535');
    if (!Number.isFinite(timeout) || timeout < 1000 || timeout > 120000) throw new Error('--connect-timeout must be between 1000 and 120000 ms');
    if (!Number.isFinite(responseTimeout) || responseTimeout < 1000 || responseTimeout > 300000) throw new Error('--response-timeout must be between 1000 and 300000 ms');
    if (typeof path !== 'string' || !path.startsWith('/') || /[\r\n]/.test(path)) throw new Error('--path must start with / and must not contain CR/LF');

    let url;
    try { url = new URL(`https://${host}:${port}${path}`); }
    catch { throw new Error('host/path is not a valid HTTPS target'); }
    if (url.hostname.toLowerCase() !== host.toLowerCase() && !(host.startsWith('[') && url.hostname === host.slice(1, -1))) {
        throw new Error('host must be a hostname or IP literal, not a URL or authority string');
    }
    if (caPath !== null && (!caPath || /[\r\n]/.test(caPath))) throw new Error('--ca requires a valid certificate file path');
    return { host, port, timeout, responseTimeout, fallback, path, caPath };
}

const startedAt = process.hrtime.bigint();
let previousAt = startedAt;
const logLines = [];

function logEvent(label, message) {
    const now = process.hrtime.bigint();
    const elapsed = Number(now - startedAt) / 1e6;
    const delta = Number(now - previousAt) / 1e6;
    previousAt = now;
    const line = `[${elapsed.toFixed(2).padStart(9)} ms | +${delta.toFixed(2).padStart(9)} ms] ${String(label).toUpperCase().padEnd(10)} ${message}`;
    logLines.push(line);
    console.log(line);
}

function safeJson(value, maxLength = 2400) {
    let text;
    try {
        text = JSON.stringify(value, (_key, item) => {
            if (Buffer.isBuffer(item)) return `<Buffer ${item.length} bytes>`;
            if (typeof item === 'bigint') return item.toString();
            return item;
        }, 2);
    } catch (err) {
        text = String(value);
    }
    if (text.length > maxLength) return `${text.slice(0, maxLength)}… [truncated]`;
    return text;
}

function summarizeBody(body) {
    const buffer = Buffer.isBuffer(body) ? body : Buffer.from(body || '');
    const preview = buffer.subarray(0, MAX_BODY_PREVIEW).toString('utf8');
    return {
        bytes: buffer.length,
        preview: preview + (buffer.length > MAX_BODY_PREVIEW ? '… [preview truncated]' : '')
    };
}

function waitReady(conn, timeout, logger) {
    if (conn.readyState === 'open') return Promise.resolve(conn);
    return new Promise((resolve, reject) => {
        const start = process.hrtime.bigint();
        let settled = false;
        const cleanup = () => {
            clearTimeout(timer);
            clearInterval(progress);
            conn.off('ready', onReady);
            conn.off('error', onError);
        };
        const finish = (err) => {
            if (settled) return;
            settled = true;
            cleanup();
            err ? reject(err) : resolve(conn);
        };
        const onReady = () => finish();
        const onError = err => finish(err);
        const timer = setTimeout(() => {
            const err = new Error(`QUIC handshake timeout (${timeout}ms)`);
            err.code = 'ERR_QUIC_HANDSHAKE_TIMEOUT';
            finish(err);
        }, timeout);
        const progress = setInterval(() => {
            const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
            logger('HANDSHAKE', `still waiting... state=${conn.readyState}, elapsed ${elapsed.toFixed(2)} ms`);
        }, 1000);
        timer.unref?.();
        progress.unref?.();
        conn.once('ready', onReady);
        conn.once('error', onError);
    });
}

function monitorSettings(h3, timeout, logger = logEvent) {
    // SETTINGS arrive instead of blocking request transmission. Keep observing
    // the control stream, but make a missing SETTINGS frame diagnostic-only;
    // the request's own response deadline remains authoritative.
    let timer = null;
    let stopped = false;
    let warned = false;

    const cleanup = () => {
        if (stopped) return;
        stopped = true;
        if (timer) clearTimeout(timer);
        h3.off('settings', onSettings);
    };
    const onSettings = () => {
        if (stopped) return;
        logger('HTTP/3', 'peer SETTINGS received');
        cleanup();
    };

    if (h3.settingsReceived) {
        logger('HTTP/3', 'peer SETTINGS received before request setup');
        return cleanup;
    }

    h3.once('settings', onSettings);
    timer = setTimeout(() => {
        timer = null;
        if (stopped || h3.settingsReceived || warned) return;
        warned = true;
        logger('HTTP/3', `peer SETTINGS not observed within ${timeout}ms; continuing with initial defaults`);
    }, timeout);
    timer.unref?.();
    return cleanup;
}

function withTimeout(promise, timeout, label) {
    let timer;
    return Promise.race([
        promise,
        new Promise((_, reject) => {
            timer = setTimeout(() => {
                const err = new Error(`${label} timeout (${timeout}ms)`);
                err.code = 'ETIMEDOUT';
                reject(err);
            }, timeout);
            timer.unref?.();
        })
    ]).finally(() => clearTimeout(timer));
}

function closeQuic(client, conn) {
    try { conn?.close?.(); } catch {}
    try { client?.close?.(); } catch {}
}

function isCertificateValidationFailure(err) {
    const seen = new Set();
    let current = err;
    for (let depth = 0; current && depth < 6 && !seen.has(current); depth++, current = current.cause) {
        seen.add(current);
        const transportCode = String(current.transportCode || '');
        const code = String(current.code || '');
        const message = String(current.message || '');
        if (transportCode.startsWith('CERTIFICATE_') || code === 'ERR_QUIC_CERTIFICATE_CHAIN') return true;
        if ((code === 'ERR_QUIC_CRYPTO' || code === 'ERR_QUIC_PROTOCOL') &&
            /certificate|hostname|untrusted root|trusted root|certificateverify/i.test(message)) return true;
        if (/certificate hostname mismatch|untrusted root certificate|certificate chain|certificateverify signature invalid/i.test(message)) return true;
    }
    return false;
}

async function attemptHttp3({ host, address, family, port, path, timeout, responseTimeout, ca }) {
    const client = new QUICClient({
        host: address,
        port,
        ipv6: family === 6,
        version: 1,
        alpn: 'h3',
        noPsk: true,
        servername: host,
        ca,
        rejectUnauthorized: true,
        handshakeTimeout: Math.min(120000, timeout + 1500),
        qlog: false
    });
    let conn = null;
    let stopSettingsMonitor = () => {};

    try {
        client.on('error', err => logEvent('QUIC', `client error: ${err.message}`));
        client.on('versionNegotiation', info => logEvent('QUIC', `version negotiation: ${safeJson(info, 400)}`));
        conn = await client.connect(address, port);
        const local = client.socket?.address?.();
        logEvent('UDP', `QUIC connection object created; local=${local?.address || '?'}:${local?.port || '?'}, remote=${address}:${port}`);

        // Attach HTTP/3 stream listeners before awaiting the TLS/QUIC ready event.
        // This prevents any immediately delivered peer uni-stream bytes from being
        // emitted before the HTTP/3 layer has subscribed to the transport.
        const h3 = attachHTTP3(conn, { useHuffman: true, maxFieldSectionSize: 65536 });
        h3.on('error', err => logEvent('HTTP/3', `error: ${err.message}`));
        logEvent('STATE', 'HTTP/3 receive layer attached; QUIC Initial sent / handshake pending');
        logEvent('HANDSHAKE', 'waiting for QUIC TLS handshake...');
        await waitReady(conn, timeout, logEvent);

        logEvent('HANDSHAKE', `complete; QUIC v${conn.version}, ALPN=${conn.selectedALPN || 'h3'}`);
        const diagnostics = typeof conn.getDiagnostics === 'function' ? conn.getDiagnostics() : null;
        const certMeta = diagnostics?.tls?.peer?.certificate || null;
        const cipher = diagnostics?.crypto?.handshake?.cipher || 'TLS_AES_128_GCM_SHA256';
        logEvent('TLS', `version=TLSv1.3, cipher=${cipher}, hostname=${host}, certificate trust=${certMeta?.trustValidated ? 'verified' : 'not reported'}`);
        if (certMeta) logEvent('CERT', safeJson(certMeta, 1600));
        else logEvent('CERT', 'peer certificate summary not available from connection diagnostics');
        if (conn.getPath) logEvent('PATH', safeJson(conn.getPath(), 700));
        if (conn.getPeerTransportParameters) logEvent('QUIC PARAMS', safeJson(conn.getPeerTransportParameters(), 1000));

        stopSettingsMonitor = monitorSettings(h3, timeout, logEvent);
        logEvent('STATE', 'HTTP/3 control/QPACK streams initialized; sending GET without blocking on peer SETTINGS');
        const authority = port === 443 ? host : `${host}:${port}`;
        const request = h3.request({ method: 'GET', scheme: 'https', authority, path });
        let finalHeadersReceived = false;
        request.once('headers', headers => {
            const status = Number(headers?.[':status'] || 0);
            if (status >= 200) {
                finalHeadersReceived = true;
                logEvent('HEADERS', `HTTP/3 status ${status}`);
                for (const [name, value] of Object.entries(headers || {})) logEvent('HEADER', `${name}: ${Array.isArray(value) ? value.join(', ') : String(value)}`);
            }
        });
        logEvent('REQUEST', `GET ${path} over HTTP/3; stream=${request.id}`);
        let state;
        try {
            state = await withTimeout(request.response, responseTimeout, 'HTTP/3 response');
        } catch (err) {
            err.responseReceived = finalHeadersReceived;
            throw err;
        }
        const body = Buffer.isBuffer(state.body) ? state.body : Buffer.from(state.body || '');
        const headers = state.headers || Object.create(null);
        const bodySummary = summarizeBody(body);
        logEvent('BODY', `${bodySummary.bytes} bytes; preview=${JSON.stringify(bodySummary.preview)}`);
        if (!h3.settingsReceived) {
            logEvent('HTTP/3', 'warning: response completed before peer SETTINGS was observed; HTTP/3 defaults were used for this request');
        }
        logEvent('RESULT', `protocol=HTTP/3, fallback=not-used, peerSettings=${h3.settingsReceived ? 'received' : 'not-observed'}`);
        return { protocol: 'HTTP/3', status: Number(state.status ?? headers[':status'] ?? 0), headers, body, peerSettingsReceived: h3.settingsReceived, quic: { version: conn.version, alpn: conn.selectedALPN || 'h3', readyState: conn.readyState, path: conn.getPath?.() || null, peerTransportParameters: conn.getPeerTransportParameters?.() || null } };
    } finally {
        stopSettingsMonitor();
        closeQuic(client, conn);
    }
}

async function tryTCPFallback(options) {
    logEvent('FALLBACK', 'QUIC/HTTP/3 did not produce a response; trying TCP-based HTTPS (GET may be retried safely)');
    let h2Error;
    try {
        logEvent('STATE', 'connecting TCP/TLS with ALPN h2...');
        const result = await requestHttp2({ ...options, connectTimeout: options.connectTimeout ?? 5000, responseTimeout: options.responseTimeout ?? options.timeout ?? 10000, onEvent: logEvent });
        logEvent('RESULT', `protocol=HTTP/2, status=${result.status}, fallback=used`);
        logEvent('TLS META', safeJson(result.tls, 2000));
        logEvent('BODY', `${result.bodyBytes} bytes${result.bodyTruncated ? ' (stored preview/body capped)' : ''}; preview=${JSON.stringify(summarizeBody(result.body).preview)}`);
        return result;
    } catch (err) {
        h2Error = err;
        logEvent('HTTP/2', `failed before a complete response: ${err.code || err.name}: ${err.message}`);
        if (err.responseReceived) {
            err.fallbackStopped = true;
            throw err;
        }
    }

    try {
        logEvent('STATE', 'HTTP/2 unavailable; connecting TCP/TLS with ALPN http/1.1...');
        const result = await requestHttp1({ ...options, connectTimeout: options.connectTimeout ?? 5000, responseTimeout: options.responseTimeout ?? options.timeout ?? 10000, onEvent: logEvent });
        logEvent('RESULT', `protocol=HTTP/1.1, status=${result.status}, fallback=used`);
        logEvent('TLS META', safeJson(result.tls, 2000));
        logEvent('BODY', `${result.bodyBytes} bytes${result.bodyTruncated ? ' (stored preview/body capped)' : ''}; preview=${JSON.stringify(summarizeBody(result.body).preview)}`);
        return result;
    } catch (h1Error) {
        logEvent('HTTP/1.1', `failed: ${h1Error.code || h1Error.name}: ${h1Error.message}`);
        h1Error.cause = h1Error.cause || h2Error;
        throw h1Error;
    }
}

function validateCABundle(buffer, filename) {
    const pem = Buffer.isBuffer(buffer) ? buffer.toString('utf8') : String(buffer || '');
    const certs = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
    if (!certs.length) throw new Error(`CA file ${filename} contains no PEM CERTIFICATE block`);
    for (const certificate of certs) new X509Certificate(certificate);
    return buffer;
}

function saveDiagnostics() {
    if (!SAVE_DIAGNOSTICS) return;
    try {
        fs.writeFileSync(DIAGNOSTIC_FILE, logLines.join('\n') + '\n', { encoding: 'utf8', mode: 0o600, flag: 'w' });
        fs.chmodSync(DIAGNOSTIC_FILE, 0o600);
        console.log(`Diagnostic metadata saved with owner-only permissions: ${DIAGNOSTIC_FILE}`);
    } catch (err) {
        console.error(`Failed to save diagnostic metadata: ${err.message}`);
    }
}

async function main() {
    let options;
    try { options = parseArgs(process.argv.slice(2)); }
    catch (err) {
        console.error(`Error: ${err.message}\nUsage: node client.js <host> [port] [--connect-timeout ms] [--response-timeout ms] [--path /] [--ca trusted-ca.pem] [--no-fallback]`);
        process.exitCode = 2;
        return;
    }
    if (options.help) {
        console.log('Usage: node client.js <host> [port] [--connect-timeout ms] [--response-timeout ms] [--path /] [--ca trusted-ca.pem] [--no-fallback]');
        console.log('Attempts HTTP/3 first, then HTTP/2 and HTTP/1.1 over verified TLS if the H3 attempt fails before a response.');
        console.log('Certificate verification is always enabled. --ca uses a supplied trust store; it does not disable hostname checks.');
        return;
    }

    const { host, port, timeout, responseTimeout, fallback, path, caPath } = options;
    logEvent('START', `target https://${host}:${port}${path}`);
    let ca;
    try {
        if (caPath) {
            ca = validateCABundle(fs.readFileSync(caPath), caPath);
            logEvent('TLS', `using explicit CA trust store ${caPath}; hostname verification remains enabled`);
        }
    } catch (err) {
        logEvent('TLS', `cannot read CA file: ${err.message}`);
        process.exitCode = 2;
        saveDiagnostics();
        return;
    }
    logEvent('META', `method=GET, connectTimeout=${timeout}ms, responseTimeout=${responseTimeout}ms, fallback=${fallback ? 'enabled' : 'disabled'}`);
    let address;
    try {
        const addresses = await dns.lookup(host, { all: true, verbatim: true });
        const selected = addresses.find(item => item.family === 4) || addresses[0];
        if (!selected) throw Object.assign(new Error('No address found'), { code: 'ENODATA' });
        address = selected;
        logEvent('DNS', `${host} resolved to ${address.address} (IPv${address.family})`);
    } catch (err) {
        logEvent('DNS', `resolution failed: ${err.code || err.name}: ${err.message}`);
        process.exitCode = 1;
        saveDiagnostics();
        return;
    }

    try {
        logEvent('STATE', 'attempting HTTP/3 over QUIC/UDP first; certificate verification remains enabled');
        const result = await attemptHttp3({ host, address: address.address, family: address.family, port, path, timeout, responseTimeout, ca });
        logEvent('DONE', `HTTP/3 response received; status=${result.status}`);
        logEvent('META', safeJson({ protocol: result.protocol, status: result.status, bodyBytes: result.body.length, peerSettingsReceived: result.peerSettingsReceived, quic: result.quic }, 2800));
    } catch (h3Error) {
        logEvent('HTTP/3', `attempt failed: ${h3Error.code || h3Error.name}${h3Error.transportCode ? `/${h3Error.transportCode}` : ''}: ${h3Error.message}`);
        if (h3Error.responseReceived) {
            logEvent('FALLBACK', 'stopped: an HTTP/3 final response was already received; not retrying on another protocol');
            process.exitCode = 1;
        } else if (isCertificateValidationFailure(h3Error)) {
            logEvent('SECURITY', `certificate validation failed${h3Error.transportCode ? ` (${h3Error.transportCode})` : ''}; refusing automatic TCP fallback`);
            logEvent('DONE', 'request stopped because the QUIC peer identity could not be authenticated; verify the target hostname and configure a trusted CA with --ca when using a private test certificate');
            process.exitCode = 1;
        } else if (!fallback) {
            logEvent('DONE', 'fallback disabled; no TCP retry performed');
            process.exitCode = 1;
        } else {
            try {
                const result = await tryTCPFallback({ host, port, path, connectTimeout: timeout, responseTimeout, ca, maxBodyBytes: 1024 * 1024 });
                logEvent('DONE', `${result.protocol} response received; status=${result.status}`);
                logEvent('META', safeJson({ protocol: result.protocol, status: result.status, bodyBytes: result.bodyBytes, bodyTruncated: result.bodyTruncated, tls: result.tls }, 3200));
            } catch (tcpError) {
                logEvent('DONE', `all protocols failed: ${tcpError.code || tcpError.name}: ${tcpError.message}`);
                process.exitCode = 1;
            }
        }
    } finally {
        saveDiagnostics();
    }
}

main().catch(err => {
    logEvent('FATAL', `${err.code || err.name}: ${err.message}`);
    process.exitCode = 1;
    saveDiagnostics();
});
