'use strict';

const { QUICServer, attachHTTP3 } = require('./lib');

const server = new QUICServer({
    host: '0.0.0.0',
    port: 4433,
    alpn: 'h3',
    noPsk: true,
    cert: './certs/cert.pem',
    key: './certs/key.pem'
});

server.on('listening', ({ address, port }) => {
    console.log(`XQUIC HTTP/3 Server listening on https://${address}:${port}`);
});

server.on('connection', conn => {
    console.log('[QUIC] Connection established');

    const h3 = attachHTTP3(conn);

    h3.on('request', req => {
        const contentType = req.headers['content-type'] || '-';
        const contentLength = Number(req.headers['content-length'] || 0);

        console.log(
             `[HTTP/3] ${req.method} ${req.path}` +
            ` | type=${contentType}` +
            ` | length=${contentLength}B`);

        let received = 0;
        const chunks = [];

        req.on('data', chunk => {
            received += chunk.length;
            chunks.push(chunk);

            console.log(`[HTTP/3 DATA] chunk=${chunk.length}B total=${received}B`);
        });

        req.on('end', () => {
            console.log(`[HTTP/3 BODY END] received=${received}B expected=${contentLength}B`);

            if (contentLength > 0 && received !== contentLength) {
                console.error(`[HTTP/3 BODY ERROR] expected ${contentLength}B, received ${received}`);
            }

            const body = Buffer.concat(chunks);
            if (body.length > 0 && body.length <= 4096) {
                console.log(`[HTTP/3 ECHO] ${body.toString('utf8')}`);
            }

            req.respond(200, { 'content-type': contentType === '-' ? 'application/octet-stream' : contentType }, body );
        });
    });

    h3.on('streamError', info => {
        console.error('[HTTP/3] Stream error:', info.error);
    });

    h3.on('close', () => {
        console.log('[HTTP/3] Connection closed');
    });
});

server.on('clientError', err => {
    console.error('[QUIC] Client error:', err);
});

server.on('error', err => {
    console.error('[QUIC] Server error:', err);
});

server.listen().catch(err => {
    console.error('[FATAL]', err);
    process.exitCode = 1;
});

process.once('SIGINT', async () => {
    console.log('\n[SHUTDOWN] Closing XQUIC server...');
    await server.close({ graceful: true, drainTimeout: 5000 }).catch(() => {});
    process.exit(0);
});