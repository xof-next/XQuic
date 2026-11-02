# @xof/quic — English documentation

`@xof/quic` is a low-level QUIC v1/v2 and HTTP/3 implementation for Node.js. It is intended for developers who need direct access to QUIC connections, streams, HTTP/3 messages, and transport-level diagnostics.

- [Back to the language selector](./README.md)
- [Error handling guide](./in.error.md)
- [Indonesian documentation](./id.md)

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Importing the package](#importing-the-package)
- [Security modes](#security-modes)
- [Create an HTTP/3 server](#create-an-http3-server)
- [Connect with an HTTP/3 client](#connect-with-an-http3-client)
- [Send a request body](#send-a-request-body)
- [Use QUIC streams directly](#use-quic-streams-directly)
- [API overview](#api-overview)
- [Configuration reference](#configuration-reference)
- [Operational and security notes](#operational-and-security-notes)
- [Troubleshooting](#troubleshooting)

## Requirements

| Requirement | Supported value |
| --- | --- |
| Node.js | `>=20.0.0` |
| Module system | CommonJS (`require`) |
| Runtime dependencies | Node.js built-in modules; no additional runtime package is declared |
| Network transport | UDP for QUIC |

The package is published as CommonJS. Use `require()` in your application.

## Installation

```bash
npm install @xof/quic
```

Verify the installed package:

```bash
npm ls @xof/quic
node --version
```

## Importing the package

```js
const {
  QUICClient,
  QUICServer,
  QUICConnection,
  HTTP3Connection,
  attachHTTP3,
  QUIC_VERSION,
  QUICError,
  QUICTransportError,
  QUICProtocolError,
  QUICCryptoError,
  H3,
  h3Name
} = require('@xof/quic');
```

The root export also exposes protocol constants, codecs, transport helpers, QPACK utilities, HTTP/3 helpers, structured-field utilities, Capsule Protocol helpers, and datagram helpers. The package is intentionally low-level; use only the parts your application needs.

## Security modes

XQuic supports two explicit handshake modes.

### TLS certificate mode

Use a certificate and private key on the server, and configure the client to validate that server's certificate. This is the recommended mode for public-facing HTTP/3 services.

- Server: set `noPsk: true`, `cert`, and `key`.
- Client: set `noPsk: true`; provide `ca` when the certificate chains to a private or development CA.
- Keep `rejectUnauthorized` enabled. It defaults to `true`.
- The `servername` value must match the certificate identity.

### Pre-shared key (PSK) mode

Both endpoints must be configured with the same deployment-specific PSK and identity. Keep the PSK in a secret manager or environment variable. Do not commit it to source control or reuse a development key in production.

Do not mix the two modes on opposite ends of the same connection. A client and server must agree on the handshake mode and ALPN.

## Create an HTTP/3 server

The following example starts an HTTP/3 endpoint using a PEM certificate and private key. Replace the file paths with certificates issued for your hostname. The certificate and key shipped with a development repository, if any, must not be treated as production credentials.

```js
const {
  QUICServer,
  attachHTTP3
} = require('@xof/quic');

const server = new QUICServer({
  host: '0.0.0.0',
  port: 4433,
  alpn: 'h3',
  noPsk: true,
  cert: './certs/fullchain.pem',
  key: './certs/privkey.pem'
});

server.on('connection', connection => {
  const h3 = attachHTTP3(connection);

  h3.on('request', req => {
    const chunks = [];

    req.on('data', chunk => chunks.push(chunk));
    req.on('error', error => {
      console.error('[HTTP/3 request]', error);
    });

    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const response = Buffer.from(JSON.stringify({
        ok: true,
        method: req.method,
        path: req.path,
        receivedBytes: body.length
      }));

      req.respond(200, {
        'content-type': 'application/json',
        'cache-control': 'no-store'
      }, response);
    });
  });

  h3.on('streamError', info => {
    console.error('[HTTP/3 stream error]', info.errorCode, info.error);
  });

  h3.on('error', error => {
    console.error('[HTTP/3 connection error]', error);
  });
});

server.on('clientError', error => {
  console.error('[QUIC client error]', error);
});

server.on('error', error => {
  console.error('[QUIC server error]', error);
});

server.listen()
  .then(() => {
    const { address, port } = server.addressInfo;
    console.log(`HTTP/3 listening on ${address}:${port}`);
  })
  .catch(error => {
    console.error('Unable to start QUIC server:', error);
    process.exitCode = 1;
  });

process.once('SIGINT', async () => {
  await server.close();
});
```

### Server behavior

- `server.listen()` returns a Promise and resolves after the UDP socket is bound.
- `connection` is emitted when a QUIC connection becomes ready.
- Call `attachHTTP3(connection)` once for each accepted connection.
- The HTTP/3 `request` event supplies a readable request stream. Read its body through `data` and `end` before responding when the application needs the complete body.
- `req.respond(status, headers, body)` sends the final response.

## Connect with an HTTP/3 client

`QUICClient.connect()` performs DNS lookup, binds a local UDP socket, starts the handshake, and returns the connection object. The handshake completes asynchronously. Attach HTTP/3 and wait for its `ready` event before creating requests.

```js
const fs = require('node:fs');
const {
  QUICClient,
  attachHTTP3
} = require('@xof/quic');

async function main() {
  const client = new QUICClient({
    host: 'localhost',
    port: 4433,
    alpn: 'h3',
    noPsk: true,
    servername: 'localhost',
    ca: fs.readFileSync('./certs/ca.pem')
  });

  let h3;

  try {
    const connection = await client.connect();
    h3 = attachHTTP3(connection);

    await new Promise((resolve, reject) => {
      h3.once('ready', resolve);
      h3.once('error', reject);
      connection.once('error', reject);
    });

    const request = h3.request({
      method: 'GET',
      scheme: 'https',
      authority: 'localhost:4433',
      path: '/'
    });

    const response = await request.response;

    console.log('HTTP status:', response.status);
    console.log('Response headers:', response.headers);
    console.log('Response body:', response.text());
  } finally {
    h3?.close();
    client.close();
  }
}

main().catch(error => {
  console.error('HTTP/3 request failed:', error);
  process.exitCode = 1;
});
```

For a publicly trusted certificate, you normally do not need to pass a custom `ca`. The default certificate verification remains enabled. For a private CA, pass that CA certificate through `ca`; do not disable verification to work around a certificate error.

### Request and response model

`h3.request(options)` returns a request handle with:

| Member | Description |
| --- | --- |
| `id` | QUIC request stream ID (`BigInt`) |
| `response` | Promise resolved with the completed response, or rejected on a request/stream failure |
| `write(data)` / `writeAsync(data, options)` | Write request-body data |
| `end(data)` / `endAsync(data, options)` | Finish the request stream, optionally with final data |
| `cancel()` | Cancel the request stream |
| `on(event, listener)` / `once(...)` / `off(...)` | Listen to events scoped to this request |

The resolved response contains `status`, `headers`, `trailers`, `body` (`Buffer`), `bodyBytes`, `text(encoding)`, and `json()`.

A response Promise normally resolves when the complete response stream ends. A successful `CONNECT` response is the exception: its response becomes available after the successful response headers, because the stream remains open for tunnel data.

## Send a request body

Pass a string or `Buffer` through `body` for a request that can be sent as a single body value:

```js
const request = h3.request({
  method: 'POST',
  authority: 'example.test',
  path: '/ingest',
  headers: {
    'content-type': 'application/json'
  },
  body: JSON.stringify({ event: 'created' })
});

const response = await request.response;
console.log(response.status, response.json());
```

For streaming uploads, omit `body` and write chunks explicitly:

```js
const request = h3.request({
  method: 'POST',
  authority: 'example.test',
  path: '/upload',
  headers: {
    'content-type': 'application/octet-stream'
  }
});

await request.writeAsync(Buffer.from('first chunk'));
await request.writeAsync(Buffer.from('second chunk'));
request.end();

const response = await request.response;
console.log(response.status);
```

When sending a `content-length` header, its value must match the exact body length in bytes. Do not set it for a streaming body unless your application can guarantee the final byte count. `CONNECT` requests follow different rules and cannot include an HTTP request body.

## Use QUIC streams directly

For applications that need transport-level control without HTTP/3 framing, use `QUICClient` and the returned `QUICConnection` directly.

```js
const { QUICClient } = require('@xof/quic');

async function main() {
  const client = new QUICClient({
    host: '127.0.0.1',
    port: 4433,
    alpn: 'xof',
    psk: process.env.QUIC_PSK,
    identity: 'my-service'
  });

  client.on('error', error => {
    console.error('[QUIC]', error.code, error.message);
  });

  try {
    const connection = await client.connect();

    await new Promise((resolve, reject) => {
      connection.once('ready', resolve);
      connection.once('error', reject);
    });

    const stream = connection.openStream();
    stream.write(Buffer.from('hello over QUIC'));
    stream.end();
  } finally {
    client.close();
  }
}

main().catch(console.error);
```

The peer must run a compatible QUIC endpoint configured with the same PSK, identity, and ALPN. For certificate mode, configure `noPsk: true` and the appropriate certificate settings instead.

### Stream methods

`connection.openStream()` creates a bidirectional stream. `connection.openUnidirectionalStream()` creates a unidirectional stream. Both return a stream handle with `id`, `write()`, `writeAsync()`, `end()`, `endAsync()`, and `reset()`; bidirectional stream handles also expose `on(event, listener)`.

At the connection level:

- `write(data, { streamId, offset, fin })` writes data to a stream.
- `writeAsync(data, { streamId, fin, signal, timeout, maxChunkSize })` waits for flow-control or congestion capacity and writes in chunks. It resolves with write statistics.
- `sendDatagram(data)` sends a QUIC DATAGRAM frame when peer support has been negotiated.
- `stopSending(streamId, errorCode)` asks the peer to stop sending on a stream.
- `resetStream(streamId, errorCode)` resets the local sending side of a stream.
- `close(code, reason)` closes the connection.

## API overview

### Main exports

| Export | Purpose |
| --- | --- |
| `QUICClient` | QUIC client and connection initiator |
| `QUICServer` | UDP QUIC server |
| `QUICConnection` | QUIC transport connection implementation |
| `HTTP3Connection` | HTTP/3 session bound to a QUIC connection |
| `attachHTTP3(connection, options)` | Creates and binds an HTTP/3 session |
| `QUIC_VERSION` | QUIC v1/v2 version constants |
| `QUICError` | Base QUIC error class and error-code constants |
| `QUICTransportError` | QUIC transport error type |
| `QUICProtocolError` | QUIC protocol error type |
| `QUICCryptoError` | TLS/cryptographic handshake error type |
| `H3`, `h3Name(code)` | HTTP/3 error constants and readable names |

### Useful events

| Emitter | Event | Meaning |
| --- | --- | --- |
| `QUICClient` | `connect` | Client connection is ready |
| `QUICClient` | `error` | Client, socket, or connection error |
| `QUICServer` | `listening` | UDP socket is bound |
| `QUICServer` | `connection` | A QUIC connection is ready |
| `QUICServer` | `clientError` | Error associated with a client connection |
| `QUICServer` | `error` | Server socket or listener error |
| `HTTP3Connection` | `ready` | HTTP/3 control and QPACK streams have been opened |
| `HTTP3Connection` | `settings` | Peer HTTP/3 SETTINGS received |
| `HTTP3Connection` | `request` | Incoming request; server side only |
| `HTTP3Connection` | `streamError` | Request-stream level error with an error code and cause |
| `HTTP3Connection` | `error` | HTTP/3 connection-level error |
| `HTTP3Connection` | `goaway` / `close` | Peer initiated draining or the session closed |

The HTTP/3 emitter also exposes message-related events such as `headers`, `data`, `trailers`, `end`, `informational`, and extension events for priority and datagrams. Event arguments are documented by the emitted event shape in the implementation; request-scoped listeners can be registered on the handle returned by `h3.request()`.

## Configuration reference

The following table lists commonly used constructor options. Advanced transport parameters are also accepted by the underlying connection implementation; consult the source before relying on less common tuning options.

### `QUICClient`

| Option | Default | Description |
| --- | --- | --- |
| `host` | `127.0.0.1` | Remote hostname or IP address |
| `port` | `4433` | Remote UDP port |
| `version` | `QUIC_VERSION.V1` | Initial QUIC version |
| `supportedVersions` | Initial version and v2 when starting with v1 | Versions accepted during version negotiation |
| `psk` | `null` | Deployment-specific pre-shared key |
| `noPsk` | `true` when no PSK is supplied | Select certificate/TLS mode when `true` |
| `identity` | `xof` | PSK identity |
| `alpn` | `xof` | Application protocol identifier; use `h3` for HTTP/3 |
| `servername` | `host` | TLS server name used for certificate validation |
| `ca` | Node.js trust store | Optional CA certificate or trust bundle |
| `rejectUnauthorized` | `true` | Validate the peer certificate |
| `handshakeTimeout` | `15000` ms | Handshake timeout; values are clamped to at least 1000 ms |
| `qlog` | `false` | Enable qlog collection |
| `maxDatagramFrameSize` | `0` | Advertised QUIC DATAGRAM frame capacity |
| `ipv6` | `false` | Use an IPv6 UDP socket |

### `QUICServer`

| Option | Default | Description |
| --- | --- | --- |
| `host` | `127.0.0.1` | Local bind address |
| `port` | `4433` | Local UDP port |
| `version` | `QUIC_VERSION.V1` | Preferred QUIC version |
| `supportedVersions` | Initial version and v2 when starting with v1 | QUIC versions accepted by the server |
| `psk` | `null` | Deployment-specific pre-shared key |
| `noPsk` | Certificate mode when cert/key are supplied | Explicitly selects certificate mode |
| `identity` | `xof` | PSK identity |
| `alpn` | `xof` | Application protocol identifier; use `h3` for HTTP/3 |
| `cert`, `key` | — | Server certificate and private key; required for certificate mode |
| `certChain` | `[]` | Additional certificate-chain entries |
| `requireRetry` | `false` | Require address validation through QUIC Retry |
| `handshakeTimeout` | `15000` ms | Handshake timeout |
| `qlog` | `false` | Enable qlog collection |
| `maxDatagramFrameSize` | `0` | Advertised QUIC DATAGRAM frame capacity |
| `ipv6` | `false` | Use an IPv6 UDP socket |

The HTTP/3 attachment accepts options for `settings`, `maxFieldSectionSize`, `maxBlockedFieldSectionBytes`, `maxStreamBufferBytes`, `maxCapsuleSize`, `knownCapsuleTypes`, and `useHuffman`. Review the implementation defaults and protocol requirements before changing these limits.

## Operational and security notes

1. **Allow UDP traffic.** QUIC runs over UDP. Opening only TCP/443 is not sufficient for a QUIC listener.
2. **Use matching ALPN values.** Configure `h3` on both sides for HTTP/3. The transport default is `xof`, not `h3`.
3. **Validate certificates.** Keep `rejectUnauthorized: true`, use a hostname matching the certificate, and configure a trusted CA when required.
4. **Protect PSKs and private keys.** Keep secrets outside source control and rotate them according to your deployment policy.
5. **Do not expose key material in production.** `exposeKeyMaterial` and `XOF_EXPOSE_KEY_MATERIAL` are diagnostic controls; leave them disabled unless you have a controlled debugging requirement.
6. **Set application limits.** Apply request-size limits, authentication, authorization, rate limiting, and timeouts at the application boundary.
7. **Treat the package as a protocol stack.** It does not provide a complete web framework, router, reverse proxy, or automatic HTTP/2/HTTP/1.1 fallback API.

HTTP/3 Server Push is not implemented by this stack. HTTP/3 Datagrams and Capsule Protocol APIs have negotiation and stream-state requirements; enable them only when both peers support and negotiate the corresponding settings.

## Troubleshooting

For error codes, likely causes, and recovery patterns, see the [Error Handling Guide](./in.error.md). The Indonesian guide is available at [id.error.md](./id.error.md).

Common checks:

- Confirm the hostname resolves and the UDP port is reachable.
- Confirm the server is listening on the expected address and port.
- Confirm both endpoints use the same security mode, PSK (if used), identity, and ALPN.
- For certificate mode, verify the certificate chain, hostname, and configured CA.
- Wait for the transport and HTTP/3 `ready` events before creating requests.
- For large stream writes, prefer `writeAsync()` and handle its rejected Promise.
- Check `error.code`, `error.transportCode`, `error.cause`, and `error.diagnosis` where present.
