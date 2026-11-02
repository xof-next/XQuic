# @xof/quic — Error Handling Guide

This guide explains how to capture, classify, diagnose, and recover from errors exposed by `@xof/quic`.

- [Back to the language selector](./README.md)
- [English setup and usage](./in.md)
- [Panduan error Bahasa Indonesia](./id.error.md)

## 1. Error handling principles

XQuic uses Node.js `EventEmitter`, Promises, and standard `Error` objects. Handle both synchronous exceptions and asynchronous failures:

- Wrap constructor calls and synchronous operations such as `request()`, `write()`, and `respond()` in `try/catch` where appropriate.
- Attach `error` listeners to long-lived emitters such as `QUICClient`, `QUICServer`, `QUICConnection`, and `HTTP3Connection`.
- Handle rejected Promises from `connect()`, `listen()`, `writeAsync()`, `endAsync()`, and `request.response`.
- On the HTTP/3 server, listen for `streamError` separately from connection-level `error` events.

An event listener does not replace Promise rejection handling. A request can fail after the call that created it has already returned.

## 2. Error object structure

The package exports four QUIC error classes:

| Class | Purpose |
| --- | --- |
| `QUICError` | Base error for QUIC validation, state, transport, and connection failures |
| `QUICTransportError` | Error carrying a QUIC transport error code |
| `QUICProtocolError` | Protocol-level transport error |
| `QUICCryptoError` | Cryptographic/TLS error carrying `cryptoErrorCode` |

Depending on the failure, an error may expose:

| Property | Meaning |
| --- | --- |
| `name` | Error class name |
| `message` | Human-readable description |
| `code` | Stable package code or a Node.js-style code such as `ETIMEDOUT` |
| `transportCode` | Numeric QUIC transport/application error code, when applicable |
| `frameType` | Frame type associated with an error, when available |
| `cryptoErrorCode` | TLS/crypto alert code on `QUICCryptoError` |
| `cause` | Underlying error supplied through the `cause` option |
| `diagnosis` | Additional connection diagnosis for selected DNS/handshake failures |

Do not assume every property exists on every error. Check it before logging or branching.

## 3. Recommended handling pattern

```js
const {
  QUICClient,
  attachHTTP3
} = require('@xof/quic');

async function run() {
  const client = new QUICClient({
    host: 'example.test',
    port: 443,
    alpn: 'h3',
    noPsk: true
  });

  client.on('error', error => {
    console.error('[client error]', {
      name: error.name,
      code: error.code,
      transportCode: error.transportCode,
      message: error.message
    });
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

    h3.on('streamError', info => {
      console.error('[stream error]', info.message, info.error);
    });

    const request = h3.request({
      method: 'GET',
      authority: 'example.test',
      path: '/health'
    });

    const response = await request.response;
    console.log(response.status, response.text());
  } catch (error) {
    console.error('[request failed]', error.code, error.message);
    console.error('cause:', error.cause);
    console.error('diagnosis:', error.diagnosis);
    throw error;
  } finally {
    h3?.close();
    client.close();
  }
}

run().catch(() => {
  process.exitCode = 1;
});
```

For production systems, prefer structured logging and avoid writing PSKs, private keys, raw TLS secrets, or sensitive request bodies into logs.

## 4. Common QUIC error codes

The following constants are available on `QUICError`. The constant value is the string to compare against `error.code`.

| Constant | Code value | Typical meaning |
| --- | --- | --- |
| `ERR_INVALID_ARGUMENT` | `ERR_QUIC_INVALID_ARGUMENT` | Invalid option, argument, or value |
| `ERR_INVALID_PACKET` | `ERR_QUIC_INVALID_PACKET` | Packet cannot be parsed or validated |
| `ERR_INVALID_VARINT` | `ERR_QUIC_INVALID_VARINT` | Invalid QUIC variable-length integer |
| `ERR_INVALID_CONNECTION_ID` | `ERR_QUIC_INVALID_CONNECTION_ID` | Invalid connection ID |
| `ERR_INVALID_PACKET_NUMBER` | `ERR_QUIC_INVALID_PACKET_NUMBER` | Invalid packet number |
| `ERR_INVALID_FRAME` | `ERR_QUIC_INVALID_FRAME` | Invalid or malformed frame |
| `ERR_INVALID_LENGTH` | `ERR_QUIC_INVALID_LENGTH` | Invalid length or payload exceeds a supported limit |
| `ERR_CRYPTO` | `ERR_QUIC_CRYPTO` | Cryptographic processing failure |
| `ERR_CRYPTO_BUFFER_EXCEEDED` | `ERR_QUIC_CRYPTO_BUFFER_EXCEEDED` | Crypto reassembly buffer limit exceeded |
| `ERR_PROTOCOL` | `ERR_QUIC_PROTOCOL` | QUIC protocol violation |
| `ERR_STATE` | `ERR_QUIC_STATE` | Operation is invalid in the current connection/stream state |
| `ERR_FLOW_CONTROL` | `ERR_QUIC_FLOW_CONTROL` | Stream or connection flow-control limit reached |
| `ERR_STREAM_LIMIT` | `ERR_QUIC_STREAM_LIMIT` | Stream limit or stream ownership violation |
| `ERR_STREAM_STATE` | `ERR_QUIC_STREAM_STATE` | Operation is not valid for the stream state |
| `ERR_CONNECTION_ID_LIMIT` | `ERR_QUIC_CONNECTION_ID_LIMIT` | Connection ID limit violation |
| `ERR_INTERNAL` | `ERR_QUIC_INTERNAL` | Internal implementation failure |
| `ERR_FINAL_SIZE` | `ERR_QUIC_FINAL_SIZE` | Inconsistent final stream size |
| `ERR_TRANSPORT_PARAMETER` | `ERR_QUIC_TRANSPORT_PARAMETER` | Invalid transport parameter |
| `ERR_KEY_UPDATE` | `ERR_QUIC_KEY_UPDATE` | Invalid or excessive key update |
| `ERR_CONNECTION_CLOSED` | `ERR_QUIC_CONNECTION_CLOSED` | Connection has closed |
| `ERR_HANDSHAKE_TIMEOUT` | `ETIMEDOUT` | Handshake did not complete before timeout |
| `ERR_DNS` | `ENOTFOUND` | DNS lookup failed |
| `ERR_UNREACHABLE` | `ERR_QUIC_UNREACHABLE` | Peer or network path is unreachable |
| `ERR_CERTIFICATE_CHAIN` | `ERR_QUIC_CERTIFICATE_CHAIN` | Certificate chain validation failed |

Example:

```js
const { QUICError } = require('@xof/quic');

try {
  connection.writeAsync(Buffer.alloc(1024 * 1024), {
    streamId: 0n,
    timeout: 5000
  });
} catch (error) {
  if (error.code === QUICError.ERR_FLOW_CONTROL) {
    console.error('Flow-control limit reached:', error.message);
  } else {
    throw error;
  }
}
```

`writeAsync()` is asynchronous; use `await` and `try/catch` to capture its rejected Promise:

```js
try {
  const result = await connection.writeAsync(payload, {
    streamId: 0n,
    timeout: 5000
  });
  console.log(result);
} catch (error) {
  console.error(error.code, error.message);
}
```

## 5. HTTP/3 error codes

The package exports `H3`, `H3_NAMES`, and `h3Name(code)`. Use constants as `H3.MESSAGE_ERROR`; the readable name returned by `h3Name()` is `MESSAGE_ERROR` (without an `H3_` prefix).

| Name | Code | Description |
| --- | ---: | --- |
| `NO_ERROR` | `0x100` | No HTTP/3 error |
| `GENERAL_PROTOCOL_ERROR` | `0x101` | General HTTP/3 protocol error |
| `INTERNAL_ERROR` | `0x102` | Internal HTTP/3 error |
| `STREAM_CREATION_ERROR` | `0x103` | Critical or stream creation failure |
| `CLOSED_CRITICAL_STREAM` | `0x104` | A critical HTTP/3 stream was closed |
| `FRAME_UNEXPECTED` | `0x105` | Frame is not valid in its current context |
| `FRAME_ERROR` | `0x106` | Malformed or invalid HTTP/3 frame |
| `EXCESSIVE_LOAD` | `0x107` | Resource or buffering limit exceeded |
| `ID_ERROR` | `0x108` | Invalid identifier or stream ID |
| `SETTINGS_ERROR` | `0x109` | Invalid SETTINGS value or configuration |
| `MISSING_SETTINGS` | `0x10a` | SETTINGS was not the first control-stream frame |
| `REQUEST_REJECTED` | `0x10b` | Request rejected |
| `REQUEST_CANCELLED` | `0x10c` | Request cancelled |
| `REQUEST_INCOMPLETE` | `0x10d` | Request did not complete |
| `MESSAGE_ERROR` | `0x10e` | HTTP message validation failed |
| `CONNECT_ERROR` | `0x10f` | CONNECT-related failure |
| `VERSION_FALLBACK` | `0x110` | Version fallback error |
| `QPACK_DECOMPRESSION_FAILED` | `0x200` | QPACK field section could not be decoded |
| `QPACK_ENCODER_STREAM_ERROR` | `0x201` | Invalid QPACK encoder instruction stream |
| `QPACK_DECODER_STREAM_ERROR` | `0x202` | Invalid QPACK decoder instruction stream |
| `DATAGRAM_ERROR` | `0x33` | HTTP Datagrams or Capsule Protocol error |

Use the helper for readable logs:

```js
const { H3, h3Name } = require('@xof/quic');

console.log(H3.MESSAGE_ERROR);        // 270
console.log(h3Name(H3.MESSAGE_ERROR)); // MESSAGE_ERROR
```

`h3Name()` returns `H3_UNKNOWN` for an unrecognized code.

## 6. Event routing: connection error vs stream error

Not every failed request requires the entire HTTP/3 connection to close.

### Connection-level errors

Listen to `h3.on('error', error => ...)`. Protocol failures that affect shared HTTP/3 state may cause the HTTP/3 layer to close the underlying QUIC connection. Examples include invalid critical streams, invalid control-stream state, or QPACK connection-level failures.

### Stream-level errors

Listen to `h3.on('streamError', info => ...)`:

```js
h3.on('streamError', ({ id, errorCode, error, message }) => {
  console.error({
    streamId: String(id),
    errorCode,
    errorName: message,
    detail: error?.message
  });
});
```

The stream error event carries the request/stream identifier, HTTP/3 error code, original `Error`, and readable error name. A malformed request body or content-length mismatch can fail one stream without being equivalent to a DNS or handshake failure.

### Transport-level errors

On a server, use `server.on('clientError', error => ...)` for errors associated with a peer connection. Use `server.on('error', error => ...)` for server socket/listener failures.

## 7. Common causes and recovery

| Symptom | Likely cause | Recommended checks |
| --- | --- | --- |
| `ENOTFOUND` | DNS lookup failed | Check hostname, DNS records, and resolver availability |
| `ETIMEDOUT` during handshake | UDP blocked, wrong port, peer unavailable, or incompatible handshake settings | Confirm UDP reachability, listener address/port, security mode, ALPN, and timeout |
| Certificate validation error | Untrusted CA, expired certificate, or hostname mismatch | Verify the certificate chain and `servername`; configure a trusted `ca` when necessary |
| PSK/handshake failure | Key or identity mismatch, or mixed PSK/certificate modes | Verify both endpoints use the same secret, identity, and mode |
| HTTP/3 session never becomes ready | QUIC handshake has not completed, or HTTP/3 negotiation/configuration failed | Observe connection `ready`/`error` and HTTP/3 `ready`/`error`; ensure ALPN is `h3` |
| UDP socket bind error | Port already in use or insufficient permission | Check the process using the port and operating-system permissions |
| `ERR_QUIC_FLOW_CONTROL` | Peer stream/connection credit is exhausted | Use `writeAsync()`, wait for writable capacity, and review peer limits |
| `ERR_QUIC_STATE` | Operation attempted before readiness or after close | Wait for `ready` and avoid writes after stream/connection closure |
| `MESSAGE_ERROR` | HTTP message framing or body-length mismatch | Verify `content-length`, HEAD/CONNECT rules, and request/response framing |
| `SETTINGS_ERROR` | Invalid or incompatible HTTP/3 setting | Check local and peer SETTINGS values and extension negotiation |
| `QPACK_*` | Invalid QPACK instruction or field section | Check peer compatibility, SETTINGS, and QPACK stream handling |
| `DATAGRAM_ERROR` | Datagram/Capsule negotiation or stream association is invalid | Verify both peers enabled the required setting and the request uses the required CONNECT semantics |

## 8. Handshake diagnosis

Selected DNS and handshake failures may include an `error.diagnosis` object.

For a DNS failure, the diagnosis can identify `DNS_FAILURE` and include the host and port. For a handshake timeout, the diagnostic object can include:

- `reason: 'QUIC_HANDSHAKE_TIMEOUT'`
- `host` and `port`
- `udpReachable: false` as the state observed by the failed QUIC attempt
- a `tcp443` probe result when the diagnostic TCP probe completes
- a coarse state such as `web-up-quic-unavailable` or `down-or-unreachable`

A successful TCP probe does **not** prove that QUIC is available. TCP and UDP are different transports. Treat diagnosis as troubleshooting evidence, not as a definitive network health verdict.

Example:

```js
client.on('error', error => {
  console.error('code:', error.code);
  console.error('message:', error.message);

  if (error.diagnosis) {
    console.error('diagnosis:', error.diagnosis);
  }

  if (error.cause) {
    console.error('underlying cause:', error.cause.message);
  }
});
```

## 9. Flow control and asynchronous writes

`connection.write()` is a synchronous low-level operation. It can throw when the connection is not open, stream state is invalid, flow-control credit is exhausted, or the congestion window cannot accept more data.

For larger payloads, use `writeAsync()`:

```js
const controller = new AbortController();

try {
  const result = await connection.writeAsync(largeBuffer, {
    streamId: stream.id,
    signal: controller.signal,
    timeout: 15000,
    maxChunkSize: 1000
  });

  console.log('bytes written:', result.bytesWritten);
} catch (error) {
  if (error.code === 'ETIMEDOUT') {
    console.error('Timed out while waiting for transport capacity');
  } else {
    console.error('Write failed:', error.code, error.message);
  }
}
```

`writeAsync()` appends to the current stream offset. It does not accept an explicit `offset`. Its `timeout` applies while waiting for flow-control or congestion capacity; it is not a general request-response timeout.

## 10. Safe logging checklist

- Log `name`, `code`, `transportCode`, `message`, and a request/stream ID when available.
- Preserve `cause` for debugging, but sanitize it before sending logs to third-party services.
- Do not log PSKs, private keys, TLS traffic secrets, authentication headers, or private request bodies.
- Keep `exposeKeyMaterial` disabled outside isolated debugging environments.
- Avoid retrying a request automatically after a response has already started unless the application can guarantee that the operation is safe and idempotent.
- Close sessions and client sockets during application shutdown.

For setup examples and the full API overview, see the [English documentation](./in.md) or [Indonesian documentation](./id.md).
