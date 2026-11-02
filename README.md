# @xof/quic

**A low-level QUIC v1/v2 and HTTP/3 stack for Node.js.**

`@xof/quic` provides transport and protocol primitives for building QUIC and HTTP/3 applications. It includes QUIC connection management, TLS 1.3 handshake support, stream flow control, loss recovery, congestion handling, QPACK, HTTP/3 messaging, and optional datagram-related extensions.

## Choose your language

| Documentation | English | Bahasa Indonesia |
| --- | --- | --- |
| Setup and usage | [Open `in.md`](./in.md) | [Buka `id.md`](./id.md) |
| Error handling | [Open `in.error.md`](./in.error.md) | [Buka `id.error.md`](./id.error.md) |

## At a glance

- **Runtime:** Node.js 20 or newer.
- **Module format:** CommonJS.
- **Protocols:** QUIC v1, QUIC v2, and HTTP/3.
- **Security modes:** TLS certificate mode or an explicitly configured pre-shared key (PSK).
- **Transport capabilities:** bidirectional and unidirectional streams, asynchronous writes, flow control, recovery, pacing, connection IDs, and optional path-MTU probing.
- **HTTP/3 capabilities:** request/response handling, QPACK, trailers, priorities, GOAWAY, HTTP Datagrams, and Capsule Protocol support for eligible CONNECT flows.

## Install

```bash
npm install @xof/quic
```

## Important

This package exposes a low-level protocol stack. It is not a drop-in replacement for `fetch`, `axios`, or Node.js `http`/`https`. Applications are responsible for configuring their listener, certificates or PSK, ALPN, connection lifecycle, and application-level routing.

For the complete installation guide, examples, configuration reference, and API overview, start with the language documentation above. For troubleshooting, use the matching error-handling guide.

## Project links

- [GitHub repository](https://github.com/Xyraakyzzz/XQuic)
- [Issue tracker](https://github.com/Xyraakyzzz/XQuic/issues)
- [XOF Project](https://github.com/xof-next)
