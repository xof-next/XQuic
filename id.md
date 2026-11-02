# @xof/quic — Dokumentasi Bahasa Indonesia

`@xof/quic` adalah implementasi stack QUIC v1/v2 dan HTTP/3 tingkat rendah untuk Node.js. Paket ini ditujukan bagi developer yang membutuhkan kontrol langsung terhadap koneksi QUIC, stream, pesan HTTP/3, dan diagnostik transport.

- [Kembali ke pemilih bahasa](./README.md)
- [Panduan penanganan error](./id.error.md)
- [English documentation](./in.md)

## Daftar isi

- [Persyaratan](#persyaratan)
- [Instalasi](#instalasi)
- [Import package](#import-package)
- [Mode keamanan](#mode-keamanan)
- [Membuat server HTTP/3](#membuat-server-http3)
- [Menghubungkan client HTTP/3](#menghubungkan-client-http3)
- [Mengirim request body](#mengirim-request-body)
- [Menggunakan QUIC stream secara langsung](#menggunakan-quic-stream-secara-langsung)
- [Ringkasan API](#ringkasan-api)
- [Referensi konfigurasi](#referensi-konfigurasi)
- [Catatan operasional dan keamanan](#catatan-operasional-dan-keamanan)
- [Troubleshooting](#troubleshooting)

## Persyaratan

| Persyaratan | Nilai yang didukung |
| --- | --- |
| Node.js | `>=20.0.0` |
| Sistem module | CommonJS (`require`) |
| Runtime dependency | Modul bawaan Node.js; tidak ada runtime package tambahan yang dideklarasikan |
| Transport jaringan | UDP untuk QUIC |

Package dipublikasikan dalam format CommonJS. Gunakan `require()` pada aplikasi.

## Instalasi

```bash
npm install @xof/quic
```

Periksa package yang terpasang:

```bash
npm ls @xof/quic
node --version
```

## Import package

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

Root export juga menyediakan konstanta protokol, codec, helper transport, utilitas QPACK, helper HTTP/3, structured-field, Capsule Protocol, dan datagram. API dibuat tingkat rendah; gunakan komponen yang memang diperlukan aplikasi.

## Mode keamanan

XQuic menyediakan dua mode handshake yang harus dikonfigurasi secara eksplisit dan konsisten di kedua sisi.

### Mode sertifikat TLS

Gunakan sertifikat dan private key pada server, lalu pastikan client memvalidasi sertifikat server. Mode ini direkomendasikan untuk layanan HTTP/3 yang diakses publik.

- Server: atur `noPsk: true`, `cert`, dan `key`.
- Client: atur `noPsk: true`; berikan `ca` jika sertifikat menggunakan CA privat atau CA development.
- Biarkan `rejectUnauthorized` aktif. Nilai default-nya `true`.
- Nilai `servername` harus sesuai dengan identitas pada sertifikat.

### Mode pre-shared key (PSK)

Kedua endpoint wajib menggunakan PSK khusus deployment dan identity yang sama. Simpan PSK di secret manager atau environment variable. Jangan commit PSK ke repository dan jangan gunakan ulang key development untuk production.

Jangan mencampur mode keamanan yang berbeda pada dua endpoint dalam koneksi yang sama. Kedua sisi harus sepakat tentang mode handshake dan ALPN.

## Membuat server HTTP/3

Contoh berikut menjalankan endpoint HTTP/3 menggunakan sertifikat PEM dan private key. Ganti path file dengan sertifikat yang diterbitkan untuk hostname milikmu. Sertifikat dan key development yang mungkin ada di repository tidak boleh dianggap sebagai kredensial production.

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
  .then(({ address, port }) => {
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

### Cara kerja server

- `server.listen()` mengembalikan Promise dan selesai ketika UDP socket berhasil di-bind.
- Event `connection` dikirim ketika koneksi QUIC sudah siap.
- Panggil `attachHTTP3(connection)` satu kali untuk setiap koneksi yang diterima.
- Event HTTP/3 `request` memberikan request stream yang dapat dibaca. Baca body melalui event `data` dan `end` sebelum mengirim response apabila aplikasi membutuhkan seluruh body.
- `req.respond(status, headers, body)` mengirim response final.

## Menghubungkan client HTTP/3

`QUICClient.connect()` melakukan DNS lookup, bind UDP socket lokal, memulai handshake, lalu mengembalikan objek koneksi. Handshake selesai secara asynchronous. Pasang HTTP/3 dan tunggu event `ready` sebelum membuat request.

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

Untuk sertifikat publik yang sudah dipercaya sistem, biasanya kamu tidak perlu mengirim `ca` khusus. Validasi sertifikat tetap aktif secara default. Untuk private CA, berikan sertifikat CA melalui `ca`; jangan menonaktifkan validasi hanya untuk menghindari error sertifikat.

### Model request dan response

`h3.request(options)` mengembalikan handle request dengan properti berikut:

| Member | Penjelasan |
| --- | --- |
| `id` | ID request stream QUIC (`BigInt`) |
| `response` | Promise yang selesai dengan response lengkap atau ditolak saat terjadi kegagalan request/stream |
| `write(data)` / `writeAsync(data, options)` | Mengirim data ke request body |
| `end(data)` / `endAsync(data, options)` | Mengakhiri request stream, dapat disertai data terakhir |
| `cancel()` | Membatalkan request stream |
| `on(event, listener)` / `once(...)` / `off(...)` | Memasang listener yang dibatasi pada request tersebut |

Response yang diterima memiliki `status`, `headers`, `trailers`, `body` (`Buffer`), `bodyBytes`, `text(encoding)`, dan `json()`.

Promise response umumnya selesai ketika seluruh response stream berakhir. Pengecualiannya adalah response `CONNECT` yang berhasil: response tersedia setelah header sukses diterima karena stream tetap terbuka untuk data tunnel.

## Mengirim request body

Kirim string atau `Buffer` melalui properti `body` untuk request dengan body yang dikirim sebagai satu nilai:

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

Untuk streaming upload, jangan isi `body`; kirim potongan data secara manual:

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

Jika mengirim header `content-length`, nilainya wajib sama dengan panjang body dalam byte. Jangan mengaturnya pada streaming body kecuali aplikasi dapat memastikan jumlah byte akhir. Request `CONNECT` memiliki aturan berbeda dan tidak boleh menyertakan HTTP request body.

## Menggunakan QUIC stream secara langsung

Untuk aplikasi yang membutuhkan kontrol transport tanpa framing HTTP/3, gunakan `QUICClient` dan `QUICConnection` secara langsung.

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

Peer harus menjalankan endpoint QUIC yang kompatibel dengan PSK, identity, dan ALPN yang sama. Untuk mode sertifikat, atur `noPsk: true` dan konfigurasi sertifikat yang sesuai.

### Method stream

`connection.openStream()` membuat bidirectional stream. `connection.openUnidirectionalStream()` membuat unidirectional stream. Keduanya mengembalikan handle dengan `id`, `write()`, `writeAsync()`, `end()`, `endAsync()`, dan `reset()`; handle bidirectional juga menyediakan `on(event, listener)`.

Pada level koneksi:

- `write(data, { streamId, offset, fin })` mengirim data ke stream.
- `writeAsync(data, { streamId, fin, signal, timeout, maxChunkSize })` menunggu kapasitas flow control atau congestion, lalu mengirim data per chunk. Promise mengembalikan statistik penulisan.
- `sendDatagram(data)` mengirim frame QUIC DATAGRAM jika dukungan peer sudah dinegosiasikan.
- `stopSending(streamId, errorCode)` meminta peer menghentikan pengiriman pada stream.
- `resetStream(streamId, errorCode)` mereset sisi pengiriman lokal sebuah stream.
- `close(code, reason)` menutup koneksi.

## Ringkasan API

### Export utama

| Export | Fungsi |
| --- | --- |
| `QUICClient` | Client QUIC dan pembuka koneksi |
| `QUICServer` | Server QUIC berbasis UDP |
| `QUICConnection` | Implementasi koneksi transport QUIC |
| `HTTP3Connection` | Sesi HTTP/3 yang terikat pada koneksi QUIC |
| `attachHTTP3(connection, options)` | Membuat dan menghubungkan sesi HTTP/3 |
| `QUIC_VERSION` | Konstanta versi QUIC v1/v2 |
| `QUICError` | Kelas error dasar QUIC dan konstanta error code |
| `QUICTransportError` | Jenis error transport QUIC |
| `QUICProtocolError` | Jenis error protokol QUIC |
| `QUICCryptoError` | Jenis error TLS/kriptografi |
| `H3`, `h3Name(code)` | Konstanta dan nama error HTTP/3 |

### Event yang sering digunakan

| Emitter | Event | Fungsi |
| --- | --- | --- |
| `QUICClient` | `connect` | Koneksi client siap |
| `QUICClient` | `error` | Error client, socket, atau koneksi |
| `QUICServer` | `listening` | UDP socket berhasil di-bind |
| `QUICServer` | `connection` | Koneksi QUIC siap |
| `QUICServer` | `clientError` | Error yang berkaitan dengan koneksi client |
| `QUICServer` | `error` | Error socket atau listener server |
| `HTTP3Connection` | `ready` | Control stream dan QPACK stream HTTP/3 telah dibuka |
| `HTTP3Connection` | `settings` | HTTP/3 SETTINGS dari peer diterima |
| `HTTP3Connection` | `request` | Request masuk; hanya di sisi server |
| `HTTP3Connection` | `streamError` | Error pada request stream beserta kode dan penyebabnya |
| `HTTP3Connection` | `error` | Error pada level koneksi HTTP/3 |
| `HTTP3Connection` | `goaway` / `close` | Peer memulai proses draining atau sesi ditutup |

HTTP/3 emitter juga menyediakan event pesan seperti `headers`, `data`, `trailers`, `end`, `informational`, serta event extension untuk priority dan datagram. Argumen event mengikuti bentuk yang dikirim implementasi; listener khusus request dapat dipasang pada handle hasil `h3.request()`.

## Referensi konfigurasi

Tabel berikut memuat opsi constructor yang umum digunakan. Parameter transport tingkat lanjut juga diterima oleh implementasi koneksi; periksa source sebelum mengandalkan tuning yang lebih khusus.

### `QUICClient`

| Opsi | Default | Penjelasan |
| --- | --- | --- |
| `host` | `127.0.0.1` | Hostname atau IP remote |
| `port` | `4433` | Port UDP remote |
| `version` | `QUIC_VERSION.V1` | Versi QUIC awal |
| `supportedVersions` | Versi awal dan v2 jika dimulai dari v1 | Versi yang diterima saat version negotiation |
| `psk` | `null` | Pre-shared key khusus deployment |
| `noPsk` | `true` jika PSK tidak diberikan | Pilih mode sertifikat/TLS jika `true` |
| `identity` | `xof` | Identity PSK |
| `alpn` | `xof` | Identifier protokol aplikasi; gunakan `h3` untuk HTTP/3 |
| `servername` | `host` | Nama TLS server untuk validasi sertifikat |
| `ca` | Trust store Node.js | Sertifikat CA atau trust bundle tambahan |
| `rejectUnauthorized` | `true` | Validasi sertifikat peer |
| `handshakeTimeout` | `15000` ms | Batas waktu handshake; nilai minimal 1000 ms |
| `qlog` | `false` | Mengaktifkan pengumpulan qlog |
| `maxDatagramFrameSize` | `0` | Kapasitas frame QUIC DATAGRAM yang diiklankan |
| `ipv6` | `false` | Menggunakan UDP socket IPv6 |

### `QUICServer`

| Opsi | Default | Penjelasan |
| --- | --- | --- |
| `host` | `127.0.0.1` | Alamat bind lokal |
| `port` | `4433` | Port UDP lokal |
| `version` | `QUIC_VERSION.V1` | Versi QUIC pilihan |
| `supportedVersions` | Versi awal dan v2 jika dimulai dari v1 | Versi QUIC yang diterima server |
| `psk` | `null` | Pre-shared key khusus deployment |
| `noPsk` | Mode sertifikat jika cert/key diberikan | Memilih mode sertifikat secara eksplisit |
| `identity` | `xof` | Identity PSK |
| `alpn` | `xof` | Identifier protokol aplikasi; gunakan `h3` untuk HTTP/3 |
| `cert`, `key` | — | Sertifikat server dan private key; wajib untuk mode sertifikat |
| `certChain` | `[]` | Entri tambahan certificate chain |
| `requireRetry` | `false` | Memerlukan validasi alamat melalui QUIC Retry |
| `handshakeTimeout` | `15000` ms | Batas waktu handshake |
| `qlog` | `false` | Mengaktifkan pengumpulan qlog |
| `maxDatagramFrameSize` | `0` | Kapasitas frame QUIC DATAGRAM yang diiklankan |
| `ipv6` | `false` | Menggunakan UDP socket IPv6 |

HTTP/3 attachment menerima opsi `settings`, `maxFieldSectionSize`, `maxBlockedFieldSectionBytes`, `maxStreamBufferBytes`, `maxCapsuleSize`, `knownCapsuleTypes`, dan `useHuffman`. Periksa default implementasi dan kebutuhan protokol sebelum mengubah batas tersebut.

## Catatan operasional dan keamanan

1. **Izinkan trafik UDP.** QUIC berjalan di atas UDP. Membuka TCP/443 saja tidak cukup untuk listener QUIC.
2. **Samakan ALPN.** Gunakan `h3` pada kedua sisi untuk HTTP/3. Default transport adalah `xof`, bukan `h3`.
3. **Validasi sertifikat.** Biarkan `rejectUnauthorized: true`, gunakan hostname yang sesuai sertifikat, dan tambahkan CA tepercaya jika diperlukan.
4. **Lindungi PSK dan private key.** Simpan secret di luar source control dan rotasi sesuai kebijakan deployment.
5. **Jangan mengekspos key material di production.** `exposeKeyMaterial` dan `XOF_EXPOSE_KEY_MATERIAL` adalah kontrol diagnostik; biarkan nonaktif kecuali ada kebutuhan debugging yang terkontrol.
6. **Terapkan batas aplikasi.** Tambahkan batas ukuran request, autentikasi, otorisasi, rate limit, dan timeout pada lapisan aplikasi.
7. **Pahami cakupan package.** Package ini bukan web framework lengkap, router, reverse proxy, atau API fallback otomatis HTTP/2 dan HTTP/1.1.

HTTP/3 Server Push belum diimplementasikan pada stack ini. API HTTP/3 Datagrams dan Capsule Protocol memiliki persyaratan negosiasi dan status stream; aktifkan hanya ketika kedua peer mendukung dan menegosiasikan setting yang sesuai.

## Troubleshooting

Untuk daftar error code, kemungkinan penyebab, dan cara pemulihan, baca [Panduan Penanganan Error](./id.error.md). Versi bahasa Inggris tersedia di [in.error.md](./in.error.md).

Pemeriksaan umum:

- Pastikan hostname berhasil di-resolve dan port UDP dapat dijangkau.
- Pastikan server listen pada alamat dan port yang benar.
- Pastikan kedua endpoint memakai mode keamanan, PSK (jika digunakan), identity, dan ALPN yang sama.
- Untuk mode sertifikat, periksa certificate chain, hostname, dan CA yang dikonfigurasi.
- Tunggu event `ready` pada transport dan HTTP/3 sebelum membuat request.
- Untuk pengiriman stream berukuran besar, gunakan `writeAsync()` dan tangani Promise yang ditolak.
- Periksa `error.code`, `error.transportCode`, `error.cause`, dan `error.diagnosis` jika tersedia.
