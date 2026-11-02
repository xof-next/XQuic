# @xof/quic — Panduan Penanganan Error

Dokumen ini menjelaskan cara menangkap, mengelompokkan, mendiagnosis, dan menangani error yang dikeluarkan oleh `@xof/quic`.

- [Kembali ke pemilih bahasa](./README.md)
- [Dokumentasi setup dan penggunaan](./id.md)
- [English error guide](./in.error.md)

## 1. Prinsip penanganan error

XQuic menggunakan `EventEmitter` Node.js, Promise, dan objek `Error` standar. Tangani error synchronous dan asynchronous:

- Bungkus pemanggilan constructor dan operasi synchronous seperti `request()`, `write()`, serta `respond()` dengan `try/catch` jika diperlukan.
- Pasang listener `error` pada emitter yang berumur panjang seperti `QUICClient`, `QUICServer`, `QUICConnection`, dan `HTTP3Connection`.
- Tangani Promise yang ditolak dari `connect()`, `listen()`, `writeAsync()`, `endAsync()`, dan `request.response`.
- Pada server HTTP/3, dengarkan `streamError` secara terpisah dari event `error` tingkat koneksi.

Event listener tidak menggantikan penanganan Promise rejection. Sebuah request masih dapat gagal setelah pemanggilan pembuat request selesai dijalankan.

## 2. Struktur objek error

Package menyediakan empat kelas error QUIC:

| Class | Fungsi |
| --- | --- |
| `QUICError` | Error dasar untuk validasi, state, transport, dan koneksi QUIC |
| `QUICTransportError` | Error yang membawa kode error transport QUIC |
| `QUICProtocolError` | Error pada level protokol transport |
| `QUICCryptoError` | Error TLS/kriptografi yang membawa `cryptoErrorCode` |

Tergantung penyebabnya, objek error dapat memiliki properti berikut:

| Properti | Arti |
| --- | --- |
| `name` | Nama class error |
| `message` | Penjelasan error yang dapat dibaca |
| `code` | Kode package atau kode bergaya Node.js seperti `ETIMEDOUT` |
| `transportCode` | Kode error transport/aplikasi QUIC numerik, jika tersedia |
| `frameType` | Jenis frame yang berkaitan dengan error, jika tersedia |
| `cryptoErrorCode` | Kode TLS/crypto alert pada `QUICCryptoError` |
| `cause` | Error asli yang diberikan melalui opsi `cause` |
| `diagnosis` | Informasi diagnosis koneksi untuk beberapa kegagalan DNS/handshake |

Jangan menganggap semua properti selalu tersedia. Periksa keberadaannya sebelum membuat log atau kondisi percabangan.

## 3. Pola penanganan yang disarankan

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

Untuk sistem production, gunakan structured logging. Hindari menyimpan PSK, private key, raw TLS secret, atau isi request sensitif ke dalam log.

## 4. Daftar kode error QUIC

Konstanta berikut tersedia melalui `QUICError`. Nilai constant merupakan string yang dibandingkan dengan `error.code`.

| Constant | Nilai code | Makna umum |
| --- | --- | --- |
| `ERR_INVALID_ARGUMENT` | `ERR_QUIC_INVALID_ARGUMENT` | Opsi, argumen, atau nilai tidak valid |
| `ERR_INVALID_PACKET` | `ERR_QUIC_INVALID_PACKET` | Packet tidak dapat diparse atau divalidasi |
| `ERR_INVALID_VARINT` | `ERR_QUIC_INVALID_VARINT` | QUIC variable-length integer tidak valid |
| `ERR_INVALID_CONNECTION_ID` | `ERR_QUIC_INVALID_CONNECTION_ID` | Connection ID tidak valid |
| `ERR_INVALID_PACKET_NUMBER` | `ERR_QUIC_INVALID_PACKET_NUMBER` | Packet number tidak valid |
| `ERR_INVALID_FRAME` | `ERR_QUIC_INVALID_FRAME` | Frame tidak valid atau malformed |
| `ERR_INVALID_LENGTH` | `ERR_QUIC_INVALID_LENGTH` | Panjang tidak valid atau payload melewati batas |
| `ERR_CRYPTO` | `ERR_QUIC_CRYPTO` | Proses kriptografi gagal |
| `ERR_CRYPTO_BUFFER_EXCEEDED` | `ERR_QUIC_CRYPTO_BUFFER_EXCEEDED` | Batas buffer crypto reassembly terlampaui |
| `ERR_PROTOCOL` | `ERR_QUIC_PROTOCOL` | Pelanggaran protokol QUIC |
| `ERR_STATE` | `ERR_QUIC_STATE` | Operasi tidak sesuai dengan state koneksi/stream saat ini |
| `ERR_FLOW_CONTROL` | `ERR_QUIC_FLOW_CONTROL` | Batas flow control stream atau koneksi tercapai |
| `ERR_STREAM_LIMIT` | `ERR_QUIC_STREAM_LIMIT` | Batas stream atau pelanggaran kepemilikan stream |
| `ERR_STREAM_STATE` | `ERR_QUIC_STREAM_STATE` | Operasi tidak valid untuk state stream |
| `ERR_CONNECTION_ID_LIMIT` | `ERR_QUIC_CONNECTION_ID_LIMIT` | Pelanggaran batas connection ID |
| `ERR_INTERNAL` | `ERR_QUIC_INTERNAL` | Kegagalan internal implementasi |
| `ERR_FINAL_SIZE` | `ERR_QUIC_FINAL_SIZE` | Ukuran akhir stream tidak konsisten |
| `ERR_TRANSPORT_PARAMETER` | `ERR_QUIC_TRANSPORT_PARAMETER` | Transport parameter tidak valid |
| `ERR_KEY_UPDATE` | `ERR_QUIC_KEY_UPDATE` | Key update tidak valid atau melewati batas |
| `ERR_CONNECTION_CLOSED` | `ERR_QUIC_CONNECTION_CLOSED` | Koneksi sudah ditutup |
| `ERR_HANDSHAKE_TIMEOUT` | `ETIMEDOUT` | Handshake belum selesai sampai batas waktu |
| `ERR_DNS` | `ENOTFOUND` | DNS lookup gagal |
| `ERR_UNREACHABLE` | `ERR_QUIC_UNREACHABLE` | Peer atau jalur jaringan tidak dapat dijangkau |
| `ERR_CERTIFICATE_CHAIN` | `ERR_QUIC_CERTIFICATE_CHAIN` | Validasi certificate chain gagal |

Contoh:

```js
const { QUICError } = require('@xof/quic');

try {
  await connection.writeAsync(Buffer.alloc(1024 * 1024), {
    streamId: 0n,
    timeout: 5000
  });
} catch (error) {
  if (error.code === QUICError.ERR_FLOW_CONTROL) {
    console.error('Batas flow control tercapai:', error.message);
  } else {
    throw error;
  }
}
```

Perlu diingat, `writeAsync()` bersifat asynchronous. Gunakan `await` dan `try/catch` untuk menangkap Promise rejection.

## 5. Daftar kode error HTTP/3

Package mengekspor `H3`, `H3_NAMES`, dan `h3Name(code)`. Gunakan konstanta seperti `H3.MESSAGE_ERROR`; nama yang dikembalikan `h3Name()` adalah `MESSAGE_ERROR` (tanpa prefix `H3_`).

| Nama | Code | Penjelasan |
| --- | ---: | --- |
| `NO_ERROR` | `0x100` | Tidak ada error HTTP/3 |
| `GENERAL_PROTOCOL_ERROR` | `0x101` | Error protokol HTTP/3 umum |
| `INTERNAL_ERROR` | `0x102` | Error internal HTTP/3 |
| `STREAM_CREATION_ERROR` | `0x103` | Kegagalan pembuatan critical stream atau stream |
| `CLOSED_CRITICAL_STREAM` | `0x104` | Critical stream HTTP/3 ditutup |
| `FRAME_UNEXPECTED` | `0x105` | Frame tidak valid pada konteks saat ini |
| `FRAME_ERROR` | `0x106` | Frame HTTP/3 malformed atau tidak valid |
| `EXCESSIVE_LOAD` | `0x107` | Batas resource atau buffer terlampaui |
| `ID_ERROR` | `0x108` | Identifier atau stream ID tidak valid |
| `SETTINGS_ERROR` | `0x109` | Nilai atau konfigurasi SETTINGS tidak valid |
| `MISSING_SETTINGS` | `0x10a` | SETTINGS bukan frame pertama pada control stream |
| `REQUEST_REJECTED` | `0x10b` | Request ditolak |
| `REQUEST_CANCELLED` | `0x10c` | Request dibatalkan |
| `REQUEST_INCOMPLETE` | `0x10d` | Request tidak selesai |
| `MESSAGE_ERROR` | `0x10e` | Validasi pesan HTTP gagal |
| `CONNECT_ERROR` | `0x10f` | Kegagalan terkait CONNECT |
| `VERSION_FALLBACK` | `0x110` | Error version fallback |
| `QPACK_DECOMPRESSION_FAILED` | `0x200` | Field section QPACK tidak dapat didecode |
| `QPACK_ENCODER_STREAM_ERROR` | `0x201` | Instruction stream QPACK encoder tidak valid |
| `QPACK_DECODER_STREAM_ERROR` | `0x202` | Instruction stream QPACK decoder tidak valid |
| `DATAGRAM_ERROR` | `0x33` | Error HTTP Datagrams atau Capsule Protocol |

Gunakan helper untuk menghasilkan log yang lebih mudah dibaca:

```js
const { H3, h3Name } = require('@xof/quic');

console.log(H3.MESSAGE_ERROR);         // 270
console.log(h3Name(H3.MESSAGE_ERROR)); // MESSAGE_ERROR
```

`h3Name()` mengembalikan `H3_UNKNOWN` ketika kode tidak dikenali.

## 6. Perbedaan error koneksi dan error stream

Tidak semua request yang gagal harus menyebabkan seluruh koneksi HTTP/3 ditutup.

### Error tingkat koneksi

Gunakan `h3.on('error', error => ...)`. Kegagalan protokol yang memengaruhi state HTTP/3 bersama dapat membuat lapisan HTTP/3 menutup koneksi QUIC di bawahnya. Contohnya critical stream tidak valid, state control stream yang salah, atau kegagalan QPACK tingkat koneksi.

### Error tingkat stream

Gunakan `h3.on('streamError', info => ...)`:

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

Event ini membawa identifier request/stream, kode error HTTP/3, objek `Error` asli, dan nama error yang dapat dibaca. Body request malformed atau ketidaksesuaian `content-length` dapat menggagalkan satu stream tanpa berarti DNS atau handshake ikut gagal.

### Error tingkat transport

Pada server, gunakan `server.on('clientError', error => ...)` untuk error yang berhubungan dengan koneksi peer. Gunakan `server.on('error', error => ...)` untuk kegagalan socket atau listener server.

## 7. Penyebab umum dan langkah penanganan

| Gejala | Kemungkinan penyebab | Pemeriksaan yang disarankan |
| --- | --- | --- |
| `ENOTFOUND` | DNS lookup gagal | Periksa hostname, DNS record, dan resolver |
| `ETIMEDOUT` saat handshake | UDP diblokir, port salah, peer tidak tersedia, atau konfigurasi handshake tidak cocok | Periksa akses UDP, alamat/port listener, mode keamanan, ALPN, dan timeout |
| Error validasi sertifikat | CA tidak dipercaya, sertifikat kedaluwarsa, atau hostname tidak cocok | Periksa certificate chain dan `servername`; atur `ca` tepercaya jika diperlukan |
| PSK/handshake gagal | Key atau identity berbeda, atau mode PSK dan sertifikat tercampur | Pastikan kedua endpoint memakai secret, identity, dan mode yang sama |
| Sesi HTTP/3 tidak menjadi ready | Handshake QUIC belum selesai atau negosiasi/konfigurasi HTTP/3 gagal | Pantau event `ready`/`error` koneksi dan HTTP/3; pastikan ALPN `h3` |
| Error bind UDP socket | Port sedang digunakan atau permission tidak mencukupi | Periksa proses yang menggunakan port dan permission OS |
| `ERR_QUIC_FLOW_CONTROL` | Credit stream/koneksi dari peer habis | Gunakan `writeAsync()`, tunggu kapasitas writable, dan periksa limit peer |
| `ERR_QUIC_STATE` | Operasi dilakukan sebelum ready atau setelah koneksi ditutup | Tunggu `ready` dan hindari menulis setelah stream/koneksi ditutup |
| `MESSAGE_ERROR` | Framing pesan HTTP atau panjang body tidak cocok | Periksa `content-length`, aturan HEAD/CONNECT, dan framing request/response |
| `SETTINGS_ERROR` | HTTP/3 setting tidak valid atau tidak kompatibel | Periksa SETTINGS lokal dan peer serta negosiasi extension |
| `QPACK_*` | Instruction atau field section QPACK tidak valid | Periksa kompatibilitas peer, SETTINGS, dan penanganan QPACK stream |
| `DATAGRAM_ERROR` | Negosiasi datagram/Capsule atau asosiasi stream tidak valid | Pastikan kedua peer mengaktifkan setting yang diperlukan dan request memakai semantik CONNECT yang sesuai |

## 8. Diagnosis handshake

Kegagalan DNS dan handshake tertentu dapat menyertakan objek `error.diagnosis`.

Untuk DNS failure, diagnosis dapat menunjukkan `DNS_FAILURE` dan menyertakan host serta port. Untuk handshake timeout, objek diagnosis dapat berisi:

- `reason: 'QUIC_HANDSHAKE_TIMEOUT'`
- `host` dan `port`
- `udpReachable: false` sebagai status yang terlihat dari percobaan QUIC yang gagal
- hasil probe `tcp443` jika probe TCP diagnostik selesai
- status umum seperti `web-up-quic-unavailable` atau `down-or-unreachable`

Probe TCP yang berhasil **tidak** membuktikan bahwa QUIC tersedia. TCP dan UDP adalah transport yang berbeda. Gunakan diagnosis sebagai petunjuk troubleshooting, bukan keputusan final tentang kondisi jaringan.

Contoh:

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

## 9. Flow control dan asynchronous write

`connection.write()` adalah operasi low-level synchronous. Method ini dapat melempar error ketika koneksi belum terbuka, state stream tidak valid, credit flow control habis, atau congestion window belum dapat menerima data.

Untuk payload besar, gunakan `writeAsync()`:

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
    console.error('Timeout saat menunggu kapasitas transport');
  } else {
    console.error('Write gagal:', error.code, error.message);
  }
}
```

`writeAsync()` menambahkan data pada stream offset saat ini. Method ini tidak menerima `offset` eksplisit. Opsi `timeout` berlaku saat menunggu kapasitas flow control atau congestion; opsi tersebut bukan timeout umum untuk response request.

## 10. Checklist logging yang aman

- Catat `name`, `code`, `transportCode`, `message`, dan request/stream ID jika tersedia.
- Simpan `cause` untuk debugging, tetapi sanitasi sebelum mengirim log ke layanan pihak ketiga.
- Jangan mencatat PSK, private key, TLS traffic secret, authentication header, atau body request privat.
- Biarkan `exposeKeyMaterial` nonaktif di luar lingkungan debugging terisolasi.
- Hindari retry otomatis setelah response mulai diterima, kecuali aplikasi dapat memastikan operasi tersebut aman dan idempotent.
- Tutup sesi dan client socket saat aplikasi shutdown.

Untuk contoh setup dan ringkasan API lengkap, baca [Dokumentasi Bahasa Indonesia](./id.md) atau [English documentation](./in.md).
