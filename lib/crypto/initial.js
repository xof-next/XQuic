'use strict';

const { QUIC_VERSION } = require('../constants');
const { QUICError } = require('../errors');
const { hkdfExtract, hkdfExpandLabel } = require('./hkdf');
const { attachDetails } = require('./diagnostics');

const SALT_V1 = Buffer.from('38762cf7f55934b34d179ae6a4c80cadccbb7f0a', 'hex');
const SALT_V2 = Buffer.from('0dede3def700a6db819381be6e269dcbf9bd2ed9', 'hex');

function salt(version) {
  if (version === QUIC_VERSION.V1) return Buffer.from(SALT_V1);
  if (version === QUIC_VERSION.V2) return Buffer.from(SALT_V2);
  throw new QUICError('Unsupported QUIC version', { code: QUICError.ERR_INVALID_ARGUMENT });
}

function labelPrefix(version) {
  return version === QUIC_VERSION.V2 ? 'quicv2 ' : 'quic ';
}

function deriveInitialSecrets({ version = QUIC_VERSION.V1, destinationConnectionId } = {}) {
  if (!Buffer.isBuffer(destinationConnectionId) && !(destinationConnectionId instanceof Uint8Array)) {
    throw new QUICError('Invalid DCID', { code: QUICError.ERR_INVALID_CONNECTION_ID });
  }
  const dcid = Buffer.from(destinationConnectionId);
  if (dcid.length > 20) throw new QUICError('Invalid DCID', { code: QUICError.ERR_INVALID_CONNECTION_ID });
  const initialSalt = salt(version);
  const initialSecret = hkdfExtract(initialSalt, dcid);
  const clientInitialSecret = hkdfExpandLabel(initialSecret, 'client in', Buffer.alloc(0), 32);
  const serverInitialSecret = hkdfExpandLabel(initialSecret, 'server in', Buffer.alloc(0), 32);
  return {
    version,
    initialSecret,
    clientInitialSecret,
    serverInitialSecret,
    details: {
      version,
      salt: Buffer.from(initialSalt),
      destinationConnectionId: Buffer.from(dcid),
      initialSecret: Buffer.from(initialSecret),
      clientInitialSecret: Buffer.from(clientInitialSecret),
      serverInitialSecret: Buffer.from(serverInitialSecret)
    }
  };
}

function derivePacketKeys(secret, version = QUIC_VERSION.V1) {
  const s = Buffer.from(secret);
  if (s.length !== 32) throw new QUICError('Secret must be 32 bytes', { code: QUICError.ERR_CRYPTO });
  const p = labelPrefix(version);
  const key = hkdfExpandLabel(s, p + 'key', Buffer.alloc(0), 16);
  const iv = hkdfExpandLabel(s, p + 'iv', Buffer.alloc(0), 12);
  const headerProtectionKey = hkdfExpandLabel(s, p + 'hp', Buffer.alloc(0), 16);
  return {
    key,
    iv,
    headerProtectionKey,
    details: {
      version,
      labelPrefix: p,
      secret: Buffer.from(s),
      key: Buffer.from(key),
      iv: Buffer.from(iv),
      headerProtectionKey: Buffer.from(headerProtectionKey),
      aead: 'AES-128-GCM',
      headerProtection: 'AES-128-ECB'
    }
  };
}

function deriveNextTrafficSecret(secret, version = QUIC_VERSION.V1) {
  const s = Buffer.from(secret);
  if (s.length !== 32) throw new QUICError('Traffic secret must be 32 bytes', { code: QUICError.ERR_CRYPTO });
  const label = version === QUIC_VERSION.V2 ? 'quicv2 ku' : 'quic ku';
  const nextSecret = hkdfExpandLabel(s, label, Buffer.alloc(0), 32);
  return attachDetails(nextSecret, {
    version,
    label,
    inputSecret: Buffer.from(s),
    outputSecret: Buffer.from(nextSecret)
  });
}

module.exports = { getInitialSalt: salt, deriveInitialSecrets, derivePacketKeys, deriveNextTrafficSecret, labelPrefix };
module.exports.default = module.exports;
