'use strict';

const net = require('node:net');
const { domainToASCII } = require('node:url');
const { QUICError } = require('../errors');

const OID = Object.freeze({
    basicConstraints: '2.5.29.19',
    keyUsage: '2.5.29.15',
    subjectAltName: '2.5.29.17',
    extendedKeyUsage: '2.5.29.37',
    serverAuth: '1.3.6.1.5.5.7.3.1',
    anyExtendedKeyUsage: '2.5.29.37.0'
});

const HANDLED_CRITICAL_EXTENSIONS = new Set([
    OID.basicConstraints,
    OID.keyUsage,
    OID.subjectAltName,
    OID.extendedKeyUsage
]);

function policyError(message, transportCode = 'CERTIFICATE_POLICY_VIOLATION') {
    throw new QUICError(message, {
        code: QUICError.ERR_CERTIFICATE_CHAIN,
        transportCode
    });
}

function readTLV(buf, offset, parentEnd = buf.length) {
    if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
    if (offset < 0 || offset + 2 > parentEnd || parentEnd > buf.length) throw new Error('Malformed DER TLV');
    const tag = buf[offset];
    let pos = offset + 1;
    let length = buf[pos++];
    if (length & 0x80) {
        const count = length & 0x7f;
        if (count === 0 || count > 4 || pos + count > parentEnd) throw new Error('Invalid DER length');
        length = 0;
        for (let i = 0; i < count; i++) length = length * 256 + buf[pos++];
        if (length < 128) throw new Error('Non-minimal DER length');
    }
    const end = pos + length;
    if (end > parentEnd) throw new Error('DER value overruns parent');
    return { tag, start: offset, contentStart: pos, end, next: end };
}

function children(buf, parent) {
    const out = [];
    let pos = parent.contentStart;
    while (pos < parent.end) {
        const item = readTLV(buf, pos, parent.end);
        out.push(item);
        pos = item.next;
    }
    if (pos !== parent.end) throw new Error('Malformed DER child sequence');
    return out;
}

function decodeOID(value) {
    const b = Buffer.from(value);
    if (!b.length) throw new Error('Empty OID');
    const values = [];
    let acc = 0n;
    let inValue = false;
    for (const byte of b) {
        acc = (acc << 7n) | BigInt(byte & 0x7f);
        inValue = true;
        if ((byte & 0x80) === 0) {
            values.push(acc);
            acc = 0n;
            inValue = false;
        }
    }
    if (inValue) throw new Error('Truncated OID');
    const first = values.shift();
    const firstArc = first < 40n ? 0n : first < 80n ? 1n : 2n;
    const secondArc = first - firstArc * 40n;
    return [firstArc, secondArc, ...values].map(String).join('.');
}

function extensionsOf(cert) {
    const der = Buffer.from(cert.raw);
    const outer = readTLV(der, 0);
    if (outer.tag !== 0x30 || outer.next !== der.length) throw new Error('Invalid Certificate DER');
    const outerChildren = children(der, outer);
    if (!outerChildren.length || outerChildren[0].tag !== 0x30) throw new Error('Missing TBSCertificate');
    const tbs = outerChildren[0];
    for (const field of children(der, tbs)) {
        if (field.tag !== 0xa3) continue; // [3] EXPLICIT Extensions
        const explicitChildren = children(der, field);
        if (explicitChildren.length !== 1 || explicitChildren[0].tag !== 0x30) throw new Error('Invalid Extensions wrapper');
        const result = new Map();
        for (const ext of children(der, explicitChildren[0])) {
            if (ext.tag !== 0x30) throw new Error('Invalid Extension entry');
            const parts = children(der, ext);
            if (parts.length < 2 || parts.length > 3 || parts[0].tag !== 0x06) throw new Error('Invalid Extension structure');
            const oid = decodeOID(der.subarray(parts[0].contentStart, parts[0].end));
            let index = 1;
            let critical = false;
            if (parts[index].tag === 0x01) {
                const b = der.subarray(parts[index].contentStart, parts[index].end);
                if (b.length !== 1 || (b[0] !== 0x00 && b[0] !== 0xff)) throw new Error('Invalid extension critical flag');
                critical = b[0] !== 0;
                index++;
            }
            if (index !== parts.length - 1 || parts[index].tag !== 0x04) throw new Error('Invalid extension value');
            if (result.has(oid)) throw new Error('Duplicate certificate extension');
            result.set(oid, {
                oid,
                critical,
                value: Buffer.from(der.subarray(parts[index].contentStart, parts[index].end))
            });
        }
        return result;
    }
    return new Map();
}

function parseSequence(value) {
    const b = Buffer.from(value);
    const seq = readTLV(b, 0);
    if (seq.tag !== 0x30 || seq.next !== b.length) throw new Error('Expected DER SEQUENCE');
    return children(b, seq).map(item => ({ tag: item.tag, value: Buffer.from(b.subarray(item.contentStart, item.end)) }));
}

function parseBasicConstraints(value) {
    const parts = parseSequence(value);
    let ca = false;
    let pathLenConstraint = null;
    for (const part of parts) {
        if (part.tag === 0x01) {
            if (part.value.length !== 1 || (part.value[0] !== 0x00 && part.value[0] !== 0xff)) throw new Error('Invalid CA boolean');
            ca = part.value[0] !== 0;
        } else if (part.tag === 0x02) {
            if (!part.value.length || (part.value[0] & 0x80)) throw new Error('Invalid pathLenConstraint');
            let n = 0n;
            for (const byte of part.value) n = (n << 8n) | BigInt(byte);
            if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('pathLenConstraint out of range');
            pathLenConstraint = Number(n);
        } else {
            throw new Error('Unsupported BasicConstraints field');
        }
    }
    if (pathLenConstraint !== null && !ca) throw new Error('pathLenConstraint requires cA=TRUE');
    return { ca, pathLenConstraint };
}

function parseKeyUsage(value) {
    const b = Buffer.from(value);
    const bitString = readTLV(b, 0);
    if (bitString.tag !== 0x03 || bitString.next !== b.length || bitString.end <= bitString.contentStart) throw new Error('Invalid KeyUsage BIT STRING');
    const data = b.subarray(bitString.contentStart, bitString.end);
    const unused = data[0];
    if (unused > 7 || data.length === 1 && unused !== 0) throw new Error('Invalid KeyUsage unused bits');
    const bits = data.subarray(1);
    if (unused && bits.length && (bits[bits.length - 1] & ((1 << unused) - 1)) !== 0) {
        throw new Error('Non-zero KeyUsage unused bits');
    }
    const has = bit => {
        const index = Math.floor(bit / 8);
        return index < bits.length && (bits[index] & (0x80 >> (bit % 8))) !== 0;
    };
    return {
        digitalSignature: has(0),
        keyEncipherment: has(2),
        keyCertSign: has(5),
        cRLSign: has(6)
    };
}

function parseExtendedKeyUsage(value) {
    return parseSequence(value).map(part => {
        if (part.tag !== 0x06) throw new Error('Invalid ExtendedKeyUsage entry');
        return decodeOID(part.value);
    });
}

function assertValidity(cert, now = Date.now()) {
    const from = cert.validFromDate ? cert.validFromDate.getTime() : new Date(cert.validFrom).getTime();
    const to = cert.validToDate ? cert.validToDate.getTime() : new Date(cert.validTo).getTime();
    if (!Number.isFinite(from) || !Number.isFinite(to) || now < from || now > to) {
        policyError('Certificate is not currently valid', 'CERTIFICATE_CHAIN_EXPIRED');
    }
}

function inspectCertificate(cert) {
    let extensions;
    try { extensions = extensionsOf(cert); }
    catch (cause) {
        policyError('Unable to parse certificate extensions safely', 'CERTIFICATE_EXTENSION_INVALID');
    }
    for (const ext of extensions.values()) {
        if (ext.critical && !HANDLED_CRITICAL_EXTENSIONS.has(ext.oid)) {
            policyError(`Unsupported critical certificate extension ${ext.oid}`, 'CERTIFICATE_UNSUPPORTED_CRITICAL_EXTENSION');
        }
    }
    let basicConstraints = null;
    let keyUsage = null;
    let extendedKeyUsage = null;
    try {
        const bc = extensions.get(OID.basicConstraints);
        const ku = extensions.get(OID.keyUsage);
        const eku = extensions.get(OID.extendedKeyUsage);
        if (bc) basicConstraints = parseBasicConstraints(bc.value);
        if (ku) keyUsage = parseKeyUsage(ku.value);
        if (eku) extendedKeyUsage = parseExtendedKeyUsage(eku.value);
    } catch (cause) {
        policyError('Malformed X.509 certificate extension', 'CERTIFICATE_EXTENSION_INVALID');
    }
    return { extensions, basicConstraints, keyUsage, extendedKeyUsage };
}

function validatePublicKey(cert) {
    const key = cert.publicKey;
    const type = key?.asymmetricKeyType;
    const details = key?.asymmetricKeyDetails || {};
    if (type === 'rsa' || type === 'rsa-pss') {
        if (!Number.isFinite(details.modulusLength) || details.modulusLength < 2048) {
            policyError('RSA certificate public key is below the XOF TLS security floor (2048 bits)', 'CERTIFICATE_WEAK_PUBLIC_KEY');
        }
        return;
    }
    if (type === 'ec') {
        if (!['prime256v1', 'P-256', 'secp384r1', 'P-384', 'secp521r1', 'P-521'].includes(details.namedCurve)) {
            policyError('Unsupported EC certificate curve for the configured TLS signature profile', 'CERTIFICATE_UNSUPPORTED_PUBLIC_KEY');
        }
        return;
    }
    if (type === 'ed25519') return;
    policyError(`Unsupported certificate public-key type: ${type || 'unknown'}`, 'CERTIFICATE_UNSUPPORTED_PUBLIC_KEY');
}

function normalizeReferenceIdentity(value) {
    const identity = String(value).replace(/^\[|\]$/g, '');
    if (net.isIP(identity)) return { identity, isIp: true };
    if (!identity || identity.includes('*') || /[\s\u0000-\u001f\u007f]/.test(identity)) {
        policyError('Invalid DNS reference identity', 'CERTIFICATE_HOSTNAME_MISMATCH');
    }
    const ascii = domainToASCII(identity);
    if (!ascii || ascii.length > 253) policyError('Invalid DNS reference identity', 'CERTIFICATE_HOSTNAME_MISMATCH');
    const name = ascii.endsWith('.') ? ascii.slice(0, -1) : ascii;
    const labels = name.split('.');
    if (!name || labels.some(label =>
        label.length < 1 || label.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
    )) {
        policyError('Invalid DNS reference identity', 'CERTIFICATE_HOSTNAME_MISMATCH');
    }
    return { identity: name, isIp: false };
}

function validateLeafCertificate(cert, servername, now = Date.now()) {
    assertValidity(cert, now);
    const parsed = inspectCertificate(cert);
    validatePublicKey(cert);
    if (parsed.keyUsage && !parsed.keyUsage.digitalSignature) {
        policyError('TLS 1.3 server certificate keyUsage must permit digitalSignature', 'CERTIFICATE_KEY_USAGE_INVALID');
    }
    if (parsed.extendedKeyUsage &&
        !parsed.extendedKeyUsage.includes(OID.serverAuth) &&
        !parsed.extendedKeyUsage.includes(OID.anyExtendedKeyUsage)) {
        policyError('Server certificate EKU does not permit TLS server authentication', 'CERTIFICATE_EKU_INVALID');
    }
    if (servername) {
        const reference = normalizeReferenceIdentity(servername);
        let matched = false;
        try {
            matched = reference.isIp
                ? (typeof cert.checkIP === 'function' && !!cert.checkIP(reference.identity))
                : (typeof cert.checkHost === 'function' && !!cert.checkHost(reference.identity, {
                    subject: 'never',
                    wildcards: true,
                    partialWildcards: false,
                    multiLabelWildcards: false,
                    singleLabelSubdomains: false
                }));
        } catch {}
        if (!matched) policyError('Server certificate hostname mismatch', 'CERTIFICATE_HOSTNAME_MISMATCH');
    }
    return parsed;
}

function validateIssuerCertificate(cert, { caCertificatesBelow = 0, now = Date.now() } = {}) {
    assertValidity(cert, now);
    const parsed = inspectCertificate(cert);
    const bcExtension = parsed.extensions.get(OID.basicConstraints);
    if (!parsed.basicConstraints || !parsed.basicConstraints.ca || !bcExtension?.critical) {
        policyError('Issuer certificate must assert CA:TRUE in critical basicConstraints', 'CERTIFICATE_CA_INVALID');
    }
    if (parsed.keyUsage && !parsed.keyUsage.keyCertSign) {
        policyError('Issuer certificate keyUsage does not permit certificate signing', 'CERTIFICATE_KEY_USAGE_INVALID');
    }
    if (parsed.extendedKeyUsage &&
        !parsed.extendedKeyUsage.includes(OID.serverAuth) &&
        !parsed.extendedKeyUsage.includes(OID.anyExtendedKeyUsage)) {
        policyError('Issuer certificate EKU restricts this path away from TLS server authentication', 'CERTIFICATE_EKU_INVALID');
    }
    if (parsed.basicConstraints.pathLenConstraint !== null &&
        caCertificatesBelow > parsed.basicConstraints.pathLenConstraint) {
        policyError('Certificate path exceeds the issuer pathLenConstraint', 'CERTIFICATE_PATH_LENGTH_EXCEEDED');
    }
    validatePublicKey(cert);
    return parsed;
}

function countNonSelfIssuedCAs(certs) {
    return certs.slice(1).filter(cert => cert.ca && cert.subject !== cert.issuer).length;
}

module.exports = {
    OID,
    extensionsOf,
    inspectCertificate,
    validateLeafCertificate,
    validateIssuerCertificate,
    countNonSelfIssuedCAs,
    normalizeReferenceIdentity
};
