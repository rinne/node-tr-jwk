'use strict';

const crypto = require('node:crypto');

const keyOpts = {
    HS256: { mode: 'hmac', len: 256 },
    HS384: { mode: 'hmac', len: 384 },
    HS512: { mode: 'hmac', len: 512 },
    ES256: { mode: 'ec', curve: 'prime256v1' },
    ES384: { mode: 'ec', curve: 'secp384r1' },
    ES512: { mode: 'ec', curve: 'secp521r1' },
    RS256: { mode: 'rsa', len: 1024 },
    RS384: { mode: 'rsa', len: 2048 },
    RS512: { mode: 'rsa', len: 4096 },
    'ML-DSA-44': { mode: 'ml-dsa', type: 'ml-dsa-44' },
    'ML-DSA-65': { mode: 'ml-dsa', type: 'ml-dsa-65' },
    'ML-DSA-87': { mode: 'ml-dsa', type: 'ml-dsa-87' }
}

function macKeyGen(alg) {
    let opt = keyOpts[alg];
    if (! opt) {
        throw new Error('Invalid MAC algorighm');
    }
    let k = { alg };
    switch (opt.mode) {
    case 'hmac':
        k.kty = 'oct';
        k.k = crypto.randomBytes(opt.len >> 3).toString('base64url');
        break;
    case 'ec':
        Object.assign(k, (crypto
                          .generateKeyPairSync('ec', { namedCurve: opt.curve })
                          .privateKey
                          .export({ format: 'jwk' })));
        break;
    case 'rsa':
        Object.assign(k, (crypto
                          .generateKeyPairSync('rsa', { modulusLength: opt.len })
                          .privateKey
                          .export({ format: 'jwk' })));
        break;
    case 'ml-dsa':
        Object.assign(k, (crypto
                          .generateKeyPairSync(opt.type, {})
                          .privateKey.export({ format: 'jwk' })));
        break;
    default:
        throw new Error('Internal error');
    }
    Object.assign(k, { kid: crypto.randomUUID() });
    return k;
}

module.exports = macKeyGen;

//Object.keys(keyOpts).forEach((x) => console.log(macKeyGen(x)));
