'use strict';

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const randomBytes = promisify(crypto.randomBytes);
const generateKeyPair = promisify(crypto.generateKeyPair);

const HMAC_MAX_BITS = 4096;

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

// HS* keys default to the hash size but may be requested longer via
// opts.length (bits, multiple of 8, capped). The length option is not
// applicable to the asymmetric algorithms.
function _keyBits(opt, opts) {
    if (opts === undefined || opts === null) {
        opts = {};
    }
    if (! ((typeof opts === 'object') && ! Array.isArray(opts))) {
        throw new Error('Invalid options');
    }
    for (const key of Object.keys(opts)) {
        if (key !== 'length') {
            throw new Error('Unknown option: ' + key);
        }
    }
    if (opts.length === undefined) {
        return (opt.mode === 'hmac') ? opt.len : undefined;
    }
    if (opt.mode !== 'hmac') {
        throw new Error('Invalid length option for algorithm');
    }
    if (! (Number.isSafeInteger(opts.length) &&
           (opts.length >= opt.len) &&
           (opts.length <= HMAC_MAX_BITS) &&
           ((opts.length % 8) === 0))) {
        throw new Error('Invalid key length');
    }
    return opts.length;
}

function macKeyGen(alg, opts) {
    let opt = keyOpts[alg];
    if (! opt) {
        throw new Error('Invalid MAC algorighm');
    }
    const bits = _keyBits(opt, opts);
    let k = { alg };
    switch (opt.mode) {
    case 'hmac':
        k.kty = 'oct';
        k.k = crypto.randomBytes(bits >> 3).toString('base64url');
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

async function macKeyGenAsync(alg, opts) {
    let opt = keyOpts[alg];
    if (! opt) {
        throw new Error('Invalid MAC algorighm');
    }
    const bits = _keyBits(opt, opts);
    let k = { alg };
    switch (opt.mode) {
    case 'hmac':
        k.kty = 'oct';
        k.k = (await randomBytes(bits >> 3)).toString('base64url');
        break;
    case 'ec':
        Object.assign(k, ((await generateKeyPair('ec', { namedCurve: opt.curve }))
                          .privateKey
                          .export({ format: 'jwk' })));
        break;
    case 'rsa':
        Object.assign(k, ((await generateKeyPair('rsa', { modulusLength: opt.len }))
                          .privateKey
                          .export({ format: 'jwk' })));
        break;
    case 'ml-dsa':
        Object.assign(k, ((await generateKeyPair(opt.type, {}))
                          .privateKey.export({ format: 'jwk' })));
        break;
    default:
        throw new Error('Internal error');
    }
    Object.assign(k, { kid: crypto.randomUUID() });
    return k;
}

module.exports = { macKeyGen, macKeyGenAsync };

//Object.keys(keyOpts).forEach((x) => console.log(macKeyGen(x)));
