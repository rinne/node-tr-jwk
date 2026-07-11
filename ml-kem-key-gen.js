'use strict';

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const generateKeyPair = promisify(crypto.generateKeyPair);

const variants = {
    'ML-KEM-512': 'ml-kem-512',
    'ML-KEM-768': 'ml-kem-768',
    'ML-KEM-1024': 'ml-kem-1024'
};

function mlKemKeyGen(variant) {
    if (! variants[variant]) {
        throw new Error('Invalid ML-KEM variant');
    }
    const k = crypto.generateKeyPairSync(variants[variant], {});
    const kid = crypto.randomUUID();
    // node:crypto stamps the variant into the exported JWK alg, but
    // consumers depend on it, so it is set explicitly for robustness.
    const secretKey = k.privateKey.export({ format: 'jwk' });
    secretKey.alg = variant;
    secretKey.kid = kid;
    const publicKey = k.publicKey.export({ format: 'jwk' });
    publicKey.alg = variant;
    publicKey.kid = kid;
    return { secretKey, publicKey };
}

async function mlKemKeyGenAsync(variant) {
    if (! variants[variant]) {
        throw new Error('Invalid ML-KEM variant');
    }
    const k = await generateKeyPair(variants[variant], {});
    const kid = crypto.randomUUID();
    const secretKey = k.privateKey.export({ format: 'jwk' });
    secretKey.alg = variant;
    secretKey.kid = kid;
    const publicKey = k.publicKey.export({ format: 'jwk' });
    publicKey.alg = variant;
    publicKey.kid = kid;
    return { secretKey, publicKey };
}

module.exports = { mlKemKeyGen, mlKemKeyGenAsync };
