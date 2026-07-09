'use strict';

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const generateKeyPair = promisify(crypto.generateKeyPair);

const variants = {
    'ML-DSA-44': 'ml-dsa-44',
    'ML-DSA-65': 'ml-dsa-65',
    'ML-DSA-87': 'ml-dsa-87'
};

function mlDsaKeyGen(variant) {
    if (! variants[variant]) {
        throw new Error('Invalid ML-DSA variant');
    }
    const k = crypto.generateKeyPairSync(variants[variant], {});
    const kid = crypto.randomUUID();
    const secretKey = k.privateKey.export({ format: 'jwk' });
    secretKey.kid = kid;
    const publicKey = k.publicKey.export({ format: 'jwk' });
    publicKey.kid = kid;
    return { secretKey, publicKey };
}

async function mlDsaKeyGenAsync(variant) {
    if (! variants[variant]) {
        throw new Error('Invalid ML-DSA variant');
    }
    const k = await generateKeyPair(variants[variant], {});
    const kid = crypto.randomUUID();
    const secretKey = k.privateKey.export({ format: 'jwk' });
    secretKey.kid = kid;
    const publicKey = k.publicKey.export({ format: 'jwk' });
    publicKey.kid = kid;
    return { secretKey, publicKey };
}

module.exports = { mlDsaKeyGen, mlDsaKeyGenAsync };
