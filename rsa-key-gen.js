'use strict';

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const generateKeyPair = promisify(crypto.generateKeyPair);

function rsaKeyGen(modulusLength) {
    if (modulusLength === undefined) {
        modulusLength = 4096;
    }
    if (! (Number.isInteger(modulusLength) &&
           (modulusLength >= 1024) &&
           (modulusLength <= 16384))) {
        throw new Error('Invalid RSA modulus length');
    }
    const k = crypto.generateKeyPairSync('rsa', { modulusLength });
    const kid = crypto.randomUUID();
    const secretKey = k.privateKey.export({ format: 'jwk' });
    delete secretKey.key_ops;
    secretKey.kid = kid;
    const publicKey = k.publicKey.export({ format: 'jwk' });
    delete publicKey.key_ops;
    publicKey.kid = kid;
    return { secretKey, publicKey };
}

async function rsaKeyGenAsync(modulusLength) {
    if (modulusLength === undefined) {
        modulusLength = 4096;
    }
    if (! (Number.isInteger(modulusLength) &&
           (modulusLength >= 1024) &&
           (modulusLength <= 16384))) {
        throw new Error('Invalid RSA modulus length');
    }
    const k = await generateKeyPair('rsa', { modulusLength });
    const kid = crypto.randomUUID();
    const secretKey = k.privateKey.export({ format: 'jwk' });
    delete secretKey.key_ops;
    secretKey.kid = kid;
    const publicKey = k.publicKey.export({ format: 'jwk' });
    delete publicKey.key_ops;
    publicKey.kid = kid;
    return { secretKey, publicKey };
}

module.exports = { rsaKeyGen, rsaKeyGenAsync };
