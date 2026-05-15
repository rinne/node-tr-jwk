'use strict';

const crypto = require('node:crypto');

const curves = [ 'P-256', 'P-384', 'P-521' ];

function ecKeyGen(curve) {
    if (! curves.includes(curve)) {
        throw new Error('Invalid ECC curve');
    }
    const k = crypto.generateKeyPairSync('ec', { namedCurve: curve });
    const kid = crypto.randomUUID();
    const secretKey = k.privateKey.export({ format: 'jwk' });
    secretKey.kid = kid;
    const publicKey = k.publicKey.export({ format: 'jwk' });
    publicKey.kid = kid;
    return { secretKey, publicKey };
}

module.exports = ecKeyGen;

//curves.forEach((x) => console.log(ecKeyGen(x)));
