'use strict';

const { macKeyGen, cipherKeyGen, ecKeyGen } = require('..');

const hmacKey = macKeyGen('HS256');
if (hmacKey.kty !== 'oct') throw new Error('macKeyGen HS256 failed');

const aesKey = cipherKeyGen('A256GCM');
if (aesKey.kty !== 'oct') throw new Error('cipherKeyGen A256GCM failed');

const { secretKey, publicKey } = ecKeyGen('P-256');
if (secretKey.kty !== 'EC') throw new Error('ecKeyGen P-256 failed');
if (secretKey.kid !== publicKey.kid) throw new Error('ecKeyGen kid mismatch');

console.log('tr-jwk OK');
