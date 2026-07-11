'use strict';

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const generateKey = promisify(crypto.generateKey);

const keyOpts = {
    A128GCM: { keyLength: 128, ops: [ 'encrypt', 'decrypt' ] },
    A192GCM: { keyLength: 192, ops: [ 'encrypt', 'decrypt' ] },
    A256GCM: { keyLength: 256, ops: [ 'encrypt', 'decrypt' ] },
    A128GCMKW: { keyLength: 128, ops: ['wrapKey', 'unwrapKey'] },
    A192GCMKW: { keyLength: 192, ops: ['wrapKey', 'unwrapKey'] },
    A256GCMKW: { keyLength: 256, ops: ['wrapKey', 'unwrapKey'] },
    A128KW: { keyLength: 128, ops: ['wrapKey', 'unwrapKey'] },
    A192KW: { keyLength: 192, ops: ['wrapKey', 'unwrapKey'] },
    A256KW: { keyLength: 256, ops: ['wrapKey', 'unwrapKey'] }
};

function cipherKeyGen(alg) {

  const length = keyOpts[alg]?.keyLength;
  if (! length) {
    throw new Error('Invalid encryption algorithm');
  }
  return {
      ...(crypto.generateKeySync('aes', { length }).export({ format: 'jwk' })),
      alg,
      key_ops: [ ...keyOpts[alg].ops ],
      use: 'enc',
      kid: crypto.randomUUID()
  };
}

async function cipherKeyGenAsync(alg) {

  const length = keyOpts[alg]?.keyLength;
  if (! length) {
    throw new Error('Invalid encryption algorithm');
  }
  return {
      ...((await generateKey('aes', { length })).export({ format: 'jwk' })),
      alg,
      key_ops: [ ...keyOpts[alg].ops ],
      use: 'enc',
      kid: crypto.randomUUID()
  };
}

module.exports = { cipherKeyGen, cipherKeyGenAsync };

// Object.keys(keyOpts).forEach((x) => console.log(cipherKeyGen(x)));
