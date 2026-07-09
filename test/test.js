'use strict';

const verbose = [ 'Y', 'YES' ].includes(process.env.VERBOSE);

const assert = require('node:assert/strict');

const crypto = require('node:crypto');

const { macKeyGen, macKeyGenAsync,
        cipherKeyGen, cipherKeyGenAsync,
        ecKeyGen, ecKeyGenAsync,
        rsaKeyGen, rsaKeyGenAsync,
        mlDsaKeyGen, mlDsaKeyGenAsync,
        mlKemKeyGen, mlKemKeyGenAsync } = require('..');

const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function verboseOutput(k) {
    if (verbose) {
        console.log('Key: ' + JSON.stringify(k));
    }
}

function checkMacKey(alg, k) {
    assert.equal(k.alg, alg);
    assert.match(k.kid, uuidRe);
    if (alg.startsWith('HS')) {
        assert.equal(k.kty, 'oct');
        assert.equal(Buffer.from(k.k, 'base64url').length, parseInt(alg.slice(2)) >> 3);
    } else if (alg.startsWith('ES')) {
        assert.equal(k.kty, 'EC');
        assert.equal(k.crv, { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' }[alg]);
        assert.ok(k.d);
        crypto.createPrivateKey({ key: k, format: 'jwk' });
    } else if (alg.startsWith('RS')) {
        assert.equal(k.kty, 'RSA');
        assert.ok(k.d);
        const modulusLength = { RS256: 1024, RS384: 2048, RS512: 4096 }[alg];
        assert.equal((crypto
                      .createPrivateKey({ key: k, format: 'jwk' })
                      .asymmetricKeyDetails
                      .modulusLength),
                     modulusLength);
    } else {
        assert.equal(k.kty, 'AKP');
        assert.ok(k.priv);
        assert.ok(k.pub);
        crypto.createPrivateKey({ key: k, format: 'jwk' });
    }
    verboseOutput(k);
}

function checkCipherKey(alg, k) {
    assert.equal(k.kty, 'oct');
    assert.equal(k.alg, alg);
    assert.equal(Buffer.from(k.k, 'base64url').length, parseInt(alg.slice(1, 4)) >> 3);
    assert.deepEqual(k.key_ops, (alg.endsWith('KW') ?
                                 [ 'wrapKey', 'unwrapKey' ] :
                                 [ 'encrypt', 'decrypt' ]));
    assert.equal(k.use, 'enc');
    assert.match(k.kid, uuidRe);
    verboseOutput(k);
}

function checkEcPair(curve, kp) {
    assert.equal(kp.secretKey.kty, 'EC');
    assert.equal(kp.secretKey.crv, curve);
    assert.ok(kp.secretKey.d);
    assert.equal(kp.publicKey.kty, 'EC');
    assert.equal(kp.publicKey.crv, curve);
    assert.equal(kp.publicKey.d, undefined);
    assert.match(kp.secretKey.kid, uuidRe);
    assert.equal(kp.publicKey.kid, kp.secretKey.kid);
    crypto.createPrivateKey({ key: kp.secretKey, format: 'jwk' });
    crypto.createPublicKey({ key: kp.publicKey, format: 'jwk' });
    verboseOutput(kp);
}

function checkRsaPair(modulusLength, kp) {
    assert.equal(kp.secretKey.kty, 'RSA');
    assert.ok(kp.secretKey.d);
    assert.equal(kp.secretKey.key_ops, undefined);
    assert.equal(kp.publicKey.kty, 'RSA');
    assert.equal(kp.publicKey.d, undefined);
    assert.equal(kp.publicKey.key_ops, undefined);
    assert.match(kp.secretKey.kid, uuidRe);
    assert.equal(kp.publicKey.kid, kp.secretKey.kid);
    assert.equal((crypto
                  .createPrivateKey({ key: kp.secretKey, format: 'jwk' })
                  .asymmetricKeyDetails
                  .modulusLength),
                 modulusLength);
    verboseOutput(kp);
}

function checkAkpPair(variant, kp) {
    assert.equal(kp.secretKey.kty, 'AKP');
    assert.equal(kp.secretKey.alg, variant);
    assert.ok(kp.secretKey.priv);
    assert.ok(kp.secretKey.pub);
    assert.equal(kp.publicKey.kty, 'AKP');
    assert.equal(kp.publicKey.alg, variant);
    assert.equal(kp.publicKey.priv, undefined);
    assert.equal(kp.publicKey.pub, kp.secretKey.pub);
    assert.match(kp.secretKey.kid, uuidRe);
    assert.equal(kp.publicKey.kid, kp.secretKey.kid);
    const secretKey = crypto.createPrivateKey({ key: kp.secretKey, format: 'jwk' });
    const publicKey = crypto.createPublicKey({ key: kp.publicKey, format: 'jwk' });
    if (variant.startsWith('ML-DSA')) {
        const data = Buffer.from('kukkuu');
        const signature = crypto.sign(null, data, secretKey);
        assert.ok(crypto.verify(null, data, publicKey, signature));
    }
    verboseOutput(kp);
}

const macAlgs = [ 'HS256', 'HS384', 'HS512',
                  'ES256', 'ES384', 'ES512',
                  'RS256', 'RS384', 'RS512',
                  'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87' ];
const cipherAlgs = [ 'A128GCM', 'A192GCM', 'A256GCM',
                     'A128GCMKW', 'A192GCMKW', 'A256GCMKW' ];
const ecCurves = [ 'P-256', 'P-384', 'P-521' ];
const mlDsaVariants = [ 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87' ];
const mlKemVariants = [ 'ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024' ];

// Synchronous API.
macAlgs.forEach((alg) => checkMacKey(alg, macKeyGen(alg)));
cipherAlgs.forEach((alg) => checkCipherKey(alg, cipherKeyGen(alg)));
ecCurves.forEach((curve) => checkEcPair(curve, ecKeyGen(curve)));
checkRsaPair(1024, rsaKeyGen(1024));
mlDsaVariants.forEach((variant) => checkAkpPair(variant, mlDsaKeyGen(variant)));
mlKemVariants.forEach((variant) => checkAkpPair(variant, mlKemKeyGen(variant)));

assert.throws(() => macKeyGen('nope'), /Invalid MAC/);
assert.throws(() => cipherKeyGen('nope'), /Invalid encryption/);
assert.throws(() => ecKeyGen('P-123'), /Invalid ECC/);
assert.throws(() => rsaKeyGen(123), /Invalid RSA/);
assert.throws(() => mlDsaKeyGen('ML-DSA-99'), /Invalid ML-DSA/);
assert.throws(() => mlKemKeyGen('ML-KEM-99'), /Invalid ML-KEM/);

// Asynchronous API.
(async () => {
    for (const alg of macAlgs) {
        const p = macKeyGenAsync(alg);
        assert.ok(p instanceof Promise);
        checkMacKey(alg, await p);
    }
    for (const alg of cipherAlgs) {
        checkCipherKey(alg, await cipherKeyGenAsync(alg));
    }
    for (const curve of ecCurves) {
        checkEcPair(curve, await ecKeyGenAsync(curve));
    }
    checkRsaPair(2048, await rsaKeyGenAsync(2048));
    for (const variant of mlDsaVariants) {
        const p = mlDsaKeyGenAsync(variant);
        assert.ok(p instanceof Promise);
        checkAkpPair(variant, await p);
    }
    for (const variant of mlKemVariants) {
        checkAkpPair(variant, await mlKemKeyGenAsync(variant));
    }

    await assert.rejects(macKeyGenAsync('nope'), /Invalid MAC/);
    await assert.rejects(cipherKeyGenAsync('nope'), /Invalid encryption/);
    await assert.rejects(ecKeyGenAsync('P-123'), /Invalid ECC/);
    await assert.rejects(rsaKeyGenAsync(123), /Invalid RSA/);
    await assert.rejects(mlDsaKeyGenAsync('ML-DSA-99'), /Invalid ML-DSA/);
    await assert.rejects(mlKemKeyGenAsync('ML-KEM-99'), /Invalid ML-KEM/);

    console.log('JWK tests passed');
})().catch((e) => {
    console.error(e);
    process.exit(1);
});
