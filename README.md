# tr-jwk

JWK key generation library for Node.js. Produces JSON Web Keys ready
to use with JWT signers, JWE encryptors, ECDH-ES key agreement, and
AES content-encryption / key-wrap operations.

The package exposes four utilities:

- `macKeyGen(alg)` for HMAC, ECDSA, RSA, and ML-DSA signing keys
- `cipherKeyGen(alg)` for AES content-encryption and AES-GCM key-wrap keys
- `ecKeyGen(curve)` for EC key pairs used with ECDH-ES
- `rsaKeyGen(modulusLength)` for generic RSA key pairs

Each utility also has an asynchronous counterpart (`macKeyGenAsync`,
`cipherKeyGenAsync`, `ecKeyGenAsync`, `rsaKeyGenAsync`) that takes the
same arguments and returns a promise resolving to the same result.

# Reference

## Installation

```sh
npm install tr-jwk
```

Node.js `>=24.0.0` is required.

## `macKeyGen(alg)`

Generates a private JWK suitable for JWT signing.

Supported `alg` values:

- `HS256`, `HS384`, `HS512`
- `ES256`, `ES384`, `ES512`
- `RS256`, `RS384`, `RS512`
- `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`

Example:

```js
const { macKeyGen } = require('tr-jwk');

const key = macKeyGen('ES256');
console.log(key);
```

Notes:

- HMAC keys are returned as `oct` JWKs with random `k` material.
- EC, RSA, and ML-DSA keys are returned as private JWKs.
- A random `kid` is always added.

## `cipherKeyGen(alg)`

Generates a symmetric JWK for encryption or key wrapping.

Supported `alg` values:

- `A128GCM`, `A192GCM`, `A256GCM`
- `A128GCMKW`, `A192GCMKW`, `A256GCMKW`

Example:

```js
const { cipherKeyGen } = require('tr-jwk');

const key = cipherKeyGen('A256GCM');
console.log(key);
```

Returned keys include:

- `kty: "oct"`
- `alg`
- `key_ops`
- `use: "enc"`
- random `kid`

## `ecKeyGen(curve)`

Generates an EC key pair and returns both the private and public JWK.

Supported `curve` values:

- `P-256`
- `P-384`
- `P-521`

Example:

```js
const { ecKeyGen } = require('tr-jwk');

const { secretKey, publicKey } = ecKeyGen('P-256');
```

Both returned JWKs share the same `kid`.

## `rsaKeyGen(modulusLength)`

Generates an RSA key pair and returns both the private and public JWK.

The optional `modulusLength` is an integer between `1024` and `16384`
(inclusive) and defaults to `4096`.

Example:

```js
const { rsaKeyGen } = require('tr-jwk');

const { secretKey, publicKey } = rsaKeyGen(2048);
```

Notes:

- Both returned JWKs share the same random `kid`.
- No `alg`, `use`, or `key_ops` are set (`kty: "RSA"` is enough); the
  caller decides the key's purpose and sets the intended algorithm
  (e.g. `RSA-OAEP`, `RSA-OAEP-256`, `RS256`).

## Asynchronous API

Every generator has a promise-returning variant:

- `macKeyGenAsync(alg)`
- `cipherKeyGenAsync(alg)`
- `ecKeyGenAsync(curve)`
- `rsaKeyGenAsync(modulusLength)`

Arguments, results, and validation are identical to the synchronous
functions. Key material is generated with the asynchronous
`node:crypto` primitives, so key pair generation (notably RSA) does
not block the event loop. Invalid arguments reject the returned
promise instead of throwing synchronously.

Example:

```js
const { rsaKeyGenAsync } = require('tr-jwk');

const { secretKey, publicKey } = await rsaKeyGenAsync(4096);
```

## `jwk-gen` command line tool

Generates a key or a key pair and writes it to file(s).

```sh
jwk-gen -a <alg> [ -k <kid> ] <file>
```

Options:

- `-a <alg>`, `--algorithm=<alg>` — key algorithm; any `alg` accepted
  by `macKeyGen` or `cipherKeyGen`, an EC curve accepted by
  `ecKeyGen`, or `RSA-OAEP` / `RSA-OAEP-256`
- `-k <kid>`, `--key-identifier=<kid>` — key identifier; a random
  UUID is assigned if not given

A symmetric key is written to `<file>.json`. A key pair is written to
`<file>.json` (private key) and `<file>-pub.json` (public key), both
sharing the same `kid`. The private key file is created with mode
`0600`, and existing files are never overwritten.

`RSA-OAEP` generates a 2048-bit and `RSA-OAEP-256` a 4096-bit RSA key
pair (a convention of this tool; the algorithm names themselves only
specify the OAEP hash). Both files get the corresponding `alg`,
`use: "enc"`, and `key_ops` (`unwrapKey`/`decrypt` for the private
key, `wrapKey`/`encrypt` for the public key).

Example:

```sh
jwk-gen -a ES256 -k my-signing-key signing-key
```

writes `signing-key.json` and `signing-key-pub.json`.

## Exports

```js
const { macKeyGen, macKeyGenAsync,
        cipherKeyGen, cipherKeyGenAsync,
        ecKeyGen, ecKeyGenAsync,
        rsaKeyGen, rsaKeyGenAsync } = require('tr-jwk');
```

# Author

Timo J. Rinne <tri@iki.fi> — https://github.com/rinne/

# Copyright

Copyright © 2023–2026 Timo J. Rinne <tri@iki.fi>.
See `COPYING` for the full MIT license text.

# License

MIT License
