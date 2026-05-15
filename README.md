# tr-jwk

JWK key generation library for Node.js. Produces JSON Web Keys ready
to use with JWT signers, JWE encryptors, ECDH-ES key agreement, and
AES content-encryption / key-wrap operations.

The package exposes three utilities:

- `macKeyGen(alg)` for HMAC, ECDSA, RSA, and ML-DSA signing keys
- `cipherKeyGen(alg)` for AES content-encryption and AES-GCM key-wrap keys
- `ecKeyGen(curve)` for EC key pairs used with ECDH-ES

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

## Exports

```js
const { macKeyGen, cipherKeyGen, ecKeyGen } = require('tr-jwk');
```

# Author

Timo J. Rinne <tri@iki.fi> — https://github.com/rinne/

# Copyright

Copyright © 2023–2026 Timo J. Rinne <tri@iki.fi>.
See `COPYING` for the full MIT license text.

# License

MIT License
