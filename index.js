'use strict';

const { macKeyGen, macKeyGenAsync } = require('./mac-key-gen');
const { cipherKeyGen, cipherKeyGenAsync } = require('./cipher-key-gen');
const { ecKeyGen, ecKeyGenAsync } = require('./ec-key-gen');
const { rsaKeyGen, rsaKeyGenAsync } = require('./rsa-key-gen');
const { mlDsaKeyGen, mlDsaKeyGenAsync } = require('./ml-dsa-key-gen');
const { mlKemKeyGen, mlKemKeyGenAsync } = require('./ml-kem-key-gen');

module.exports = { macKeyGen, macKeyGenAsync,
                   cipherKeyGen, cipherKeyGenAsync,
                   ecKeyGen, ecKeyGenAsync,
                   rsaKeyGen, rsaKeyGenAsync,
                   mlDsaKeyGen, mlDsaKeyGenAsync,
                   mlKemKeyGen, mlKemKeyGenAsync };
