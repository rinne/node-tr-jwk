'use strict';

const { macKeyGen, macKeyGenAsync } = require('./mac-key-gen');
const { cipherKeyGen, cipherKeyGenAsync } = require('./cipher-key-gen');
const { ecKeyGen, ecKeyGenAsync } = require('./ec-key-gen');
const { rsaKeyGen, rsaKeyGenAsync } = require('./rsa-key-gen');

module.exports = { macKeyGen, macKeyGenAsync,
                   cipherKeyGen, cipherKeyGenAsync,
                   ecKeyGen, ecKeyGenAsync,
                   rsaKeyGen, rsaKeyGenAsync };
