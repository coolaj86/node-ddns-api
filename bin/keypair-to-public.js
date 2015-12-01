'use strict';

// take any input keypair privkey.pem
// and generate an output privkey.pem.pub with only the private key

var fs = require('fs');
var ursa = require('ursa');
var keypairPath = process.argv[2];
var pubkeyPath = process.argv[3] || (keypairPath + '.pub');

var pem = fs.readFileSync(keypairPath, 'ascii');
var key = ursa.createPrivateKey(pem);
var pub = key.toPublicPem();

fs.writeFileSync(pubkeyPath, pub, 'ascii');
