'use strict';

var PromiseA = require('bluebird');
var jwt = require('jsonwebtoken');
var fs = PromiseA.promisifyAll(require('fs'));
var privkey = process.argv[2];
var domainname = process.argv[3];
var devname = process.argv[4];

if (!privkey || !domainname || !devname) {
  console.error("Usage: node ./bin/sign-jwt 'path/to/privkey.pem' 'example.com' 'device-name'");
  return;
}

var pem = fs.readFileSync(privkey, 'ascii');
var tok = jwt.sign({ cn: domainname, device: devname }, pem, { algorithm: 'RS256' });
console.warn(jwt.decode(tok));
console.log(tok);
process.exit(0);
