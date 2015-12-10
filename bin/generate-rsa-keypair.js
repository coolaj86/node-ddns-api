'use strict';

var filepath = process.argv[2];
var ursa = require('ursa');
var fs = require('bluebird').promisifyAll(require('fs'));
var bits = 1024;
var mod = 65537; // seems to be the most common, not sure why
var key = ursa.generatePrivateKey(bits, mod);
var pem = key.toPrivatePem();

if (!filepath) {
  console.error("Please specify a file '/path/to/privkey.pem' to which to write");
  return;
}

return fs.existsAsync(filepath).then(function () {
  return;
}, function () {
  throw new Error("Error: '" + filepath + "' already exists");
}).then(function () {
  return fs.writeFileAsync(filepath, pem, 'ascii').then(function () {
    return key;
  });
});
