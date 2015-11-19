'use strict';

var cnMatch = require('../lib/cn-auth').cnMatch;

var pat = '*.example.com';

[ 'example.com'
, 'foo.example.com'
].forEach(function (sub) {
  if (!cnMatch(pat, sub)) {
    throw new Error("Pattern should match '" + pat + "': '" + sub + "'");
  }
});

[ 'example.comz'
, 'foo.example.comz'
, 'zexample.com'
, 'foo.zexample.com'
].forEach(function (sub) {
  if (cnMatch(pat, sub)) {
    throw new Error("Pattern should not match '" + pat + "': '" + sub + "'");
  }
});

console.log('PASS');
