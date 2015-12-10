'use strict';

var fs = require('fs');
var PromiseA = require('bluebird');
var dyndnsApi = require('./app');
var express = require('express');
var app = express();

var conf = {
  apiBase: '/api/com.daplie.ddns'
, pubkey: fs.readFileSync('examples/pubkey.pem')
};

// You may provide the Storage API however you wish
// (easy to adapt to sql, mongo, rethinkdb, couchdb, etc)
// however, you will find that masterquest-sqlite3
// and masterquest-pg provide the necessary methods
var Domains = {
  upsert: function (id, obj) {
    return new PromiseA(function (resolve) {
      // ...
      resolve();
    });
  }
, find: function (attrs, opts) {
    return new PromiseA(function (resolve) {
      // ...
      resolve([
        { name: '*.example.com'
        , zone: 'example.com'
        , ttl: 600
        , type: 'A' // A, AAAA, ANAME, CNAME, MX, TXT, SRV, FWD, etc
        , value: '127.0.0.1'
        , priority: null // only used for MX
        , device: 'foo-device'
        }
      ]);
    });
  }
};

app.use(require('body-parser').json());

PromiseA.resolve(dyndnsApi.create(conf, { Domains: Domains }, app)).then(function () {
  var server = require('http').createServer();
  server.on('request', app);
  server.listen(8080, function () {
    console.log(server.address());
  });
});
