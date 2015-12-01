Node.js DynDNS API
======

**STOP:** You probably want [node-dyndns](https://github.com/Daplie/node-dyndns)

A Dynamic DNS (DDNS / DynDNS) api written in node.js.

This is one distinct part of a 3-part system.

  * node-ddns (full stack demo)
  * node-ddns-api (RESTful HTTP API)
  * node-ddns-frontend (HTML5 Management App)
  * node-ddns-service (UDP DNS Server)

API
---

* `POST /ddns`
* `GET /public`

Install & Configure
-------------------

```bash
# npm
npm install --save ddns-api

# git
git clone git@github.com:Daplie/node-ddns-api.git
```

```bash
# generate keypair
node ./bin/generate-rsa-keypair examples/privkey.pem

# generate public key
node ./bin/keypair-to-public examples/privkey.pem examples/pubkey.pem

# generate signed token
node bin/sign-jwt.js examples/privkey.pem example.com foo-servername
```

```javascript
'use strict';

var fs = require('fs');
var PromiseA = require('bluebird');
var dyndnsApi = require('dyndns-api');
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
, find: function (attrs /*null*/, opts /*{ limit: 500 }*/) {
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
  var server = http.createServer();
  server.on('request', app);
  server.listen(8080, function () {
    console.log(server.address());
  });
});
```

Test that it all works
----------------------

```bash
node example.js
```

```bash
# update a DNS record
JWT=$(node bin/sign-jwt examples/privkey.pem '*.example.com' 'foo-server')
curl http://localhost:8080/api/com.daplie.ddns/ddns \
  -X POST \
  -H 'Authorization: Bearer '$JWT \
  -H 'Content-Type: application/json; charset=utf-8' \
  -d '[
        { "name": "example.com"
        , "value": "127.0.0.1"
        , "type": "A"
        , "device": "foo-server"
        // priority
        // ttl
        }
      ]'

# test that the record was updated
curl http://localhost:8080/api/com.daplie.ddns/public
```

LICENSE
=======

Dual-licensed MIT and Apache-2.0

See LICENSE
