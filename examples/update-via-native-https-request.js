#!/usr/bin/env node
'use strict';

var https = require('https')
  , fs = require('fs')
  , path = require('path')
  , hostname = process.argv[2] || 'localhost'
  , port = process.argv[3] || 65443
  , options
  ;

options = {
  host: hostname
, port: port
, method: 'POST'
, headers: {
    'Content-Type': 'application/json'
  }
, path: '/api/ddns'
, auth: 'admin:secret'
, ca: fs.readFileSync(path.join(__dirname, '..', 'certs', 'ca', 'my-root-ca.crt.pem'))
};
options.agent = new https.Agent(options);

https.request(options, function(res) {
  res.pipe(process.stdout);
}).end('{ "name": "doesntexist.com", "value": "250.250.250.1", "type": "A" }');
