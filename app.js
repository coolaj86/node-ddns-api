'use strict';

var PromiseA = require('bluebird').Promise;
var jwt = PromiseA.promisifyAll(require('jsonwebtoken'));
var expressJwt = require('express-jwt');
var url = require('url');
var ndns = require('native-dns');

function cnMatch(pat, sub) {
  var bare = pat.replace(/^\*\./, '');
  var dot = '.' + bare;
  var index;

  if ('*' === pat) {
    return true;
  }

  if (bare === sub) {
    return true;
  }

  // 'foo.example.com'.lastIndexOf('.example.com') + '.example.com'.length
  // === 'foo.example.com'.length;
  index = sub.lastIndexOf(dot);
  return sub.length === index + dot.length;
}

exports.create = function (conf, DnsStore, app) {
  //console.log('conf');
  //console.log(conf);
  var pubPem = conf.pubkey; // conf.keypair.toPublicPem();

  function ddnsTokenWall(req, res, next) {
    var domains = req.body && req.body.domains || req.body;
    var tokens;
    var err;

    tokens = (req.body && req.body.tokens || [(req.headers.authorization||'').replace(/Bearer\s+/, '')])
      .map(function (token) {
        try {
          return jwt.verify(token, pubPem);
        } catch(e) {
          return null;
        }
      }).filter(function (token) {
        return token;
      });

    if (!domains.every(function (entry) {
      // TODO if token exists at entry.token, validate by that token
      return tokens.some(function (token) {
        if (!cnMatch(token.cn, entry.name)) {
          err = entry.name;
          return false;
        }

        return true;
      });
    })) {
      res.send({ error: { message: "Not authenticated for '" + (err && err.message || err) + "'" } });
      return;
    }

    next();
  }

  function ddnsUpdater(req, res) {
    var promise;
    var domains = [];
    var query;
    var domain;
    var updates;
    var update;
    var err;
    var updatedAt = new Date().toISOString();

    query = url.parse(req.url, true).query;
    if (query.key || query.name || query.hostname) {
      update = query;
      updates = [query];
    }
    if (Array.isArray(req.body)) {
      update = null;
      updates = req.body;
    }

    if (!updates || !updates.length) {
      console.error(query);
      console.error(req.body);
      res.send({ error: { message:
        'usage: POST [{ "name": "example.com", "value": "127.0.0.1", "ttl": 300, "type": "A" }]'
      } });
      return;
    }

    if (!updates.every(function (update) {
      if (!update.type) {
        update.type = 'A';
      }
      update.host = update.host || update.key || update.name || update.hostname;

      // TODO BUG XXX must test if address is ipv4 or ipv6
      // (my comcast connection is ipv6)
      update.answer = update.answer || update.value || update.address || update.ip || update.myip
        || req.connection.remoteAddress
        ;
      update.answers = Array.isArray(update.answers) && update.answers || [update.answer];
      if (update.ttl) {
        update.ttl = parseInt(update.ttl, 10);
      }
      if (!update.ttl) {
        update.ttl = 300;
      }
      // TODO update.priority


      if (!ndns.consts.NAME_TO_QTYPE[update.type.toString().toUpperCase()]) {
        err = { error: { message: "unrecognized type '" + update.type + "'" } };
        return false;
      }

      if (!update.answer) {
        err = { error: { message: "missing key (hostname) and or value (ip)" } };
        return false;
      }

      domain = {
        host : update.host
      , name : update.host
      , type: update.type || 'A' //dns.consts.NAME_TO_QTYPE[update.type || 'A'],
      , values : update.answers
      , answers : update.answers
      , ttl : update.ttl
      , priority: update.priority
      };

      domains.push(domain);

      return true;
    })) {
      res.status(500).send(err);
      return;
    }

    promise = PromiseA.resolve();
    domains.forEach(function (domain, i) {
      promise = promise.then(function () {
        var id = domain.type + ':' + domain.name + ':' + (domain.device || '');
        domain.id = require('crypto').createHash('sha1').update(id).digest('base64').replace(/=+/g, '');
        return DnsStore.Domains.upsert(domain.id, domain).then(function () {
          updates[i] = {
            type: domain.type
          , name: domain.host
          , value: domain.value || (domain.answers && domain.answers[0] || undefined)
          , ttl: domain.ttl
          , priority: domain.priority
          , updatedAt: updatedAt
          , device: domain.device // TODO use global
          // 'zone', 'name', 'type', 'value', 'device'
          };
        }, function (/*err*/) {
          // TODO trigger logger
          updates[i] = {
            error: { message: "db error for '" + domain.name + "'" }
          };
        });
      });
    });

    /*
    if (err) {
      // TODO should differentiate between bad user data and server failure
      res.status(500).send({ error: { message: err.message || err.toString() } });
      return;
    }
    */

    promise.then(function () {
      res.send(update || updates);
    });
  }

  // server, store, host, port, publicDir, options
  app.get('/api/dns/public', function (req, res) {
    //console.log('[LOG DNS API]', req.method, req.url);
    DnsStore.Domains.find(null, { limit: 500 }).then(function (rows) {
      rows.forEach(function (row) {
        Object.keys(row).forEach(function (key) {
          if (null === row[key] || '' === row[key]) {
            row[key] = undefined;
          }
        });
      });
      res.send(rows);
    });
  });
  app.post('/api/dns/', expressJwt({ secret: pubPem }), ddnsTokenWall, ddnsUpdater);
  app.post('/api/ddns', expressJwt({ secret: pubPem }), ddnsTokenWall, ddnsUpdater);

  return app;
};
