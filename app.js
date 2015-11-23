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
    var zone;

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

      // TODO this only works for 4+ character domains
      // example.com
      // example.co.uk
      // example.com.au
      // abc.com.au // fail
      //update.host.replace(/^.*?\.([^\.]{4,})(\.[^\.]{2,3})?(\.[^\.]{2,})$/, "$1$2$3")

      // How can we get all of these cases right?
      // o.co             => o.co
      // ba.fo.ex.co.uk   => ex.co.uk
      // ba.fo.ex.com.au  => ex.com.au
      // ba.fo.ex.com     => ex.cam

      // simplest solution: we ignore .co.uk, .com.au, .co.in, etc
      zone = update.host.split('.').slice(-2).join('.');

      domain = {
        host : update.host
      , zone: zone
      //, zone:
      , name : update.host
      , type: update.type || 'A' //dns.consts.NAME_TO_QTYPE[update.type || 'A'],
      , value : update.value
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
        var id;

        // one per device
        if (-1 !== ['A', 'AAAA'].indexOf(domain.type)) {
          id = domain.type
            + ':' + domain.name
            + ':' + (domain.device || '')
            ;
        }
        // one per value (per zone?)
        else /*if (-1 !== ['MX', 'CNAME', 'ANAME', 'TXT'].indexOf(domain.type))*/ {
          id = domain.type
            + ':' + domain.name
            + ':' + (domain.value || (domain.answers && domain.answers[0] || ''))
            ;
        }

        domain.id = require('crypto').createHash('sha1').update(id).digest('base64')
          .replace(/=+/g, '').replace(/\+/g, '-').replace(/\//g, '_');

        return DnsStore.Domains.upsert(domain.id, domain).then(function () {
          updates[i] = {
            type: domain.type
          , name: (domain.zone !== domain.host) ? domain.host : ''
          , value: domain.value || (domain.answers && domain.answers[0] || undefined)
          , ttl: domain.ttl
          , priority: domain.priority
          , updatedAt: updatedAt
          , device: domain.device // TODO use global
          , zone: domain.zone
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

  // /api/<<package-api-name>>/<<version>>

  // server, store, host, port, publicDir, options
  app.get('/public', function (req, res) {
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
  app.post('/dns/', expressJwt({ secret: pubPem }), ddnsTokenWall, ddnsUpdater);
  app.post('/ddns', expressJwt({ secret: pubPem }), ddnsTokenWall, ddnsUpdater);

  return app;
};
