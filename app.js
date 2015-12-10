'use strict';

var PromiseA = require('bluebird');
var jwt = PromiseA.promisifyAll(require('jsonwebtoken'));
var expressJwt = require('express-jwt');
//var url = require('url');
var ndns = require('native-dns');

function checkMx(hostname) {
  return new PromiseA(function (resolve, reject) {
    require('dns').resolve(hostname, 'MX', function (err, records) {
      if (err) {
        reject({
          message: "invalid mx (email) lookup"
        });
        return;
      }

      if (!records.length) {
        reject({
          message: "no mx (email) records"
        });
        return;
      }

      resolve();
    });
  });
}

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
  var apiBase = conf.apiBase || '';

  function ddnsTokenWall(req, res, next) {
    var body = req.body;
    var domains = body && (body.records || body.domains) || body;
    var tokens = body && body.tokens || body;
    var err;

    if (!Array.isArray(domains)) {
      res.send({ error: { message: "malformed request" } });
      return;
    }

    tokens = tokens.map(function (token) {
      token = token && token.token || token;

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

        if (!token.cn || !cnMatch(token.cn, entry.name)) {
          err = entry.name;
          return false;
        }

        if (token.device) {
          if (!entry.device) {
            entry.device = token.device;
          }
          else if (entry.device !== token.device) {
            err = entry.name + '@' + entry.device;
            return false;
          }
        }

        if ('anonymous' === token.device && !entry.email) {
          err = entry.name + ':E_EMAIL_REQUIRED';
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
    var domain;
    var updates;
    var err;
    var updatedAt = new Date().toISOString();
    var zone;

    updates = req.body && req.body.records || req.body;

    if (!Array.isArray(updates)) {
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
      update.value = update.value || update.answer || update.address || update.ip || update.myip
        || req.ip || req.connection.remoteAddress
        ;
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

      if (!update.value) {
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
      , type: (update.type || 'A').toUpperCase() //dns.consts.NAME_TO_QTYPE[update.type || 'A'],
      , value : update.value
      , ttl : update.ttl
      , priority: update.priority
      , device: update.device
      , email: update.email
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
            + ':' + domain.value
            ;
        }

        domain.id = require('crypto').createHash('sha1').update(id).digest('base64')
          .replace(/=+/g, '').replace(/\+/g, '-').replace(/\//g, '_');

        return DnsStore.Domains.get(domain.id).then(function (oldDomain) {
          if (oldDomain) {
            if (oldDomain.email && oldDomain.email !== domain.email) {
              return PromiseA.reject({
                message: "already registered to a different email"
              });
            }
          }

          var p2;
          var hostname;

          if (domain.email) {
            if (!/.+@/.test(domain.email)) {
              p2 = PromiseA.reject({
                message: "invalid email address format"
              });
            } else {
              hostname = domain.email.replace(/.*@/, '');
              p2 = checkMx(hostname);
            }
          } else {
            p2 = PromiseA.resolve();
          }


          return p2.then(function () {

            return DnsStore.Domains.upsert(domain.id, domain).then(function () {
              updates[i] = {
                type: domain.type
              , name: (domain.zone !== domain.host) ? domain.host : ''
              , value: domain.value
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
          }, function (err) {
            updates[i] = {
              error: {
                message: "mx error for '" + domain.email + "': " + (err.message || err.code)
              }
            };
          });
        }, function (/*err*/) {
          // TODO trigger logger
          updates[i] = {
            error: { message: "db error for '" + domain.name + "'" }
          };
        });
      }).then(function () {
        // Promise Hack
        // because we're looping this promise and an error may occur
        // in the body of the promise, we catch catch it's errors in
        // that error handler.
        // Instead we ignore this body and handle the error with the
        // next handler.
      }, function (err) {
        updates[i] = {
          error: { message: (err.message || err.code || err.toString().split('\n')[0]) }
        };
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
      res.send(updates);
    }, function (err) {
      updates.push({
        error: { message: (err.message || err.code || err.toString().split('\n')[0]) }
      });
      res.send(updates);
    });
  }

  // /api/<<package-api-name>>/<<version>>

  // server, store, host, port, publicDir, options
  app.get(apiBase + '/public', function (req, res) {
    DnsStore.Domains.find(null, { limit: 500 }).then(function (rows) {
      rows.forEach(function (row) {
        Object.keys(row).forEach(function (key) {
          // don't expose email addresses
          row.email = undefined;
          if (null === row[key] || '' === row[key]) {
            row[key] = undefined;
          }
        });
      });
      res.send(rows);
    });
  });
  app.post(apiBase + '/dns/', expressJwt({ secret: pubPem }), ddnsTokenWall, ddnsUpdater);
  app.post(apiBase + '/ddns', expressJwt({ secret: pubPem }), ddnsTokenWall, ddnsUpdater);

  return app;
};
