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
  var ANON = 'anonymous';
  var pubPem = conf.pubkey; // conf.keypair.toPublicPem();
  var apiBase = conf.apiBase || '';
  var Records = {};
  var Devices = {};

  // UPGRADE ONLY
  DnsStore.Domains.find({ device: null }).then(function (d1) {
    return DnsStore.Domains.find({ device: '' }).then(function (d2) {
      var domains = d1.concat(d2);

      console.log('DEBUG domains.length', domains.length);

      return PromiseA.all(domains.filter(function (d) {
        return !d.device;
      }).map(function (d) {
        d.device = ANON;
        return DnsStore.Domains.upsert(d);
      }));
    });
  });

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

        entry.groupIdx = null;
        if (token.groupIdx) {
          entry.groupIdx = token.groupIdx;
        }

        entry.registered = null;
        if (token.registered) {
          entry.registered = token.registered;
        }

        if (!entry.device) {
          entry.device = token.device || ANON;
        }

        if (token.device) {
          if (entry.device !== token.device) {
            err = entry.name + '@' + entry.device;
            return false;
          }
        }

        if (ANON === token.device && !entry.email) {
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
      // TODO use tld, private tld, and public suffix lists
      if ('daplie.me' === zone && update.host.replace(/^www\./i, '') !== 'daplie.me') {
        zone = update.host.split('.').slice(-3).join('.');
      }

      domain = {
        host : update.host
      , zone: zone
      //, zone:
      , name : update.host
      , type: (update.type || 'A').toUpperCase() //dns.consts.NAME_TO_QTYPE[update.type || 'A'],
      , value : update.value
      , ttl : update.ttl
      , priority: update.priority
      , device: update.device || ANON
      , email: update.email
      , registered: update.registered
      , destroy: update.destroy
      , groupIdx: update.groupIdx
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
            + ':' + (domain.device || ANON)
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

        return DnsStore.Domains.find({ zone: domain.zone }).then(function (oldDomains) {
          var registered = oldDomains.some(function (d) { return d.registered; });
          var oldDomain = oldDomains.filter(function (d) { return domain.id === d.id; })[0];
          var p2;
          var hostname;

          if (registered && !domain.registered) {
            return PromiseA.reject({
              message: "domain is registered via https://daplie.domains Please `npm install -g install daplie-tools` and use `daplie devices:update` instead"
            });
          }

          if (oldDomain) {
            if (oldDomain.email && oldDomain.email !== domain.email) {
              return PromiseA.reject({
                message: "already registered to a different email"
              });
            }
          } else if (!/\-/.test(domain.name)) {
            // TODO reserve non-hyphenated (non-random) domains for registered users
          }

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

            if (domain.destroy) {
              return DnsStore.Domains.destroy(domain.id).then(function () {
              }, function (/*err*/) {
                // TODO trigger logger
                updates[i] = {
                  error: { message: "db error for destroy '" + domain.name + "'" }
                };
              });
            }

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
              , registered: domain.registered
              , groupIdx: domain.groupIdx
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
        Object.keys(row).filter(function (row) {
          return !row.registered;
        }).forEach(function (key) {
          // don't expose idx or email addresses
          row.accountIdx = undefined;
          row.email = undefined;
          if (null === row[key] || '' === row[key]) {
            row[key] = undefined;
          }
        });
      });
      res.send(rows);
    });
  });

  /*
  function deviceUpdater(req, res) {
  }

  app.get(
    apiBase + '/com.daplie.ddns/devices'
  , expressJwt({ secret: pubPem })
  , ddnsTokenWall
  , getDevices
  );
  app.post(
    apiBase + '/com.daplie.ddns/devices/:deviceId'
  , expressJwt({ secret: pubPem })
  , ddnsTokenWall
  , deviceUpdater
  );
  */

  Records.get = function (req, res) {
    var token = (req.headers.authorization || req.query.token)
      .replace(/^(Bearer|JWT|Token)\s*/i, '');
    var data;
    var bare;
    var parts;
    var zone;
    var promise = PromiseA.resolve([]);

    try {
      data = jwt.verify(token, pubPem);
    } catch(e) {
      data = null;
    }

    if (!data) {
      res.send({ error: { message: "invalid token" }});
      return;
    }

    bare = data.cn.replace(/^\*\./, '');
    parts = bare.split('.');

    function getOtherRecords(recs) {
      if (recs.length) {
        return recs;
      }

      return DnsStore.Domains.find({ zone: zone });
    }

    // /(^|\.)daplie.me$/i.test(bare) ? parts.length >= 3 :
    while (parts.length >= 2) {
      zone = parts.join('.');
      parts.shift();
      promise = promise.then(getOtherRecords);
    }

    promise.then(function (records) {
      res.send({ records: records.filter(function (record) {
        return bare === record.name
          || record.name.substr(record.name.length - ('.' + bare).length) === ('.' + bare);
      }) });
    });
  };
  Records.update = function (req, res) {
    res.send({ error: { message: "Not Implemented" } });
  };

  function getDomainId(domain) {
    var id = domain.type
      + ':' + domain.name
      + ':' + domain.value
      + ':' + (domain.device || ANON)
      ;

    return require('crypto').createHash('sha1').update(id).digest('base64')
      .replace(/=+/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  }

  Devices.update = function (req, res) {
    var promise = PromiseA.resolve().then(function () {
      var token = req.user;
      var dev = req.body;
      var addresses;
      var q = { device: dev.name, groupIdx: token.groupIdx };
      var deleters = [];
      var placers = [];
      var domainnames;

      if (!token.groupIdx) {
        return PromiseA.reject(new Error("Sanity Fail: missing group id"));
      }
      if (!Array.isArray(dev.addresses) || !(dev.addresses[0]||{}).value) {
        return PromiseA.reject(new Error("Sanity Fail: uncheked addresses"));
      }
      addresses = dev.addresses.map(function (addr) {
        return addr.value;
      });

      return DnsStore.Domains.find(q).then(function (domains) {
        var domainsMap = {};

        domains.forEach(function (domain) {
          // for upgrade
          deleters.push(domain.id);
          domainsMap[domain.name] = domain;
        });

        domainnames = Object.keys(domainsMap);

        domainnames.forEach(function (domainname) {
          addresses.forEach(function (addr) {
            var index;
            var record = {
              id: null
            , host: domainname
            , zone: domainsMap[domainname].zone
            //, zone:
            , name: domainname
            , type: addr.type // A or AAAA
            , value: addr.value
            , ttl: domainsMap[domainname].ttl || 600
            , priority: undefined
            , device: dev.name
            , groupIdx: q.groupIdx
            , registered: true
            };

            record.id = getDomainId(record);
            index = deleters.indexOf(record.id);

            if (-1 !== index) {
              deleters.splice(index, 1);
            }

            placers.push(record);
          });
        });

        // either A (do nothing) or B (add and destroy)
        return PromiseA.all(placers.map(function (r) {
          return DnsStore.Domains.upsert(r);
        })).then(function () {
          return PromiseA.all(deleters.map(function (rid) {
            return DnsStore.Domains.destroy(rid);
          }));
        });
      });
    });

    promise.then(function () {
      res.send({ success: true });
    }, function (err) {
      console.error('Error: unexpected error in ddns/app.js');
      console.error(err.stack || err);
      res.send({ error: { message: 'INTERNAL ERROR (not your fault)' } });
    });
  };

  Devices.destroy = function (req, res) {
    var promise = PromiseA.resolve().then(function () {
      var token = req.user;
      var dev = req.body;
      var q = { device: dev.name, groupIdx: token.groupIdx };

      if (!token.groupIdx) {
        return PromiseA.reject(new Error("Sanity Fail: missing group id"));
      }

      return DnsStore.Domains.find(q).then(function (domains) {
        return PromiseA.all(domains.map(function (domain) {
          return DnsStore.Domains.destroy(domain.id);
        })).then(function () {
          return domains;
        });
      });
    });

    promise.then(function (domains) {
      res.send({ domains: domains });
    }, function (err) {
      console.error('Error: unexpected error in ddns/app.js');
      console.error(err.stack || err);
      res.send({ error: { message: 'INTERNAL ERROR (not your fault)' } });
    });
  };

  app.get(   apiBase + '/records', expressJwt({ secret: pubPem }), Records.get);
  app.post(  apiBase + '/records', expressJwt({ secret: pubPem }), Records.update);
  app.post(  apiBase + '/devices', expressJwt({ secret: pubPem }), Devices.update);
  app.delete(apiBase + '/devices/:name', expressJwt({ secret: pubPem }), Devices.destroy);

  app.post(  apiBase + '/dns/', expressJwt({ secret: pubPem }), ddnsTokenWall, ddnsUpdater);
  app.post(  apiBase + '/ddns', expressJwt({ secret: pubPem }), ddnsTokenWall, ddnsUpdater);

  return app;
};
