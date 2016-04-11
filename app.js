'use strict';

var PromiseA = require('bluebird');
var jwt = PromiseA.promisifyAll(require('jsonwebtoken'));
var expressJwt = require('express-jwt');
//var url = require('url');
var ndns = require('native-dns');
//var rtypes = [ 'A', 'AAAA', 'ANAME', 'CNAME', 'MX', 'SRV', 'TXT' ];

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
  var Records = { restful: {} };
  var Devices = { restful: {} };

  // UPGRADE ONLY
  DnsStore.Domains.find({ device: null }).then(function (d1) {
    return DnsStore.Domains.find({ device: '' }).then(function (d2) {
      var domains = d1.concat(d2);

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
    var domains = getUpdateRecords(req);
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

  /*
  var Dns = { restful: {} };
  Dns.restful.update = function (req, res) {
  };
  Dns.update = function (req, q) {
  };
  */
  function getUpdateRecords(req) {
    return req.body && (req.body.records || req.body.domains) || req.body;
  }

  function ddnsUpdater(req, res) {
    var domains = getUpdateRecords(req);
    var updates = getUpdateRecords(req);

    if (!Array.isArray(updates)) {
      res.send({ error: { message:
        'usage: POST [{ "name": "example.com", "value": "127.0.0.1", "ttl": 300, "type": "A" }]'
      } });
      return;
    }

    if (domains[0].registered) {
      return ddnsUpdaterNew(req, res, updates);
    } else {
      // ddns
      return ddnsUpdaterOld(req, res, updates);
    }
  }

  function convertAllToRegistered(groupIdx) {
    return DnsStore.Domains.find({ groupIdx: groupIdx }).then(function (domains) {
      var zonesMap = {};

      domains.forEach(function (domain) {
        zonesMap[domain.zone] = true;
      });

      return PromiseA.all(Object.keys(zonesMap).map(function (zonename) {
        return convertToRegistered(groupIdx, zonename);
      }));
    });
  }
  function convertToRegistered(groupIdx, zonename) {
    return DnsStore.Domains.find({ zone: zonename }).then(function (oldDomains) {
      //
      // convert from unregistered to registered
      //
      return PromiseA.all(oldDomains.map(function (d) {
        if (d.groupIdx) {
          return PromiseA.resolve();
        }
        d.groupIdx = groupIdx;
        d.registered = true;

        return DnsStore.Domains.upsert(d.id, d);
      }));
    });

    //var registered = oldDomains.some(function (d) { return d.registered; });

    /*
    if (oldDomains.length && !registered) {
      return PromiseA.reject({
        message: "Error: This domain was registered with `ddns` which is available via `npm install -g ddns`."
          + " It cannot be used with `daplie` yet and must be converted manually."
          + " Open an issue at https://github.com/Daplie/daplie-tools for help."
      });
    }
    */
  }

  function ddnsUpdaterNew(req, res, updates) {
    var promise;
    var domains = [];
    var domain;
    var err;
    var updatedAt = new Date().toISOString();
    var zone;
    var groupsMap = {};

    if (!updates.every(function (update) {
      if (!update.registered || !update.groupIdx) {
        err = new Error('Cannot mix old-style unregistered domains with new-style registered domains');
        return false;
      }
      groupsMap[update.groupIdx] = true;
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

    //promise = PromiseA.resolve();
    promise = PromiseA.all(Object.keys(groupsMap).map(function (groupIdx) {
      return convertAllToRegistered(groupIdx);
    }));
    domains.forEach(function (domain, i) {
      promise = promise.then(function () {
        domain.id = getDomainId(domain);

        if (domain.destroy) {
          return DnsStore.Domains.destroy(domain.id).then(function () {
            return null;
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
  //
  // OLD
  //
  function ddnsUpdaterOld(req, res, updates) {
    var promise;
    var domains = [];
    var domain;
    var err;
    var updatedAt = new Date().toISOString();
    var zone;

    if (!Array.isArray(updates)) {
      res.send({ error: { message:
        'usage: POST [{ "name": "example.com", "value": "127.0.0.1", "ttl": 300, "type": "A" }]'
      } });
      return;
    }

    if (!updates.every(function (update) {
      if (update.registered) {
        err = new Error('Cannot mix old-style unregistered domains with new-style registered domains');
        return false;
      }
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
      , destroy: update.destroy
      };

      domains.push(domain);

      return true;
    })) {
      console.error('DEBUG Error dns/app.js');
      console.error(err);
      res.status(500).send(err);
      return;
    }

    promise = PromiseA.resolve();
    domains.forEach(function (domain, i) {
      console.log(
        'DEBUG [OLD] ddns'
      , domain.zone
      , domain.type
      , (domain.name || '').substr(0, (domain.zone.length - (domain.name.length + 1)))
      , domain.device
      , domain.value
      );
      promise = promise.then(function () {
        domain.id = getDomainId(domain, { old: true });

        return DnsStore.Domains.find({ zone: domain.zone }).then(function (existingDomains) {
          var registered = existingDomains.some(function (d) { return d.registered; });
          var oldDomains = existingDomains.filter(function (d) { return (domain.host === d.name || domain.host === d.zone) && domain.type === d.type; });
          var p2;
          var hostname;

          if (registered) {
            return PromiseA.reject({
              message: "Error: This domain was registered with https://daplie.domains via `daplie`."
                + " Please `npm install -g install daplie-tools` and use `daplie devices:update` instead of `ddns`."
                + " Open an issue at https://github.com/Daplie/daplie-tools for help."
            });
          }

          if (oldDomains.length) {
            // existing registration
            if (oldDomains[0].email && (oldDomains[0].email !== domain.email)) {
              return PromiseA.reject({
                message: "already registered to a different email"
              });
            }
          }
          else {
            // new registration
            if (!/\-/.test(domain.name)) {
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
            }
          }


          p2 = p2 || PromiseA.resolve();
          return p2.then(function () {
            return PromiseA.all(oldDomains.map(function (d) {
              return DnsStore.Domains.destroy(d.id);
            }));
          }).then(function () {
            if (domain.destroy) {
              updates[i] = oldDomains[0];
              return;
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
  function getOtherRecords(data, zone, ignoreOwner) {
    return function (recs) {
      var query = {};

      if (recs && recs.length) {
        return recs;
      }

      if (zone) {
        query.zone = zone;
      }
      if (!ignoreOwner && (data.groupIdx || data.accountIdx)) {
        query.groupIdx = data.groupIdx || data.accountIdx;
      }

      return DnsStore.Domains.find(query);
    };
  }
  Records.get = function (data) {
    var bare;
    var parts;
    var first = true;
    var promise1;

    data.cn = data.cn || '';
    bare = data.cn.replace(/^\*\./, '');
    parts = bare.split('.');

    if (data.groupIdx) {
      promise1 = convertAllToRegistered(data.groupIdx);
    }
    else {
      promise1 = PromiseA.resolve();
    }

    return promise1.then(function () {
      var promise = PromiseA.resolve([]);

      if (!data.cn) {
        promise = promise.then(getOtherRecords(data, null));
      }

      // /(^|\.)daplie.me$/i.test(bare) ? parts.length >= 3 :
      while (parts.length >= 2) {
        promise = promise.then(getOtherRecords(data, parts.join('.'), first));
        first = false;
        parts.shift();
      }

      return promise.then(function (records) {
        if (data.cn) {
          records = records.filter(function (record) {
            return bare === record.name
              || record.name.substr(record.name.length - ('.' + bare).length) === ('.' + bare);
          });
        }

        return records;
      });
    });
  };
  Records.restful.get = function (req, res) {
    var token = (req.headers.authorization || req.query.token)
      .replace(/^(Bearer|JWT|Token)\s*/i, '');
    var data;

    try {
      data = jwt.verify(token, pubPem);
    } catch(e) {
      data = null;
    }

    if (!data) {
      res.send({ error: { message: "invalid token", code: 'E_INVALID_TOKEN' }});
      return;
    }

    return Records.get(data).then(function (records) {
      res.send({ records: records });
    }, function (err) {
      console.error('ERROR app.js Records.get');
      console.error(err.stack || err);
      res.send({ error: { message: "unknown error" } });
    });
  };
  // Update
  Records.restful.update = function (req, res) {
    res.send({ error: { message: "Not Implemented" } });
  };
  Records.restful.destroy = function (req, res) {
    /*
    req.params.name
    req.params.type
    req.params.value
    req.params.device?
    */
    Records.destroy(req, req.params).then(function (record) {
      res.send(record);
    }, function (err) {
      console.error('ERROR app.js Records.destroy');
      console.error(err.stack || err);
      res.send({ error: { message: "unknown error" } });
    });
  };
  Records.destroy = function (req, opts) {
    // opts = { name, type, value, device };
    var query = { name: opts.name, value: opts.value };

    return DnsStore.Domains.find(query).then(function (devs) {
      var id;

      if (devs.length) {
        id = devs[0].id;
      }
      else {
        id = getDomainId(opts);
      }

      return DnsStore.Domains.destroy(id).then(function () {
        return devs[0] || {};
      });
    });
  };

  function getDomainId(domain, opts) {
    opts = opts || {};
    // TODO don't allow two devices to share the same ip?
    // (no, because they could be behind the same firewall
    var id = domain.type
      + ':' + domain.name
      ;

    if (!opts.old) {
      id += ':' + domain.value;
    }

    if (domain.device) {
      // Note: two devices could be behind the same ip,
      // but we don't want to restrict adding both of them to the same domain
      // (but we do need to filter them)
      id += ':' + (domain.device || ANON);
    }

    /*
    if (-1 !== ['A', 'AAAA'].indexOf(domain.type)) { // domain.device
      id = domain.type
        + ':' + domain.name
        + ':' + (domain.device || ANON)
        ;
    }
    else { // 'MX', 'CNAME', 'ANAME', 'TXT', 'SRV'
      id = domain.type
        + ':' + domain.name
        + ':' + domain.value
        ;
    }
    */

    return require('crypto').createHash('sha1').update(id).digest('base64')
      .replace(/=+/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  }

  Devices.restful = {};
  Devices.restful.update = function (req, res) {
    var token = req.user;
    var dev = req.body;

    Devices.update(token, dev).then(function () {
      res.send({ success: true });
    }, function (err) {
      console.error('Error: unexpected error in ddns/app.js');
      console.error(err.stack || err);
      res.send({ error: { message: 'INTERNAL ERROR (not your fault)' } });
    });
  };
  Devices.update = function (token, dev) {
    return PromiseA.resolve().then(function () {
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
      addresses = dev.addresses;
      /*
      .map(function (addr) {
        return addr.value;
      });
      */
      return convertAllToRegistered(token.groupIdx).then(function () {
        return DnsStore.Domains.find(q).then(function (domains) {
          var domainsMap = {};

          domains.forEach(function (domain) {
            // for upgrade
            deleters.push(domain.id);
            domainsMap[domain.name || domain.zone] = domain;
          });

          domainnames = Object.keys(domainsMap);

          return domainsMap;
        });
      }).then(function (domainsMap) {

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
  };

  Devices.restful.detach = function (req, res) {
    var token = req.user;
    var devicename = req.params.device || req.params.name;
    var name = req.params.sld + '.' + req.params.tld;

    if (req.params.sub) {
      name = req.params.sub + '.' + name;
    }

    if (req.params.domain) {
      name = req.params.domain;
    }

    Devices.destroy(token, devicename, name).then(function (domains) {
      res.send({ records: domains });
    }, function (err) {
      console.error('Error: unexpected error in ddns/app.js');
      console.error(err.stack || err);
      res.send({ error: { message: 'INTERNAL ERROR (not your fault)' } });
    });
  };
  Devices.restful.destroy = function (req, res) {
    var token = req.user;
    var devicename = req.params.name;

    Devices.destroy(token, devicename).then(function (domains) {
      res.send({ domains: domains });
    }, function (err) {
      console.error('Error: unexpected error in ddns/app.js');
      console.error(err.stack || err);
      res.send({ error: { message: 'INTERNAL ERROR (not your fault)' } });
    });
  };
  Devices.destroy = function (token, devicename, name) {
    return PromiseA.resolve().then(function () {
      // TODO dbwrap should throw an error when undefined is used
      var q = { /*device: devicename,*/ groupIdx: token.groupIdx };

      if (name) {
        q.name = name;
      }

      if (!token.groupIdx) {
        return PromiseA.reject(new Error("Sanity Fail: missing group id"));
      }

      return convertAllToRegistered(token.groupIdx).then(function () {

        return DnsStore.Domains.find(q).then(function (domains) {
          domains = domains.filter(function (d) {
            return d.device === devicename;
          });
          return PromiseA.all(domains.map(function (domain) {
            return DnsStore.Domains.destroy(domain.id);
          })).then(function () {
            return domains;
          });
        });
      });
    });
  };

  function listDomains(req, res) {
    DnsStore.Domains.find(null, { limit: 1000 }).then(function (rows) {
      rows = rows.filter(function (row) {
        return true || !row.registered;
      });
      rows.forEach(function (row) {
        // don't expose idx or email addresses
        row.accountIdx = undefined;
        row.groupIdx = undefined;
        row.email = undefined;

        Object.keys(row).forEach(function (key) {
          if (null === row[key] || '' === row[key]) {
            row[key] = undefined;
          }
        });
      });
      res.send(rows);
    });
  }

  function logr(req, res, next) {
    //console.log('DEBUG app.js [logger]', req.method, req.url, Object.keys(req.headers).join(','));
    next();
  }

  // /api/<<package-api-name>>/<<version>>

  // server, store, host, port, publicDir, options
  app.get(   apiBase + '/public', logr, listDomains);

  app.get(   apiBase + '/records', logr, expressJwt({ secret: pubPem }), Records.restful.get);
  app.post(  apiBase + '/records', logr, expressJwt({ secret: pubPem }), Records.restful.update);
  app.delete(apiBase + '/records/:name/:type/:value/:device?', logr, expressJwt({ secret: pubPem }), Records.restful.destroy);

  app.post(  apiBase + '/devices', logr, expressJwt({ secret: pubPem }), Devices.restful.update);
  app.delete(apiBase + '/devices/:name', logr, expressJwt({ secret: pubPem }), Devices.restful.destroy);
  app.delete(apiBase + '/devices/:name/:tld/:sld/:sub?', logr, expressJwt({ secret: pubPem }), Devices.restful.detach);
  app.delete(apiBase + '/devices/:device/:domain', logr, expressJwt({ secret: pubPem }), Devices.restful.detach);

  app.post(  apiBase + '/dns/', logr, expressJwt({ secret: pubPem }), ddnsTokenWall, ddnsUpdater);
  app.post(  apiBase + '/ddns', logr, expressJwt({ secret: pubPem }), ddnsTokenWall, ddnsUpdater);

  return app;
};
