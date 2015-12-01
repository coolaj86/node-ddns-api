'use strict';

module.exports.create = function (conf, deps, app) {
  // TODO there should be an adapter
  //var PromiseA = deps.Promise;
  //var Kv = deps.memstore;
  //var Sqlstore = deps.sqlstores.config;
  var wrap = require('masterquest-sqlite3');
  var dir = [
    // TODO consider zones separately from domains
    // i.e. jake.smithfamily.com could be owned by jake alone
    { tablename: 'domains'
    , idname: 'id' // crypto random
    , indices: ['createdAt', 'updatedAt', 'deletedAt', 'revokedAt', 'zone', 'name', 'type', 'value', 'device']
    , hasMany: ['accounts', 'groups']
    }
  , { tablename: 'accounts_domains'
    , idname: 'id'
    , indices: ['createdAt', 'updatedAt', 'deletedAt', 'revokedAt', 'accountId']
    , hasMany: ['accounts', 'domains']
    }
  , { tablename: 'domains_groups'
    , idname: 'id'
    , indices: ['createdAt', 'updatedAt', 'deletedAt', 'revokedAt', 'accountId']
    , hasMany: ['domains', 'groups']
    }
  ];

  return deps.systemSqlFactory.create({
    init: true
  , dbname: 'dns'
  }).then(function (DnsSql) {
    return wrap.wrap(DnsSql, dir);
  }).then(function (DnsStore) {
    return require('./app').create(conf, DnsStore, app);
  });
};
