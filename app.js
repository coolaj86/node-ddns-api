'use strict';

exports.create = function (conf, DnsStore, app) {
  // server, store, host, port, publicDir, options
  app.use('/', function (req, res) {
    console.log('[LOG DNS API]', req.method, req.url);
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

  return app;
};
