'use strict';

exports.create = function (conf, DnsStore, app) {
  // server, store, host, port, publicDir, options
  app.use('/', function (req, res) {
    console.log('[LOG DNS API]', req.method, req.url);
    DnsStore.Domains.find(null, { limit: 100 }).then(function (rows) {
      res.send(rows);
    });
  });

  return app;
};
