curl https://localhost:65443/api/ddns \
  -X POST \
  --cacert ../certs/ca/my-root-ca.crt.pem \
  -u admin:secret \
  -H 'Content-Type: application/json' \
  -d '{ "name": "doesntexist.com"
      , "value": "250.250.250.1"
      , "type": "A"
      }'
