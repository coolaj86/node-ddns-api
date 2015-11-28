node-ddns
======

A Dynamic DNS (DDNS / DynDNS) server written in node.js.

Install & Configure
-------------------

```bash
git clone git@github.com:Daplie/node-ddns.git
pushd node-ddns

echo '{}' > dns.db.json

# edit config.example.json with nameserver information
rsync -av config.example.json config.json
vim config.json
```

Start DNS Server and Web Portal
-------------------------------

```bash
# node bin/node-dyndns <<dns port>> <<https port>>
node bin/node-dyndns 65053 65443

# or sudo node bin/node-dyndns 53 443
```

Generate Domain Update Tokens
-----------------------------

```bash
# Generate a JWT that will allow updates of a particular domain
# node lib/cn-auth <<valid domain pattern>> <<pattern test>>
# (the second argument is the test parameter, which must be set to a matching domain)

# Generate a JWT allowing any and all domain updates whatsoever
# (i.e. for super user / admin use)
node lib/cn-auth '*' 'example.com'

# Generate a JWT allowing only *.example.com and example.com
# (i.e. for distributing to domain owners)
node lib/cn-auth '*.example.com' 'bar.foo.example.com'
```

Test that it all works
----------------------

```bash
# update a DNS record
curl https://localhost:65443/api/ddns \
  -X POST \
  --cacert certs/ca/my-root-ca.crt.pem \
  -H 'Authorization: Bearer '$JWT \
  -H 'Content-Type: application/json; charset=utf-8' \
  -d '[
        { "name": "example.com"
        , "value": "127.0.0.1"
        , "type": "A"
        }
      ]'

# test that the record was updated
dig -p 65053 @localhost example.com A
```

**via GET**

```
/nic/update?name=example.com&type=A&value=127.0.0.1
```

IP Address Resolve
--------

The resolve API refers RFC 1035.

License
========

Apache2
