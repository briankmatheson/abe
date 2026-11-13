Test-only PKI for `cargo test` and tests/e2e.sh. Every private key here
is public, by design: these certificates authenticate nothing outside
the unit tests. Never install them anywhere. Regenerate with gen.sh
(openssl, 10-year validity).

  ca.pem / ca-key.pem                  the test CA (CN "abe test CA")
  server.pem / server-key.pem          server cert signed by it, SAN 127.0.0.1 and localhost
  client.pem / client-key.pem          client cert signed by it (serverAuth + clientAuth)
  other-ca.pem / other-ca-key.pem      an unrelated CA; clients it signed must be refused
  other-client.pem / other-client-key.pem
