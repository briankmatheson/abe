#!/bin/bash
# Regenerates the test-only PKI under tests/certs/ (10-year validity).
# Nothing here protects anything: the keys are committed to the repo.
#   tests/certs/gen.sh
set -euo pipefail
cd "$(dirname "$0")"
days=3650
ext=$(mktemp); trap 'rm -f "$ext"' EXIT
mk_ca() {  # mk_ca <name> <cn>
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$1-key.pem" -out "$1.pem" -days $days -subj "/CN=$2" \
        -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
}
mk_leaf() {  # mk_leaf <ca> <name> <cn> <san>
    printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=%s\n' "$4" > "$ext"
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$2-key.pem" -out "$2.csr" -subj "/CN=$3" 2>/dev/null
    openssl x509 -req -in "$2.csr" -CA "$1.pem" -CAkey "$1-key.pem" -CAcreateserial \
        -out "$2.pem" -days $days -extfile "$ext" 2>/dev/null
    rm -f "$2.csr"
}
mk_ca ca "abe test CA"
mk_leaf ca server "abe test server" "IP:127.0.0.1,DNS:localhost"
mk_leaf ca client "abe test client" "DNS:client.test"
mk_ca other-ca "abe other test CA"
mk_leaf other-ca other-client "abe other test client" "DNS:other.test"
rm -f ./*.srl
echo "regenerated: $(ls ./*.pem | tr '\n' ' ')"
