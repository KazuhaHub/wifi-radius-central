#!/bin/bash
# Renew the RADIUS server certificate (radius.kazuha.org) from the existing private CA. PRIMARY host only.
# Devices trust the CA + the name, so a renewal with the same CA and name needs no change on any client.
#
#   renew-server-cert.sh                 issue a new cert + key into pki/staging/<timestamp>/ and check it (no live change)
#   renew-server-cert.sh --out DIR       the same, into DIR
#   renew-server-cert.sh --install DIR   archive the current certs, install DIR's cert + key into certs/,
#                                        publish the set to dist/ (publish-site-certs: the sites pull it
#                                        within 6 h), restart the central FreeRADIUS, wait until it is ready
#                                        and show the handshake (the backup node pulls the new set from the
#                                        cert-dist service by itself)
#
# This script lives in host/ of the deployment folder (the one with compose.yaml); it finds that folder from its own
# location. Expected layout there: pki/ca/ca.key (the CA's private key), certs/ca.pem, certs/server.pem, certs/server.key.
# Apple devices reject TLS server certificates valid for more than 825 days, so never raise DAYS.
set -euo pipefail
BASE=${WIFI_RADIUS_BASE:-$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)}
CA_KEY=$BASE/pki/ca/ca.key
CA_PEM=$BASE/certs/ca.pem
NAME=radius.kazuha.org
DAYS=825

env_get() {  # VAR: its value in the deployment's .env (not sourced: the file is data), surrounding quotes removed
  local v
  v=$(grep -m1 "^$1=" "$BASE/.env" 2>/dev/null | cut -d= -f2- || true)
  v=${v%$'\r'}
  if [[ $v == \"*\" || $v == \'*\' ]]; then v=${v:1:${#v}-2}; fi
  printf '%s' "$v"
}

check() {  # $1 = dir with server.pem/server.key
  local d=$1
  openssl verify -no-CApath -no-CAstore -CAfile "$CA_PEM" "$d/server.pem" >/dev/null
  openssl x509 -in "$d/server.pem" -noout -ext subjectAltName | grep -q "DNS:$NAME"
  openssl x509 -in "$d/server.pem" -noout -ext extendedKeyUsage | grep -q "TLS Web Server Authentication"
  [ "$(openssl x509 -in "$d/server.pem" -noout -pubkey | openssl sha256)" = \
    "$(openssl pkey -in "$d/server.key" -pubout | openssl sha256)" ]
  local start end
  start=$(date -d "$(openssl x509 -in "$d/server.pem" -noout -startdate | cut -d= -f2)" +%s)
  end=$(date -d "$(openssl x509 -in "$d/server.pem" -noout -enddate | cut -d= -f2)" +%s)
  [ $(( (end - start) / 86400 )) -le 825 ]
}

issue() {
  local d=${1:-$BASE/pki/staging/$(date +%Y%m%d-%H%M%S)}
  mkdir -p "$d"; chmod 700 "$d"
  openssl genrsa -out "$d/server.key" 3072 2>/dev/null
  openssl req -new -key "$d/server.key" -subj "/O=Kazuha Hub/CN=$NAME" -out "$d/server.csr"
  cat > "$d/server.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$NAME
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EXT
  openssl x509 -req -in "$d/server.csr" -CA "$CA_PEM" -CAkey "$CA_KEY" \
    -set_serial "0x$(openssl rand -hex 16)" -days "$DAYS" -sha256 -extfile "$d/server.ext" -out "$d/server.pem" 2>/dev/null
  check "$d"
  echo "Issued and checked: $d"
  openssl x509 -in "$d/server.pem" -noout -subject -enddate -fingerprint -sha256
  echo "Install with: $0 --install $d"
}

install_cert() {
  local d=$1 ts dest=$BASE/certs
  check "$d"
  ts=$(date +%Y%m%d-%H%M%S)
  mkdir -p "$BASE/pki/archive/$ts"; chmod 700 "$BASE/pki/archive/$ts"
  cp -p "$dest/server.pem" "$dest/server.key" "$BASE/pki/archive/$ts/"
  install -m 644 -o root -g "$(stat -c %g "$dest/server.pem")" "$d/server.pem" "$dest/server.pem"
  install -m 640 -o root -g "$(stat -c %g "$dest/server.key")" "$d/server.key" "$dest/server.key"
  echo "Old certs archived in $BASE/pki/archive/$ts"
  "$BASE/host/publish-site-certs" && echo "Published to dist/: sites pull it within 6 h and restart their FreeRADIUS"
  if [ -n "${NO_RESTART:-}" ]; then echo "(NO_RESTART set: skipping restart and handshake test)"; return; fi
  # The container reads certs/ at start, so it is restarted. It refuses to start on a set that fails its
  # checks, so wait for "Ready to process requests" and fail loudly if it does not come.
  local since out i ready=""
  since=$(date +%s)
  (cd "$BASE" && docker compose restart freeradius >/dev/null)
  for i in $(seq 30); do
    out=$(cd "$BASE" && docker compose logs --since "$since" freeradius 2>&1 || true)
    if grep -q "Ready to process requests" <<< "$out"; then ready=1; break; fi
    sleep 1
  done
  if [ -z "$ready" ]; then
    echo "ERROR: the Primary FreeRADIUS did not become ready within 30 s after the restart. The new set is installed and published; fix it or put the archived pair back from $BASE/pki/archive/$ts." >&2
    grep wifi-radius-central <<< "$out" | tail -n 8 >&2 || true
    exit 1
  fi
  # Handshake test from inside the container, where eapol_test, the address and the secret are: the secret
  # never appears on this host's command line. Loopback and the local client if LISTEN_ADDRS has loopback,
  # otherwise the first listen address and the sites secret (that address must then be in SITE_CLIENTS).
  # The CA is /certs/ca.pem there; the configuration comes in on stdin.
  printf 'network={\n key_mgmt=WPA-EAP\n eap=TTLS\n identity="wifi-probe@kazuha.org"\n anonymous_identity="anonymous@kazuha.org"\n password="x"\n phase2="auth=PAP"\n ca_cert="/certs/ca.pem"\n domain_match="%s"\n}\n' "$NAME" \
    | (cd "$BASE" && docker compose exec -T freeradius sh -c '
        cat > /tmp/probe.conf
        case ",$LISTEN_ADDRS," in
          *,127.0.0.1,*) a=127.0.0.1; s=$RADIUS_SECRET_LOCAL ;;
          *) a=${LISTEN_ADDRS%%,*}; s=$RADIUS_SECRET_SITES ;;
        esac
        eapol_test -c /tmp/probe.conf -a "$a" -p "${LISTEN_PORT:-11812}" -s "$s" -t 20 2>&1 | grep -E "EAP-PEER-CERT"
        rm -f /tmp/probe.conf') || true
  echo
  echo "Primary updated. The backup node and the sites pick up dist/ by themselves (cert-dist);"
  echo "check that \`docker compose logs cert-dist\` (in $BASE) shows each site fetching the new files."
}

case "${1:-}" in
  "")            issue ;;
  --out)         issue "$2" ;;
  --install)     install_cert "$2" ;;
  *) echo "usage: $0 [--out DIR | --install DIR]" >&2; exit 2 ;;
esac
