#!/bin/bash
# End-to-end test of a built central image, with no real secrets, no real Entra and nothing outside this
# host: a throwaway CA and server certs, a fake password service (nginx on 127.0.0.1, the role of
# entra-forward-auth: 204 for alice / correct-horse, 401 for any other credentials, 503 on demand), the
# real cert-dist configuration (cert-dist/default.conf.template, in nginx) standing in for the primary's
# certificate service, and the real host scripts (host/) run in a container to renew, publish and manage
# accounts. Everything on 127.0.0.1 with host networking, plus one throwaway Docker network
# (198.51.100.0/24) to send RADIUS from a site-like source address.
# Then, with radclient and eapol_test as the site / AP + client:
#   1. host scripts: renew, publish (modes, group), accounts (add, reset, del, same inode)
#   2. PRIMARY: PAP accept / reject, empty password and ':' in the user name rejected, EAP-TTLS, a site
#      source address (secret, unlisted source dropped), Status-Server, generated config, auth log
#   3. the password service answering 503 or being down: a login is rejected, never accepted; recovery
#   4. PRIMARY refuses a certificate set that fails the checks (FreeRADIUS refuses it, key mismatch, wrong CA)
#   5. invalid .env items: exit 1, every one named, no secret in the output
#   6. cert-dist template: accounts, /htpasswd only for the backup account
#   7. BACKUP: pulls the set (second URL when the first is dead), publishes the set and the site accounts
#      for its own cert-dist, an accounts-file change alone does not restart FreeRADIUS, a bad accounts
#      file is refused, a new certificate set makes the container exit and the restart serves it
#   8. BACKUP refusals: wrong CA, a set FreeRADIUS refuses (the running set stays live), a SHA256SUMS with
#      an extra line, boot fall-back to previous/; docker stop is quick and clean
# The image's own CA_SHA256 is overridden with the throwaway CA's fingerprint (except where a wrong CA is
# tested), which makes the image log a warning; the test checks for it.
# eapol_test: used from the PATH if there is one (CI: apt install eapoltest); otherwise a throwaway
# image with it is built from Ubuntu, so any Docker host will do.
# Usage: test/e2e.sh IMAGE      (needs docker, openssl; pulls nginx:alpine)
set -euo pipefail

IMAGE=${1:?usage: $0 IMAGE}
REPO=$(cd "$(dirname "$0")/.." && pwd)
P=wrc-e2e-$$
AUTH_PORT=${E2E_AUTH_PORT:-15002}         # the fake password service
DIST_PORT=${E2E_DIST_PORT:-18880}         # the throwaway primary's cert-dist
BDIST_PORT=${E2E_BACKUP_DIST_PORT:-18881} # the backup's own cert-dist
RAD_PORT=${E2E_RADIUS_PORT:-18812}        # the central under test
NET_SUBNET=${E2E_NET_SUBNET:-198.51.100.0/24}
GW=${NET_SUBNET%.0/24}.1                  # the host's address on that network
SITE_IP=${NET_SUBNET%.0/24}.2             # a "site": inside SITE_CLIENTS
OTHER_IP=${NET_SUBNET%.0/24}.200          # not inside SITE_CLIENTS (the /25 below ends at .127)
T=$(mktemp -d)
pass=0; fail=0
EAPOL_IMG=""

cleanup() {
  docker rm -f "$P-fr" "$P-auth" "$P-pdist" "$P-bdist" "$P-env" "$P-seed" >/dev/null 2>&1 || true
  docker network rm "$P-net" >/dev/null 2>&1 || true
  docker volume rm "$P-cache" "$P-dist" >/dev/null 2>&1 || true
  [ -z "$EAPOL_IMG" ] || docker rmi -f "$EAPOL_IMG" >/dev/null 2>&1 || true
  # Files made by the host scripts in a container belong to root: remove them from a container too.
  docker run --rm --entrypoint sh -v "$T:/t" "$IMAGE" -c 'rm -rf /t/hb' >/dev/null 2>&1 || true
  rm -rf "$T"
}
trap cleanup EXIT

ok()  { echo "PASS: $*"; pass=$((pass + 1)); }
bad() { echo "FAIL: $*"; fail=$((fail + 1)); }

wait_log() {  # container pattern seconds
  local i
  for ((i = 0; i < $3; i++)); do
    { docker logs "$1" > "$T/wl.log" 2>&1; grep -q "$2" "$T/wl.log"; } && return 0
    sleep 1
  done
  return 1
}
wait_count() {  # container pattern n seconds: the pattern has appeared at least n times in the log
  local i c
  for ((i = 0; i < $4; i++)); do
    docker logs "$1" > "$T/wl.log" 2>&1; c=$(grep -c -- "$2" "$T/wl.log" || true)
    [ "$c" -ge "$3" ] && return 0
    sleep 1
  done
  return 1
}
logs() { docker logs "$P-fr" 2>&1; }
# grep -q on a pipe can end the pipeline early (SIGPIPE, which pipefail reports as a failure): read from a file.
logs_q() { docker logs "$P-fr" > "$T/fr.log" 2>&1; grep -q "$@" "$T/fr.log"; }

# --- eapol_test ----------------------------------------------------------------------------------
if command -v eapol_test >/dev/null 2>&1; then
  eapol_test_run() { eapol_test "$@"; }
else
  EAPOL_IMG=$P-eapol:test
  mkdir -p "$T/eapol-build"
  printf 'FROM ubuntu:24.04\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq eapoltest >/dev/null && command -v eapol_test\n' > "$T/eapol-build/Dockerfile"
  docker build -q --builder default -t "$EAPOL_IMG" "$T/eapol-build" >/dev/null 2>&1 \
    || docker build -q -t "$EAPOL_IMG" "$T/eapol-build" >/dev/null
  eapol_test_run() { docker run --rm --network host --user "$(id -u):$(id -g)" -v "$T:$T" "$EAPOL_IMG" eapol_test "$@"; }
fi

# --- throwaway PKI -------------------------------------------------------------------------------
mkdir -p "$T/pki" "$T/ctl" "$T/auth"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=e2e test CA" \
  -keyout "$T/pki/ca.key" -out "$T/pki/ca.pem" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
# The pin, in the form most unlike the image default (lower case, no colons) to exercise the normalisation.
CA_FP=$(openssl x509 -in "$T/pki/ca.pem" -noout -fingerprint -sha256 | sed 's/.*=//' | tr -d : | tr 'A-F' 'a-f')
issue() {  # dir [rsa bits]
  local bits=${2:-2048}
  openssl req -newkey "rsa:$bits" -nodes -subj "/CN=radius.kazuha.org" -keyout "$1/server.key" -out "$1/server.csr" 2>/dev/null
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:radius.kazuha.org\n' > "$1/ext"
  openssl x509 -req -in "$1/server.csr" -CA "$T/pki/ca.pem" -CAkey "$T/pki/ca.key" -CAcreateserial \
    -days 2 -extfile "$1/ext" -out "$1/server.pem" 2>/dev/null
  rm -f "$1/server.csr" "$1/ext"
  cp "$T/pki/ca.pem" "$1/ca.pem"
}
mkdir -p "$T/set1" "$T/weak" "$T/mismatch"
issue "$T/set1"
issue "$T/weak" 1024          # an RSA-1024 leaf: chains, not expired, right name, key matches; FreeRADIUS refuses it
issue "$T/mismatch"
cp "$T/set1/server.key" "$T/mismatch/server.key"     # a leaf with somebody else's key
chmod -R a+rX "$T/pki" "$T/set1" "$T/weak" "$T/mismatch"

# --- the deployment folder of the (throwaway) primary host, worked on by the real host scripts -------
mkdir -p "$T/hb/host" "$T/hb/pki/ca" "$T/hb/certs"
cp "$REPO"/host/* "$T/hb/host/"
cp "$T/pki/ca.key" "$T/hb/pki/ca/ca.key"; cp "$T/pki/ca.pem" "$T/hb/certs/ca.pem"
cp "$T/set1/server.pem" "$T/set1/server.key" "$T/hb/certs/"
printf 'CERT_DIST_BACKUP_USER=e2e-backup\nLISTEN_ADDRS=127.0.0.1\n' > "$T/hb/.env"
chmod -R a+rX "$T/hb"
hostrun() {  # command [args]: run one of the host scripts (or any command) as root in the image, on the folder above
  docker run --rm -e NO_RESTART=1 -e "CA_SHA256=$CA_FP" --entrypoint "$1" -v "$T/hb:/base" "$IMAGE" "${@:2}"
}
setcerts() {  # set-dir: put that set into the primary's certs/ (as the host operator would)
  docker run --rm --entrypoint sh -v "$T/hb:/base" -v "$1:/src:ro" "$IMAGE" -c \
    'cp /src/server.pem /src/server.key /src/ca.pem /base/certs/ && chmod 644 /base/certs/*.pem'
}
publish() { hostrun /base/host/publish-site-certs; }          # certs/ -> dist/
leaf_fp() { openssl x509 -in "$1" -noout -fingerprint -sha256; }

# --- 1. host scripts ----------------------------------------------------------------------------------
out=$(hostrun /base/host/renew-server-cert.sh 2>&1) || true
STAGE=$(echo "$out" | sed -n 's/^Issued and checked: //p')
if [ -n "$STAGE" ] && echo "$out" | grep -q "subject=.*radius.kazuha.org"; then ok "renew-server-cert.sh issues and checks a new certificate"
else bad "renew-server-cert.sh did not issue"; echo "$out" | tail -5; fi
out=$(hostrun /base/host/renew-server-cert.sh --install "$STAGE" 2>&1) || true
if echo "$out" | grep -q "Old certs archived" && echo "$out" | grep -q "Published to dist/" \
   && [ "$(hostrun stat -c '%a %g' /base/dist/server.key /base/dist/SHA256SUMS | sort -u)" = "640 101" ] \
   && [ "$(leaf_fp "$T/hb/certs/server.pem")" != "$(leaf_fp "$T/set1/server.pem")" ]; then
  ok "renew --install replaces certs/, archives the old pair and publishes dist/ (640, gid 101)"
else bad "renew --install"; echo "$out" | tail -8; fi
hostrun sh -c 'mkdir -p /base/renewed && cp /base/certs/server.pem /base/certs/server.key /base/certs/ca.pem /base/renewed/'
RENEWED=$T/hb/renewed
setcerts "$T/set1"; publish >/dev/null          # the tests below start from set1; "renewed" is the rotation
if [ "$(hostrun sh -c 'cd /base/dist && sha256sum -c --quiet SHA256SUMS && echo good')" = good ]; then ok "publish-site-certs: dist/ matches its SHA256SUMS"
else bad "publish-site-certs: dist/ does not match SHA256SUMS"; fi
out=$(hostrun /base/host/cert-account add e2e-backup 2>&1); BK_PW=$(echo "$out" | sed -n 's/^password: //p')
out=$(hostrun /base/host/cert-account add site-a 2>&1); SA_PW=$(echo "$out" | sed -n 's/^password: //p')
[ -n "$BK_PW" ] && [ -n "$SA_PW" ] && [ "$(hostrun /base/host/cert-account list | tr '\n' ' ')" = "e2e-backup site-a " ] \
  && ok "cert-account add creates the accounts file and prints each password" || bad "cert-account add / list"
hostrun /base/host/cert-account add 'Bad_Name' >/dev/null 2>&1 && bad "cert-account accepted a bad name" || ok "cert-account refuses a bad account name"
hostrun /base/host/cert-account reset site-a >/dev/null 2>&1; hostrun /base/host/cert-account add site-tmp >/dev/null 2>&1
hostrun /base/host/cert-account del site-tmp >/dev/null 2>&1
SA_PW=$(hostrun /base/host/cert-account reset site-a 2>&1 | sed -n 's/^password: //p')
[ "$(hostrun stat -c '%a %g' /base/dist/htpasswd)" = "640 101" ] && [ "$(hostrun /base/host/cert-account list | tr '\n' ' ')" = "e2e-backup site-a " ] \
  && [ -z "$(hostrun sh -c 'ls -A /base/dist | grep htpasswd. || true')" ] \
  && ok "cert-account reset / del replace the accounts file atomically (640, gid 101, no temporary file left)" || bad "cert-account reset / del: mode, list or a leftover temporary file"
# publish-site-certs refuses a set whose CA is not the pinned one, and leaves dist/ as it was
before=$(hostrun cat /base/dist/SHA256SUMS)
if docker run --rm -e "CA_SHA256=$(printf '%064d' 0)" --entrypoint /base/host/publish-site-certs -v "$T/hb:/base" "$IMAGE" >/dev/null 2>&1; then
  bad "publish-site-certs published a set whose CA is not the pinned one"
elif [ "$(hostrun cat /base/dist/SHA256SUMS)" = "$before" ] && [ -z "$(hostrun sh -c 'ls -A /base/dist | grep "^\.[a-z]" || true')" ]; then
  ok "publish-site-certs refuses a CA that is not the pinned one; dist/ is unchanged and clean"
else bad "publish-site-certs: dist/ changed or has leftovers after a refusal"; fi

# --- the fake password service, the cert-dist of the primary -----------------------------------------
# The fake compares exactly (apr1 hashes of the whole password, read from stdin: no shell or argv quoting).
SPECIAL='p"q\r%{User-Name}:t'"'"'x$HOME;`id`'          # " \ % { } : ' $ ; ` in one password
UNI='pässwörd-日本語-ÿ'                                    # non-ASCII (UTF-8)
LONG=$(printf 'aB3"\\%%:z%.0s' $(seq 16))                  # 128 bytes, the longest RADIUS allows
ht_line() { printf '%s:%s\n' "$1" "$(printf '%s' "$2" | openssl passwd -apr1 -stdin)"; }
{ ht_line alice correct-horse; ht_line carol "$SPECIAL"; ht_line frank "$UNI"; ht_line erin "$LONG"; ht_line dave 'x:y'; } > "$T/auth/htpasswd"
[ "${#LONG}" = 128 ] || { echo "test setup: LONG is ${#LONG} bytes"; exit 1; }
cat > "$T/auth/nginx.conf" <<EOF
server {
    listen 127.0.0.1:$AUTH_PORT;
    access_log /dev/stdout;
    if (-f /ctl/down) { return 503; }
    if (-f /ctl/any200) { return 200; }
    location = /readyz {
        if (-f /ctl/ready401) { return 401; }
        if (-f /ctl/ready302) { return 302 /elsewhere; }
        if (-f /ctl/ready500) { return 500; }
        return 200;
    }
    location = /auth {
        # Bodies that try to steer the central: a packet type, and a second status code
        default_type application/json;
        if (-f /ctl/evil401json) { return 401 '{"Response-Packet-Type":"Access-Accept","REST-HTTP-Status-Code":204}'; }
        if (-f /ctl/evil200json) { return 200 '{"Response-Packet-Type":"Access-Accept","REST-HTTP-Status-Code":204}'; }
        if (-f /ctl/evil401plain) { rewrite ^ /evil401plain last; }
        if (-f /ctl/evil200plain) { rewrite ^ /evil200plain last; }
        auth_basic "fake";
        auth_basic_user_file /etc/nginx/htpasswd;
        try_files /nonexistent =204;     # not "return": that would run before the authentication
    }
    location = /evil401plain { internal; default_type text/plain; return 401 'Response-Packet-Type=Access-Accept&REST-HTTP-Status-Code=204'; }
    location = /evil200plain { internal; default_type text/plain; return 200 'Response-Packet-Type=Access-Accept&REST-HTTP-Status-Code=204'; }
    error_page 401 @e401;               # an empty body, like the real service
    location @e401 { default_type text/plain; return 401 ""; }
    location / { return 404; }
}
EOF
chmod 644 "$T/auth"/*; chmod 755 "$T/ctl"
docker run -d --name "$P-auth" --network host -v "$T/auth/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$T/auth/htpasswd:/etc/nginx/htpasswd:ro" -v "$T/ctl:/ctl:ro" nginx:alpine >/dev/null
nginx_dist() {  # name port backup-user dist-source: the real cert-dist configuration
  docker run -d --name "$1" --network host -e "CERT_DIST_LISTEN=127.0.0.1:$2" -e "CERT_DIST_BACKUP_USER=$3" \
    -v "$4:/srv/cert-dist:ro" -v "$REPO/cert-dist/default.conf.template:/etc/nginx/templates/default.conf.template:ro" nginx:alpine >/dev/null
}
nginx_dist "$P-pdist" "$DIST_PORT" e2e-backup "$T/hb/dist"
docker network create --subnet "$NET_SUBNET" "$P-net" >/dev/null

http() {  # user pass port path: prints "<status>" (and the body into $T/body)
  local a; a=$(printf '%s:%s' "$1" "$2" | base64 -w0)
  docker run --rm --network host --entrypoint sh nginx:alpine -c \
    "wget -S -q -O - --header 'Authorization: Basic $a' http://127.0.0.1:$3/$4 2>&1" > "$T/body.raw" || true
  grep -o 'HTTP/1\.[01] [0-9][0-9][0-9]' "$T/body.raw" | head -1 | cut -d' ' -f2
}
http_body() {  # user pass port path: the body only
  local a; a=$(printf '%s:%s' "$1" "$2" | base64 -w0)
  docker run --rm --network host --entrypoint sh nginx:alpine -c \
    "wget -q -O - --header 'Authorization: Basic $a' http://127.0.0.1:$3/$4 2>/dev/null"
}

# --- central under test ---------------------------------------------------------------------------------
LOCAL_SECRET=$(openssl rand -hex 16); SITES_SECRET=$(openssl rand -hex 16)
# node ROLE [NAME=value ...]: start the central (container $P-fr). The pairs override the default .env;
# the value <default> removes a variable, so the image's own default applies.
node() {
  local role=$1; shift
  # shellcheck disable=SC2054 # the commas are part of the associative-array values, not element separators
  local -A e=(
    [LISTEN_ADDRS]=127.0.0.1,$GW [SITE_CLIENTS]=${NET_SUBNET%.0/24}.0/25 [RADIUS_SECRET_SITES]=$SITES_SECRET
    [RADIUS_SECRET_LOCAL]=$LOCAL_SECRET [LISTEN_PORT]=$RAD_PORT [CA_SHA256]=$CA_FP
    [ENTRA_AUTH_URL]=http://127.0.0.1:$AUTH_PORT/auth
  )
  local -a mounts
  if [ "$role" = primary ]; then
    e[CERT_DIST_LISTEN]=127.0.0.1:$DIST_PORT; e[CERT_DIST_BACKUP_USER]=e2e-backup
    mounts=(-v "$T/hb/certs:/certs:ro")
  else
    e[CERT_DIST_LISTEN]=127.0.0.1:$BDIST_PORT; e[CERT_SYNC_INTERVAL]=3
    e[CERT_SYNC_URL]=http://127.0.0.1:9,http://127.0.0.1:$DIST_PORT; e[CERT_SYNC_USER]=e2e-backup; e[CERT_SYNC_PASSWORD]=$BK_PW
    mounts=(-v "$P-cache:/var/lib/cert-sync" -v "$P-dist:/srv/cert-dist")
  fi
  local kv k args=()
  for kv in "$@"; do e[${kv%%=*}]=${kv#*=}; done
  for k in "${!e[@]}"; do [ "${e[$k]}" = "<default>" ] || args+=(-e "$k=${e[$k]}"); done
  docker run -d --name "$P-fr" --network host "${mounts[@]}" "${args[@]}" "${NODE_IMAGE:-$IMAGE}" >/dev/null
}
radq() { local v=$1; v=${v//\\/\\\\}; v=${v//\"/\\\"}; printf '%s' "$v"; }   # escape \ and " for radclient
rad() {  # user password [secret]: accept | reject | none (no reply, after RAD_T seconds), via the container
  local r
  r=$(printf 'User-Name = "%s", User-Password = "%s"' "$(radq "$1")" "$(radq "$2")" \
    | docker exec -i "$P-fr" radclient -t "${RAD_T:-15}" -r 1 "127.0.0.1:$RAD_PORT" auth "${3:-$LOCAL_SECRET}" 2>&1) || true
  [ -z "${E2E_DEBUG:-}" ] || echo "rad $1: $r" | sed "s/$LOCAL_SECRET/<secret>/" >&2
  case "$r" in *"Received Access-Accept"*) echo accept ;; *"Received Access-Reject"*) echo reject ;; *) echo none ;; esac
}
site_rad() {  # source-ip user password secret: the same from a "site" on the throwaway network
  local r
  r=$(docker run --rm --network "$P-net" --ip "$1" --entrypoint sh "$IMAGE" -c \
    "printf 'User-Name = \"%s\", User-Password = \"%s\"' '$2' '$3' | radclient -t 3 -r 1 $GW:$RAD_PORT auth '$4'" 2>&1) || true
  [ -z "${E2E_DEBUG:-}" ] || echo "site_rad: $r" >&2
  case "$r" in *"Received Access-Accept"*) echo accept ;; *"Received Access-Reject"*) echo reject ;; *) echo none ;; esac
}
eap() {  # user password [server-cert-out]
  local conf="$T/eapol.conf"
  printf 'network={\n key_mgmt=WPA-EAP\n eap=TTLS\n identity="%s"\n anonymous_identity="anonymous@kazuha.org"\n password="%s"\n phase2="auth=PAP"\n ca_cert="%s"\n domain_match="radius.kazuha.org"\n}\n' \
    "$1" "$2" "$T/pki/ca.pem" > "$conf"
  eapol_test_run -c "$conf" -a 127.0.0.1 -p "$RAD_PORT" -s "$LOCAL_SECRET" -t 40 ${3:+-o"$3"} 2>&1 | tail -1
}
fp() { openssl x509 -in "$1" -noout -fingerprint -sha256; }
served_leaf() {  # eapol_test -o writes every received cert (CA first): keep the radius.kazuha.org one
  rm -f "$T"/served-*.pem
  awk -v d="$T" '/BEGIN CERTIFICATE/{n++; f=d"/served-"n".pem"} f{print > f} /END CERTIFICATE/{f=""}' "$1"
  local c
  for c in "$T"/served-*.pem; do
    openssl x509 -in "$c" -noout -subject | grep -q "CN *= *radius.kazuha.org" && { echo "$c"; return; }
  done
}
status_rad() {  # Status-Server with the local secret: accept | none
  local r
  r=$(echo 'Message-Authenticator = 0x00' | docker exec -i "$P-fr" radclient -t "${RAD_T:-15}" -r 1 "127.0.0.1:$RAD_PORT" status "$LOCAL_SECRET" 2>&1 || true)
  case "$r" in *"Received Access-Accept"*) echo accept ;; *) echo none ;; esac
}
serves() {  # server.pem of the set: does the central now present that certificate?
  local leaf
  rm -f "$T/served.pem"
  eap alice correct-horse "$T/served.pem" >/dev/null || true
  leaf=$(served_leaf "$T/served.pem" 2>/dev/null || true)
  [ -n "$leaf" ] && [ "$(fp "$leaf")" = "$(fp "$1")" ]
}
stop_quick() {  # container: docker stop returns fast with exit code 0 and FreeRADIUS shut down cleanly
  local t0=$SECONDS code
  docker stop -t 15 "$1" >/dev/null
  code=$(docker inspect -f '{{.State.ExitCode}}' "$1")
  [ $((SECONDS - t0)) -le 6 ] && [ "$code" = "0" ]
}
refused() {  # description pattern [node args...]: the primary must exit non-zero, say why, and never get ready
  local desc=$1 pat=$2; shift 2
  node primary "$@"
  local code; code=$(timeout 60 docker wait "$P-fr" || echo timeout)
  if [ "$code" = 1 ] && logs_q "$pat" && logs_q "refusing to start" && ! logs_q "Ready to process requests"; then
    ok "primary refuses to start: $desc"
  else bad "primary: $desc (exit $code)"; logs | tail -8; fi
  docker rm -f "$P-fr" >/dev/null
}

# --- 2. primary ---------------------------------------------------------------------------------------------
# The password service is not up yet: FreeRADIUS must start anyway, say nothing meanwhile, and work once it is up.
docker stop -t 3 "$P-auth" >/dev/null
node primary
if wait_log "$P-fr" "Ready to process requests" 40; then ok "primary starts on the set in /certs although the password service is not up"
else bad "primary did not start without the password service"; logs | tail -20; exit 1; fi
logs_q "role: PRIMARY" && ok "role PRIMARY (no CERT_SYNC_URL)" || bad "role not logged as PRIMARY"
[ "$(RAD_T=5 rad alice correct-horse)" = none ] && ok "password service not up yet: a login gets no reply (the sites fail over)" || bad "a login got a reply while the password service was not up"
[ "$(RAD_T=5 status_rad)" = none ] && ok "password service not up yet: Status-Server gets no reply (the central looks dead to the sites)" || bad "Status-Server answered while the password service was not up"
docker start "$P-auth" >/dev/null; sleep 2
[ "$(rad alice correct-horse)" = accept ] && ok "the password service starts after FreeRADIUS: logins work once it is up" || bad "no login after the password service came up"
[ "$(rad alice correct-horse)" = accept ] && ok "PAP: correct password accepted" || bad "PAP: correct password not accepted"
[ "$(rad alice wrong-pass)" = reject ] && ok "PAP: wrong password rejected" || bad "PAP: wrong password not rejected"
[ "$(rad bob correct-horse)" = reject ] && ok "PAP: unknown user rejected" || bad "PAP: unknown user not rejected"
[ "$(rad alice '')" = reject ] && ok "PAP: empty password rejected" || bad "PAP: empty password not rejected"
# a password with an absent or an empty user name must be rejected here, never sent to entra (silence would follow)
r=$(printf 'User-Password = "correct-horse"' | docker exec -i "$P-fr" radclient -t 5 -r 1 "127.0.0.1:$RAD_PORT" auth "$LOCAL_SECRET" 2>&1 || true)
case "$r" in *"Received Access-Reject"*) ok "PAP: no User-Name at all is rejected" ;; *) bad "PAP: a request without User-Name: $r" ;; esac
[ "$(rad '' correct-horse)" = reject ] && ok "PAP: an empty User-Name is rejected" || bad "PAP: an empty User-Name was not rejected"
[ "$(rad 'alice:x' correct-horse)" = reject ] && ok "PAP: a user name with ':' rejected" || bad "PAP: a user name with ':' not rejected"
[ "$(eap alice correct-horse)" = "SUCCESS" ] && ok "EAP-TTLS: correct password accepted" || bad "EAP-TTLS: correct password not accepted"
[ "$(eap alice wrong-pass)" = "FAILURE" ] && ok "EAP-TTLS: wrong password rejected" || bad "EAP-TTLS: wrong password not rejected"
serves "$T/set1/server.pem" && ok "the central presents the certificate of its set" || bad "the certificate served is not the set's"
# Some hosts' firewalls drop packets from a Docker bridge to the host itself; then the three checks
# below cannot say anything and are skipped (with a line saying so) instead of failing.
reach=$(docker run --rm --network "$P-net" --ip "$SITE_IP" --entrypoint sh "$IMAGE" -c \
  "echo 'Message-Authenticator = 0x00' | radclient -t 3 -r 1 $GW:$RAD_PORT status '$SITES_SECRET'" 2>&1 || true)
if echo "$reach" | grep -q "Received Access-Accept"; then
  [ "$(site_rad "$SITE_IP" alice correct-horse "$SITES_SECRET")" = accept ] \
    && ok "a site network (SITE_CLIENTS, RADIUS_SECRET_SITES) is accepted" || { bad "PAP from a site address failed"; logs | tail -4; }
  [ "$(site_rad "$SITE_IP" alice correct-horse "$LOCAL_SECRET")" = none ] \
    && ok "a site with the wrong secret gets no answer" || bad "a site with the wrong secret got an answer"
  [ "$(site_rad "$OTHER_IP" alice correct-horse "$SITES_SECRET")" = none ] \
    && ok "a source outside SITE_CLIENTS is dropped" || bad "a source outside SITE_CLIENTS got an answer"
else
  echo "SKIP: site-network checks (this host does not deliver packets from the Docker network $NET_SUBNET to $GW)"
fi
[ "$(status_rad)" = accept ] && ok "Status-Server is answered while the password service is ready (the sites' dead-server probe)" || bad "Status-Server not answered"
# Passwords that are hard for quoting, escaping and Basic auth, through PAP and EAP-TTLS (the fake compares exactly).
for pair in "carol:$SPECIAL" "frank:$UNI" "erin:$LONG" "dave:x:y"; do
  u=${pair%%:*}; pw=${pair#*:}
  [ "$(rad "$u" "$pw")" = accept ] && ok "PAP: $u's password (${#pw} bytes with special characters) accepted" || bad "PAP: $u's special password not accepted"
  [ "$(rad "$u" "${pw}x")" = reject ] && ok "PAP: $u's password plus one character rejected" || bad "PAP: $u's altered password not rejected"
  [ "$(eap "$u" "$pw")" = "SUCCESS" ] && ok "EAP-TTLS: $u's special password accepted" || bad "EAP-TTLS: $u's special password not accepted"
done
# Basic auth cannot carry ':' in a user name: "dave:x" with "y" would reach the service as dave / "x:y", which is valid
[ "$(rad 'dave:x' y)" = reject ] && ok "PAP: user name 'dave:x' with password 'y' is rejected, not turned into dave / 'x:y'" || bad "PAP: a user name with ':' was accepted"
[ "$(eap 'dave:x' y)" = "FAILURE" ] && ok "EAP-TTLS: a user name with ':' is rejected" || bad "EAP-TTLS: a user name with ':' was accepted"
cfg=$(docker exec "$P-fr" sh -c 'stat -c "%U:%G %a" /etc/freeradius/clients.conf /etc/freeradius/listen.conf' | sort -u)
[ "$cfg" = "root:freerad 640" ] && ok "generated config is root:freerad 640" || bad "generated config owner/mode: $cfg"
if docker exec "$P-fr" grep -q 'secret = \$ENV{RADIUS_SECRET_SITES}' /etc/freeradius/clients.conf \
   && docker exec "$P-fr" grep -q 'secret = \$ENV{RADIUS_SECRET_LOCAL}' /etc/freeradius/clients.conf \
   && ! docker exec "$P-fr" grep -rqE "$LOCAL_SECRET|$SITES_SECRET" /etc/freeradius/clients.conf /etc/freeradius/listen.conf \
   && [ "$(docker exec "$P-fr" grep -c '^listen {' /etc/freeradius/listen.conf)" = 2 ] \
   && docker exec "$P-fr" grep -q "ipaddr = $GW" /etc/freeradius/listen.conf; then
  ok "clients and listeners are generated; secrets are \$ENV references, not values"
else bad "generated clients.conf / listen.conf"; fi
REAL_NC=$(docker run --rm --entrypoint printenv "$IMAGE" CA_SHA256 | tr -d : | tr 'a-f' 'A-F')
if logs_q "WARNING: CA_SHA256 is overridden" && logs_q "built-in: $REAL_NC" \
   && logs_q "in use:   $(echo "$CA_FP" | tr 'a-f' 'A-F')"; then
  ok "an overridden CA_SHA256 logs a warning naming both fingerprints"
else bad "no warning for the overridden CA_SHA256"; fi
if logs_q "Login OK: \[alice\]" && logs_q "Login incorrect.*\[alice\]" \
   && ! logs_q -E "correct-horse|wrong-pass|$LOCAL_SECRET|$SITES_SECRET"; then
  ok "auth log shows Login OK / Login incorrect, without any password or secret"
else bad "auth log: missing Login OK / Login incorrect, or a password or secret is in the log"; logs | grep -E "Login|correct-horse" | head -5; fi

# --- 3. the password service misbehaves or is away --------------------------------------------------
# Only a 204 accepts. A service failure is not a reject: no reply at all, so that a site's home server
# times out and fails over to the other central server.
touch "$T/ctl/any200"
[ "$(rad alice correct-horse)" = reject ] && [ "$(rad bob whatever)" = reject ] \
  && ok "the password service answers 200 to everything: every login is rejected (only 204 accepts)" || bad "a 200 from the password service accepted a login"
[ "$(eap alice correct-horse)" = "FAILURE" ] && ok "EAP-TTLS with 200 from the password service: failure" || bad "EAP-TTLS accepted a 200"
rm -f "$T/ctl/any200"
# response bodies that try to set Response-Packet-Type = Access-Accept and a second REST-HTTP-Status-Code = 204
for ev in evil401json evil200json evil401plain evil200plain; do
  touch "$T/ctl/$ev"
  [ "$(rad alice correct-horse)" = reject ] && ok "a $ev response (a body setting Response-Packet-Type and a 204): rejected" || bad "a $ev response was not rejected"
  rm -f "$T/ctl/$ev"
done
# Status-Server is answered only for a 2xx from /readyz
for rd in ready401 ready302 ready500; do
  touch "$T/ctl/$rd"
  [ "$(RAD_T=5 status_rad)" = none ] && ok "/readyz answers ${rd#ready}: no reply to Status-Server" || bad "Status-Server answered while /readyz said ${rd#ready}"
  rm -f "$T/ctl/$rd"
done
[ "$(status_rad)" = accept ] || bad "Status-Server not answered again after /readyz recovered"
touch "$T/ctl/down"
[ "$(RAD_T=5 rad alice correct-horse)" = none ] && ok "password service answers 503: no reply to the login (not an accept, not a reject)" || bad "503 from the password service: the login got a reply"
[ "$(RAD_T=5 status_rad)" = none ] && ok "password service answers 503 on /readyz: no reply to Status-Server" || bad "Status-Server answered while the service was not ready"
[ "$(eap alice correct-horse)" = "FAILURE" ] && ok "EAP-TTLS with a 503 from the password service: failure" || bad "EAP-TTLS accepted or hung on a 503"
rm -f "$T/ctl/down"
[ "$(rad alice correct-horse)" = accept ] && [ "$(status_rad)" = accept ] && ok "the password service recovers: logins and Status-Server are answered again" || bad "no recovery after the 503"
docker stop -t 3 "$P-auth" >/dev/null
t0=$SECONDS; r=$(RAD_T=5 rad alice correct-horse)
[ "$r" = none ] && [ "$(RAD_T=5 status_rad)" = none ] && ok "password service down (connection refused): no reply to the login or to Status-Server" || bad "password service down: got $r"
docker start "$P-auth" >/dev/null; sleep 2
[ "$(rad alice correct-horse)" = accept ] && [ "$(status_rad)" = accept ] && ok "password service back: normal again" || bad "no recovery after the service was down"
stop_quick "$P-fr" && ok "docker stop on the primary is quick and exits 0" || bad "docker stop on the primary was slow or not clean"
logs_q "Exiting normally" && ok "FreeRADIUS shut down cleanly on TERM" || bad "FreeRADIUS did not log a clean exit"
docker rm -f "$P-fr" >/dev/null

# --- 4. the primary refuses a bad set ------------------------------------------------------------------
setcerts "$T/weak"
refused "a set that passes the checks but that FreeRADIUS refuses" "FreeRADIUS refuses this certificate set"
setcerts "$T/mismatch"
refused "server.key does not match server.pem" "server.key does not match server.pem"
setcerts "$T/set1"
refused "ca.pem is not the pinned CA" "does not match the pinned CA_SHA256" "CA_SHA256=<default>"

# --- 5. invalid .env items ---------------------------------------------------------------------------------
secret_marker=Sup3rS3cretValue
good=(-e LISTEN_ADDRS=192.0.2.1 -e SITE_CLIENTS=192.0.2.0/24 -e RADIUS_SECRET_SITES=a -e RADIUS_SECRET_LOCAL=b -e CERT_DIST_LISTEN=192.0.2.1:11880)
envrun() { docker run --rm --name "$P-env" "$@" "$IMAGE" 2>&1; }
out=$(envrun -e LISTEN_ADDRS=10.0.0.1:80 -e SITE_CLIENTS=10.0.0.0/33,300.1.1.1 -e RADIUS_SECRET_SITES="${secret_marker}\"x" \
  -e RADIUS_SECRET_LOCAL="a\$b{c}#d${secret_marker}" -e CERT_DIST_LISTEN=192.0.2.1 -e ENTRA_AUTH_URL=https://x/auth \
  -e LISTEN_PORT=70000 -e CERT_SYNC_INTERVAL=0 -e CERT_DIST_BACKUP_USER=Bad_Name) && rc=0 || rc=$?
missing_all=""
for v in LISTEN_ADDRS SITE_CLIENTS RADIUS_SECRET_SITES RADIUS_SECRET_LOCAL CERT_DIST_LISTEN ENTRA_AUTH_URL LISTEN_PORT CERT_SYNC_INTERVAL CERT_DIST_BACKUP_USER; do
  echo "$out" | grep -q "invalid setting: $v" || missing_all="$missing_all $v"
done
[ "$rc" = 1 ] && [ -z "$missing_all" ] && ok "invalid .env: exit 1, every bad item named" || bad "invalid .env: rc=$rc, not named:$missing_all"
echo "$out" | grep -q "$secret_marker" && bad "invalid .env: a secret value was printed" || ok "invalid .env: no secret value in the message"
out=$(envrun -e LISTEN_ADDRS=0.0.0.0,224.0.0.1,192.0.2.1,192.0.2.1 -e SITE_CLIENTS=10.0.0.0/7,0.0.0.0/0,127.0.0.1,192.168.1.0/24 \
  -e RADIUS_SECRET_SITES=a -e RADIUS_SECRET_LOCAL=b -e CERT_DIST_LISTEN=0.0.0.0:80) && rc=0 || rc=$?
if [ "$rc" = 1 ] && echo "$out" | grep -q "10.0.0.0/7 .*shorter than /8" && echo "$out" | grep -q "0.0.0.0/0 .*every address" \
   && echo "$out" | grep -q "127.0.0.1 .*loopback" && ! echo "$out" | grep -q "192.168.1.0/24"; then
  ok "SITE_CLIENTS: /7, 0.0.0.0/x and loopback are refused with a reason; a normal network is not"
else bad "SITE_CLIENTS policy: rc=$rc"; echo "$out"; fi
if echo "$out" | grep -q "LISTEN_ADDRS: 0.0.0.0 " && echo "$out" | grep -q "LISTEN_ADDRS: 224.0.0.1 .*multicast" \
   && echo "$out" | grep -q "lists an address twice" && echo "$out" | grep -q "CERT_DIST_LISTEN starts with 0"; then
  ok "LISTEN_ADDRS: 0.0.0.0, multicast and duplicates are refused; CERT_DIST_LISTEN 0.0.0.0 too"
else bad "LISTEN_ADDRS policy"; echo "$out"; fi
out=$(envrun -e LISTEN_ADDRS=192.0.2.1) && rc=0 || rc=$?
miss=""; for v in SITE_CLIENTS RADIUS_SECRET_SITES RADIUS_SECRET_LOCAL CERT_DIST_LISTEN; do echo "$out" | grep -q "$v" || miss="$miss $v"; done
[ "$rc" = 1 ] && [ -z "$miss" ] && ok "missing variables: exit 1, each named" || bad "missing variables: rc=$rc, not named:$miss"
out=$(envrun -e LISTEN_ADDRS=192.0.2.1 -e SITE_CLIENTS=192.0.2.0/24,192.0.2.0/24 -e RADIUS_SECRET_SITES=a -e RADIUS_SECRET_LOCAL=b \
  -e CERT_DIST_LISTEN=192.0.2.1:11880 -e ENTRA_AUTH_URL=http://192.0.2.9:5002/auth) && rc=0 || rc=$?
[ "$rc" = 1 ] && echo "$out" | grep -q "SITE_CLIENTS lists an entry twice" && echo "$out" | grep -q "ENTRA_AUTH_URL must be http://127" \
  && ok "a duplicate SITE_CLIENTS entry and a non-loopback ENTRA_AUTH_URL are refused" || bad "duplicate SITE_CLIENTS / non-loopback ENTRA_AUTH_URL: rc=$rc"
out=$(envrun "${good[@]}" -e CERT_SYNC_URL=http://203.0.113.1,https://203.0.113.1:80/x,http://192.0.2.1:11880 -e CERT_SYNC_USER=Bad_User -e CERT_SYNC_PASSWORD="p${secret_marker}\$") && rc=0 || rc=$?
if [ "$rc" = 1 ] && echo "$out" | grep -q "invalid setting: CERT_SYNC_URL: .*203.0.113.1.* is not" && echo "$out" | grep -q "https://203.0.113.1:80/x" \
   && echo "$out" | grep -q "own certificate service" && echo "$out" | grep -q "CERT_SYNC_USER must be" \
   && echo "$out" | grep -q "CERT_SYNC_PASSWORD contains forbidden" && echo "$out" | grep -q "/srv/cert-dist is not a mounted volume" \
   && ! echo "$out" | grep -q "$secret_marker"; then
  ok "backup settings: bad URLs, own service, user name, password and the missing volume are all named"
else bad "backup settings validation: rc=$rc"; echo "$out"; fi
out=$(envrun "${good[@]}" -e CERT_SYNC_USER=host-a) && rc=0 || rc=$?
[ "$rc" = 1 ] && echo "$out" | grep -q "CERT_SYNC_URL is not" && ok "CERT_SYNC_USER without CERT_SYNC_URL (a backup that lost its URL) is refused" \
  || bad "CERT_SYNC_USER without CERT_SYNC_URL: rc=$rc"

# --- 6. the cert-dist configuration -----------------------------------------------------------------------------
sleep 1
[ "$(http '' '' "$DIST_PORT" SHA256SUMS)" = 401 ] && ok "cert-dist: no credentials -> 401" || bad "cert-dist: no credentials not refused"
[ "$(http site-a wrong "$DIST_PORT" SHA256SUMS)" = 401 ] && ok "cert-dist: wrong password -> 401" || bad "cert-dist: wrong password not refused"
[ "$(http site-a "$SA_PW" "$DIST_PORT" SHA256SUMS)" = 200 ] && ok "cert-dist: a site account gets SHA256SUMS" || bad "cert-dist: a site account was refused"
[ "$(http site-a "$SA_PW" "$DIST_PORT" htpasswd)" = 403 ] && ok "cert-dist: /htpasswd is refused for a site account" || bad "cert-dist: /htpasswd open to a site account"
[ "$(http e2e-backup "$BK_PW" "$DIST_PORT" htpasswd)" = 200 ] && ok "cert-dist: /htpasswd is served to CERT_DIST_BACKUP_USER" || bad "cert-dist: /htpasswd refused for the backup account"
[ "$(http site-a "$SA_PW" "$DIST_PORT" other)" = 404 ] && ok "cert-dist: other paths -> 404" || bad "cert-dist: other path not 404"

# --- 7. backup --------------------------------------------------------------------------------------------------
nginx_dist "$P-bdist" "$BDIST_PORT" "" "$P-dist"
node backup
if wait_log "$P-fr" "Ready to process requests" 60; then ok "backup starts with a set pulled from the primary"
else bad "backup did not start"; logs | tail -20; exit 1; fi
logs_q "role: BACKUP" && ok "role BACKUP (CERT_SYNC_URL set)" || bad "role not logged as BACKUP"
if logs_q "cannot get the certificate set from 127.0.0.1:9 " && logs_q "got a new certificate set from 127.0.0.1:$DIST_PORT"; then
  ok "CERT_SYNC_URL fail-over: the first service is down, the set comes from the second"
else bad "CERT_SYNC_URL fail-over"; logs | grep wifi-radius-central | head -5; fi
# Nothing is published to cert-dist until FreeRADIUS has survived the grace period on the set (5 s).
if ! docker exec "$P-fr" test -e /srv/cert-dist/SHA256SUMS; then ok "backup: nothing is published to cert-dist before FreeRADIUS has survived the grace period"
else bad "backup: the set was published at once, before the grace period"; fi
[ "$(rad alice correct-horse)" = accept ] && [ "$(eap alice correct-horse)" = SUCCESS ] && serves "$T/set1/server.pem" \
  && ok "backup: PAP and EAP-TTLS login, serving the primary's certificate" || bad "backup: login or certificate"
wait_count "$P-fr" "published the certificate set" 1 20 || bad "backup: the set was not published after the grace period"
if [ "$(docker exec "$P-fr" stat -c '%a %g' /srv/cert-dist/server.pem /srv/cert-dist/server.key /srv/cert-dist/ca.pem /srv/cert-dist/SHA256SUMS /srv/cert-dist/htpasswd | sort -u)" = "640 101" ]; then
  ok "backup publishes the set, SHA256SUMS and htpasswd for cert-dist (640, gid 101)"
else bad "backup published files: modes"; docker exec "$P-fr" ls -ln /srv/cert-dist; fi
if [ "$(http site-a "$SA_PW" "$BDIST_PORT" SHA256SUMS)" = 200 ] \
   && [ "$(http_body site-a "$SA_PW" "$BDIST_PORT" SHA256SUMS)" = "$(http_body site-a "$SA_PW" "$DIST_PORT" SHA256SUMS)" ] \
   && [ "$(http_body site-a "$SA_PW" "$BDIST_PORT" server.pem | openssl x509 -noout -fingerprint -sha256)" = "$(fp "$T/set1/server.pem")" ]; then
  ok "the backup's cert-dist serves the same set to a site account, as the primary does"
else bad "backup cert-dist does not serve the primary's set to a site account"; fi
[ "$(http site-a wrong "$BDIST_PORT" SHA256SUMS)" = 401 ] && [ "$(http e2e-backup "$BK_PW" "$BDIST_PORT" htpasswd)" = 403 ] \
  && ok "backup cert-dist: wrong password -> 401, /htpasswd -> 403 for everybody" || bad "backup cert-dist access rules"
# an accounts-file change alone does not restart FreeRADIUS
started=$(docker inspect -f '{{.State.StartedAt}}' "$P-fr")
SB_PW=$(hostrun /base/host/cert-account add site-b 2>&1 | sed -n 's/^password: //p')
if wait_log "$P-fr" "updated the site accounts file.*(3 accounts)" 20; then
  sleep 4
  if [ "$(docker inspect -f '{{.State.StartedAt}}' "$P-fr")" = "$started" ] && [ "$(docker inspect -f '{{.RestartCount}}' "$P-fr")" = 0 ] \
     && [ "$(docker exec "$P-fr" stat -c '%a %g' /srv/cert-dist/htpasswd)" = "640 101" ] && ! logs_q "restarting to load it" \
     && [ -z "$(docker exec "$P-fr" sh -c 'ls -A /srv/cert-dist | grep "htpasswd\." || true')" ] \
     && [ "$(http site-b "$SB_PW" "$BDIST_PORT" SHA256SUMS)" = 200 ]; then
    ok "an accounts-file change alone: replaced atomically (640, gid 101), served at once, FreeRADIUS not restarted"
  else bad "accounts-file change: restart, mode, a leftover temporary file, or the new account is not served"; fi
else bad "the backup did not pick up the new account"; logs | tail -5; fi
# an accounts file that is malformed, or lacks this host's account, is refused
hostrun sh -c 'echo "Bad_Name:{PLAIN}x" >> /base/dist/htpasswd'
if wait_log "$P-fr" "accounts file from 127.0.0.1:$DIST_PORT was rejected: it has a line that is not" 20 \
   && [ "$(docker exec "$P-fr" grep -c Bad_Name /srv/cert-dist/htpasswd)" = 0 ]; then
  ok "a malformed accounts file is rejected; the published one is kept"
else bad "malformed accounts file not rejected"; logs | tail -5; fi
hostrun sh -c 'grep -v "^Bad_Name:" /base/dist/htpasswd > /tmp/h; cat /tmp/h > /base/dist/htpasswd'
# a new certificate set: the container exits (cleanly) and the restart serves it
setcerts "$RENEWED"; publish >/dev/null
if [ "$(timeout 60 docker wait "$P-fr")" = "0" ] && logs_q "restarting to load it"; then ok "backup: a new certificate set makes the container exit cleanly"
else bad "backup did not exit after a new certificate set"; logs | tail -5; fi
docker start "$P-fr" >/dev/null
wait_log "$P-fr" "Ready to process requests" 60 || bad "backup did not restart"
wait_count "$P-fr" "published the certificate set" 2 20 || bad "backup: the new set was not published after the restart"
serves "$RENEWED/server.pem" && ok "after the restart the new certificate is served" || bad "the new certificate is not served"
if docker exec "$P-fr" test -s /var/lib/cert-sync/previous/server.pem \
   && cmp -s <(docker exec "$P-fr" cat /var/lib/cert-sync/previous/server.pem) "$T/set1/server.pem" \
   && [ "$(http_body site-a "$SA_PW" "$BDIST_PORT" server.pem | openssl x509 -noout -fingerprint -sha256)" = "$(fp "$RENEWED/server.pem")" ]; then
  ok "the replaced set is kept in previous/; the backup's cert-dist now serves the new set"
else bad "previous/ or the published set is wrong after rotation"; fi
if ! logs_q -E "correct-horse|wrong-pass|$LOCAL_SECRET|$SITES_SECRET|$BK_PW"; then ok "backup: no password or secret in the log"
else bad "backup: a password or secret appears in the log"; fi
# a set that FreeRADIUS refuses is not adopted; the running set stays live
setcerts "$T/weak"; publish >/dev/null
if wait_log "$P-fr" "was rejected: FreeRADIUS cannot load it" 25; then ok "backup: a set that passes the checks but that FreeRADIUS refuses is rejected"
else bad "backup: the FreeRADIUS-refused set was not rejected"; logs | tail -8; fi
serves "$RENEWED/server.pem" && ok "backup: the previous set stays live" || bad "backup: the live set changed"
stop_quick "$P-fr" && ok "backup: docker stop is quick and exits 0" || bad "backup: docker stop was slow or not clean"
logs_q "Exiting normally" && ok "backup: FreeRADIUS shut down cleanly on TERM" || bad "backup: no clean FreeRADIUS exit"
docker rm -f "$P-fr" >/dev/null

# --- 8. backup refusals and boot fall-back ----------------------------------------------------------------
docker volume rm "$P-cache" >/dev/null; setcerts "$T/set1"; publish >/dev/null
node backup "CA_SHA256=<default>"
if wait_log "$P-fr" "does not match the pinned CA_SHA256" 25 && wait_log "$P-fr" "no valid certificate set yet" 5 && ! logs_q "Ready to process requests"; then
  ok "backup: a set with a non-matching CA is rejected; the fresh host keeps waiting"
else bad "backup: non-matching CA"; logs | tail -5; fi
stop_quick "$P-fr" && ok "backup: docker stop during the first-start wait is quick and exits 0" || bad "backup: docker stop during the wait was slow or not clean"
docker rm -f "$P-fr" >/dev/null
docker volume rm "$P-cache" >/dev/null
hostrun sh -c 'printf "%064d  /dev/zero\n" 0 >> /base/dist/SHA256SUMS'
node backup
if wait_log "$P-fr" "SHA256SUMS must be exactly three lines" 15 && ! logs_q "Ready to process requests"; then
  ok "backup: a SHA256SUMS with an extra /dev/zero line is rejected quickly"
else bad "backup: extra line in SHA256SUMS not rejected"; logs | tail -5; fi
docker rm -f "$P-fr" >/dev/null; publish >/dev/null
seed_cache() {  # CURRENT_DIR PREVIOUS_DIR: fill the (empty) cache volume with a current and a previous set
  rm -rf "$T/seed"; mkdir -p "$T/seed/cur" "$T/seed/prev"
  cp "$1"/{server.pem,server.key,ca.pem} "$T/seed/cur/"; cp "$2"/{server.pem,server.key,ca.pem} "$T/seed/prev/"
  local d
  for d in cur prev; do (cd "$T/seed/$d" && sha256sum server.pem server.key ca.pem > SHA256SUMS); done
  chmod -R a+rX "$T/seed"
  docker run --name "$P-seed" --rm --entrypoint sh -v "$P-cache:/c" -v "$T/seed:/seed:ro" "$IMAGE" -c \
    'cp /seed/cur/* /c/ && mkdir /c/previous && cp /seed/prev/* /c/previous/' >/dev/null
}
docker volume rm "$P-cache" >/dev/null
seed_cache "$T/weak" "$T/set1"
node backup "CERT_SYNC_PASSWORD=not-the-password" CERT_RETRY_CURRENT_INTERVAL=10
if wait_log "$P-fr" "Ready to process requests" 40 && logs_q "running on the PREVIOUS set" && serves "$T/set1/server.pem"; then
  ok "backup: boot falls back to previous/ when the current cached set is unusable (primary refuses the account)"
else bad "backup: boot fall-back did not work"; logs | tail -10; fi
wait_count "$P-fr" "published the certificate set" 1 25 || true
if [ "$(docker exec "$P-fr" stat -c %a /srv/cert-dist/server.key)" = 640 ] \
   && [ "$(http_body site-a "$SA_PW" "$BDIST_PORT" server.pem | openssl x509 -noout -fingerprint -sha256)" = "$(fp "$T/set1/server.pem")" ]; then
  ok "backup: the set it runs on is the one its cert-dist serves"
else bad "backup: cert-dist does not serve the live set after a fall-back"; fi
if wait_count "$P-fr" "WARNING: still running on the PREVIOUS certificate set" 2 20; then ok "backup on previous/: a WARNING is logged at every check interval"
else bad "backup on previous/: no repeated WARNING"; logs | tail -5; fi
# the current set becomes usable (here: put a good one in the cache): the next hourly retry (10 s here) restarts onto it
mkdir -p "$T/seed2"; cp "$T/set1"/{server.pem,server.key,ca.pem} "$T/seed2/"; (cd "$T/seed2" && sha256sum server.pem server.key ca.pem > SHA256SUMS); chmod -R a+rX "$T/seed2"
docker run --rm --entrypoint sh -v "$P-cache:/c" -v "$T/seed2:/seed:ro" "$IMAGE" -c 'cp /seed/* /c/' >/dev/null
if [ "$(timeout 40 docker wait "$P-fr" || echo timeout)" = 0 ] && logs_q "the current certificate set is usable again"; then
  ok "backup on previous/: the current set is retried, and the container restarts onto it once it is usable"
else bad "backup on previous/: no retry of the current set"; logs | tail -5; fi
docker rm -f "$P-fr" >/dev/null
# FreeRADIUS dying at start for a reason that is not the certificate (a listen address that is not up): no roll-back
docker volume rm "$P-cache" >/dev/null
seed_cache "$T/set1" "$T/set1"
node backup "CERT_SYNC_PASSWORD=not-the-password" "LISTEN_ADDRS=127.0.0.1,192.0.2.77"
code=$(timeout 60 docker wait "$P-fr" || echo timeout)
if [ "$code" != 0 ] && [ "$code" != timeout ] && logs_q "FreeRADIUS exited at start" && ! logs_q "ROLLING BACK" && ! logs_q "published the certificate set"; then
  ok "backup: an early death that is not the certificate (unbindable address) exits non-zero: no roll-back, nothing published"
else bad "backup: early death not handled as expected (exit $code)"; logs | tail -8; fi
docker rm -f "$P-fr" >/dev/null

echo "e2e: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
