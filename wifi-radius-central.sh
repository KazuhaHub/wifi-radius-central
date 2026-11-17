#!/bin/bash
# Entrypoint of the wifi-radius-central image.
#
# What it does, in order:
#   1. Validates the settings (.env) strictly and exits 1 naming every bad item. Nothing is started
#      on a setting that is merely "probably fine".
#   2. Picks the role: CERT_SYNC_URL set -> BACKUP, otherwise PRIMARY.
#   3. Generates /etc/freeradius/clients.conf and listen.conf from the lists in .env.
#   4. Gets the RADIUS certificate set (server.pem, server.key, ca.pem):
#        PRIMARY  reads it from the mounted directory /certs (the host renewal script puts it there
#                 and restarts the container).
#        BACKUP   pulls it, with SHA256SUMS, from the primary's certificate service (plain HTTP,
#                 Basic auth, this host's own account), and keeps it in /var/lib/cert-sync.
#      A set is accepted only if ALL of these hold:
#        - (backup) SHA256SUMS has exactly the three expected lines and the files match it
#        - ca.pem is exactly one certificate whose SHA-256 fingerprint equals the pinned CA_SHA256
#        - server.pem (the leaf, optionally followed by intermediates) chains to that CA and only
#          to that CA (the system trust store is not consulted), is not expired, names
#          radius.kazuha.org in its subjectAltName, and matches server.key
#        - FreeRADIUS really loads it (`freeradius -C` against a temporary copy)
#      PRIMARY refuses to start on a set that fails. BACKUP caches accepted sets in /var/lib/cert-sync;
#      the set that was replaced is kept in /var/lib/cert-sync/previous (if it is itself loadable),
#      so a bad set can be rolled back.
#   5. Runs FreeRADIUS. BACKUP: if it dies right after start AND `freeradius -C` now refuses that set
#      (so the certificate is plausibly the cause), it falls back to the previous set once, and says
#      so loudly. Any other early death just exits non-zero and Docker restarts the container.
#   6. BACKUP only: once FreeRADIUS has survived the grace period on the set, publishes that set (and
#      the site accounts file pulled from the primary) into /srv/cert-dist, which the cert-dist
#      container serves to the sites. A set that FreeRADIUS did not survive is never published.
#   7. BACKUP only: re-checks every CERT_SYNC_INTERVAL seconds. A new valid set is cached and the
#      container exits, so Docker restarts it on the new set. A changed site accounts file is only
#      rewritten in /srv/cert-dist (a temporary file, then mv); FreeRADIUS is not restarted for it.
#      While running on previous/ (after a fall-back) it logs a WARNING at every check, and retries
#      the current set every hour (exits when it has become usable, so Docker restarts it on it).
#
# Secrets: they are never written to a file and never logged. The two RADIUS secrets reach
# FreeRADIUS only as environment variables ($ENV{...} in the generated config). The sync
# password is turned into a Basic auth value that is handed only to the fetch subprocess.
# There is no `set -x` anywhere in this script, on purpose.

set -uo pipefail
# ASCII character ranges in the patterns below ([a-z] must not match upper case in some locales).
export LC_ALL=C

log() { echo "wifi-radius-central: $*"; }

# --- shutdown handling --------------------------------------------------------------------
# Installed first, so that `docker stop` works at every point, including the first-start wait
# loop. Bash runs a trap only when the foreground command ends, so everything that can take a
# while (fetches, sleeps, freeradius -C) runs in the background and is waited for with `wait`,
# which a signal interrupts at once. `child` is the current background job, `fr` is FreeRADIUS.
child=""
fr=""
# Scratch space for downloads and checks. A set contains server.key, so this directory is
# removed on TERM and also emptied at every start (a container restart keeps its /tmp, and a
# killed run could have left files behind).
WORK=/tmp/wifi-radius-central-work
rm -rf "$WORK"; mkdir -m 755 "$WORK"
on_term() {
  trap '' TERM INT
  [ -n "$child" ] && kill "$child" 2>/dev/null
  rm -rf "$WORK"
  if [ -n "$fr" ]; then
    log "stopping FreeRADIUS"
    kill -TERM "$fr" 2>/dev/null
    wait "$fr" 2>/dev/null   # a clean FreeRADIUS shutdown, not a kill after the Docker grace period
  fi
  log "stopped"
  exit 0
}
trap on_term TERM INT

bg() {  # run a command in the background and wait for it; returns its exit status
  "$@" &
  child=$!
  wait "$child"
  local rc=$?
  child=""
  return $rc
}

# --- settings: validation ---------------------------------------------------------------------
# Why so strict: these values end up in a generated FreeRADIUS configuration, in an HTTP request
# and in the log. A typo should stop the container with a clear message at start, not show up
# later as a site that cannot log in. A missing required variable is an error.
errors=()
err() { errors+=("$*"); }

OCT='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'     # 0-255, no leading zeros
IPV4_RE="^${OCT}(\\.${OCT}){3}\$"
is_ipv4() { [[ $1 =~ $IPV4_RE ]]; }
is_port() { [[ $1 =~ ^[1-9][0-9]{0,4}$ ]] && [ "$1" -le 65535 ]; }
is_net() {  # IPv4 address or IPv4/prefix (0-32)
  is_ipv4 "${1%%/*}" || return 1
  [[ $1 != */* ]] || [[ ${1#*/} =~ ^(3[0-2]|[12]?[0-9])$ ]]
}
# SITE_CLIENTS policy, on top of the format check. These entries become RADIUS clients, so a typo
# must not be able to open the server to a huge range or to everyone.
site_policy() {  # entry -> message on stdout and status 1 if the entry is not acceptable
  local a=${1%%/*} len=32
  [[ $1 == */* ]] && len=${1#*/}
  if [[ $a == 0.* ]]; then
    echo "starts with 0 (0.0.0.0 means every address); that would let anyone send RADIUS requests"; return 1
  fi
  if [ "$len" -lt 8 ]; then
    echo "prefix /$len is shorter than /8; that is too wide for a site network (a typo?)"; return 1
  fi
  if [[ $a == 127.* ]]; then
    echo "is a loopback address (127.0.0.0/8); the local client 127.0.0.1 is built in (RADIUS_SECRET_LOCAL)"; return 1
  fi
  return 0
}
listen_policy() {  # address -> message and status 1 if it is not an address to listen on
  if [[ $1 == 0.* ]]; then
    echo "starts with 0 (0.0.0.0 means every address); list the addresses to listen on"; return 1
  fi
  if [ "${1%%.*}" -ge 224 ]; then
    echo "is a multicast or reserved address"; return 1
  fi
  return 0
}

is_server() {  # IPv4:port
  [[ $1 == *:* ]] && is_ipv4 "${1%:*}" && is_port "${1##*:}"
}

check_list() {  # VAR validator "what an item must be"
  local var=$1 fn=$2 what=$3 v=${!1:-} item
  local -a items
  if [[ $v == ,* || $v == *, || $v == *,,* ]]; then err "$var has an empty entry (stray comma)"; return; fi
  IFS=, read -ra items <<< "$v"
  for item in "${items[@]}"; do
    "$fn" "$item" || err "$var: $(printf '%q' "$item") is not $what"
  done
}

check_secret() {  # VAR: never prints the value
  local var=$1 v=${!1:-} c bad=""
  for c in '"' '\' '$' '{' '}' '#'; do
    [[ $v == *"$c"* ]] && bad+=" $c"
  done
  [[ $v =~ [[:cntrl:]] ]] && bad+=" (a newline or other control character)"
  if [ -n "$bad" ]; then
    err "$var contains forbidden character(s):$bad. These are special in FreeRADIUS configuration or in .env files and could break parsing or quoting, or be changed silently. Use letters and digits, e.g. the output of: openssl rand -hex 16"
  fi
}

# Role: CERT_SYNC_URL set -> BACKUP (certificate set and site accounts come from the primary).
ROLE=primary
[ -z "${CERT_SYNC_URL:-}" ] || ROLE=backup

missing=()
for v in LISTEN_ADDRS SITE_CLIENTS RADIUS_SECRET_SITES RADIUS_SECRET_LOCAL CERT_DIST_LISTEN; do
  [ -n "${!v:-}" ] || missing+=("$v")
done
if [ "$ROLE" = backup ]; then
  for v in CERT_SYNC_USER CERT_SYNC_PASSWORD; do
    [ -n "${!v:-}" ] || missing+=("$v")
  done
fi
[ ${#missing[@]} -eq 0 ] || err "missing or empty in .env: ${missing[*]} (see .env.example)"

# Optional knobs. They are generic, so they do have defaults.
LISTEN_PORT=${LISTEN_PORT:-11812}                 # UDP port of the RADIUS listeners
INTERVAL=${CERT_SYNC_INTERVAL:-600}               # backup: seconds between checks of the primary (10 min)
ENTRA_AUTH_URL=${ENTRA_AUTH_URL:-http://127.0.0.1:5002/auth}
RETRY_CURRENT=${CERT_RETRY_CURRENT_INTERVAL:-3600}   # backup, running on previous/: how often the current set is tried again
is_port "$LISTEN_PORT" || err "LISTEN_PORT must be a port 1-65535 (optional, default 11812)"
[[ $INTERVAL =~ ^[1-9][0-9]{0,6}$ ]] || err "CERT_SYNC_INTERVAL must be a number of seconds (optional, default 600)"
[[ $RETRY_CURRENT =~ ^[1-9][0-9]{0,6}$ ]] || err "CERT_RETRY_CURRENT_INTERVAL must be a number of seconds (optional, default 3600)"
# (the two parts are taken out first: is_ipv4 and is_port run their own regex matches)
# Loopback only: the passwords of the logins travel on this connection, in clear.
if [[ $ENTRA_AUTH_URL =~ ^http://(127(\.[0-9]+){3}):([0-9]+)(/[A-Za-z0-9._/-]*)$ ]]; then
  _h=${BASH_REMATCH[1]}; _q=${BASH_REMATCH[3]}
  { is_ipv4 "$_h" && is_port "$_q"; } || _bad_url=1
else _bad_url=1; fi
[ -z "${_bad_url:-}" ] || err "ENTRA_AUTH_URL must be http://127.x.x.x:port/path, a loopback address (optional, default http://127.0.0.1:5002/auth)"
ENTRA_READY_URL=${ENTRA_AUTH_URL%/*}/readyz   # entra-auth's readiness endpoint, for Status-Server

if [ -n "${LISTEN_ADDRS:-}" ]; then
  n_before=${#errors[@]}
  check_list LISTEN_ADDRS is_ipv4 "an IPv4 address (e.g. 192.0.2.10)"
  if [ ${#errors[@]} -eq "$n_before" ]; then      # well-formed: now the policy and duplicates
    IFS=, read -ra _la <<< "$LISTEN_ADDRS"
    for item in "${_la[@]}"; do
      msg=$(listen_policy "$item") || err "LISTEN_ADDRS: $item $msg"
    done
    [ "$(printf '%s\n' "${_la[@]}" | sort -u | wc -l)" = "${#_la[@]}" ] || err "LISTEN_ADDRS lists an address twice"
  fi
fi
if [ -n "${SITE_CLIENTS:-}" ]; then
  n_before=${#errors[@]}
  check_list SITE_CLIENTS is_net "an IPv4 address or CIDR (e.g. 198.51.100.0/24)"
  if [ ${#errors[@]} -eq "$n_before" ]; then      # well-formed: now the policy
    IFS=, read -ra _sc <<< "$SITE_CLIENTS"
    for item in "${_sc[@]}"; do
      msg=$(site_policy "$item") || err "SITE_CLIENTS: $item $msg"
    done
    [ "$(printf '%s\n' "${_sc[@]}" | sort -u | wc -l)" = "${#_sc[@]}" ] || err "SITE_CLIENTS lists an entry twice"
  fi
fi
for v in RADIUS_SECRET_SITES RADIUS_SECRET_LOCAL; do
  [ -z "${!v:-}" ] || check_secret "$v"
done

# The certificate service of this host (the cert-dist container reads these from the same .env).
if [ -n "${CERT_DIST_LISTEN:-}" ]; then
  if ! is_server "$CERT_DIST_LISTEN"; then err "CERT_DIST_LISTEN: $(printf '%q' "$CERT_DIST_LISTEN") is not IPv4:port (e.g. 192.0.2.10:11880)"
  elif [[ $CERT_DIST_LISTEN == 0.* ]]; then err "CERT_DIST_LISTEN starts with 0 (every address); give the private-network address"; fi
fi
if [ -n "${CERT_DIST_BACKUP_USER:-}" ] && ! [[ $CERT_DIST_BACKUP_USER =~ ^[a-z0-9-]{1,64}$ ]]; then
  err "CERT_DIST_BACKUP_USER must be 1-64 characters from a-z, 0-9 and '-' (optional; the primary's account that may fetch /htpasswd)"
fi

# CERT_SYNC_URL (backup): one or more primaries' certificate services, comma-separated, in fail-over
# order. Each check takes the whole set from the first one that delivers a usable set.
SRC_LIST=()      # host:port
SRC_HOST=""; SRC_PORT=""   # the one being tried (or last used)
is_cert_url() {  # http://IPv4:port; on success the host:port is added to SRC_LIST
  # Take the two parts out first: is_ipv4 and is_port run their own regex matches, which would
  # overwrite BASH_REMATCH.
  [[ $1 =~ ^http://([0-9.]+):([0-9]+)$ ]] || return 1
  local h=${BASH_REMATCH[1]} q=${BASH_REMATCH[2]}
  is_ipv4 "$h" && is_port "$q" && SRC_LIST+=("$h:$q")
}
if [ "$ROLE" = backup ]; then
  if [[ $CERT_SYNC_URL == *[[:cntrl:]]* ]]; then err "CERT_SYNC_URL contains a newline or other control character"
  else
    check_list CERT_SYNC_URL is_cert_url "http://IPv4:port, plain http, no path (e.g. http://192.0.2.10:11880)"
    for s in "${SRC_LIST[@]}"; do
      [ "$s" != "${CERT_DIST_LISTEN:-}" ] || err "CERT_SYNC_URL lists this host's own certificate service ($s); it must name the primary"
    done
  fi
  # The account name is also a line of the primary's accounts file, so it has that file's format.
  if [ -n "${CERT_SYNC_USER:-}" ] && ! [[ $CERT_SYNC_USER =~ ^[a-z0-9-]{1,64}$ ]]; then
    err "CERT_SYNC_USER must be 1-64 characters from a-z, 0-9 and '-' (the name of this host's account on the primary)"
  fi
  [ -z "${CERT_SYNC_PASSWORD:-}" ] || check_secret CERT_SYNC_PASSWORD
  # The shared volume that the cert-dist container serves: without it the sites would get nothing.
  grep -q ' /srv/cert-dist ' /proc/self/mountinfo 2>/dev/null \
    || err "/srv/cert-dist is not a mounted volume; the backup publishes the certificate set there for the cert-dist container (see compose.yaml)"
elif [ -n "${CERT_SYNC_USER:-}${CERT_SYNC_PASSWORD:-}" ]; then
  err "CERT_SYNC_USER / CERT_SYNC_PASSWORD are set but CERT_SYNC_URL is not; set CERT_SYNC_URL to run as the backup, or remove them to run as the primary"
fi

# The pinned CA fingerprint comes from the image (see the Dockerfile); compare without colons, ignoring case.
CA_PIN=${CA_SHA256:-}; CA_PIN=${CA_PIN//:/}; CA_PIN=${CA_PIN^^}
[[ $CA_PIN =~ ^[0-9A-F]{64}$ ]] || err "CA_SHA256 (pinned CA fingerprint, baked into the image) is not a SHA-256 fingerprint"
# The image's own value, kept in a file written at build time, so that a run-time override of
# CA_SHA256 (meant for tests) cannot go unnoticed.
BUILTIN_CA=$(cat /usr/local/share/wifi-radius-central/ca-sha256 2>/dev/null) || BUILTIN_CA=""
BUILTIN_CA=${BUILTIN_CA//:/}; BUILTIN_CA=${BUILTIN_CA^^}
[[ $BUILTIN_CA =~ ^[0-9A-F]{64}$ ]] || err "the image's built-in CA fingerprint (/usr/local/share/wifi-radius-central/ca-sha256) is missing or damaged"

if [ ${#errors[@]} -gt 0 ]; then
  for e in "${errors[@]}"; do log "invalid setting: $e"; done
  exit 1
fi

if [ "$CA_PIN" != "$BUILTIN_CA" ]; then
  log "WARNING: CA_SHA256 is overridden and differs from the CA fingerprint built into this image."
  log "WARNING:   in use:   $CA_PIN"
  log "WARNING:   built-in: $BUILTIN_CA"
  log "WARNING: this is for tests only; on a real host, remove CA_SHA256 from the environment."
fi
IFS=, read -ra LISTEN_LIST <<< "$LISTEN_ADDRS"
IFS=, read -ra SITE_LIST <<< "$SITE_CLIENTS"
export LISTEN_PORT ENTRA_AUTH_URL ENTRA_READY_URL
RETRY=30    # seconds between attempts while no usable certificate set exists yet (backup)
GRACE=5     # seconds FreeRADIUS must stay up after start before it counts as started
NAME=radius.kazuha.org
CACHE=/var/lib/cert-sync
LIVE=/etc/freeradius/certs-site
PRIMARY_DIR=/certs             # primary: the set the host renewal script maintains
DIST=/srv/cert-dist            # backup: what the cert-dist container serves
NGINX_GID=101                  # the nginx user's group inside the nginx image
export SITE_CERT_DIR=$LIVE     # read by mods-enabled/eap; overridden for the pre-check
FILES="server.pem server.key ca.pem"
MY_ACCOUNT=${CERT_SYNC_USER:-}
AUTH=$(printf '%s:%s' "${CERT_SYNC_USER:-}" "${CERT_SYNC_PASSWORD:-}" | base64 -w0)
unset CERT_SYNC_USER CERT_SYNC_PASSWORD   # FreeRADIUS and the other children do not need them

# --- generated FreeRADIUS configuration -------------------------------------------------------
# clients.conf and listen.conf are built from the lists in .env instead of being templates, because
# the number of listen addresses and site networks differs per host. The secrets are written as
# $ENV{...} references and never as values: no file, image layer or `docker cp` ever holds them.
write_conf() {  # path; the content comes on stdin. root:freerad 640, swapped in atomically.
  local path=$1
  ( umask 027; cat > "$path.new" ) &&
    chown root:freerad "$path.new" && chmod 640 "$path.new" && mv -f "$path.new" "$path"
}

gen_clients() {
  local i=0 net
  {
    cat <<'EOF'
# Generated by wifi-radius-central at container start from SITE_CLIENTS. Do not edit.
# The secrets are read from the environment (RADIUS_SECRET_LOCAL, RADIUS_SECRET_SITES).

# Local tests and monitoring.
client local {
	ipaddr = 127.0.0.1
	secret = $ENV{RADIUS_SECRET_LOCAL}
	require_message_authenticator = yes
	limit_proxy_state = auto
	shortname = local
}
EOF
    for net in "${SITE_LIST[@]}"; do
      i=$((i + 1))
      cat <<EOF

# The site proxies (and APs pointed here directly).
client sites-$i {
	ipaddr = $net
	secret = \$ENV{RADIUS_SECRET_SITES}
	require_message_authenticator = yes
	limit_proxy_state = auto
	shortname = sites-$i
}
EOF
    done
  } | write_conf /etc/freeradius/clients.conf
}

gen_listen() {
  local a
  {
    echo "# Generated by wifi-radius-central at container start from LISTEN_ADDRS and LISTEN_PORT. Do not edit."
    echo "# Included by sites-enabled/default."
    for a in "${LISTEN_LIST[@]}"; do
      cat <<EOF

listen {
	type = auth
	ipaddr = $a
	port = $LISTEN_PORT
}
EOF
    done
  } | write_conf /etc/freeradius/listen.conf
}

gen_clients && gen_listen || { log "cannot write the generated configuration in /etc/freeradius"; exit 1; }

# --- certificate set ----------------------------------------------------------------------
# GET one file over plain HTTP; body to stdout, fails unless the answer is 200. Plain HTTP is
# acceptable only because the service is on a private network; what makes a set trustworthy is
# not the channel but the checks in valid_set (above all the pinned CA).
get() {
  exec 3<>"/dev/tcp/$SRC_HOST/$SRC_PORT" || return 1
  printf 'GET /%s HTTP/1.0\r\nHost: %s\r\nAuthorization: Basic %s\r\n\r\n' "$1" "$SRC_HOST" "$AUTH" >&3
  local status line cl="" tmp n
  IFS= read -r status <&3 || return 1
  case "$status" in *" 200 "*) ;; *) echo "${status%$'\r'}" >&2; exec 3<&-; return 1 ;; esac
  while IFS= read -r line <&3; do
    line=${line%$'\r'}
    [ -z "$line" ] && break
    case ${line,,} in content-length:*) cl=${line#*:}; cl=${cl//[[:space:]]/} ;; esac
  done
  # The body goes to a file first, so that its length can be compared with the Content-Length: a
  # connection cut short must not hand over half a file (the checks would catch it, but say so here).
  tmp=$(mktemp -p "${WORK:-/tmp}") || return 1
  head -c 1048576 <&3 > "$tmp"     # a certificate file is a few KB; refuse to be filled up
  exec 3<&-
  n=$(wc -c < "$tmp")
  if [ -n "$cl" ] && { ! [[ $cl =~ ^[0-9]+$ ]] || [ "$n" != "$cl" ]; }; then
    echo "body is $n bytes, Content-Length says $cl" >&2; rm -f "$tmp"; return 1
  fi
  cat "$tmp"; rm -f "$tmp"
}
GET_FN=$(declare -f get)

fetch() {  # name outfile errfile. In the background so a TERM is handled at once; 30 s limit.
  # The Basic auth value is given to this one process only, as an environment variable (not argv).
  AUTH=$AUTH SRC_HOST=$SRC_HOST SRC_PORT=$SRC_PORT WORK=$WORK \
    timeout 30 bash -c "$GET_FN"'; get "$1"' _ "$1" > "$2" 2> "$3" &
  child=$!
  wait "$child"
  local rc=$?
  child=""
  return $rc
}

why=""   # the reason the last check failed, for the log

sums_ok() {  # dir: SHA256SUMS is exactly the expected three lines, and the files match it
  local f=$1/SHA256SUMS
  [ -s "$f" ] || { why="SHA256SUMS is missing"; return 1; }
  # Checked before sha256sum ever sees the file: sha256sum -c opens whatever path a line names
  # (a /dev/zero line would hang it). Exactly "<64 hex>  <name>" for our three names, each once.
  [ "$(wc -l < "$f")" = 3 ] \
    && ! grep -qvE '^[0-9a-fA-F]{64}  (server\.pem|server\.key|ca\.pem)$' "$f" \
    && [ "$(cut -c67- "$f" | sort | tr '\n' ' ')" = "ca.pem server.key server.pem " ] \
    || { why="SHA256SUMS must be exactly three lines, '<64 hex>  <name>', for server.pem, server.key and ca.pem"; return 1; }
  # In the background like every other slow step, so a TERM is handled at once.
  bg sh -c 'cd "$1" && exec sha256sum -c --quiet --strict SHA256SUMS' _ "$1" >/dev/null 2>&1 \
    || { why="the files do not match SHA256SUMS"; return 1; }
}

valid_set() {  # dir: the cryptographic checks (see the header)
  local w rc
  w=$(mktemp -d -p "$WORK") || { why="cannot create a temporary directory"; return 1; }
  valid_set_in "$1" "$w"; rc=$?
  rm -rf "$w"
  return $rc
}

valid_set_in() {  # dir workdir
  local d=$1 w=$2 f n fp out
  local -a verify=(-CAfile "$d/ca.pem" -no-CApath -no-CAstore)
  for f in $FILES; do [ -s "$d/$f" ] || { why="$f is missing or empty"; return 1; }; done

  # Trust anchor. ca.pem must be one certificate and must be THE pinned CA. "One" matters:
  # openssl verify trusts every certificate in the file, while a fingerprint covers only the first.
  n=$(grep -c -- '-----BEGIN' "$d/ca.pem")
  [ "$n" = 1 ] || { why="ca.pem must contain exactly one certificate (found $n PEM blocks)"; return 1; }
  fp=$(openssl x509 -in "$d/ca.pem" -noout -fingerprint -sha256 2>/dev/null) || { why="ca.pem is not a certificate"; return 1; }
  fp=${fp#*=}; fp=${fp//:/}; fp=${fp^^}
  [ "$fp" = "$CA_PIN" ] || { why="ca.pem fingerprint $fp does not match the pinned CA_SHA256"; return 1; }

  # server.pem is the leaf, optionally followed by intermediates. Verify the leaf alone, with the
  # rest only as "untrusted" helpers to build the path; the only trust anchor is the pinned
  # ca.pem. -no-CApath/-no-CAstore matter: without them openssl also trusts the system store,
  # so a leaf from any public or locally installed CA would verify even though ca.pem is not its issuer.
  openssl x509 -in "$d/server.pem" -out "$w/leaf.pem" 2>/dev/null || { why="server.pem holds no readable certificate"; return 1; }
  awk '/-----BEGIN CERTIFICATE-----/{n++} n>1' "$d/server.pem" > "$w/chain.pem"
  [ ! -s "$w/chain.pem" ] || verify+=(-untrusted "$w/chain.pem")
  out=$(openssl verify "${verify[@]}" "$w/leaf.pem" 2>&1) && [[ $out == *": OK" ]] \
    || { why="server.pem does not chain to the pinned ca.pem"; return 1; }
  openssl x509 -in "$w/leaf.pem" -noout -checkend 0 >/dev/null 2>&1 || { why="server.pem is expired"; return 1; }

  # The name: one of the DNS entries of subjectAltName must be exactly $NAME. Parsed entry by
  # entry and compared whole, so radius.kazuha.org.evil.example or x-radius.kazuha.org do not pass.
  openssl x509 -in "$w/leaf.pem" -noout -ext subjectAltName 2>/dev/null \
    | tail -n +2 | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -Fxq "DNS:$NAME" \
    || { why="server.pem has no subjectAltName DNS entry equal to $NAME"; return 1; }

  [ "$(openssl x509 -in "$w/leaf.pem" -noout -pubkey | openssl sha256)" = \
    "$(openssl pkey -in "$d/server.key" -pubout 2>/dev/null | openssl sha256)" ] \
    || { why="server.key does not match server.pem"; return 1; }
}

install_set() {  # src dst: copy a set with the owner and modes FreeRADIUS expects
  local f
  mkdir -p "$2" && chown root:freerad "$2" && chmod 750 "$2" || return 1
  for f in $FILES; do cp "$1/$f" "$2/$f" || return 1; done
  chown root:freerad "$2"/* && chmod 644 "$2"/*.pem && chmod 640 "$2/server.key"
}

# Does FreeRADIUS itself accept this set (and the generated configuration)? valid_set cannot know
# what the TLS library will refuse (a too-small key for the security level, an unsupported
# algorithm, ...). So the set is copied to a temporary directory and `freeradius -C` is run with the
# certificate paths pointing there. A refusal is found before the set can replace anything that works.
fr_check() {  # dir [quiet]: with "quiet" a refusal is not logged (the caller reports it)
  local stg log_file rc
  stg=$(mktemp -d -p "$WORK" stage.XXXXXX) || return 1
  # FreeRADIUS drops to its own user before it reads the key, so it must be able to enter this
  # directory (mktemp makes it 700). The key file itself stays root:freerad 640.
  chmod 755 "$stg"
  log_file="$stg/check.log"
  if install_set "$1" "$stg/set"; then
    bg env SITE_CERT_DIR="$stg/set" freeradius -C -l stdout > "$log_file" 2>&1
    rc=$?
  else
    rc=1; echo "cannot copy the set to a temporary directory" > "$log_file"
  fi
  if [ $rc -ne 0 ] && [ "${2:-}" != quiet ]; then
    log "FreeRADIUS refuses this certificate set (or the generated configuration):"
    grep -viE 'secret|password' "$log_file" | tail -n 8 | sed 's/^/wifi-radius-central:   /'
  fi
  rm -rf "$stg"
  return $rc
}

usable() {  # dir: complete, verified and loadable (backup: with SHA256SUMS)
  sums_ok "$1" && valid_set "$1" || { log "set in $1 is not usable: $why"; return 1; }
  fr_check "$1"
}

adopt() {  # dir: make a verified set the current one, keeping the one it replaces as previous/
  local d=$1 f
  mkdir -p "$CACHE" && chmod 700 "$CACHE"
  # Keep the old set as previous/ only if FreeRADIUS really loads it. A previous/ that does not
  # load is no use as a roll-back, so a broken current set must never overwrite a good previous/.
  if [ -e "$CACHE/server.pem" ]; then
    if sums_ok "$CACHE" && valid_set "$CACHE" && fr_check "$CACHE" quiet; then
      rm -rf "$CACHE/.previous.new"; mkdir -m 700 "$CACHE/.previous.new"
      for f in $FILES SHA256SUMS; do cp "$CACHE/$f" "$CACHE/.previous.new/$f"; done
      rm -rf "$CACHE/previous"; mv "$CACHE/.previous.new" "$CACHE/previous"
    else
      log "the current cached set is not loadable; keeping the existing previous/ as it is"
    fi
  fi
  for f in $FILES SHA256SUMS; do install -m 600 "$d/$f" "$CACHE/.$f.new"; done
  for f in $FILES SHA256SUMS; do mv -f "$CACHE/.$f.new" "$CACHE/$f"; done
}

# Pull the set from each service in CERT_SYNC_URL in turn, until one gives a result:
# 0 = a new set was verified and cached, 1 = unchanged, 2 = every service failed (the cache is
# left alone). The whole set always comes from one service.
pull() {
  local s
  for s in "${SRC_LIST[@]}"; do
    SRC_HOST=${s%:*}; SRC_PORT=${s##*:}
    pull_one && return 0
    [ $? -eq 1 ] && return 1
  done
  [ "${#SRC_LIST[@]}" -gt 1 ] && log "no certificate service gave a usable set (tried ${CERT_SYNC_URL//,/, })"
  return 2
}

# Pull from $SRC_HOST:$SRC_PORT. 0 = a new set was verified and cached, 1 = unchanged, 2 = failed.
# "Unchanged" needs more than equal SHA256SUMS: the cached files must still pass the sums and the
# checks, otherwise the set is fetched again.
pull_one() {
  local t f
  t=$(mktemp -d -p "$WORK" pull.XXXXXX) || return 2
  if ! fetch SHA256SUMS "$t/SHA256SUMS" "$t/err" || [ ! -s "$t/SHA256SUMS" ]; then
    log "cannot get the certificate set from $SRC_HOST:$SRC_PORT ($(head -n1 "$t/err" 2>/dev/null))"
    rm -rf "$t"; return 2
  fi
  if cmp -s "$t/SHA256SUMS" "$CACHE/SHA256SUMS" && sums_ok "$CACHE" && valid_set "$CACHE"; then
    rm -rf "$t"; return 1
  fi
  for f in $FILES; do
    if ! fetch "$f" "$t/$f" "$t/err"; then
      log "cannot get $f from $SRC_HOST:$SRC_PORT ($(head -n1 "$t/err" 2>/dev/null))"
      rm -rf "$t"; return 2
    fi
  done
  if ! sums_ok "$t" || ! valid_set "$t"; then
    log "the set from $SRC_HOST:$SRC_PORT was rejected: $why"; rm -rf "$t"; return 2
  fi
  if ! fr_check "$t"; then
    log "the set from $SRC_HOST:$SRC_PORT was rejected: FreeRADIUS cannot load it; keeping the current set"
    rm -rf "$t"; return 2
  fi
  adopt "$t"; rm -rf "$t"
  return 0
}

# --- backup: what the cert-dist container serves ------------------------------------------------
# The same set that this host runs on, and the site accounts file of the primary, so that the sites
# can fail over to this host's certificate service too.
publish_dist() {  # dir: a verified set (with SHA256SUMS) -> $DIST
  local d=$1 f
  chown root:$NGINX_GID "$DIST" && chmod 750 "$DIST" || return 1
  for f in $FILES SHA256SUMS; do install -m 640 -o root -g $NGINX_GID "$d/$f" "$DIST/.$f.new" || return 1; done
  # SHA256SUMS last: a site reads it first and fetches the files after it.
  for f in $FILES SHA256SUMS; do mv -f "$DIST/.$f.new" "$DIST/$f" || return 1; done
}

# One account per line, exactly what `openssl passwd -apr1` makes: name:$apr1$salt$hash.
HT_RE='^[a-z0-9-]{1,64}:\$apr1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$'
ht_ok() {  # file: well-formed, and holds this host's own account (else it could not sync any more)
  [ -s "$1" ] || { why="the file is empty"; return 1; }
  ! grep -qvE "$HT_RE" "$1" || { why="it has a line that is not 'name:\$apr1\$salt\$hash'"; return 1; }
  grep -q "^$MY_ACCOUNT:" "$1" || { why="it does not contain this host's account"; return 1; }
}

# Pull the accounts file from each service in turn (same list as the set). 0 = $DIST/htpasswd was
# updated, 1 = unchanged, 2 = no service gave a usable file (nothing changed).
pull_htpasswd() {
  local s t f=$DIST/htpasswd
  t=$(mktemp -d -p "$WORK" ht.XXXXXX) || return 2
  for s in "${SRC_LIST[@]}"; do
    SRC_HOST=${s%:*}; SRC_PORT=${s##*:}
    if ! fetch htpasswd "$t/htpasswd" "$t/err"; then
      log "cannot get the accounts file from $SRC_HOST:$SRC_PORT ($(head -n1 "$t/err" 2>/dev/null))"; continue
    fi
    if ! ht_ok "$t/htpasswd"; then
      log "the accounts file from $SRC_HOST:$SRC_PORT was rejected: $why"; continue
    fi
    if cmp -s "$t/htpasswd" "$f"; then rm -rf "$t"; return 1; fi
    # A temporary file in the same directory, then mv: nginx (which has the directory mounted) never sees
    # a half-written file. Group and mode are set before the content goes in.
    if ! { install -m 640 -o root -g $NGINX_GID /dev/null "$DIST/.htpasswd.new" \
           && cat "$t/htpasswd" > "$DIST/.htpasswd.new" && mv -f "$DIST/.htpasswd.new" "$f"; }; then
      log "cannot write $f"; rm -f "$DIST/.htpasswd.new"; rm -rf "$t"; return 2
    fi
    log "updated the site accounts file from $SRC_HOST:$SRC_PORT ($(wc -l < "$f") accounts); FreeRADIUS is not restarted for it"
    rm -rf "$t"; return 0
  done
  rm -rf "$t"; return 2
}

# --- start --------------------------------------------------------------------------------
LIVE_FROM=""
LIVE_DIR=""
select_live() {  # install the newest usable set into $LIVE: the current one, else previous/
  local d
  for d in "$CACHE" "$CACHE/previous"; do
    [ -d "$d" ] && usable "$d" || continue
    install_set "$d" "$LIVE" || { log "cannot install the set into $LIVE"; return 1; }
    LIVE_DIR=$d
    if [ "$d" = "$CACHE" ]; then LIVE_FROM=current
    else
      LIVE_FROM=previous
      log "WARNING: the current cached certificate set is unusable; running on the PREVIOUS set ($CACHE/previous). Check the primary."
    fi
    return 0
  done
  return 1
}

select_primary() {  # the set in $PRIMARY_DIR must pass every check; there is nothing to fall back to
  valid_set "$PRIMARY_DIR" || { log "the certificate set in $PRIMARY_DIR is not usable: $why"; return 1; }
  fr_check "$PRIMARY_DIR" || return 1
  install_set "$PRIMARY_DIR" "$LIVE" || { log "cannot install the set into $LIVE"; return 1; }
}

if [ "$ROLE" = backup ]; then
  pull; r=$?
  case $r in
    0) log "got a new certificate set from $SRC_HOST:$SRC_PORT" ;;
    1) log "certificate set unchanged" ;;
  esac
  until select_live; do
    log "no valid certificate set yet (first start needs the primary's certificate service and this host's account); retrying in ${RETRY}s"
    bg sleep "$RETRY"
    pull
  done
  pull_htpasswd
  [ -s "$DIST/htpasswd" ] || log "WARNING: no site accounts file yet: the sites cannot fetch from this host's certificate service until the primary's /htpasswd is reachable (CERT_DIST_BACKUP_USER on the primary must name this host's account)"
  log "role: BACKUP; sets and site accounts from ${CERT_SYNC_URL//,/, }, checked every ${INTERVAL}s"
else
  select_primary || { log "refusing to start: fix the certificate set in $PRIMARY_DIR (server.pem, server.key, ca.pem) and restart"; exit 1; }
  log "role: PRIMARY; certificate set from $PRIMARY_DIR (restart the container after renewing it)"
fi

log "cert $(openssl x509 -in "$LIVE/server.pem" -noout -enddate), CA $(openssl x509 -in "$LIVE/ca.pem" -noout -enddate)"
log "listening on ${LISTEN_ADDRS//,/, } port $LISTEN_PORT; ${#SITE_LIST[@]} site network(s): ${SITE_CLIENTS//,/, }; passwords checked at $ENTRA_AUTH_URL"

start_fr() { freeradius -f -l stdout & fr=$!; }

# True if FreeRADIUS died within the grace period. The status is left in $frc.
died_early() {
  local sp who=""
  sleep "$GRACE" & sp=$!; child=$sp
  wait -n -p who "$fr" "$sp"; frc=$?
  child=""
  [ "$who" = "$fr" ] || return 1
  kill "$sp" 2>/dev/null
  return 0
}

start_fr
if died_early; then
  log "FreeRADIUS exited at start ($frc)"
  # Backup: a fall-back to the set that was in use before the current one, but only if the certificate
  # is plausibly the cause: `freeradius -C` refuses the set now. FreeRADIUS can also die at start for
  # reasons that have nothing to do with the set (a listen address that is not up yet, a port in use);
  # rolling back would then hide the real problem, so the container just exits and Docker restarts it.
  if [ "$ROLE" = backup ] && [ "$LIVE_FROM" = current ] && ! fr_check "$LIVE_DIR" quiet \
     && [ -d "$CACHE/previous" ] && usable "$CACHE/previous" && install_set "$CACHE/previous" "$LIVE"; then
    LIVE_FROM=previous
    LIVE_DIR=$CACHE/previous
    log "!!! ROLLING BACK: FreeRADIUS would not start on the current certificate set; starting on the PREVIOUS one ($CACHE/previous). Investigate the primary's set."
    start_fr
    if died_early; then log "FreeRADIUS does not start on the previous set either"; exit 1; fi
  else
    exit "$frc"
  fi
fi

if [ "$ROLE" = primary ]; then
  wait "$fr"; rc=$?      # a TERM interrupts this and runs on_term
  log "FreeRADIUS exited ($rc)"
  exit "$rc"
fi

# Backup: FreeRADIUS has survived the grace period on this set, so the sites may now be given it.
if publish_dist "$LIVE_DIR"; then log "published the certificate set to $DIST for cert-dist"
else log "cannot publish the certificate set in $DIST"; kill -TERM "$fr"; wait "$fr"; exit 1; fi

RETRY_AT=$((SECONDS + RETRY_CURRENT))
while :; do
  sleep "$INTERVAL" & sp=$!; child=$sp
  who=""
  wait -n -p who "$fr" "$sp"; rc=$?
  child=""
  if [ "$who" = "$fr" ]; then kill "$sp" 2>/dev/null; log "FreeRADIUS exited ($rc)"; exit "$rc"; fi
  pull_htpasswd
  pull
  if [ $? -eq 0 ]; then
    log "new certificate set from $SRC_HOST:$SRC_PORT, restarting to load it"
    kill -TERM "$fr"; wait "$fr"
    exit 0
  fi
  if [ "$LIVE_FROM" = previous ]; then
    log "WARNING: still running on the PREVIOUS certificate set ($CACHE/previous); the current one is unusable. Check the primary's set."
    if [ "$SECONDS" -ge "$RETRY_AT" ]; then
      RETRY_AT=$((SECONDS + RETRY_CURRENT))
      if usable "$CACHE"; then
        log "the current certificate set is usable again; restarting to load it"
        kill -TERM "$fr"; wait "$fr"
        exit 0
      fi
    fi
  fi
done
