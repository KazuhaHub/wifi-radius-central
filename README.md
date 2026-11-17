# wifi-radius-central

The Docker version of the Kazuha Hub Wi-Fi RADIUS central server: the two central hosts (a primary and a backup) run
the same compose file. The site proxies ([wifi-radius-proxy](https://github.com/KazuhaHub/wifi-radius-proxy)) send their
inner PAP requests here; this server checks the password against Microsoft Entra ID.

```
site proxy --inner PAP, RADIUS over a private network--> freeradius --HTTP Basic, loopback--> entra-auth --> Entra ID
 (or an AP, EAP-TTLS directly)                            (this image)                (entra-forward-auth)

sites <--certificate set, HTTP Basic, private network-- cert-dist (nginx)
```

Three containers per host, all with host networking (clients are recognised by source IP):

| Container | Image | What |
|---|---|---|
| `freeradius` | `ghcr.io/kazuhahub/wifi-radius-central` (this repo) | PAP and EAP-TTLS; module `entra` (`rlm_rest`) asks `entra-auth` |
| `entra-auth` | `ghcr.io/kazuhahub/entra-forward-auth` | `GET /auth` with Basic user:password, answers 204 allow / 401 deny / 503 Entra unavailable; listens on 127.0.0.1:5002 only |
| `cert-dist` | `nginx:alpine` | serves the certificate set to the sites, one Basic-auth account per site |

- Based on the official `freeradius/freeradius-server:latest-3.2` image. It stays on 3.2 on purpose:
  FreeRADIUS 4 changes the configuration format. The [upstream watch](.github/workflows/upstream-watch.yml)
  opens an issue when a 4.x release appears.
- No certificates, keys or secrets are in the repository or the image.
- The authentication log is on (`log { auth = yes }`, set at build time; the build fails if the edit does not
  apply). `auth_badpass` and `auth_goodpass` stay off: no password is ever logged.

## Logs

FreeRADIUS logs `Login OK` / `Login incorrect` per login (`docker compose logs freeradius`). That is all it knows:
`entra-auth` answers 401 without a reason. The reason (rejected, banned, throttled, forbidden, plus the Entra `AADSTS`
code) is only in that service's own log: `docker compose logs entra-auth`.

## How a login is decided

- PAP (from a site proxy) or the inner PAP of EAP-TTLS (terminated here) goes to `entra`:
  204 is accept, 401 is reject, and anything else (503, another status, no answer, timeout) is a failure, which the client
  receives as Access-Reject. A failure never turns into an accept.
- An empty password and a user name containing `:` (which Basic auth cannot carry) are rejected without asking Entra.
- Status-Server probes (the sites use them to notice a dead central server) are answered.
- Only EAP-TTLS is offered: PEAP/MSCHAPv2 cannot work, because Entra exposes no password hashes.

## Roles

The role follows from `.env`: with `CERT_SYNC_URL` the host is the **backup**, without it the **primary**.

**Primary.** The certificate set (`server.pem`, `server.key`, `ca.pem`) is read from `./certs` (mounted at `/certs`).
At start it must pass the checks below, or the container refuses to start. The host scripts in [`host/`](host) renew
and publish the set and restart the container (it reads `certs/` only at start). `dist/` (published set and the
accounts file `dist/htpasswd`) is served by `cert-dist`.

**Backup.** It pulls the set and the site accounts file (`/htpasswd`) from the primary's certificate service, with
its own account, at start and every `CERT_SYNC_INTERVAL` seconds (default 600). The set is cached in a volume
(current and `previous/`), run by FreeRADIUS, and published, together with the accounts file, in the `cert-dist` volume,
so the sites can fail over to this host's certificate service too.

- The set is the same code as the proxy's sync: `CERT_SYNC_URL` lists the primary's services in fail-over order;
  `SHA256SUMS` is exactly three lines and the files match it; `freeradius -C` must accept the set before anything is
  replaced; a new set makes the container exit so Docker restarts it on the new set (the replaced set is kept as
  `previous/` if FreeRADIUS loads it; at boot an unusable current set falls back to `previous/` once, loudly).
- The accounts file is checked before use: every line is `name:$apr1$salt$hash`, and it holds this host's own account.
  It is rewritten in place (same inode). **A change of the accounts file alone does not restart FreeRADIUS.**
- `docker stop` is handled at any time; FreeRADIUS is shut down cleanly.

**Checks on every set** (primary at start, backup on every pull): `ca.pem` is one certificate and has exactly the
SHA-256 fingerprint built into the image (`CA_SHA256` in the [Dockerfile](Dockerfile); a change of CA is a
reviewed commit and a new image); `server.pem` (the leaf, optionally followed by intermediates) chains to that CA alone
(the system trust store is off), is not expired, has `radius.kazuha.org` as an exact subjectAltName DNS entry and matches
the key; and FreeRADIUS really loads it.

## Deploying

The host must be reachable by the sites over a private network (or VPN), and be allowed to reach Entra.

1. Put these in one folder, called `wifi-radius-central` like the compose project: [`compose.yaml`](compose.yaml),
   [`cert-dist/`](cert-dist), [`host/`](host) (primary) and `.env` from [`.env.example`](.env.example).
2. `entra-cred/client.pem` and `entra-cred/client.key`: the certificate credential of the Entra app registration (see
   [entra-forward-auth](https://github.com/KazuhaHub/entra-forward-auth)). The key must be readable by UID 65532:
   `chown 65532 entra-cred/client.key && chmod 400 entra-cred/client.key`.
3. Primary: `certs/` with the set, and the accounts with `host/cert-account add NAME` (one for each site, one for the
   backup; its name goes into `CERT_DIST_BACKUP_USER`). Backup: `CERT_DIST_DIR=cert-dist`, `CERT_SYNC_URL`,
   `CERT_SYNC_USER`, `CERT_SYNC_PASSWORD` (an account created on the primary), leave `./certs` empty.
4. `docker compose up -d`. The log shows the role, the certificate dates and `Ready to process requests`.
5. Point each site's `CENTRAL_SERVERS` at the primary then the backup (`LISTEN_ADDRS` address, `LISTEN_PORT`), with
   `RADIUS_SECRET_SITES` as its `CENTRAL_SECRET`, and its `CERT_SYNC_URL` at the `CERT_DIST_LISTEN` addresses.

| Variable | Meaning |
|---|---|
| `LISTEN_ADDRS` | comma-separated IPv4 addresses to listen on (loopback and the private address); `0.0.0.0` refused |
| `SITE_CLIENTS` | comma-separated IPv4 / CIDR the sites send from; each is one client; prefixes shorter than /8, `0.x` and loopback refused |
| `RADIUS_SECRET_SITES` | the secret shared with the sites |
| `RADIUS_SECRET_LOCAL` | the secret of the built-in client `127.0.0.1` (local tests, monitoring) |
| `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_SCOPE`, `ENTRA_ALLOWED_DOMAINS` | for `entra-auth` (compose refuses to start without them) |
| `CERT_DIST_LISTEN` | `IPv4:port` of `cert-dist` (the private address) |
| `CERT_DIST_BACKUP_USER` | primary: the one account that may fetch `/htpasswd` (the backup's); backup: empty |
| `CERT_DIST_DIR` | primary: leave out (`./dist`); backup: `cert-dist` (the named volume) |
| `CERT_SYNC_URL` | backup only: comma-separated `http://IPv4:port` of the primary's certificate service, in fail-over order |
| `CERT_SYNC_USER`, `CERT_SYNC_PASSWORD` | backup only: this host's account on the primary |

Optional: `LISTEN_PORT` (default 11812), `CERT_SYNC_INTERVAL` (default 600), `ENTRA_AUTH_URL` (default
`http://127.0.0.1:5002/auth`), `CA_SHA256` (tests only: replaces the pinned CA; the container then logs a WARNING at every start).

Every setting is checked strictly at start (IPv4 octets 0-255, prefix 0-32, port 1-65535, names, URLs); the container
exits with status 1 naming every bad item. Secrets must not contain `"`, `\`, `$`, `{`, `}`, `#` or a newline;
`openssl rand -hex 16` gives a safe one. `clients.conf` and `listen.conf` are generated at start; the secrets are written
as `$ENV{...}` references, never as values. `entra-auth` runs with `FAIL_LIMIT_IP=0` (every request comes from
127.0.0.1, so only per-user bans make sense) and an empty `CLIENT_IP_HEADER` (it uses the peer address).

Updating: `docker compose pull && docker compose up -d`.

## Host scripts (primary only)

[`host/`](host) sits in the deployment folder and finds that folder from its own location. Expected there: `pki/ca/ca.key`
(the CA key; keep it off the server if you can), `certs/`, `.env`.

| Script | What |
|---|---|
| `host/renew-server-cert.sh` | issues a new server certificate from the CA into `pki/staging/<time>/` and checks it; `--install DIR` archives the old pair, installs the new one in `certs/`, publishes it, restarts `freeradius` (`docker compose restart freeradius`) and shows the handshake (needs `eapol_test`; `NO_RESTART=1` skips both) |
| `host/publish-site-certs` | copies `certs/` to `dist/` (group 101 = nginx in the `cert-dist` container) with `SHA256SUMS`; the sites and the backup pull it |
| `host/cert-account` | `list`, `add HOST`, `reset HOST`, `del HOST` on `dist/htpasswd`; prints a random password once; rewrites the file in place |

Apple devices reject server certificates valid for more than 825 days; the renewal script never exceeds that.

## Image

`ghcr.io/kazuhahub/wifi-radius-central`, for linux/amd64 and linux/arm64, signed with cosign (keyless) and with
build provenance. Tags: `3.2`, `latest`, `sha-<commit>`.

[`image.yml`](.github/workflows/image.yml) runs [`test/e2e.sh`](test/e2e.sh): PAP and EAP-TTLS logins against a fake
password service, the password service failing, both roles, the host scripts, the cert-dist configuration, certificate
rotation, refused sets and bad `.env` items. On a pull request it builds and tests for amd64. On `main` it builds amd64 and
arm64 once, tests the amd64 variant of that build, and only then tags those same digests and signs them. There is
no scheduled rebuild: the image is rebuilt on a push to `main` or a manual run, which also picks up a newer official 3.2 base.
The test runs on any Docker host (it builds `eapol_test` into a throwaway image if the host has none).

## Security notes

- The certificate service is plain HTTP and relies on the private network for confidentiality. What makes a set
  trustworthy is the checks, above all the pinned CA, not the channel. A replayed older-but-valid set is accepted by design.
- The accounts file holds apr1 hashes only. `/htpasswd` is served to one account (`CERT_DIST_BACKUP_USER`); with it
  empty nobody can fetch it.
- Passwords travel only on the loopback connection from FreeRADIUS to `entra-auth`, and are never logged.
- Downloaded files are kept in a scratch directory that is removed on `docker stop` and emptied at every start.

## Upstream watch

[`upstream-watch.yml`](.github/workflows/upstream-watch.yml) runs weekly and opens one issue when FreeRADIUS 4
appears. GitHub disables scheduled workflows after 60 days without repository activity; the workflow's run history shows
when it last ran. No keepalive is used.

## Layout

| Path | What |
|---|---|
| `Dockerfile` | the image; bakes in the pinned CA fingerprint and turns the authentication log on |
| `wifi-radius-central.sh` | entrypoint: validates `.env`, generates `clients.conf` and `listen.conf`, checks (primary) or pulls (backup) the certificate set, runs FreeRADIUS |
| `raddb/` | static FreeRADIUS configuration: EAP-TTLS, the `entra` REST module, the two virtual servers |
| `cert-dist/default.conf.template` | nginx configuration of the certificate service |
| `compose.yaml`, `.env.example` | what a host deploys |
| `host/` | primary host scripts: renew, publish, accounts |
| `test/e2e.sh` | end-to-end test used by CI |
| `.github/workflows/` | image build, test and publish; weekly FreeRADIUS 4 watch |
