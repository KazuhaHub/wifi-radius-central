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
code) is only in that service's own log: `docker compose logs entra-auth`. A login that got no reply because the password
service failed shows in the FreeRADIUS log as an `entra: ... ERROR` line followed by `Not responding to request`.

## How a login is decided

- PAP (from a site proxy) or the inner PAP of EAP-TTLS (terminated here) goes to `entra` (`rlm_rest`, `GET` with Basic auth).
  **Only a 204 accepts.** `rlm_rest` itself treats every 2xx as success, so the virtual servers also require
  `REST-HTTP-Status-Code == 204`; a 200 (or any other status that is not a failure of the service) is a reject, and no
  response body ever becomes attributes of a login. 401 and the other 4xx are rejects.
- **When the password service itself fails, the request gets no reply at all** (not a reject): timeout, connection refused,
  503 or any 5xx, no free connection. The site's home server then times out and **fails over to the other central
  server**, instead of telling every user that their password is wrong. (EAP-TTLS terminated here, which has no other
  server to go to, answers a reject.)
- **Status-Server** probes (the sites use them to notice a dead central server) are answered only while `entra-auth`
  answers `GET /readyz` within 2 s; otherwise they get no reply, so a central server that cannot check passwords looks dead
  to the sites and they use the other one. Once the service is back, the sites mark this server alive again after their
  usual number of answered probes.
- FreeRADIUS does not need `entra-auth` to start (nothing connects at start: the REST pool starts empty and there is no
  pre-connect). Until the service is up, logins and probes get no reply.
- An empty password and a user name containing `:` (which Basic auth cannot carry) are rejected without asking Entra.
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
  It is written to a temporary file in the same directory and moved into place (`cert-dist` has the directory mounted, so
  it sees the new file at once). **A change of the accounts file alone does not restart FreeRADIUS.**
- A set is published to `cert-dist` only after FreeRADIUS has survived 5 s on it. If FreeRADIUS dies right after start and
  `freeradius -C` now refuses the set, the container falls back to `previous/` once, loudly. If it dies for any other
  reason (for example a listen address that is not up yet) there is no roll-back: the container exits non-zero and Docker
  restarts it. While running on `previous/` it logs a WARNING at every check, and tries the current set again every hour
  (then restarts onto it if it has become usable).
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

Optional: `LISTEN_PORT` (default 11812), `CERT_SYNC_INTERVAL` (default 600), `CERT_RETRY_CURRENT_INTERVAL` (default 3600),
`ENTRA_AUTH_URL` (default `http://127.0.0.1:5002/auth`; loopback only, because passwords travel on that connection),
`CA_SHA256` (tests only: replaces the pinned CA; the container then logs a WARNING at every start).

Every setting is checked strictly at start (IPv4 octets 0-255, prefix 0-32, port 1-65535, names, URLs, duplicates in
`LISTEN_ADDRS` and `SITE_CLIENTS`); the container exits with status 1 naming every bad item. Secrets must not contain `"`, `\`, `$`, `{`, `}`, `#` or a newline;
`openssl rand -hex 16` gives a safe one. `clients.conf` and `listen.conf` are generated at start; the secrets are written
as `$ENV{...}` references, never as values. `entra-auth` runs with `FAIL_LIMIT_IP=0` (every request comes from
127.0.0.1, so only per-user bans make sense) and an empty `CLIENT_IP_HEADER` (it uses the peer address).

Updating: `docker compose pull && docker compose up -d`.

## Host scripts (primary only)

[`host/`](host) sits in the deployment folder and finds that folder from its own location. Expected there: `pki/ca/ca.key`
(the CA key; keep it off the server if you can), `certs/`, `.env`.

| Script | What |
|---|---|
| `host/renew-server-cert.sh` | issues a new server certificate from the CA into `pki/staging/<time>/` and checks it; `--install DIR` archives the old pair, installs the new one in `certs/`, publishes it, restarts `freeradius` (`docker compose restart freeradius`), waits up to 30 s for `Ready to process requests` (and fails loudly if it does not come) and shows the handshake. The handshake runs `eapol_test` inside the `freeradius` container (`docker compose exec`), which has the address and secret in its environment, so the secret never appears on the host's command line. `NO_RESTART=1` skips the restart and the handshake |
| `host/publish-site-certs` | checks `certs/` the way the sites and the backup do (`ca.pem` is the pinned CA, which the script carries as `CA_SHA256`: keep it equal to the Dockerfile's; the leaf chains to it alone, has the right name, matches the key) and only then copies it to `dist/` (group 101 = nginx in the `cert-dist` container) with `SHA256SUMS`; the sites and the backup pull it |
| `host/cert-account` | `list`, `add HOST`, `reset HOST`, `del HOST` on `dist/htpasswd`; prints a random password once; replaces the file atomically (temporary file, then `mv`) |

Apple devices reject server certificates valid for more than 825 days; the renewal script never exceeds that.

## Migrating from the current setup

For hosts that run the earlier, hand-made setup: the same `compose.yaml` idea with the stock `freeradius-server` image, a
`python3` module for Entra, host-side scripts (`scripts/`), a backup that pulls with a systemd timer
(`pull-from-primary`), and the certificate service configured by hand. The sites need no change: the RADIUS port, the
`cert-dist` address and port, the secrets and the accounts stay the same. Do the **backup first**: it pulls from the
primary, which is still the old, unchanged one; then migrate the primary. While the primary is down for a few minutes the
sites fail over to the backup (that is what it is for). Addresses below are placeholders: the primary's private
address is `192.0.2.10`, the backup's `192.0.2.20`, the sites' networks `198.51.100.0/24` and `203.0.113.0/24`.

**Both hosts, before anything is stopped**

1. Have the new files ready next to the old deployment: `compose.yaml`, `cert-dist/`, `host/` and the new `.env` (below).
   Keep a copy of the old folder (`cp -a`) to roll back to.
2. Build the new `.env` from the old one. Keep `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_ALLOWED_DOMAINS`, `ENTRA_SCOPE`,
   `RADIUS_SECRET_LOCAL`, `RADIUS_SECRET_SITES`. Add the new keys:
   - `LISTEN_ADDRS=127.0.0.1,<this host's private address>` (what the old `sites-enabled/default` listened on);
   - `SITE_CLIENTS=` the networks the sites send from (what the old `clients.conf` allowed, one entry per network, in CIDR form);
   - `CERT_DIST_LISTEN=<this host's private address>:<the old cert-dist port>` (the address the old `cert-dist.nginx.conf` listened on);
   - the primary: `CERT_DIST_BACKUP_USER=<the backup's account name>` (the name the old nginx config compared `$remote_user` with);
   - the backup: `CERT_DIST_DIR=cert-dist`, `CERT_SYNC_URL=http://192.0.2.10:<port>` (the primary's `cert-dist`), and
     `CERT_SYNC_USER` / `CERT_SYNC_PASSWORD` (its account and password, from the old `secrets/cert-pull.env`).
3. **`SITE_CLIENTS` on the backup must also contain the primary's own address** (for example `192.0.2.10/32`), because the
   primary's monitoring sends an EAP-TTLS handshake to the backup.
4. `entra-cred/`: the new `entra-auth` container runs as UID 65532 (the distroless `nonroot` user of the
   `entra-forward-auth` image), not as the old FreeRADIUS user. Name the files `client.pem` (the certificate) and `client.key`, then
   `chown 65532 entra-cred/client.key && chmod 400 entra-cred/client.key`. `entra-cred/` itself must be searchable by it
   (`chmod 755`). The Entra app registration, its certificate and the Conditional Access location (the two hosts' public
   addresses) do not change.

**Order of the steps, backup first**

1. **Backup.** Stop the old project from the old folder **before** anything else is started (its containers, networks and the
   project name are the same or different depending on how it was created; use the name it was started with):
   `docker compose down` in the old folder (or `docker compose -p <old name> down`).
2. On the backup, stop and disable the old pull: `systemctl disable --now pull-from-primary.timer`. The new container does
   the pulling (set and accounts file, every 10 minutes).
3. On the backup, put the new files in place (the old `config/`, `certs/` and `dist/` are not used any more), then
   `docker compose pull && docker compose up -d`.
4. Check the backup: `docker compose logs freeradius` shows `role: BACKUP`, `got a new certificate set from ...`,
   `Ready to process requests` and, about 5 s later, `published the certificate set`; `docker compose logs entra-auth` is quiet;
   a test login works (`radtest` or `eapol_test` against the backup with the local secret); a site account can fetch
   `http://192.0.2.20:<port>/SHA256SUMS`.
5. **Primary.** Stop the old project: `docker compose down` in the old folder, and stop whatever else uses the host scripts
   (cron or systemd units that call the old `scripts/`).
6. Put the new files in place. Keep `certs/` (`server.pem`, `server.key`, `ca.pem`) and `pki/` as they are. Copy the accounts file
   **before** `up`, and let the `cert-dist` container read it:
   `install -d -m 750 -o root -g 101 dist && install -m 640 -o root -g 101 secrets/cert-dist.htpasswd dist/htpasswd`,
   then run `host/publish-site-certs` (it fills `dist/` with the set, owned `root:101`, mode 640).
   Point cron or systemd at `host/renew-server-cert.sh`, `host/publish-site-certs` and `host/cert-account` (they replace `scripts/`;
   the old `wifi-cert-check` and `wifi-profile-sign` are not part of this repository and stay as they are).
7. `docker compose pull && docker compose up -d`. Check the log (`role: PRIMARY`, `Ready to process requests`), a test login, and that
   `docker compose logs cert-dist` shows the backup and the sites fetching.
8. Re-run the monitoring and check that it reaches both hosts. A site's next check of its certificate set should show no change.

Rolling back a host: `docker compose down` in the new folder, put the old folder back, `docker compose up -d` (on the backup also
re-enable `pull-from-primary.timer`).

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
  empty nobody can fetch it. (The 403 for `/htpasswd` is decided from the user name before the password is checked, so a caller can tell
  which name is the backup's account; accepted.)
- **Password spraying.** `entra-auth` runs with `FAIL_LIMIT_IP=0`: failures are counted and banned per user only, never per
  client IP (every request comes from FreeRADIUS on 127.0.0.1, so a per-IP ban would lock out everybody at once). The
  consequence is that one source can try one password against many users without being slowed down here; the only brakes
  are `ENTRA_ALLOWED_DOMAINS`, the per-user ban, the `SITE_CLIENTS` list of who may send RADIUS at all, and Entra's own
  smart lockout and Conditional Access. Watch the `entra-auth` log for many different users failing in a short time.
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
| `README.md` (below) | deploying, roles, migrating from the previous setup |
| `test/e2e.sh` | end-to-end test used by CI |
| `.github/workflows/` | image build, test and publish; weekly FreeRADIUS 4 watch |
