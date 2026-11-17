# Wi-Fi RADIUS central server: the official FreeRADIUS 3.2 image plus the central configuration and an
# entrypoint that checks the certificate set (and, on the backup node, keeps it and the site accounts in
# step with the primary). See README.md.
# The base stays on the 3.2 line on purpose: FreeRADIUS 4 has a different configuration format,
# so moving to it is a deliberate migration, tracked by .github/workflows/upstream-watch.yml.
ARG BASE_IMAGE=freeradius/freeradius-server:latest-3.2
FROM ${BASE_IMAGE}

ARG REVISION=unknown

# SHA-256 fingerprint of the CA certificate that must have issued the RADIUS server certificate.
# This is the trust anchor of the whole design: the entrypoint accepts a certificate set (from the
# mounted directory on the primary, pulled from it on the backup) only if its ca.pem has exactly this
# fingerprint. Without the pin, anyone who could answer the plain-HTTP certificate request (or who got
# hold of the sync account) could hand the backup a CA of their own and a matching certificate.
# The value is public (it is the fingerprint of a public CA certificate). It is baked in here so
# that a change of CA is a reviewed commit and a new image, not a setting on each host. It can be
# overridden at run time with `-e CA_SHA256=...` (test/e2e.sh does that for its throwaway CA), but
# the entrypoint then logs a loud warning at every start. For that comparison the build-time
# value is also written to a file, which a run-time environment variable cannot change.
ARG CA_SHA256=26:DC:20:91:BE:86:84:E5:BA:30:9C:A0:13:00:B2:9B:DC:61:8B:4F:C4:B5:4B:EF:31:25:94:09:D9:E1:04:46
ENV CA_SHA256=${CA_SHA256}
RUN mkdir -p /usr/local/share/wifi-radius-central \
 && printf '%s\n' "${CA_SHA256}" > /usr/local/share/wifi-radius-central/ca-sha256 \
 && chmod 644 /usr/local/share/wifi-radius-central/ca-sha256

LABEL org.opencontainers.image.title="wifi-radius-central" \
      org.opencontainers.image.description="Kazuha Hub Wi-Fi RADIUS central server (EAP-TTLS / PAP, passwords checked against Microsoft Entra ID through entra-forward-auth)" \
      org.opencontainers.image.source="https://github.com/KazuhaHub/wifi-radius-central" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${REVISION}"

# Static configuration: the EAP module, the `entra` REST module and the two virtual servers.
# clients.conf and listen.conf are not shipped; the entrypoint generates them at start from .env.
# The same step turns the authentication log on ("Login OK" / "Login incorrect" per login).
# auth_badpass and auth_goodpass stay off: a password must never reach a log. The build fails
# if the edit did not apply (the grep counts), so a changed upstream radiusd.conf cannot silently
# leave the log off.
COPY raddb/ /tmp/central-raddb/
RUN set -eux; \
    cd /etc/freeradius; \
    rm -f sites-enabled/* mods-enabled/eap; \
    cp /tmp/central-raddb/sites-enabled/* sites-enabled/; \
    cp /tmp/central-raddb/mods-enabled/eap /tmp/central-raddb/mods-enabled/entra mods-enabled/; \
    mkdir -p certs-site /srv/cert-dist /certs; \
    [ "$(grep -c -P '^\tauth = no$' radiusd.conf)" = 1 ]; \
    sed -i 's/^\tauth = no$/\tauth = yes/' radiusd.conf; \
    [ "$(grep -c -P '^\tauth = yes$' radiusd.conf)" = 1 ]; \
    [ "$(grep -c -P '^\tauth_(badpass|goodpass) = no$' radiusd.conf)" = 2 ]; \
    chown -R root:freerad /etc/freeradius; \
    chmod -R go-w /etc/freeradius; \
    rm -rf /tmp/central-raddb; \
    for c in bash openssl sha256sum base64 timeout install cmp; do command -v "$c"; done

COPY --chmod=755 wifi-radius-central.sh /usr/local/bin/wifi-radius-central

# The verified certificate set (current and previous) survives restarts and outages of the primary here (backup role).
VOLUME /var/lib/cert-sync
ENTRYPOINT ["/usr/local/bin/wifi-radius-central"]
