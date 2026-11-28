#!/bin/sh
# Copy the built site (dist/) into the aaPanel web root.
# Only index.html, _astro/ and images/ are touched; the signed Apple profile and the
# CA certificate in the web root belong to wifi-profile-sign and are left alone.
# Build first (needs Node 22+): npm ci && npm run build
set -eu
cd "$(dirname "$0")"
WEB=/www/wwwroot/wireless.kazuha.org
[ -f dist/index.html ] || { echo "dist/ is missing: run npm run build first" >&2; exit 1; }
rsync -a --delete dist/_astro/ "$WEB/_astro/"
rsync -a --delete dist/images/ "$WEB/images/"
install -m 644 dist/index.html "$WEB/index.html"
chown -R www:www "$WEB/index.html" "$WEB/_astro" "$WEB/images"
echo "published to $WEB"
