# wireless.kazuha.org

Setup guide for the Kazuha Hub Wi-Fi. Astro (static output), same Bento style as uci.kazuha.me.

- `src/pages/index.astro` – page content (Chinese and English side by side, `lang="zh-CN"` / `lang="en"`)
- `src/layouts/Base.astro` – head, nav, footer, and the small script for theme, language, tabs, copy and details animation
- `src/styles/hub.css` – styles
- `public/images/` – Kazuha Hub logo and favicon

Change and publish:

The source lives here (`site/` of KazuhaHub/wifi-radius-central); change it by pull request. The host keeps a
copy in `/opt/wifi-radius-central/site` (no git checkout there) and has no Node, so it builds in a throwaway
container:

```sh
# on the host, after copying the merged site/ into /opt/wifi-radius-central/site
cd /opt/wifi-radius-central/site
B=$(mktemp -d) && cp -a . "$B" && rm -rf "$B/dist" && chown -R 1000:1000 "$B"
docker run --rm -u 1000:1000 -e HOME=/tmp -e ASTRO_TELEMETRY_DISABLED=1 -v "$B":/app -w /app node:22-alpine \
  sh -c "npm ci && npm run build"                      # astro check + build into dist/
rm -rf dist && cp -a "$B/dist" dist && rm -rf "$B"
./publish.sh                                          # copies dist/ into /www/wwwroot/wireless.kazuha.org
```

Locally (Node 22+): `npm ci && npm run build`, or `npm run dev` to preview.

`dist/` is kept on the host (not in git) so `./publish.sh` works without Node. The profile
(`Kazuha-Hub-WiFi.mobileconfig`) and `kazuha-hub-wifi-ca.crt` in the web root are published by
`/opt/wifi-radius-central/scripts/wifi-profile-sign` (host only, not in this repository), not by this site.

Pushes to main that only touch `site/` do not rebuild or republish the RADIUS image (`.github/workflows/image.yml`).
