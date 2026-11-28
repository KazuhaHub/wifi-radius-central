// @ts-check
import { defineConfig } from "astro/config";

// Static site for https://wireless.kazuha.org. The signed Apple profile and the CA
// certificate are published into the same web root by /opt/wifi-radius-central/scripts/wifi-profile-sign;
// they are not part of this build.
export default defineConfig({
  site: "https://wireless.kazuha.org",
  build: { format: "preserve", inlineStylesheets: "always" },
  devToolbar: { enabled: false },
});
