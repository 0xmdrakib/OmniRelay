import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  const publicSiteUrl = (env.VITE_PUBLIC_SITE_URL || "https://omnirelay.vercel.app")
    .replace(/\/+$/, "");
  if (!/^https:\/\/[^\s/]+(?:\/[^\s]*)?$/.test(publicSiteUrl)) {
    throw new Error("VITE_PUBLIC_SITE_URL must be an absolute HTTPS URL");
  }
  return {
    plugins: [{
      name: "omnirelay-public-site-url",
      transformIndexHtml: (html) => html.replaceAll("%PUBLIC_SITE_URL%", publicSiteUrl)
    }],
    build: {
      target: "es2022",
      outDir: "dist",
      emptyOutDir: true,
      sourcemap: false
    }
  };
});
