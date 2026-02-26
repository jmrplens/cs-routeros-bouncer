// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import rehypeMermaid from "rehype-mermaid";
import fs from "node:fs";

// Load RouterOS TextMate grammar for syntax highlighting
const routerosGrammar = JSON.parse(
  fs.readFileSync(
    new URL("./src/languages/routeros.tmLanguage.json", import.meta.url),
    "utf-8",
  ),
);

/** @returns {import('astro').AstroIntegration} */
function routerosLanguage() {
  return {
    name: "routeros-language",
    hooks: {
      "astro:config:setup": ({ updateConfig }) => {
        updateConfig({
          markdown: {
            shikiConfig: {
              langs: [
                {
                  ...routerosGrammar,
                  aliases: ["routeros", "mikrotik", "rsc"],
                },
              ],
            },
          },
        });
      },
    },
  };
}

export default defineConfig({
  site: "https://jmrplens.github.io/cs-routeros-bouncer",
  base: "/cs-routeros-bouncer",
  markdown: {
    rehypePlugins: [
      [rehypeMermaid, { strategy: "img-svg" }],
    ],
  },
  integrations: [
    routerosLanguage(),
    starlight({
      title: "cs-routeros-bouncer",
      description:
        "CrowdSec bouncer for MikroTik RouterOS — automatic firewall management via the RouterOS API",
      logo: {
        src: "./src/assets/logo.svg",
        alt: "cs-routeros-bouncer",
      },
      favicon: "/favicon.svg",
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/jmrplens/cs-routeros-bouncer",
        },
      ],
      editLink: {
        baseUrl:
          "https://github.com/jmrplens/cs-routeros-bouncer/edit/main/docs/",
      },
      lastUpdated: true,
      pagination: true,
      customCss: ["./src/styles/custom.css"],
      components: {
        Header: "./src/components/overrides/Header.astro",
        Footer: "./src/components/overrides/Footer.astro",
      },
      head: [
        {
          tag: "meta",
          attrs: {
            property: "og:image",
            content:
              "https://jmrplens.github.io/cs-routeros-bouncer/og-image.png",
          },
        },
        {
          tag: "meta",
          attrs: { property: "og:type", content: "website" },
        },
        {
          tag: "meta",
          attrs: { property: "og:site_name", content: "cs-routeros-bouncer" },
        },
        {
          tag: "meta",
          attrs: {
            name: "twitter:card",
            content: "summary_large_image",
          },
        },
        {
          tag: "meta",
          attrs: {
            name: "twitter:image",
            content:
              "https://jmrplens.github.io/cs-routeros-bouncer/og-image.png",
          },
        },
        {
          tag: "meta",
          attrs: {
            name: "theme-color",
            content: "#3F51B5",
          },
        },
        {
          tag: "script",
          attrs: { type: "application/ld+json" },
          content: JSON.stringify({
            "@context": "https://schema.org",
            "@type": "SoftwareApplication",
            name: "cs-routeros-bouncer",
            description:
              "CrowdSec bouncer for MikroTik RouterOS — automatic firewall management via the RouterOS API",
            applicationCategory: "SecurityApplication",
            operatingSystem: "Linux",
            url: "https://jmrplens.github.io/cs-routeros-bouncer",
            license: "https://github.com/jmrplens/cs-routeros-bouncer/blob/main/LICENSE",
            offers: { "@type": "Offer", price: "0" },
          }),
        },
      ],
      sidebar: [
        {
          label: "Getting Started",
          items: [
            {
              label: "Quick Start",
              slug: "getting-started/quickstart",
              badge: { text: "Start here", variant: "tip" },
            },
            { label: "Installation", slug: "getting-started/installation" },
            { label: "Router Setup", slug: "getting-started/router-setup" },
          ],
        },
        {
          label: "Configuration",
          items: [
            { label: "Overview", slug: "configuration" },
            { label: "MikroTik", slug: "configuration/mikrotik" },
            { label: "CrowdSec", slug: "configuration/crowdsec" },
            { label: "Firewall", slug: "configuration/firewall" },
            {
              label: "Logging & Metrics",
              slug: "configuration/logging-metrics",
            },
            { label: "Examples", slug: "configuration/examples" },
          ],
        },
        {
          label: "Architecture",
          badge: { text: "Deep dive", variant: "note" },
          items: [
            { label: "Overview", slug: "architecture" },
            { label: "Decision Processing", slug: "architecture/decisions" },
            { label: "Firewall Rules", slug: "architecture/firewall-rules" },
            { label: "Reconciliation", slug: "architecture/reconciliation" },
          ],
        },
        {
          label: "Monitoring",
          items: [
            { label: "Prometheus Metrics", slug: "monitoring/prometheus" },
            { label: "Grafana Dashboard", slug: "monitoring/grafana" },
            { label: "Health Endpoint", slug: "monitoring/health" },
          ],
        },
        {
          label: "Development",
          items: [
            { label: "Building & Testing", slug: "development/building" },
            { label: "Project Structure", slug: "development/structure" },
            { label: "Contributing", slug: "development/contributing" },
            {
              label: "Security",
              slug: "development/security",
              badge: { text: "Policy", variant: "caution" },
            },
          ],
        },
        { label: "Troubleshooting", slug: "troubleshooting" },
      ],
    }),
  ],
});
