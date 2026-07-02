// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import sitemap from "@astrojs/sitemap";
import rehypeMermaid from "rehype-mermaid";
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const docsRoot = fileURLToPath(new URL(".", import.meta.url));
const siteBase = "/cs-routeros-bouncer";

/**
 * Resolve the newest git commit date for the content file backing a given
 * sitemap URL, so `sitemap-0.xml` carries real per-page `<lastmod>` values
 * instead of Starlight's default (which omits `lastmod` entirely).
 * @param {string} pathname
 * @returns {string | undefined}
 */
function getLastmod(pathname) {
	const slug = pathname
		.replace(new RegExp(`^${siteBase}/?`), "")
		.replace(/\/$/, "");
	const candidates =
		slug === ""
			? ["src/content/docs/index.mdx"]
			: [`src/content/docs/${slug}.mdx`, `src/content/docs/${slug}/index.mdx`];
	for (const relativePath of candidates) {
		try {
			const output = execFileSync(
				"git",
				["log", "-1", "--format=%cI", "--", relativePath],
				{ cwd: docsRoot, encoding: "utf-8" },
			).trim();
			if (output) return output;
		} catch {
			// Try the next candidate path.
		}
	}
	return undefined;
}

// Load RouterOS TextMate grammar for syntax highlighting
const routerosGrammarURL = new URL(
	"./src/languages/routeros.tmLanguage.json",
	import.meta.url,
);

/** @returns {Record<string, unknown>} */
function loadRouterOSGrammar() {
	try {
		return JSON.parse(fs.readFileSync(routerosGrammarURL, "utf-8"));
	} catch (error) {
		throw new Error(
			`Failed to load RouterOS TextMate grammar from ${routerosGrammarURL}`,
			{
				cause: error,
			},
		);
	}
}

const routerosGrammar = loadRouterOSGrammar();

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
									// Keep these explicit aliases even if the grammar provides its own names.
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
		rehypePlugins: [[rehypeMermaid, { strategy: "img-svg", dark: true }]],
	},
	integrations: [
		routerosLanguage(),
		sitemap({
			serialize(item) {
				const lastmod = getLastmod(new URL(item.url).pathname);
				return lastmod ? { ...item, lastmod } : item;
			},
		}),
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
			expressiveCode: {
				emitExternalStylesheet: false,
			},
			components: {
				Header: "./src/components/overrides/Header.astro",
				Footer: "./src/components/overrides/Footer.astro",
				Head: "./src/components/overrides/Head.astro",
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
					attrs: {
						property: "og:site_name",
						content: "cs-routeros-bouncer",
					},
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
					tag: "meta",
					attrs: {
						name: "msvalidate.01",
						content: "7574EB3B44624C239F14920DBC34EE25",
					},
				},
				{
					tag: "meta",
					attrs: {
						name: "google-site-verification",
						content: "4Hx_PJ1seU_BgKfWpo_FA7_Hkh7GeYVNrvnvzqCjF0Q",
					},
				},
				{
					tag: "meta",
					attrs: {
						"http-equiv": "Content-Security-Policy",
						content:
							"default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'self'; form-action 'self'",
					},
				},
				{
					tag: "link",
					attrs: {
						rel: "manifest",
						href: "/cs-routeros-bouncer/manifest.json",
					},
				},
				{
					tag: "link",
					attrs: { rel: "me", href: "https://github.com/jmrplens" },
				},
				{
					tag: "link",
					attrs: { rel: "me", href: "https://linkedin.com/in/jmrplens" },
				},
				{
					tag: "link",
					attrs: { rel: "me", href: "https://mstdn.jmrp.io/@jmrplens" },
				},
				{
					tag: "link",
					attrs: {
						rel: "me",
						href: "https://scholar.google.com/citations?user=9b0kPaUAAAAJ",
					},
				},
				{
					tag: "link",
					attrs: {
						rel: "me",
						href: "https://matrix.to/#/@jmrplens:matrix.jmrp.io",
					},
				},
				{
					tag: "link",
					attrs: {
						rel: "me",
						href: "https://keyoxide.org/0A993B268654DBBA52B7E8D3FCF653391E2C91FC",
					},
				},
				{
					tag: "link",
					attrs: { rel: "me", href: "https://jmrp.io" },
				},
				{
					tag: "link",
					attrs: {
						rel: "pgpkey",
						type: "application/pgp-keys",
						href: "https://keys.openpgp.org/vks/v1/by-fingerprint/0A993B268654DBBA52B7E8D3FCF653391E2C91FC",
					},
				},
				{
					tag: "script",
					content: `(() => {
	const syncMermaidPictures = () => {
		const isDark = document.documentElement.dataset.theme === "dark";
		document
			.querySelectorAll('picture source[id^="mermaid-dark-"]')
			.forEach((source) => {
				source.setAttribute("media", isDark ? "all" : "not all");
			});
	};

	new MutationObserver(syncMermaidPictures).observe(document.documentElement, {
		attributes: true,
		attributeFilter: ["data-theme"],
	});

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", syncMermaidPictures, {
			once: true,
		});
	} else {
		syncMermaidPictures();
	}
})();`,
				},
				{
					tag: "script",
					attrs: { type: "application/ld+json" },
					content: JSON.stringify({
						"@context": "https://schema.org",
						"@graph": [
							{
								"@type": "Person",
								"@id": "https://jmrp.io/#person",
								name: "José Manuel Requena Plens",
								alternateName: "jmrplens",
								url: "https://jmrp.io",
								image: "https://github.com/jmrplens.png",
								knowsAbout: [
									"CrowdSec",
									"MikroTik RouterOS",
									"Go",
									"Network Security",
									"DevOps",
								],
								sameAs: [
									"https://github.com/jmrplens",
									"https://linkedin.com/in/jmrplens",
									"https://mstdn.jmrp.io/@jmrplens",
									"https://scholar.google.com/citations?user=9b0kPaUAAAAJ",
									"https://matrix.to/#/@jmrplens:matrix.jmrp.io",
									"https://keyoxide.org/0A993B268654DBBA52B7E8D3FCF653391E2C91FC",
								],
							},
							{
								"@type": "WebSite",
								"@id":
									"https://jmrplens.github.io/cs-routeros-bouncer/#website",
								name: "cs-routeros-bouncer",
								url: "https://jmrplens.github.io/cs-routeros-bouncer/",
								description:
									"CrowdSec bouncer for MikroTik RouterOS — automatic firewall management via the RouterOS API",
								inLanguage: ["en"],
								image: {
									"@type": "ImageObject",
									url: "https://jmrplens.github.io/cs-routeros-bouncer/og-image.png",
									width: 1200,
									height: 630,
								},
								publisher: { "@id": "https://jmrp.io/#person" },
								about: {
									"@id":
										"https://github.com/jmrplens/cs-routeros-bouncer#software",
								},
								speakable: {
									"@type": "SpeakableSpecification",
									cssSelector: [".hero .tagline", "#how-it-works"],
								},
							},
							{
								"@type": "SoftwareApplication",
								"@id":
									"https://github.com/jmrplens/cs-routeros-bouncer#software",
								name: "cs-routeros-bouncer",
								applicationCategory: "SecurityApplication",
								operatingSystem: "Linux",
								softwareVersion: "1.4.5",
								dateModified: "2026-06-19",
								url: "https://github.com/jmrplens/cs-routeros-bouncer",
								downloadUrl:
									"https://github.com/jmrplens/cs-routeros-bouncer/releases",
								image: {
									"@type": "ImageObject",
									url: "https://jmrplens.github.io/cs-routeros-bouncer/og-image.png",
									width: 1200,
									height: 630,
								},
								screenshot: {
									"@type": "ImageObject",
									url: "https://jmrplens.github.io/cs-routeros-bouncer/og-image.png",
									width: 1200,
									height: 630,
								},
								license: "https://opensource.org/licenses/MIT",
								isAccessibleForFree: true,
								keywords:
									"CrowdSec, bouncer, MikroTik, RouterOS, firewall, network security, Go",
								description:
									"CrowdSec bouncer for MikroTik RouterOS — automatic firewall management via the RouterOS API",
								offers: { "@type": "Offer", price: 0, priceCurrency: "USD" },
								author: { "@id": "https://jmrp.io/#person" },
								sameAs: [
									"https://app.crowdsec.net/hub/author/jmrplens/remediation-components/cs-routeros-bouncer",
									"https://www.wikidata.org/wiki/Q140393352",
								],
							},
							{
								"@type": "SoftwareSourceCode",
								"@id":
									"https://github.com/jmrplens/cs-routeros-bouncer#source-code",
								name: "cs-routeros-bouncer source code",
								codeRepository:
									"https://github.com/jmrplens/cs-routeros-bouncer",
								programmingLanguage: "Go",
								runtimePlatform: "Linux",
								license: "https://opensource.org/licenses/MIT",
								isPartOf: {
									"@id":
										"https://github.com/jmrplens/cs-routeros-bouncer#software",
								},
								author: { "@id": "https://jmrp.io/#person" },
							},
						],
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
						{
							label: "Installation",
							slug: "getting-started/installation",
						},
						{
							label: "CLI Reference",
							slug: "getting-started/cli-reference",
						},
						{
							label: "Router Setup",
							slug: "getting-started/router-setup",
						},
					],
				},
				{
					label: "Configuration",
					items: [
						{ label: "Overview", slug: "configuration" },
						{ label: "MikroTik", slug: "configuration/mikrotik" },
						{ label: "CrowdSec", slug: "configuration/crowdsec" },
						{ label: "CAPI Blocklists", slug: "configuration/capi-blocklists" },
						{ label: "Firewall", slug: "configuration/firewall" },
						{
							label: "Logging & Metrics",
							slug: "configuration/logging-metrics",
						},
						{
							label: "Performance Tuning",
							slug: "configuration/performance-tuning",
						},
						{ label: "Examples", slug: "configuration/examples" },
					],
				},
				{
					label: "Architecture",
					badge: { text: "Deep dive", variant: "note" },
					items: [
						{ label: "Overview", slug: "architecture" },
						{
							label: "Decision Processing",
							slug: "architecture/decisions",
						},
						{
							label: "Firewall Rules",
							slug: "architecture/firewall-rules",
						},
						{
							label: "Reconciliation",
							slug: "architecture/reconciliation",
						},
					],
				},
				{
					label: "Monitoring",
					items: [
						{
							label: "Prometheus Metrics",
							slug: "monitoring/prometheus",
						},
						{
							label: "Grafana Dashboard",
							slug: "monitoring/grafana",
						},
						{ label: "Health Endpoint", slug: "monitoring/health" },
					],
				},
				{
					label: "Development",
					items: [
						{
							label: "Building & Testing",
							slug: "development/building",
						},
						{
							label: "Testing Guide",
							slug: "development/testing-guide",
						},
						{
							label: "Benchmarking",
							slug: "development/benchmarking",
						},
						{
							label: "Project Structure",
							slug: "development/structure",
						},
						{
							label: "Contributing",
							slug: "development/contributing",
						},
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
