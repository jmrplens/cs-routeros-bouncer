// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import rehypeMermaid from "rehype-mermaid";
import fs from "node:fs";

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
							},
							{
								"@type": "SoftwareApplication",
								"@id":
									"https://github.com/jmrplens/cs-routeros-bouncer#software",
								name: "cs-routeros-bouncer",
								applicationCategory: "SecurityApplication",
								operatingSystem: "Linux",
								programmingLanguage: "Go",
								url: "https://github.com/jmrplens/cs-routeros-bouncer",
								downloadUrl:
									"https://github.com/jmrplens/cs-routeros-bouncer/releases",
								codeRepository:
									"https://github.com/jmrplens/cs-routeros-bouncer",
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
								offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
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
				{
					tag: "script",
					attrs: { type: "application/ld+json" },
					content: JSON.stringify({
						"@context": "https://schema.org",
						"@type": "FAQPage",
						mainEntity: [
							{
								"@type": "Question",
								name: "What is cs-routeros-bouncer?",
								acceptedAnswer: {
									"@type": "Answer",
									text: "cs-routeros-bouncer is a free, open-source CrowdSec bouncer for MikroTik RouterOS. It syncs CrowdSec ban/unban decisions into RouterOS firewall rules (filter and raw, IPv4 and IPv6) through the RouterOS API, with startup and periodic reconciliation, Prometheus metrics, and safe rule cleanup.",
								},
							},
							{
								"@type": "Question",
								name: "Which CrowdSec and RouterOS versions does it support?",
								acceptedAnswer: {
									"@type": "Answer",
									text: "It requires CrowdSec 1.5+ with the Local API (LAPI) reachable from the bouncer host, and MikroTik RouterOS 7.x with the API service enabled (port 8728, or 8729 for TLS), using a dedicated RouterOS API user with the appropriate permissions.",
								},
							},
							{
								"@type": "Question",
								name: "Is cs-routeros-bouncer free and open source?",
								acceptedAnswer: {
									"@type": "Answer",
									text: "Yes. cs-routeros-bouncer is MIT-licensed, written in Go, distributed as a single static binary, with the full source on GitHub and no paid tier.",
								},
							},
							{
								"@type": "Question",
								name: "Does cs-routeros-bouncer support IPv6?",
								acceptedAnswer: {
									"@type": "Answer",
									text: "Yes. Each RouterOS rule type it manages (filter input, raw prerouting, and optional filter output) has an IPv6 equivalent, and IPv4/IPv6 rule placement can be configured together or overridden independently per protocol.",
								},
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
