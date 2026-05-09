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

const terminalFrameControls = {
	name: "terminal-frame-controls",
	baseStyles: `
		.frame.is-terminal .header {
			justify-content: flex-start;
		}
		.frame.is-terminal .header::before {
			position: static;
			display: block;
			width: 0.625rem;
			height: 0.625rem;
			margin-inline-end: 2.25rem;
			border-radius: 50%;
			background-color: #ff5f56;
			box-shadow: 1rem 0 0 #ffbd2e, 2rem 0 0 #27c93f;
			content: "";
			-webkit-mask-image: none;
			mask-image: none;
			opacity: 1;
		}
		.copy {
			top: calc((2.25rem - 1.75rem) / 2);
			right: 0.625rem;
			z-index: 2;
			width: 1.75rem;
			height: 1.75rem;
			gap: 0;
			align-items: center;
			justify-content: center;
			border: 1px solid var(--sl-color-gray-5);
			border-radius: 0.375rem;
			background-color: var(--sl-color-gray-6);
			opacity: 1;
			box-shadow: none;
			transition: background-color 0.2s ease, transform 0.2s ease;
		}
		.copy button {
			width: 1.625rem;
			height: 1.625rem;
			flex: 0 0 1.625rem;
			align-self: center;
			background-color: transparent;
			opacity: 1;
			transition: none;
		}
		.copy button::after {
			background-color: var(--sl-color-gray-2);
		}
		@media (hover: hover) {
			.copy button {
				width: 1.625rem;
				height: 1.625rem;
				opacity: 1;
			}
		}
	`,
};

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
				plugins: [terminalFrameControls],
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
						"@type": "SoftwareApplication",
						name: "cs-routeros-bouncer",
						description:
							"CrowdSec bouncer for MikroTik RouterOS — automatic firewall management via the RouterOS API",
						applicationCategory: "SecurityApplication",
						operatingSystem: "Linux",
						url: "https://jmrplens.github.io/cs-routeros-bouncer",
						license:
							"https://github.com/jmrplens/cs-routeros-bouncer/blob/main/LICENSE",
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
