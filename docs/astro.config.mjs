// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import sitemap from "@astrojs/sitemap";
import rehypeMermaid from "rehype-mermaid";
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { getLatestRelease, gitAvailable } from "./src/lib/latest-release.mjs";

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
	if (!gitAvailable()) return undefined;
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

const latestRelease = getLatestRelease();

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
			i18n: {
				defaultLocale: "en",
				locales: { en: "en", es: "es" },
			},
			serialize(item) {
				const lastmod = getLastmod(new URL(item.url).pathname);
				return lastmod ? { ...item, lastmod } : item;
			},
		}),
		starlight({
			title: "cs-routeros-bouncer",
			description:
				"CrowdSec bouncer for MikroTik RouterOS — automatic firewall management via the RouterOS API",
			defaultLocale: "root",
			locales: {
				root: { label: "English", lang: "en" },
				es: { label: "Español", lang: "es" },
			},
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
					// This is a baseline policy, not strong XSS mitigation: it still
					// allows 'unsafe-inline' for script-src/style-src because this page
					// ships literal inline <script type="application/ld+json"> blocks
					// (with per-page dynamic content, so build-time hashes won't match)
					// and Starlight's scoped inline styles — a static GitHub Pages site
					// can't mint per-request nonces either. Its value is narrowing
					// default-src/connect-src/base-uri/form-action to 'self', not
					// blocking inline script execution.
					tag: "meta",
					attrs: {
						"http-equiv": "Content-Security-Policy",
						// script-src needs 'wasm-unsafe-eval' (and 'unsafe-eval' as a
						// fallback for browsers that don't yet support the narrower
						// directive, e.g. Safari) because Starlight's Pagefind search
						// runs its index as WebAssembly — see
						// https://pagefind.app/docs/hosting/#content-security-policy.
						content:
							"default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' 'unsafe-eval'; connect-src 'self'; base-uri 'self'; form-action 'self'",
					},
				},
				{
					tag: "link",
					attrs: {
						rel: "manifest",
						href: "/cs-routeros-bouncer/manifest.json",
					},
				},
				// Starlight's `favicon` option above only emits one SVG <link>.
				// Add fallbacks for browsers/crawlers with weak or no SVG favicon
				// support (older Safari, Google's SERP favicon fetcher, RSS
				// readers) and for the home-screen/bookmark icon on iOS.
				{
					tag: "link",
					attrs: {
						rel: "icon",
						type: "image/png",
						sizes: "32x32",
						href: "/cs-routeros-bouncer/favicon-32x32.png",
					},
				},
				{
					// `sizes: "any"` on a raster .ico looks wrong at a glance, but
					// it's deliberate: Starlight's own SVG <link> (emitted by the
					// `favicon` option above) is appended after this whole `head`
					// array, i.e. last in document order. Some Chromium versions
					// otherwise prefer an earlier .ico with an exact/declared size
					// over a later SVG; marking it "any" makes it the least-specific
					// candidate so the SVG — which browsers that support it always
					// prefer — wins. This is the same technique documented in
					// https://evilmartians.com/chronicles/how-to-favicon-in-2021-six-files-that-fit-most-needs.
					tag: "link",
					attrs: {
						rel: "icon",
						href: "/cs-routeros-bouncer/favicon.ico",
						sizes: "any",
					},
				},
				{
					tag: "link",
					attrs: {
						rel: "apple-touch-icon",
						href: "/cs-routeros-bouncer/apple-touch-icon.png",
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
								softwareVersion: latestRelease.version,
								dateModified: latestRelease.date,
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
					translations: { es: "Primeros pasos" },
					items: [
						{
							label: "Quick Start",
							translations: { es: "Inicio rápido" },
							slug: "getting-started/quickstart",
							badge: {
								text: { en: "Start here", es: "Empieza aquí" },
								variant: "tip",
							},
						},
						{
							label: "Installation",
							translations: { es: "Instalación" },
							slug: "getting-started/installation",
						},
						{
							label: "CLI Reference",
							translations: { es: "Referencia CLI" },
							slug: "getting-started/cli-reference",
						},
						{
							label: "Router Setup",
							translations: { es: "Configuración del router" },
							slug: "getting-started/router-setup",
						},
					],
				},
				{
					label: "Configuration",
					translations: { es: "Configuración" },
					items: [
						{
							label: "Overview",
							translations: { es: "Visión general" },
							slug: "configuration",
						},
						{ label: "MikroTik", slug: "configuration/mikrotik" },
						{ label: "CrowdSec", slug: "configuration/crowdsec" },
						{
							label: "CAPI Blocklists",
							translations: { es: "Listas de bloqueo CAPI" },
							slug: "configuration/capi-blocklists",
						},
						{ label: "Firewall", slug: "configuration/firewall" },
						{
							label: "Logging & Metrics",
							translations: { es: "Logs y métricas" },
							slug: "configuration/logging-metrics",
						},
						{
							label: "Performance Tuning",
							translations: { es: "Ajuste de rendimiento" },
							slug: "configuration/performance-tuning",
						},
						{
							label: "Examples",
							translations: { es: "Ejemplos" },
							slug: "configuration/examples",
						},
					],
				},
				{
					label: "Architecture",
					translations: { es: "Arquitectura" },
					badge: {
						text: { en: "Deep dive", es: "En profundidad" },
						variant: "note",
					},
					items: [
						{
							label: "Overview",
							translations: { es: "Visión general" },
							slug: "architecture",
						},
						{
							label: "Decision Processing",
							translations: { es: "Procesamiento de decisiones" },
							slug: "architecture/decisions",
						},
						{
							label: "Firewall Rules",
							translations: { es: "Reglas de firewall" },
							slug: "architecture/firewall-rules",
						},
						{
							label: "Reconciliation",
							translations: { es: "Reconciliación" },
							slug: "architecture/reconciliation",
						},
					],
				},
				{
					label: "Monitoring",
					translations: { es: "Monitorización" },
					items: [
						{
							label: "Prometheus Metrics",
							translations: { es: "Métricas de Prometheus" },
							slug: "monitoring/prometheus",
						},
						{
							label: "Grafana Dashboard",
							translations: { es: "Dashboard de Grafana" },
							slug: "monitoring/grafana",
						},
						{
							label: "Health Endpoint",
							translations: { es: "Endpoint de salud" },
							slug: "monitoring/health",
						},
					],
				},
				{
					label: "Development",
					translations: { es: "Desarrollo" },
					items: [
						{
							label: "Building & Testing",
							translations: { es: "Compilación y pruebas" },
							slug: "development/building",
						},
						{
							label: "Testing Guide",
							translations: { es: "Guía de pruebas" },
							slug: "development/testing-guide",
						},
						{
							label: "Benchmarking",
							slug: "development/benchmarking",
						},
						{
							label: "Project Structure",
							translations: { es: "Estructura del proyecto" },
							slug: "development/structure",
						},
						{
							label: "Contributing",
							translations: { es: "Contribuir" },
							slug: "development/contributing",
						},
						{
							label: "Security",
							translations: { es: "Seguridad" },
							slug: "development/security",
							badge: {
								text: { en: "Policy", es: "Política" },
								variant: "caution",
							},
						},
					],
				},
				{
					label: "Troubleshooting",
					translations: { es: "Solución de problemas" },
					slug: "troubleshooting",
				},
			],
		}),
	],
});
