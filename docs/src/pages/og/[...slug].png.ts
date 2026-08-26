/**
 * One social card per documentation page, rendered at build time.
 *
 * The site previously shipped a single `og-image.png` for all 56 pages, so a
 * link to the reconciliation internals and a link to the Spanish CLI reference
 * previewed identically — the preview told a reader nothing the URL had not
 * already told them.
 *
 * A static endpoint rather than a script that writes into `public/`: the page
 * list lives in the content collection, and anything that enumerates it by
 * walking the filesystem is a second source of truth waiting to disagree. This
 * way a new page gets a card by existing.
 */
import type { APIRoute, GetStaticPaths } from "astro";
import { getCollection } from "astro:content";
import sharp from "sharp";
// `?raw` rather than `fs`: this module is bundled, so a path resolved from
// `import.meta.url` would point into `dist/.prerender/` at build time.
import markSource from "../../assets/logo-light.svg?raw";
import themeSource from "../../styles/theme.css?raw";
import { markBodyFrom, paletteFrom } from "../../lib/brand-assets.mjs";
import { pageCard } from "../../lib/page-card.mjs";
import { cardPath, ROOT_KICKER, SEGMENT_LABELS } from "../../lib/sections.mjs";

const palette = paletteFrom(themeSource);
const mark = markBodyFrom(markSource, "logo-light.svg");

/** Locales that prefix both the page id and the URL. */
const LOCALES = new Set(Object.keys(SEGMENT_LABELS).filter((l) => l !== "en"));

/**
 * Split a collection id into its language and the path below that language.
 * `es/architecture/index` → `["es", "architecture/index"]`.
 */
function localeOf(id: string): [string, string] {
	const [head, ...rest] = id.split("/");
	return head !== undefined && LOCALES.has(head)
		? [head, rest.join("/")]
		: ["en", id];
}

export const getStaticPaths: GetStaticPaths = async () => {
	const pages = await getCollection("docs");
	return pages.map((page) => {
		const [lang, stripped] = localeOf(page.id);
		const segment = stripped.split("/")[0] ?? "";
		const labels = SEGMENT_LABELS[lang] ?? SEGMENT_LABELS.en;
		return {
			params: { slug: cardPath(page.id) },
			props: {
				title: page.data.title,
				// A page directly under the locale root has no section above it.
				kicker: labels[segment] ?? ROOT_KICKER[lang] ?? ROOT_KICKER.en,
			},
		};
	});
};

export const GET: APIRoute = async ({ props }) => {
	const { title, kicker } = props as { title: string; kicker: string };
	const png = await sharp(pageCard({ title, kicker, palette, mark }), {
		density: 96,
	})
		.resize(1200, 630)
		.png({ compressionLevel: 9 })
		.toBuffer();
	return new Response(new Uint8Array(png), {
		headers: { "Content-Type": "image/png" },
	});
};
