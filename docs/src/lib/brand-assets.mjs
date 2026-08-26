/**
 * The brand primitives shared by everything that draws the mark outside a
 * browser: the palette, the mark's bare shapes, and the face to set text in.
 *
 * Pure on purpose — every function takes source text and returns a value, and
 * nothing here touches the filesystem. Two callers need these logic and they
 * load their sources differently: `render-brand-rasters.mjs` is plain Node and
 * reads them with `fs`, while the `og/` endpoint is bundled by Vite and imports
 * them with `?raw`. An earlier version resolved paths from `import.meta.url`
 * and worked in the first world and not the second, because once bundled that
 * URL points into `dist/.prerender/`. Sharing the logic and leaving the IO to
 * each caller is what makes one module serve both.
 */
import { assertNoSpansSurvive, stripSpans } from "./svg-spans.mjs";

/**
 * Resolve one custom property out of a selector block in theme.css.
 * @param {string} css
 * @param {string} selector block opener, e.g. `:root {`
 * @param {string} name token name without the `--` prefix
 * @returns {string}
 */
export function token(css, selector, name) {
	const start = css.indexOf(selector);
	if (start === -1) throw new Error(`theme.css: no \`${selector}\` block`);
	const end = css.indexOf("\n}", start);
	const found = new RegExp(`--${name}:\\s*([^;]+);`).exec(
		css.slice(start, end),
	);
	if (!found)
		throw new Error(`theme.css: \`${selector}\` declares no --${name}`);
	return found[1].trim();
}

/**
 * The palette the ICONS are cut from.
 *
 * The light theme, always: a favicon sits on browser chrome and an app icon on
 * a launcher, and neither follows this site's theme switch. A dark icon on a
 * light chrome is the case that actually happens, so the icons commit to it.
 * @param {string} css contents of theme.css
 */
export function paletteFrom(css) {
	const light = ':root[data-theme="light"] {';
	return {
		ink: token(css, light, "rb-heading"),
		grid: token(css, light, "rb-muted"),
		ground: token(css, light, "rb-page"),
		accent: token(css, light, "rb-accent"),
	};
}

/**
 * The palette the SOCIAL CARDS are cut from.
 *
 * The dark theme, and for the opposite reason to the icons: a card is a
 * picture in someone else's feed, not a glyph on their chrome. It is shown at
 * full size against timelines that are themselves overwhelmingly dark, and a
 * 1200x630 sheet of white is the one thing guaranteed to read as a placeholder.
 * @param {string} css contents of theme.css
 */
export function cardPaletteFrom(css) {
	const dark = ":root {";
	return {
		ink: token(css, dark, "rb-heading"),
		grid: token(css, dark, "rb-muted"),
		ground: token(css, dark, "rb-page"),
		surface: token(css, dark, "rb-surface"),
		border: token(css, dark, "rb-border"),
		accent: token(css, dark, "rb-accent"),
	};
}

/** The mono family the site's own stack resolves to on a Linux renderer. */
export const MONO = "DejaVu Sans Mono";

/**
 * Advance width of one character, as a fraction of the font size.
 *
 * True only because the face is monospaced, and the reason the card sets its
 * text in one: it makes wrapping exact arithmetic instead of a guess. librsvg
 * does not measure text for us, so a proportional face would need a font
 * metrics library to keep a title from running off the edge of the card.
 */
export const MONO_ADVANCE = 1233 / 2048;

/**
 * The mark's shapes, ready to be placed inside a larger drawing.
 *
 * Stripped of the standalone `<style>`: inside a bigger SVG that block lands
 * after the host's stylesheet and beats it on equal specificity, so the drawing
 * would be painted by the file's own literals rather than by the palette.
 * @param {string} svg contents of logo-light.svg
 * @param {string} [label] name for the error messages
 * @returns {string}
 */
export function markBodyFrom(svg, label = "the mark") {
	const open = svg.indexOf(">", svg.indexOf("<svg")) + 1;
	const close = svg.lastIndexOf("</svg>");
	if (open <= 0 || close <= open)
		throw new Error(`${label}: cannot find the mark body`);
	const inner = stripSpans(svg.slice(open, close));
	assertNoSpansSurvive(inner, label);
	if (!/<(path|rect|circle|g)\b/.test(inner))
		throw new Error(`${label}: the extracted body carries no shapes`);
	return inner;
}

/**
 * The whole standalone file with concrete colours appended for a rasteriser.
 *
 * Appended rather than substituted: editing the existing block means parsing
 * SVG with a regex, which is how the first attempt at this produced malformed
 * XML. Later rules win, so the appended values are the ones that paint.
 * @param {string} svg contents of logo-light.svg
 * @param {{ ink: string, grid: string, accent: string }} palette
 * @returns {Buffer}
 */
export function standaloneMarkFrom(svg, palette) {
	const close = svg.lastIndexOf("</svg>");
	if (close === -1) throw new Error("the mark has no closing </svg>");
	const override = `<style>
		.rb-mark__lane { fill: ${palette.ink}; }
		.rb-mark__halt { fill: ${palette.grid}; }
		.rb-mark__rail { fill: ${palette.accent}; }
	</style>`;
	return Buffer.from(svg.slice(0, close) + override + svg.slice(close));
}

/** Escape text for embedding as SVG character data. */
export function escapeText(value) {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;");
}
