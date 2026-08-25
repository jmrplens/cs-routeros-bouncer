#!/usr/bin/env node
/**
 * Renders the committed PNG brand assets from the one SVG the site uses.
 *
 * The mark carries no colour of its own — `src/styles/brand.css` paints it from
 * theme tokens — which is exactly what stops it drifting again, and also what
 * stops a rasteriser producing anything but a blank square. So this script
 * resolves the same tokens out of `src/styles/theme.css` and inlines them,
 * meaning the PNGs cannot disagree with the palette the site renders: change a
 * token, re-run, and every raster follows.
 *
 * Rasters were previously hand-cut and were left behind when the mark was
 * retokenised, so the site shipped a header in one palette and a favicon,
 * app icon and social card in the retired one.
 *
 * Usage:
 *   node scripts/render-brand-rasters.mjs           # write the PNGs
 *   node scripts/render-brand-rasters.mjs --check   # exit 1 if any is stale
 */
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

const DOCS = fileURLToPath(new URL("..", import.meta.url));
const THEME = path.join(DOCS, "src/styles/theme.css");
const MARK = path.join(DOCS, "src/assets/logo-light.svg");

/** Resolve one custom property out of a selector block in theme.css. */
function token(css, selector, name) {
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

const css = readFileSync(THEME, "utf8");
const palette = {
	// The rasters are cut from the LIGHT theme: a favicon sits on browser
	// chrome, and an app icon on a launcher, neither of which follows the
	// site's theme switch.
	ink: token(css, ':root[data-theme="light"] {', "rb-heading"),
	grid: token(css, ':root[data-theme="light"] {', "rb-muted"),
	ground: token(css, ':root[data-theme="light"] {', "rb-page"),
	accent: token(css, ':root[data-theme="light"] {', "rb-accent"),
};

/** The mono family the site's own stack resolves to on a Linux renderer. */
const MONO = "DejaVu Sans Mono";

/** Append concrete colours so the standalone file renders outside a browser. */
function standaloneMark() {
	const svg = readFileSync(MARK, "utf8");
	// The committed mark paints itself with the CSS system colours CanvasText
	// and GrayText, which is what lets it work as a favicon in any context. A
	// rasteriser resolves neither, so a second <style> is appended — later
	// rules win — carrying the same values the site's light theme computes.
	// Appended rather than substituted: editing the existing block means
	// parsing SVG with a regex, which is how the first attempt at this script
	// produced malformed XML.
	const close = svg.lastIndexOf("</svg>");
	if (close === -1) throw new Error(`${MARK}: no closing </svg>`);
	const override = `<style>
		.rb-mark__body, .rb-mark__dot { fill: ${palette.ink}; }
		.rb-mark__arc { stroke: ${palette.grid}; }
	</style>`;
	return Buffer.from(svg.slice(0, close) + override + svg.slice(close));
}

/**
 * The social card: mark, wordmark, and one line saying what the thing is.
 *
 * Composed here rather than hand-cut so it cannot fall out of step with the
 * palette the way its predecessor did — that file was still carrying the
 * retired CrowdSec-indigo and MikroTik-teal pair long after the mark had moved.
 * Workstream W13 replaces this with per-page cards; until then a single card
 * that matches the site beats a hand-cut one that contradicts it.
 */
function socialCard() {
	const mark = readFileSync(MARK, "utf8");
	// Lift the mark's own <defs> and shapes into the card, scaled and offset.
	const inner = mark.slice(mark.indexOf("<defs>"), mark.lastIndexOf("</svg>"));
	return Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
	<style>
		.rb-mark__body, .rb-mark__dot { fill: ${palette.ink}; }
		.rb-mark__arc { stroke: ${palette.grid}; }
		.name { font-family: "${MONO}"; font-size: 62px; font-weight: 600; fill: ${palette.ink}; }
		.affix { fill: ${palette.grid}; }
		.tag { font-family: "${MONO}"; font-size: 30px; fill: ${palette.grid}; }
	</style>
	<rect width="1200" height="630" fill="${palette.ground}"/>
	<rect x="0" y="0" width="1200" height="6" fill="${palette.accent}"/>
	<g transform="translate(96 168) scale(0.86)">${inner}</g>
	<text x="330" y="300" class="name"><tspan class="affix">cs-</tspan>routeros<tspan class="affix">-bouncer</tspan></text>
	<text x="332" y="356" class="tag">CrowdSec decisions, enforced as MikroTik firewall rules</text>
</svg>`);
}

/** name, pixel size, and whether the ground is painted behind the mark. */
const TARGETS = [
	["public/favicon-32x32.png", 32, false],
	["public/icon-192.png", 192, false],
	["public/icon-512.png", 512, false],
	// Apple does not honour transparency and composites on black, so this one
	// carries the ground itself.
	["public/apple-touch-icon.png", 180, true],
];

/** The card is a different composition, not a resize of the mark. */
const CARD = "public/og-image.png";

async function render(size, opaque) {
	const mark = sharp(standaloneMark(), { density: 384 }).resize(size, size);
	if (!opaque) return mark.png({ compressionLevel: 9 }).toBuffer();
	return sharp({
		create: {
			width: size,
			height: size,
			channels: 4,
			background: palette.ground,
		},
	})
		.composite([{ input: await mark.png().toBuffer() }])
		.png({ compressionLevel: 9 })
		.toBuffer();
}

const check = process.argv.includes("--check");
let stale = 0;
for (const [relative, size, opaque] of [...TARGETS, [CARD, 0, false]]) {
	const target = path.join(DOCS, relative);
	const rendered =
		relative === CARD
			? await sharp(socialCard(), { density: 96 })
					// librsvg scales by density; pin the output so the card is
					// exactly the 1200x630 every social scraper expects.
					.resize(1200, 630)
					.png({ compressionLevel: 9 })
					.toBuffer()
			: await render(size, opaque);
	if (check) {
		const current = readFileSync(target);
		if (!current.equals(rendered)) {
			console.error(`✗ ${relative} is stale — run \`pnpm run brand:rasters\``);
			stale += 1;
		}
		continue;
	}
	writeFileSync(target, rendered);
	console.log(
		`  ${relative} (${size || "1200x630"}, ${rendered.length} bytes)`,
	);
}

if (check) {
	if (stale > 0) process.exit(1);
	console.log(
		`✓ ${TARGETS.length + 1} brand rasters match the mark and the palette.`,
	);
}
