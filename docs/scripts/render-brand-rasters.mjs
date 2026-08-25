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

// The rail is the one colour the standalone copies must carry as a literal:
// there is no system colour for a brand accent (AccentColor is the READER's
// OS accent, not ours). Assert it still equals the token, so the one literal
// in the drawing cannot drift the way the retired mark's four hex values did.
function assertRailMatchesToken(accent) {
	const svg = readFileSync(MARK, "utf8");
	const declared = /\.rb-mark__rail\s*\{[^}]*fill:\s*([^;]+);/.exec(svg);
	if (!declared) {
		throw new Error(`${MARK}: no standalone fill for .rb-mark__rail to check`);
	}
	if (declared[1].trim().toLowerCase() !== accent.toLowerCase()) {
		throw new Error(
			`${MARK} paints the rail ${declared[1].trim()} but theme.css declares ` +
				`--rb-accent: ${accent} for the light theme. Update the drawing, or the ` +
				`favicon and the header will show different brands.`,
		);
	}
}
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

assertRailMatchesToken(palette.accent);

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
		.rb-mark__lane { fill: ${palette.ink}; }
		.rb-mark__halt { fill: ${palette.grid}; }
		.rb-mark__rail { fill: ${palette.accent}; }
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
	// Lift the mark's shapes into the card. Taken from the end of the opening
	// <svg> tag rather than from a <defs> block: the mark has none, and slicing
	// from a missing marker silently produced a card with no mark on it — which
	// shipped once, because the byte count still changed and nobody looked.
	const open = mark.indexOf(">", mark.indexOf("<svg")) + 1;
	const close = mark.lastIndexOf("</svg>");
	if (open <= 0 || close <= open)
		throw new Error(`${MARK}: cannot find the mark body`);
	const inner = mark.slice(open, close);
	if (!/<(path|rect|circle|g)\b/.test(inner)) {
		throw new Error(`${MARK}: the extracted body carries no shapes`);
	}
	// Laid out for a 64-unit mark: 200px tall is scale 3.125. The previous
	// layout carried a 0.86 scale tuned for a 256-unit drawing, which rendered
	// the new mark at a twelfth of its intended size.
	return Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
	<style>
		.rb-mark__lane { fill: ${palette.ink}; }
		.rb-mark__halt { fill: ${palette.grid}; }
		.rb-mark__rail { fill: ${palette.accent}; }
		.name { font-family: "${MONO}"; font-size: 60px; font-weight: 600; fill: ${palette.ink}; }
		.affix { fill: ${palette.grid}; }
		.tag { font-family: "${MONO}"; font-size: 24px; fill: ${palette.grid}; }
	</style>
	<rect width="1200" height="630" fill="${palette.ground}"/>
	<rect x="0" y="0" width="1200" height="8" fill="${palette.accent}"/>
	<g transform="translate(112 215) scale(3.125)">${inner}</g>
	<text x="360" y="330" class="name"><tspan class="affix">cs-</tspan>routeros<tspan class="affix">-bouncer</tspan></text>
	<text x="362" y="382" class="tag">CrowdSec decisions, enforced as MikroTik firewall rules</text>
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
