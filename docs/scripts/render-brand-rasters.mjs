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
import { assertNoSpansSurvive, stripSpans } from "../src/lib/svg-spans.mjs";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
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
/**
 * Fail if the web manifest has drifted from the palette or from the rasters.
 *
 * The manifest is hand-written content — name, description, categories — so it
 * is asserted rather than generated. What it must not do is carry a colour or
 * an icon path of its own: `theme_color` paints the browser chrome and stayed
 * `#0e1316` through a full change of accent, and an icon entry naming a file
 * nobody renders is how `favicon.ico` sat at the retired mark for a month.
 * @param {string} dark the dark theme's `--rb-page`
 */
function assertManifestMatchesPalette(dark) {
	const file = path.join(DOCS, "public/manifest.json");
	const manifest = JSON.parse(readFileSync(file, "utf8"));
	for (const key of ["theme_color", "background_color"]) {
		if (manifest[key]?.toLowerCase() !== dark.toLowerCase()) {
			throw new Error(
				`manifest.json declares ${key}: ${manifest[key]} but theme.css ` +
					`declares --rb-page: ${dark} for the dark theme. The browser ` +
					"chrome and the page it frames would not match.",
			);
		}
	}
	for (const icon of manifest.icons ?? []) {
		const name = icon.src.split("/").pop();
		if (!existsSync(path.join(DOCS, "public", name))) {
			throw new Error(
				`manifest.json points at public/${name}, which does not exist`,
			);
		}
	}
	if (!(manifest.icons ?? []).some((icon) => icon.purpose === "maskable")) {
		throw new Error(
			"manifest.json declares no maskable icon, so Android will shrink the " +
				"mark onto a plain tile instead of cropping it to the launcher shape",
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
assertManifestMatchesPalette(token(css, ":root {", "rb-page"));

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
	// Strip the mark's own <style> on the way in. It would land *after* the
	// card's stylesheet below and beat it on equal specificity, so the card
	// would be painted by the standalone file's colours instead of the tokens
	// read from theme.css. Today that is latent rather than broken: librsvg
	// drops `fill: CanvasText` as an unrecognised value, so the card's rule
	// survives by accident — but the rail's `#4d4a98` is a valid colour and
	// does win, which is why the card's accent only matches the theme because
	// assertRailMatchesToken() forces the two to stay equal. One rasteriser
	// release that learns system colours and the whole card changes silently.
	const inner = stripSpans(mark.slice(open, close));
	assertNoSpansSurvive(inner, MARK);
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

/**
 * Pack PNGs into an `.ico`.
 *
 * The file exists for the consumers that never learned SVG favicons — Google's
 * SERP fetcher, older Safari, some feed readers — which is exactly why it was
 * the one asset nothing regenerated. It sat at the July shield for a full mark
 * change, so the search result showed a logo the site had retired, and the
 * usual defence (someone would notice) does not apply to a surface the author
 * never looks at.
 *
 * Written by hand because sharp cannot encode ICO and an ImageMagick dependency
 * would not survive CI. The container is trivial: a 6-byte header, one 16-byte
 * directory entry per image, then the images. They are stored as PNG rather
 * than BMP, which every browser has accepted since Vista and which Google's
 * fetcher reads — and it keeps each frame identical to the PNG rendered from
 * the same mark, rather than a second encoding that could drift from it.
 * @param {{ size: number, png: Buffer }[]} images
 * @returns {Buffer}
 */
function packIco(images) {
	const header = Buffer.alloc(6);
	header.writeUInt16LE(0, 0); // reserved
	header.writeUInt16LE(1, 2); // 1 = icon
	header.writeUInt16LE(images.length, 4);

	const directory = Buffer.alloc(16 * images.length);
	let offset = header.length + directory.length;
	for (const [index, { size, png }] of images.entries()) {
		const at = 16 * index;
		// 0 means 256 in this field; no frame here is that large, but the
		// encoding is the format's, not ours.
		directory.writeUInt8(size >= 256 ? 0 : size, at);
		directory.writeUInt8(size >= 256 ? 0 : size, at + 1);
		directory.writeUInt8(0, at + 2); // palette size: not a palette image
		directory.writeUInt8(0, at + 3); // reserved
		directory.writeUInt16LE(1, at + 4); // colour planes
		directory.writeUInt16LE(32, at + 6); // bits per pixel
		directory.writeUInt32LE(png.length, at + 8);
		directory.writeUInt32LE(offset, at + 12);
		offset += png.length;
	}
	return Buffer.concat([header, directory, ...images.map((i) => i.png)]);
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

/**
 * The Android adaptive icon.
 *
 * A launcher crops a maskable icon to whatever shape it likes — circle,
 * squircle, teardrop — and only guarantees a circle of 80% of the width. A
 * mark drawn edge to edge, which every other target here is, loses its outer
 * lanes to that crop. The square that fits inside a 409.6px circle has a side
 * of 289.6px, so the drawing goes in at 288 on a 512 ground and the launcher
 * can take any bite it wants. Without an entry of this purpose Android does
 * not crop at all: it shrinks the icon and puts it on a plain white tile.
 */
const MASKABLE = "public/icon-maskable-512.png";
const MASKABLE_SIZE = 512;
const MASKABLE_MARK = 288;

/** The legacy container. Sizes are the three Windows and browser conventions. */
const ICO = "public/favicon.ico";
const ICO_SIZES = [16, 32, 48];

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
for (const [relative, size, opaque] of [
	...TARGETS,
	[CARD, 0, false],
	[ICO, 0, false],
	[MASKABLE, MASKABLE_SIZE, true],
]) {
	const target = path.join(DOCS, relative);
	let rendered;
	if (relative === MASKABLE) {
		rendered = await sharp({
			create: {
				width: MASKABLE_SIZE,
				height: MASKABLE_SIZE,
				channels: 4,
				background: palette.ground,
			},
		})
			.composite([
				{
					input: await sharp(standaloneMark(), { density: 384 })
						.resize(MASKABLE_MARK, MASKABLE_MARK)
						.png()
						.toBuffer(),
					gravity: "centre",
				},
			])
			.png({ compressionLevel: 9 })
			.toBuffer();
	} else if (relative === ICO) {
		rendered = packIco(
			await Promise.all(
				ICO_SIZES.map(async (each) => ({
					size: each,
					png: await render(each, false),
				})),
			),
		);
	} else
		rendered =
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
		`  ${relative} (${relative === ICO ? ICO_SIZES.join("/") : size || "1200x630"}, ${rendered.length} bytes)`,
	);
}

if (check) {
	if (stale > 0) process.exit(1);
	console.log(
		`✓ ${TARGETS.length + 3} brand rasters match the mark and the palette.`,
	);
}
