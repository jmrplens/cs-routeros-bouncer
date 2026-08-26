/**
 * The social card for one documentation page.
 *
 * The site shipped a single card for all 56 pages, so every link — to the
 * reconciliation internals, to the CLI reference, to a Spanish translation —
 * previewed as the same project banner. This composes one per page from the
 * same mark and the same palette as everything else.
 *
 * Deliberately not satori or a headless browser: the drawing is a handful of
 * rectangles and two runs of text, and both of those alternatives would add a
 * heavyweight dependency to a static build for a layout this simple.
 */
import { escapeText, MONO, MONO_ADVANCE } from "./brand-assets.mjs";

const WIDTH = 1200;
const HEIGHT = 630;
const MARGIN = 96;
const TITLE_SIZE = 60;
const TITLE_LEADING = 78;
const MAX_LINES = 3;

/** How many characters of `size`px mono fit across the card's text column. */
function charsPerLine(size) {
	return Math.floor((WIDTH - MARGIN * 2) / (size * MONO_ADVANCE));
}

/**
 * Break `text` into at most `MAX_LINES` lines that fit the column.
 *
 * Greedy by word, which is all a title needs. A single word longer than the
 * column is hard-split rather than allowed to overflow — that is the case a
 * naive wrapper gets wrong, and a config key like
 * `logging-metrics.track_processed` is exactly such a word. The last line is
 * ellipsised if the text runs past `MAX_LINES`, so a card is never silently
 * truncated mid-sentence.
 * @param {string} text
 * @param {number} size font size in px
 * @returns {string[]}
 */
export function wrap(text, size) {
	const limit = charsPerLine(size);
	/** @type {string[]} */
	const lines = [];
	let line = "";
	for (const word of text.split(/\s+/).filter(Boolean)) {
		let rest = word;
		while (rest.length > limit) {
			if (line !== "") {
				lines.push(line);
				line = "";
			}
			lines.push(rest.slice(0, limit));
			rest = rest.slice(limit);
		}
		const candidate = line === "" ? rest : `${line} ${rest}`;
		if (candidate.length <= limit) {
			line = candidate;
			continue;
		}
		lines.push(line);
		line = rest;
	}
	if (line !== "") lines.push(line);
	if (lines.length <= MAX_LINES) return lines;
	const kept = lines.slice(0, MAX_LINES);
	kept[MAX_LINES - 1] = `${kept[MAX_LINES - 1].slice(0, limit - 1)}…`;
	return kept;
}

/**
 * @param {{ title: string, kicker: string, palette: Record<string, string>, mark: string }} page
 *   `kicker` is the section this page sits under, or the project name for a
 *   page that sits at the top level — the line that tells a reader what they
 *   are looking at when the title alone is `Overview`.
 * @returns {Buffer} an SVG document
 */
export function pageCard({ title, kicker, palette, mark }) {
	const lines = wrap(title, TITLE_SIZE);
	// Bottom-align the title block against a fixed baseline so cards with one
	// line and cards with three share a horizon instead of drifting.
	const firstBaseline = 470 - (lines.length - 1) * TITLE_LEADING;
	const tspans = lines
		.map(
			(line, index) =>
				`<tspan x="${MARGIN}" y="${firstBaseline + index * TITLE_LEADING}">${escapeText(line)}</tspan>`,
		)
		.join("");
	return Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="${WIDTH}" height="${HEIGHT}" viewBox="0 0 ${WIDTH} ${HEIGHT}">
	<style>
		.rb-mark__lane { fill: ${palette.ink}; }
		.rb-mark__halt { fill: ${palette.grid}; }
		.rb-mark__rail { fill: ${palette.accent}; }
		.kicker { font-family: "${MONO}"; font-size: 28px; fill: ${palette.grid}; letter-spacing: 2px; }
		.title { font-family: "${MONO}"; font-size: ${TITLE_SIZE}px; font-weight: 600; fill: ${palette.ink}; }
		.project { font-family: "${MONO}"; font-size: 26px; fill: ${palette.grid}; }
	</style>
	<rect width="${WIDTH}" height="${HEIGHT}" fill="${palette.ground}"/>
	<rect x="0" y="0" width="${WIDTH}" height="8" fill="${palette.accent}"/>
	<g transform="translate(${MARGIN} 108) scale(1.5)">${mark}</g>
	<text x="${MARGIN}" y="252" class="kicker">${escapeText(kicker.toUpperCase())}</text>
	<text class="title">${tspans}</text>
	<text x="${MARGIN}" y="558" class="project">cs-routeros-bouncer</text>
</svg>`);
}
