/**
 * The brand lockup: the mark, and the wordmark beside it.
 *
 * The mark ships as three standalone SVG documents — `src/assets/logo-light.svg`
 * and `src/assets/logo-dark.svg` for the home-page hero's `<img>` pair, and
 * `public/favicon.svg` for the tab strip. Each of those is fetched as its own
 * document, so each has to be able to colour itself, and each carries a `<style>`
 * block that does so from the UA's own ink (`CanvasText`) and subordinate tone
 * (`GrayText`) rather than from a hex pair.
 *
 * INLINING IS A DIFFERENT CONTRACT, and this module is the only thing that may
 * perform it. Three things are true of an inlined copy that are not true of a
 * standalone one, and each of them was a latent bug before this helper existed:
 *
 *   1. Its `<style>` is no longer scoped to an image. A `<style>` element inside
 *      inline SVG is a style element in the HOST DOCUMENT: `svg { color-scheme }`
 *      would reach every `<svg>` on the page, including Starlight's icons, and it
 *      would answer to the reader's OS rather than to this site's theme switch —
 *      which can disagree with the OS in both directions. So it is deleted.
 *   2. Its ids are no longer document-local. `id="rb-mark-shield"` is global once
 *      inlined; inline the mark twice on one page — a header lockup and a hero,
 *      which is exactly what a lockup invites — and the second `url(#…)` silently
 *      resolves to the FIRST element. So every id is suffixed per call site.
 *   3. Its `role="img"` / `aria-label` are no longer the accessible name of
 *      anything. Inline, the mark sits beside a wordmark that is real text, so
 *      the name is already there and a second copy of it is noise. The mark
 *      becomes `aria-hidden`, and `focusable="false"` keeps it out of the tab
 *      order in browsers that still put inline SVG there.
 *
 * The assertions below are deliberately fatal. A silent no-op here — an
 * `aria-label` that was renamed, a `<style>` that survived a regex, an id that
 * was not namespaced — produces a page that looks right in the one place the
 * author checked and is wrong everywhere else. That failure has already cost
 * this project three pull requests.
 */
import { assertNoSpansSurvive, stripSpans } from "./svg-spans.mjs";
import faviconSource from "../../public/favicon.svg?raw";
import darkSource from "../assets/logo-dark.svg?raw";
import lightSource from "../assets/logo-light.svg?raw";

/**
 * The accessible markup each standalone file must carry, and what it becomes
 * when inlined. Matched as one exact string so a rename in the SVG cannot half-
 * apply: either both attributes are found together, or the build stops.
 */
const STANDALONE_A11Y = 'role="img" aria-label="cs-routeros-bouncer logo"';
const INLINE_A11Y = 'class="rb-mark" aria-hidden="true" focusable="false"';

/** Rejects a scope that would produce an id needing escaping in `url(#…)`. */
const SCOPE_PATTERN = /^[a-z][a-z0-9-]*$/;

/**
 * One standalone file → the inline form of the mark, ids not yet namespaced.
 *
 * @param source - The raw SVG document.
 * @param file - Repository path, for the error messages.
 */
function toInlineForm(source: string, file: string): string {
	const labels = source.split(STANDALONE_A11Y).length - 1;
	if (labels !== 1) {
		throw new Error(
			`${file}: expected exactly one \`${STANDALONE_A11Y}\`, found ${labels}. ` +
				"The mark's standalone accessible name is the thing brandSvg() trades " +
				"away for aria-hidden; if it is not there, inlining would either ship " +
				"a duplicate accessible name or hide nothing.",
		);
	}

	// An XML comment may not contain `--`, and the token names this mark is
	// documented against are spelled with one. Get that wrong and the file
	// still inlines perfectly — the comments are stripped two lines below —
	// while every <img> copy of it fails to parse and renders as a broken
	// image. It happened while this helper was being written — the hero pair
	// shipped unparseable for one build — so it is checked rather than
	// remembered. `DOMParser` is not available here, so the one rule that has
	// actually bitten is the one enforced.
	for (const comment of source.matchAll(/<!--([\s\S]*?)-->/g)) {
		if (comment[1]?.includes("--")) {
			throw new Error(
				`${file}: an XML comment contains a double hyphen, which is not ` +
					"well-formed XML. The mark inlines fine but every <img> copy of " +
					"it — the home-page hero, the favicon — fails to parse.",
			);
		}
	}

	const svg = collapseWhitespaceBetweenTags(
		stripSpans(source.replace(STANDALONE_A11Y, INLINE_A11Y)),
	).trim();

	assertNoSpansSurvive(svg, file, "</svg>");

	return svg;
}

/**
 * The mark, inline-ready.
 *
 * All three standalone copies are normalised and compared. They are meant to be
 * one drawing that differs only in which colour scheme it pins for its own
 * `<img>` rendering — the geometry, the class hooks and the ids must be
 * identical — and they have drifted before: the two hero files last shipped four
 * brand hex literals between them that no stylesheet declared, and the favicon a
 * third hand-kept copy of all four. Normalising removes the two things that are
 * allowed to differ
 * (the `<style>` block and the comments), so anything left over is drift, and
 * drift stops the build. The favicon is never inlined; it is imported here
 * purely so it cannot quietly become a different mark from the other two.
 */
const MARK: string = (() => {
	const copies = [
		["src/assets/logo-light.svg", lightSource],
		["src/assets/logo-dark.svg", darkSource],
		["public/favicon.svg", faviconSource],
	] as const;

	const normalised = copies.map(
		([file, source]) => [file, toInlineForm(source, file)] as const,
	);
	const [reference, ...rest] = normalised;
	if (reference === undefined) throw new Error("no copies of the mark");

	for (const [file, svg] of rest) {
		if (svg === reference[1]) continue;
		throw new Error(
			`${file} is no longer the same drawing as ${reference[0]}. The three ` +
				"copies may differ only in the `color-scheme` their standalone " +
				"<style> pins and in their comments; everything else — geometry, " +
				"class hooks, ids — is shared.\n" +
				`  ${reference[0]}: ${reference[1]}\n` +
				`  ${file}: ${svg}`,
		);
	}
	return reference[1];
})();

/** Every id the mark declares, in source order. */
const MARK_IDS: readonly string[] = [...MARK.matchAll(/\sid="([^"]+)"/g)]
	.map((match) => match[1])
	.filter((id): id is string => id !== undefined);

// No assertion that ids EXIST. The mark this replaced needed a clipPath and a
// mask, and their ids were document-global: inlining the lockup twice on one
// page made the second `url(#rb-mark-shield)` resolve to the first element.
// The current drawing is four rectangles and needs no ids at all, so having
// none is the fixed state rather than a symptom — an earlier version of this
// file threw here, and the assertion outlived the problem it was guarding.
//
// The namespacing below still runs, so an id reintroduced later is still made
// per-call-site. What IS worth failing on is a url() reference with no
// matching id, which would silently render nothing.
const MARK_REFS: readonly string[] = [...MARK.matchAll(/url\(#([^)]+)\)/g)]
	.map((match) => match[1])
	.filter((ref): ref is string => ref !== undefined);
const danglingRefs = MARK_REFS.filter((ref) => !MARK_IDS.includes(ref));
if (danglingRefs.length > 0) {
	throw new Error(
		`the mark references ${danglingRefs.map((r) => "#" + r).join(", ")} but ` +
			"declares no such id, so that element would render as nothing.",
	);
}

/**
 * The mark, ready to inline, with every id suffixed with `scope`.
 *
 * `scope` is required rather than generated so the built HTML is deterministic
 * across pages and reviewable in a diff. It must be unique among the calls on
 * any one page; a collision is a duplicate id, which `pnpm run html:validate`
 * fails on over `dist/** Squeeze the whitespace between tags that pretty-printing left behind. */
function collapseWhitespaceBetweenTags(source: string): string {
	return source.replaceAll(/>\s+</g, "><");
}

/**` — the gate that would have caught the original bug.
 *
 * @param scope - Call-site name, lowercase and hyphenated, e.g. `"site-title"`.
 * @returns SVG markup for `set:html`.
 */
export function brandSvg(scope: string): string {
	if (!SCOPE_PATTERN.test(scope)) {
		throw new Error(
			`brandSvg("${scope}"): the scope becomes part of an id referenced as ` +
				`url(#…), so it must match ${SCOPE_PATTERN.source}.`,
		);
	}

	let svg = MARK;
	for (const id of MARK_IDS) {
		// The closing quote and paren delimit the match, so an id that is a
		// prefix of another id cannot be rewritten inside it.
		svg = svg.replaceAll(`id="${id}"`, `id="${id}-${scope}"`);
		svg = svg.replaceAll(`url(#${id})`, `url(#${id}-${scope})`);
	}

	// A reference that kept its old target would resolve to whichever copy of
	// the mark rendered first, which is the bug this function exists to remove.
	for (const match of svg.matchAll(/url\(#([^)]+)\)/g)) {
		if (!match[1]?.endsWith(`-${scope}`)) {
			throw new Error(
				`brandSvg("${scope}"): \`${match[0]}\` was not namespaced. Every ` +
					"internal reference must point at this call's own ids.",
			);
		}
	}
	return svg;
}

/**
 * The wordmark, split for setting.
 *
 * `cs-routeros-bouncer` is a binary name, so it is set as live type in the mono
 * face rather than as outlines: it stays selectable, searchable and translatable
 * (well — `translate="no"`), it re-flows at any size, and because it is real
 * text the lockup's accessible name comes free instead of being restated in an
 * `alt`. The affixes are set in the muted tone and the stem in the strong one,
 * so the product name reads the way a config key reads: the scope quiet, the
 * thing it names loud.
 */
export const WORDMARK = {
	/** CrowdSec's convention for a bouncer's package name. */
	prefix: "cs-",
	stem: "routeros",
	suffix: "-bouncer",
} as const;

/** The wordmark as one string — what the segments must concatenate to. */
export const WORDMARK_TEXT: string = `${WORDMARK.prefix}${WORDMARK.stem}${WORDMARK.suffix}`;
