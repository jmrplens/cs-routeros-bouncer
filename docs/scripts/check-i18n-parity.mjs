#!/usr/bin/env node
/**
 * Gates structural parity between the English docs and their Spanish mirror.
 *
 * `src/content/docs/` holds the English pages at the top level and a full
 * Spanish mirror under `es/`. Translations drift silently: a page gets added
 * on one side only, a section is dropped mid-translation, a frontmatter key
 * (`sidebar`, `head`, `template`, …) is set in one language and forgotten in
 * the other. None of that breaks the build, so nothing catches it in review.
 *
 * This checks the three things that can be compared without reading prose:
 *   1. every English page has a Spanish twin, and vice versa;
 *   2. both twins declare the same frontmatter keys, and the same number of
 *      entries in each list (values are expected to differ — that is the
 *      translation);
 *   3. both twins have the same sequence of heading levels, so a missing or
 *      extra section shows up even though the heading text is translated.
 *
 * Deliberately dependency-free: the frontmatter reader below is a small
 * indentation-based scanner, not a YAML parser, because it only ever has to
 * recover key paths — never values.
 *
 * Usage:
 *   node scripts/check-i18n-parity.mjs   # exit 0 when clean, 1 on any mismatch
 */
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const DOCS_DIR = fileURLToPath(new URL("../src/content/docs", import.meta.url));
/** Locale directory holding the mirror, relative to DOCS_DIR. */
// Every mirror locale directly under DOCS_DIR. Anything NOT under one of these
// is treated as an English source page that must have a twin in each locale.
// Adding a locale here is the only change needed when astro.config.mjs grows one;
// leaving it out would classify the new locale's pages as untranslated English.
const LOCALES = ["es"];
const PAGE_EXTENSIONS = new Set([".md", ".mdx"]);

/**
 * List every content page under `dir`, as paths relative to `dir` using
 * forward slashes (so they double as the identity of a twin pair).
 * @param {string} dir
 * @returns {string[]}
 */
function listPages(dir) {
	/** @type {string[]} */
	const pages = [];
	/** @param {string} current */
	function walk(current) {
		let entries;
		try {
			entries = readdirSync(current, { withFileTypes: true });
		} catch {
			return; // Missing directory: reported by the caller as missing twins.
		}
		for (const entry of entries) {
			const absolute = path.join(current, entry.name);
			if (entry.isDirectory()) {
				walk(absolute);
			} else if (PAGE_EXTENSIONS.has(path.extname(entry.name))) {
				pages.push(path.relative(dir, absolute).split(path.sep).join("/"));
			}
		}
	}
	walk(dir);
	return pages.sort();
}

/**
 * Split a page into its raw frontmatter block and the body after it.
 * The frontmatter must open on the very first line, as Astro requires.
 * @param {string} source
 * @returns {{ frontmatter: string | null, body: string }}
 */
function splitFrontmatter(source) {
	const match = /^---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(
		source,
	);
	if (!match) return { frontmatter: null, body: source };
	return { frontmatter: match[1], body: source.slice(match[0].length) };
}

/**
 * Read the *shape* of a frontmatter block: the key paths it declares, e.g.
 * `hero`, `hero.image.light`, `head[].attrs.type`, plus how many entries each
 * sequence holds. Values are never looked at — they are the translation.
 *
 * Sequence indices collapse to `[]` so entries of one list contribute one set
 * of key paths regardless of order; the separate entry counts are what catch a
 * list that lost a member (a hero action translated away, say) while every key
 * it used still appears in the surviving entries. Block scalar bodies
 * (`content: |`, used for the JSON-LD islands) are skipped wholesale — their
 * contents are payload, not YAML, and a naive scan would read the embedded
 * JSON as more keys.
 * @param {string} frontmatter
 * @returns {{ keys: Set<string>, counts: Map<string, number> }}
 */
function frontmatterShape(frontmatter) {
	/** @type {Set<string>} */
	const keys = new Set();
	/** Entries per sequence, by the path of the key holding it. */
	/** @type {Map<string, number>} */
	const counts = new Map();
	// One frame per indentation level, outermost first. `prefix` is what every
	// key at that level is qualified with; `lastKey` is the key a deeper level
	// will nest under. The sentinel frame stands for the document itself.
	/** @type {{ indent: number, prefix: string, lastKey: string }[]} */
	const stack = [{ indent: -1, prefix: "", lastKey: "" }];
	/** Indent of the key introducing the block scalar we're inside, if any. */
	let blockScalarIndent = null;

	for (const line of frontmatter.split(/\r?\n/)) {
		if (line.trim() === "") continue;
		const indent = line.length - line.trimStart().length;

		// Everything more indented than the `key: |` line is opaque payload.
		if (blockScalarIndent !== null) {
			if (indent > blockScalarIndent) continue;
			blockScalarIndent = null;
		}
		if (line.trimStart().startsWith("#")) continue;

		// `- ` may prefix the first key of a sequence entry (`- tag: script`).
		const item = /^[ \t]*(-[ \t]+)?(.*)$/.exec(line);
		const isSequenceItem = Boolean(item[1]);
		const rest = item[2];
		// The key's own column is what nesting is measured against, so the keys
		// of a `- ` entry sit at the same level as its later, unprefixed keys.
		const keyIndent = isSequenceItem ? indent + item[1].length : indent;

		const keyMatch = /^([^\s:#][^:]*):(?:[ \t]|$)/.exec(rest);
		if (!keyMatch) continue;

		while (stack.length > 1 && stack[stack.length - 1].indent > keyIndent) {
			stack.pop();
		}
		let frame = stack[stack.length - 1];
		if (frame.indent < keyIndent) {
			// First key of a deeper level: it nests under the last key seen at the
			// enclosing level, and `[]` records that that key held a list.
			const parent = frame.lastKey;
			const prefix = parent ? `${parent}${isSequenceItem ? "[]" : ""}.` : "";
			frame = { indent: keyIndent, prefix, lastKey: "" };
			stack.push(frame);
		}
		const keyPath = `${frame.prefix}${keyMatch[1].trim()}`;
		keys.add(keyPath);
		frame.lastKey = keyPath;

		// Each `- ` line opens one entry of the sequence this level belongs to.
		// (Sequences of bare scalars carry no keys and so are not counted.)
		if (isSequenceItem && frame.prefix.endsWith("[].")) {
			const sequence = frame.prefix.slice(0, -3);
			counts.set(sequence, (counts.get(sequence) ?? 0) + 1);
		}

		if (/:[ \t]*[|>][+-]?\d*[ \t]*$/.test(rest)) blockScalarIndent = keyIndent;
	}
	return { keys, counts };
}

/**
 * Collect the sequence of markdown heading levels in a page body, e.g.
 * `[2, 3, 3, 2]`. Heading text is ignored — it is translated by definition;
 * the shape of the outline is what has to match.
 * @param {string} body
 * @returns {{ levels: number[], unclosedFence: boolean }}
 */
function headingLevels(body) {
	/** @type {number[]} */
	const levels = [];
	/** Open fence as {char, length}, or null outside a code block. */
	let fence = null;
	// Headings inside an HTML comment are not headings. Tracked separately from
	// fences because a comment can open and close on the same line.
	let inComment = false;

	for (const line of body.split(/\r?\n/)) {
		if (inComment) {
			if (line.includes("-->")) inComment = false;
			continue;
		}
		// Up to three leading spaces still count, per CommonMark; four or more
		// make it an indented code block instead.
		const fenceMatch = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(line);
		if (fence === null) {
			if (fenceMatch) {
				fence = { char: fenceMatch[1][0], length: fenceMatch[1].length };
				continue;
			}
		} else {
			// A closing fence is the same character, at least as long, and bare —
			// a longer run with an info string is just content inside the block.
			const closes =
				fenceMatch !== null &&
				fenceMatch[1][0] === fence.char &&
				fenceMatch[1].length >= fence.length &&
				fenceMatch[2].trim() === "";
			if (closes) fence = null;
			continue; // Never read headings out of a code block.
		}

		// An `<!--` with no `-->` on the same line opens a comment span.
		if (/<!--/.test(line) && !/-->/.test(line.slice(line.indexOf("<!--")))) {
			inComment = true;
			continue;
		}

		const heading = /^ {0,3}(#{1,6})(?:[ \t]|$)/.exec(line);
		if (heading) levels.push(heading[1].length);
	}
	// A fence left open at EOF silently swallows every heading after it, so the
	// outline this returns is not trustworthy — the caller fails the page instead.
	return { levels, unclosedFence: fence !== null };
}

/**
 * @param {string} relativePath page path relative to DOCS_DIR
 * @returns {{ keys: Set<string>, counts: Map<string, number>, levels: number[] }}
 */
function readPage(relativePath) {
	const source = readFileSync(path.join(DOCS_DIR, relativePath), "utf8");
	const { frontmatter, body } = splitFrontmatter(source);
	const shape =
		frontmatter === null
			? { keys: new Set(), counts: new Map() }
			: frontmatterShape(frontmatter);
	return { ...shape, ...headingLevels(body) };
}

/** @param {Set<string>} a @param {Set<string>} b @returns {string[]} */
function missingFrom(a, b) {
	return [...a].filter((key) => !b.has(key)).sort();
}
const englishPages = listPages(DOCS_DIR).filter(
	(page) => !LOCALES.some((locale) => page.startsWith(`${locale}/`)),
);

// A gate that reports success on an empty corpus is worse than no gate: a path
// drift, a partial checkout or a wrong cwd would turn it permanently green.
// listPages swallows a missing directory by design (a missing locale is a
// finding, not a crash), so the floor has to be asserted here.
if (englishPages.length === 0) {
	console.error(
		`✗ i18n parity: no pages found under ${DOCS_DIR} — nothing was compared.`,
	);
	console.error(
		"  Check the path and the working directory; this is not a pass.",
	);
	process.exit(1);
}

/** @type {string[]} */ const missingTranslations = [];
/** @type {string[]} */ const orphanTranslations = [];
/** @type {string[]} */ const frontmatterMismatches = [];
/** @type {string[]} */ const headingMismatches = [];
/** @type {string[]} */ const unreadableOutlines = [];

const englishSet = new Set(englishPages);
/** @type {Map<string, ReturnType<typeof readPage>>} */
const englishCache = new Map();

/** @param {string} relativePath @returns {ReturnType<typeof readPage>} */
function readEnglish(relativePath) {
	let page = englishCache.get(relativePath);
	if (page === undefined) {
		page = readPage(relativePath);
		englishCache.set(relativePath, page);
	}
	return page;
}

let twinCount = 0;

for (const locale of LOCALES) {
	const localePages = listPages(path.join(DOCS_DIR, locale));
	const localeSet = new Set(localePages);
	twinCount += localePages.length;

	for (const page of englishPages) {
		if (!localeSet.has(page)) {
			missingTranslations.push(`${locale}/${page}`);
			continue;
		}

		const english = readEnglish(page);
		const translated = readPage(`${locale}/${page}`);

		// An unclosed fence hides every heading after it, so the outline compared
		// below would be meaningless — and two pages can agree on a truncated
		// outline while differing after the fence. Fail the page instead.
		if (english.unclosedFence) {
			unreadableOutlines.push(`${page} — unclosed code fence`);
		}
		if (translated.unclosedFence) {
			unreadableOutlines.push(`${locale}/${page} — unclosed code fence`);
		}

		const onlyEnglish = missingFrom(english.keys, translated.keys);
		const onlyTranslated = missingFrom(translated.keys, english.keys);
		const details = [];
		if (onlyEnglish.length > 0) {
			details.push(`missing in ${locale}: ${onlyEnglish.join(", ")}`);
		}
		if (onlyTranslated.length > 0) {
			details.push(`extra in ${locale}: ${onlyTranslated.join(", ")}`);
		}
		for (const sequence of [
			...new Set([...english.counts.keys(), ...translated.counts.keys()]),
		].sort()) {
			const inEnglish = english.counts.get(sequence) ?? 0;
			const inTranslated = translated.counts.get(sequence) ?? 0;
			if (inEnglish !== inTranslated) {
				details.push(
					`${sequence}: ${inEnglish} entries in en, ${inTranslated} in ${locale}`,
				);
			}
		}
		if (details.length > 0) {
			frontmatterMismatches.push(`${locale}/${page} — ${details.join("; ")}`);
		}

		if (english.levels.join(",") !== translated.levels.join(",")) {
			headingMismatches.push(
				`${page} — en: [${english.levels.join(" ")}] (${english.levels.length} headings)\n` +
					`${" ".repeat(4)}${locale}: [${translated.levels.join(" ")}] (${translated.levels.length} headings)`,
			);
		}
	}

	for (const page of localePages) {
		if (!englishSet.has(page)) orphanTranslations.push(`${locale}/${page}`);
	}
}

/** @param {string} heading @param {string[]} entries @param {string} hint */
function report(heading, entries, hint) {
	if (entries.length === 0) return;
	console.error(`\n✗ ${heading} (${entries.length})`);
	console.error(`  ${hint}`);
	for (const entry of entries) console.error(`    • ${entry}`);
}

report(
	"Translated pages missing",
	missingTranslations,
	"Add the matching page under src/content/docs/<locale>/.",
);
report(
	"Translated pages whose English source is gone",
	orphanTranslations,
	"Delete the orphan, or restore the English page.",
);
report(
	"Frontmatter key mismatches",
	frontmatterMismatches,
	"Both twins must declare the same keys; only the values are translated.",
);
report(
	"Heading structure mismatches",
	headingMismatches,
	"The sequence of heading levels must match — a difference means a section was dropped, added or re-nested.",
);
report(
	"Outlines that could not be read",
	unreadableOutlines,
	"A code fence is never closed, so every heading after it is invisible to this check.",
);

const failures =
	missingTranslations.length +
	orphanTranslations.length +
	frontmatterMismatches.length +
	headingMismatches.length +
	unreadableOutlines.length;

if (failures > 0) {
	console.error(
		`\n✗ i18n parity: ${failures} problem(s) across ${englishPages.length} English pages.`,
	);
	process.exit(1);
}

// Deliberately states the scope. This gate compares page set, frontmatter key
// shape and heading outline — NOT body prose, table rows or code blocks. A
// stale translation of a paragraph whose English changed passes here, and it is
// meant to: catching that needs per-string provenance, not a structural diff.
console.log(
	`✓ i18n parity: ${englishPages.length} English pages, ${twinCount} twin(s) across ${LOCALES.join(", ")} — ` +
		"page set, frontmatter keys and heading outline match (structure only; body text is not compared).",
);
