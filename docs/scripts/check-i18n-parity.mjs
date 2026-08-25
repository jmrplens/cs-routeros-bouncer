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
 *      entries in each list — mappings and bare scalars alike (values are
 *      expected to differ — that is the translation);
 *   3. both twins have the same sequence of heading levels, ATX (`## x`) and
 *      setext (`x` over `---`) alike, so a missing or extra section shows up
 *      even though the heading text is translated.
 *
 * Deliberately dependency-free: the frontmatter reader below is a small
 * indentation-based scanner, not a YAML parser, because it only ever has to
 * recover key paths — never values. Flow style (`tags: [a, b]`) is the one
 * thing that subset cannot see into, so it is reported as an error rather than
 * silently mis-read; see frontmatterShape.
 *
 * Everything here is covered by the fixtures at the bottom, which run on every
 * invocation — the blind spots this gate has had were all invisible in the
 * corpus, so a regression reads as a pass unless something tests for it.
 *
 * Usage:
 *   node scripts/check-i18n-parity.mjs   # exit 0 when clean, 1 on any mismatch
 *   node scripts/check-i18n-parity.mjs --self-test   # fixtures only, no corpus
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

// HTML accepts BOTH `-->` and `--!>` as a comment terminator. Matching only the
// first leaves a comment closed with the second looking unterminated, which
// would swallow every heading after it — the same silent-truncation failure the
// unclosed-fence check exists to prevent. (CodeQL js/bad-tag-filter flags the
// one-form regex for exactly this reason.)
const COMMENT_END = /--!?>/;
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
 * it used still appears in the surviving entries. Entries that are bare scalars
 * (`- routeros`) carry no key at all, so their count is the *only* signal there
 * is — an untranslated tag dropped from a `tags:` list changes nothing else.
 * Block scalar bodies (`content: |`, used for the JSON-LD islands) are skipped
 * wholesale — their contents are payload, not YAML, and a naive scan would read
 * the embedded JSON as more keys.
 *
 * Flow style (`tags: [a, b]`, `sidebar: { order: 3 }`) is *reported*, never
 * parsed. An indentation scanner is blind inside a flow collection: it reports
 * `sidebar` and misses `sidebar.order`, and counts no entries for `tags`, so a
 * two-item flow list against a three-item block list passes clean. Teaching it
 * flow style means writing the YAML parser this file exists to avoid — quoting,
 * escapes, nesting, multi-line flow — to serve zero pages, since nothing in the
 * corpus uses it. Failing loudly costs one clear error the day someone writes
 * their first flow collection, and in exchange the blind spot cannot be entered
 * silently; guessing costs a gate that reports green while drifting.
 * @param {string} frontmatter
 * @returns {{ keys: Set<string>, counts: Map<string, number>, flow: string[] }}
 */
function frontmatterShape(frontmatter) {
	/** @type {Set<string>} */
	const keys = new Set();
	/** Entries per sequence, by the path of the key holding it. */
	/** @type {Map<string, number>} */
	const counts = new Map();
	/** Lines opening a flow collection, verbatim — reported, not parsed. */
	/** @type {string[]} */
	const flow = [];
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

		// A `[` or `{` where a value begins opens a flow collection. Checked here,
		// after the block scalar skip above, so the JSON-LD payloads — which are
		// full of both — stay invisible to it.
		if (keyMatch !== null || isSequenceItem) {
			const value = (
				keyMatch === null ? rest : rest.slice(keyMatch[0].length)
			).trimStart();
			if (value.startsWith("[") || value.startsWith("{"))
				flow.push(line.trim());
		}

		if (!keyMatch) {
			// A bare scalar entry (`- routeros`) has no key to record, but it still
			// occupies one slot of the sequence holding it, and losing one is exactly
			// what the counts exist to catch. Its owner is the key one level up —
			// unless it sits at the same level as mapping entries of the same list,
			// in which case that level's own `[]` prefix already names the sequence.
			if (isSequenceItem) {
				while (stack.length > 1 && stack[stack.length - 1].indent > keyIndent) {
					stack.pop();
				}
				const frame = stack[stack.length - 1];
				const sequence =
					frame.indent === keyIndent && frame.prefix.endsWith("[].")
						? frame.prefix.slice(0, -3)
						: frame.lastKey || "(document root)";
				counts.set(sequence, (counts.get(sequence) ?? 0) + 1);
			}
			continue;
		}

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
		// (Bare scalar entries are counted above, where the key match fails.)
		if (isSequenceItem && frame.prefix.endsWith("[].")) {
			const sequence = frame.prefix.slice(0, -3);
			counts.set(sequence, (counts.get(sequence) ?? 0) + 1);
		}

		if (/:[ \t]*[|>][+-]?\d*[ \t]*$/.test(rest)) blockScalarIndent = keyIndent;
	}
	return { keys, counts, flow };
}

/**
 * Whether a line is plain paragraph text — the only thing a setext underline is
 * allowed to underline. Everything a run of `-` could *also* be closing off is
 * excluded here, which is what keeps `---` after a list item, a JSX island, a
 * table row or a blank line from being read as a heading. Lines inside code
 * fences and HTML comments never reach this: the caller consumes them first.
 *
 * Deliberately conservative. Missing a setext heading costs a heading this gate
 * does not compare; inventing one costs a false failure on a page that is fine,
 * and `---` as a thematic break is common in this corpus (34 of them, every one
 * preceded by a blank line) while setext headings are currently unused.
 * @param {string} line
 * @returns {boolean}
 */
function isParagraphText(line) {
	const trimmed = line.trim();
	if (trimmed === "") return false; // Blank: nothing to underline.
	if (/^ {4,}/.test(line)) return false; // Indented code block.
	if (/^(=+|-+|\*{3,}|_{3,})$/.test(trimmed)) return false; // Rule/underline.
	if (/^([-*+]|\d{1,9}[.)])([ \t]|$)/.test(trimmed)) return false; // List item.
	if (/^#{1,6}([ \t]|$)/.test(trimmed)) return false; // ATX heading.
	if (/^[<:|>]/.test(trimmed)) return false; // JSX, ::: directive, table, quote.
	if (/^(import|export)[ \t]/.test(trimmed)) return false; // MDX statement.
	return true;
}

/**
 * Collect the sequence of markdown heading levels in a page body, e.g.
 * `[2, 3, 3, 2]`. Heading text is ignored — it is translated by definition;
 * the shape of the outline is what has to match.
 *
 * Both heading forms count: ATX (`## Section`) and setext (a line of text over
 * a rule of `=` for level 1 or `-` for level 2). Setext is rare, but a section
 * added in one language only is the whole point of this check, and "we only
 * looked at the `#` ones" is not a property anyone would guess from a pass.
 * @param {string} body
 * @returns {{ levels: number[], unterminated: string | null }}
 */
function headingLevels(body) {
	/** @type {number[]} */
	const levels = [];
	/** Open fence as {char, length}, or null outside a code block. */
	let fence = null;
	// Headings inside an HTML comment are not headings. Tracked separately from
	// fences because a comment can open and close on the same line.
	let inComment = false;
	// Whether the line just read was paragraph text a setext rule could underline.
	let underlinable = false;

	for (const line of body.split(/\r?\n/)) {
		if (inComment) {
			if (COMMENT_END.test(line)) inComment = false;
			underlinable = false;
			continue;
		}
		// Up to three leading spaces still count, per CommonMark; four or more
		// make it an indented code block instead.
		const fenceMatch = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(line);
		if (fence === null) {
			if (fenceMatch) {
				fence = { char: fenceMatch[1][0], length: fenceMatch[1].length };
				underlinable = false;
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
			underlinable = false;
			continue; // Never read headings out of a code block.
		}

		// An `<!--` not terminated on the same line opens a comment span.
		const commentStart = line.indexOf("<!--");
		if (
			commentStart !== -1 &&
			!COMMENT_END.test(line.slice(commentStart + 4))
		) {
			inComment = true;
			underlinable = false;
			continue;
		}

		// A setext underline: only a heading when it follows paragraph text —
		// otherwise the very same line is a thematic break or a list bullet.
		const underline = /^ {0,3}(=+|-+)[ \t]*$/.exec(line);
		if (underline !== null && underlinable) {
			levels.push(underline[1][0] === "=" ? 1 : 2);
			underlinable = false;
			continue;
		}

		const heading = /^ {0,3}(#{1,6})(?:[ \t]|$)/.exec(line);
		if (heading) levels.push(heading[1].length);
		underlinable = heading === null && isParagraphText(line);
	}
	// A fence — or a comment — left open at EOF silently swallows every heading
	// after it, so the outline this returns is not trustworthy. The caller fails
	// the page rather than comparing a truncated outline against another one.
	return {
		levels,
		unterminated:
			fence !== null ? "code fence" : inComment ? "HTML comment" : null,
	};
}

/**
 * @param {string} relativePath page path relative to DOCS_DIR
 * @returns {{ keys: Set<string>, counts: Map<string, number>, flow: string[], levels: number[], unterminated: string | null }}
 */
function readPage(relativePath) {
	const source = readFileSync(path.join(DOCS_DIR, relativePath), "utf8");
	const { frontmatter, body } = splitFrontmatter(source);
	const shape =
		frontmatter === null
			? { keys: new Set(), counts: new Map(), flow: [] }
			: frontmatterShape(frontmatter);
	return { ...shape, ...headingLevels(body) };
}

/** @param {Set<string>} a @param {Set<string>} b @returns {string[]} */
function missingFrom(a, b) {
	return [...a].filter((key) => !b.has(key)).sort();
}

// ---------------------------------------------------------------------------
// Fixtures.
//
// Every blind spot this checker has had was invisible in the corpus: no page
// uses flow style, a setext heading or a sequence of bare scalars, so a scanner
// that stops seeing one of them reports a pass rather than a failure, and the
// corpus run proves nothing about it. These fixtures are the only thing that
// does, so they run on every invocation instead of behind a flag no CI job
// calls — they cost a few microseconds and no I/O.
//
// They are inline strings rather than files on disk because several are
// deliberately malformed (an unclosed fence, flow-style YAML) and `prettier
// --check .`, which runs over this package, would reformat or reject them the
// moment they had a .md extension.
// ---------------------------------------------------------------------------

/** @param {boolean} ok @param {string} what */
function expect(ok, what) {
	if (!ok) throw new Error(what);
}

/** @param {string} source @returns {ReturnType<typeof frontmatterShape>} */
function shapeOf(source) {
	const { frontmatter } = splitFrontmatter(source);
	expect(frontmatter !== null, "fixture frontmatter did not parse");
	return frontmatterShape(frontmatter ?? "");
}

/** @param {string} source @returns {ReturnType<typeof headingLevels>} */
function outlineOf(source) {
	return headingLevels(splitFrontmatter(source).body);
}

/** @type {[string, () => void][]} */
const SELF_TESTS = [
	[
		"bare scalar sequence entries are counted",
		() => {
			const en = shapeOf(`---
title: T
tags:
  - one
  - two
  - three
---
`);
			const es = shapeOf(`---
title: T
tags:
  - uno
  - dos
---
`);
			expect(en.counts.get("tags") === 3, `en tags = ${en.counts.get("tags")}`);
			expect(es.counts.get("tags") === 2, `es tags = ${es.counts.get("tags")}`);
			expect(
				en.keys.has("tags") && es.keys.has("tags"),
				"tags key not recorded",
			);
		},
	],
	[
		"mapping sequence entries are still counted",
		() => {
			const shape = shapeOf(`---
title: T
hero:
  actions:
    - text: One
      link: /one/
    - text: Two
      link: /two/
---
`);
			expect(
				shape.counts.get("hero.actions") === 2,
				`hero.actions = ${shape.counts.get("hero.actions")}`,
			);
			expect(shape.keys.has("hero.actions[].link"), "nested key path lost");
		},
	],
	[
		"scalar entries nested in a mapping entry count against their own key",
		() => {
			const shape = shapeOf(`---
title: T
head:
  - tag: script
    keywords:
      - a
      - b
  - tag: meta
---
`);
			expect(
				shape.counts.get("head") === 2,
				`head = ${shape.counts.get("head")}`,
			);
			expect(
				shape.counts.get("head[].keywords") === 2,
				`head[].keywords = ${shape.counts.get("head[].keywords")}`,
			);
		},
	],
	[
		"block scalar payload stays opaque",
		() => {
			const shape = shapeOf(`---
title: T
head:
  - tag: script
    attrs:
      type: application/ld+json
    content: |
      {
        "@type": "FAQPage",
        "mainEntity": [{ "name": "x" }]
      }
---
`);
			expect(shape.flow.length === 0, `flow: ${shape.flow.join(" | ")}`);
			expect(shape.keys.has("head[].attrs.type"), "attrs.type lost");
			expect(!shape.keys.has("@type"), "JSON-LD payload read as YAML keys");
			expect(
				shape.counts.get("head") === 1,
				`head = ${shape.counts.get("head")}`,
			);
		},
	],
	[
		"flow-style values are reported",
		() => {
			const shape = shapeOf(`---
title: T
tags: [a, b, c]
sidebar: { order: 3 }
list:
  - [nested, flow]
---
`);
			expect(shape.flow.length === 3, `flow entries: ${shape.flow.length}`);
			expect(
				shape.flow[0] === "tags: [a, b, c]",
				`first flow line: ${shape.flow[0]}`,
			);
		},
	],
	[
		"block style with brackets in values is not reported as flow",
		() => {
			const shape = shapeOf(`---
title: "[WIP] Something"
description: "Fixes: (see [1])"
tags:
  - a
---
`);
			expect(shape.flow.length === 0, `flow: ${shape.flow.join(" | ")}`);
			expect(
				shape.counts.get("tags") === 1,
				`tags = ${shape.counts.get("tags")}`,
			);
		},
	],
	[
		"setext headings are recognised",
		() => {
			const outline = outlineOf(`---
title: T
---

Level one
=========

Body text.

Level two
---

## ATX two
`);
			expect(
				outline.levels.join(",") === "1,2,2",
				`levels: [${outline.levels.join(" ")}]`,
			);
		},
	],
	[
		"rules that are not setext underlines stay invisible",
		() => {
			const outline = outlineOf(`---
title: T
---

A paragraph followed by a thematic break.

---

- a list item
---

<Badge text="x" />
---

| a | b |
| - | - |

***

# ATX one
`);
			expect(
				outline.levels.join(",") === "1",
				`levels: [${outline.levels.join(" ")}]`,
			);
		},
	],
	[
		"code fences hide headings and an unclosed one is reported",
		() => {
			const closed = outlineOf(`---
title: T
---

## Real

\`\`\`yaml
# not a heading
Underlined
---
\`\`\`

### After
`);
			expect(
				closed.levels.join(",") === "2,3",
				`levels: [${closed.levels.join(" ")}]`,
			);
			expect(
				closed.unterminated === null,
				`unterminated: ${closed.unterminated}`,
			);

			const open = outlineOf(`---
title: T
---

## Real

\`\`\`text
never closed
`);
			expect(
				open.unterminated === "code fence",
				`unterminated: ${open.unterminated}`,
			);
		},
	],
	[
		"an HTML comment closed with --!> is closed",
		() => {
			const outline = outlineOf(`---
title: T
---

<!-- a note
## hidden
--!>

## Visible
`);
			expect(
				outline.levels.join(",") === "2",
				`levels: [${outline.levels.join(" ")}]`,
			);
			expect(
				outline.unterminated === null,
				`unterminated: ${outline.unterminated}`,
			);
		},
	],
];

/** @type {string[]} */
const selfTestFailures = [];
for (const [name, test] of SELF_TESTS) {
	try {
		test();
	} catch (error) {
		selfTestFailures.push(`${name} — ${error.message}`);
	}
}
if (selfTestFailures.length > 0) {
	console.error(
		`\n✗ i18n parity self-test (${selfTestFailures.length} failed)`,
	);
	console.error("  The checker is broken; the corpus was NOT compared.");
	for (const failure of selfTestFailures) console.error(`    • ${failure}`);
	process.exit(1);
}
if (process.argv.includes("--self-test")) {
	console.log(`✓ i18n parity self-test: ${SELF_TESTS.length} checks passed.`);
	process.exit(0);
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
/** @type {string[]} */ const unreadableFrontmatter = [];

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
		if (english.unterminated !== null) {
			unreadableOutlines.push(`${page} — unterminated ${english.unterminated}`);
		}
		if (translated.unterminated !== null) {
			unreadableOutlines.push(
				`${locale}/${page} — unterminated ${translated.unterminated}`,
			);
		}

		// Flow style is outside the subset frontmatterShape reads, so the key paths
		// and entry counts compared below would be wrong rather than merely
		// incomplete. Same reasoning as the unterminated fence above: report the
		// page, never compare a shape already known to be false.
		if (english.flow.length > 0) {
			unreadableFrontmatter.push(`${page} — ${english.flow.join(" / ")}`);
		}
		if (translated.flow.length > 0) {
			unreadableFrontmatter.push(
				`${locale}/${page} — ${translated.flow.join(" / ")}`,
			);
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
	"A code fence or HTML comment is never closed, so every heading after it is invisible to this check.",
);
report(
	"Frontmatter that could not be read",
	unreadableFrontmatter,
	"Flow-style YAML is not supported in frontmatter; use block style (one key or `- ` entry per line).",
);

const failures =
	missingTranslations.length +
	orphanTranslations.length +
	frontmatterMismatches.length +
	headingMismatches.length +
	unreadableOutlines.length +
	unreadableFrontmatter.length;

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
