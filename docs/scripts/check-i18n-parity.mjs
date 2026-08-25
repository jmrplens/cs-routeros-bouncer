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
 * This checks the four things that can be compared without reading prose:
 *   1. every English page has a Spanish twin, and vice versa;
 *   2. both twins declare the same frontmatter key paths, and the same number
 *      of entries in each sequence (values are expected to differ — that is
 *      the translation);
 *   3. both twins have the same sequence of heading levels, so a missing or
 *      extra section shows up even though the heading text is translated;
 *   4. both twins invoke the same components with the same identifying
 *      attributes — a heading can survive in both locales while the component
 *      that renders the section under it vanishes from one.
 *
 * ## Why this parses instead of scanning
 *
 * This file used to hand-parse markdown line by line. That approach produced
 * three defects in the same area, all of the same kind — a hand-written
 * recogniser disagreeing with the real grammar:
 *
 *   1. the HTML-comment terminator matched `-->` but not `--!>`;
 *   2. comment stripping was a chained `.replace()`, so `<!--<!-- x -->` left
 *      a bare `<!--` behind;
 *   3. code spans treated every backtick as a one-character delimiter, so a
 *      ``double-backtick`` span closed at the first tick and leaked.
 *
 * Three findings in one area say the approach was wrong, not that the patches
 * were bad. Everything structural now comes off the mdast tree produced by
 * `mdast-util-from-markdown` with the MDX extensions — the same parser stack
 * that renders this site.
 *
 * Nothing new was installed to do it. All four packages were already resolved
 * in this project's lockfile, so declaring them as direct devDependencies added
 * zero downloads (`pnpm install` reported `downloaded 0, added 0`); they are
 * pinned to exactly the versions already present so pnpm keeps linking those
 * same instances instead of resolving a second copy. Their provenance, per
 * `pnpm why`: `mdast-util-mdx` and `micromark-extension-mdxjs` via
 * `@astrojs/starlight` → `@astrojs/mdx` → `@mdx-js/mdx` → `remark-mdx`;
 * `mdast-util-from-markdown` via `@astrojs/markdown-remark` and Starlight's
 * remark plugins; `yaml` as a peer dependency of `astro` itself and via
 * `@astrojs/check`.
 *
 * The classes of bug above are gone by construction rather than by patch:
 *
 *   • a heading inside a fence, an HTML comment or an MDX `{/* … *\/}` comment
 *     is simply not a `heading` node, so it cannot be counted;
 *   • a component named inside an inline code span is text inside an
 *     `inlineCode` node, never an `mdxJsxFlowElement`, at any backtick-run
 *     length — the parser owns the delimiter rule, so #3 cannot recur;
 *   • nesting, quoting and escaping inside comments are the parser's problem,
 *     so #2 cannot recur;
 *   • setext headings, thematic breaks, indented code and MDX `import`
 *     statements are distinguished by the grammar, retiring the pile of
 *     conservative regexes that used to guess between them.
 *
 * Frontmatter is read with the `yaml` package's document AST rather than an
 * indentation scanner. Block scalars (`content: |`) are opaque for free — a
 * scalar is a leaf, so an embedded JSON-LD payload can never be mistaken for
 * more YAML keys — and malformed YAML is now reported instead of silently
 * mis-shaped.
 *
 * ## What still reads raw text, and why
 *
 * Two things, both deliberate:
 *
 *   • Splitting frontmatter from the body. The frontmatter mdast extensions
 *     are NOT in this project's dependency tree (unlike the four parser
 *     packages, they would be a genuinely new install), and the split is an
 *     anchored delimiter match, not a parse — it locates `---` fences and
 *     hands the text between them to the YAML parser, which does the parsing.
 *   • Deciding whether a fenced block or an HTML comment was ever closed. An
 *     unclosed construct is not an error in markdown: it runs to end of file
 *     and swallows every heading after it. The tree is correct, but the
 *     outline it yields is a truncation the author did not intend, so the
 *     node's own source range is re-read to see whether a closing delimiter is
 *     actually there. Positions come from the parser; only the delimiter test
 *     is textual.
 *
 * ## Scope
 *
 * Structure only. Body prose, table rows and code block contents are never
 * compared — a stale translation of a paragraph whose English changed passes
 * here, and is meant to: catching that needs per-string provenance.
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

import { fromMarkdown } from "mdast-util-from-markdown";
import { mdxFromMarkdown } from "mdast-util-mdx";
import { mdxjs } from "micromark-extension-mdxjs";
import { isMap, isSeq, parseDocument } from "yaml";

const DOCS_DIR = fileURLToPath(new URL("../src/content/docs", import.meta.url));
// Every mirror locale directly under DOCS_DIR. Anything NOT under one of these
// is treated as an English source page that must have a twin in each locale.
// Adding a locale here is the only change needed when astro.config.mjs grows one;
// leaving it out would classify the new locale's pages as untranslated English.
const LOCALES = ["es"];

const PAGE_EXTENSIONS = new Set([".md", ".mdx"]);

// Attributes that identify WHICH instance of a component this is. Anything else
// is presentation or prose and may legitimately differ per locale.
const IDENTIFYING_ATTRIBUTES = [
	"section",
	"path",
	"paths",
	"scope",
	"name",
	"id",
];

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
 *
 * Anchored delimiter match, not a parse: it finds the `---` fences and hands
 * everything between them to the YAML parser untouched.
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
 * Read the *shape* of a frontmatter block from the YAML document AST: the key
 * paths it declares, e.g. `hero`, `hero.image.light`, `head[].attrs.type`, plus
 * how many entries each sequence holds. Values are never looked at — they are
 * the translation.
 *
 * Sequence indices collapse to `[]` so entries of one list contribute one set
 * of key paths regardless of order; the separate entry counts are what catch a
 * list that lost a member (a hero action translated away, say) while every key
 * it used still appears in the surviving entries. Entries that are bare scalars
 * (`- routeros`) carry no key at all, so their count is the *only* signal there
 * is — an untranslated tag dropped from a `tags:` list changes nothing else.
 *
 * Scalars are leaves and are never descended into, so a block scalar body
 * (`content: |`, used for JSON-LD islands) is opaque for free: its embedded
 * JSON cannot be misread as further YAML keys.
 *
 * Flow style (`tags: [a, b]`, `sidebar: { order: 3 }`) is still reported as an
 * error, but the reason has changed and is worth stating honestly. The
 * indentation scanner this replaced was blind inside a flow collection, so
 * accepting one meant comparing a shape already known to be wrong. The YAML
 * parser reads flow style perfectly well — `node.flow` is an exact flag, and
 * the shape extracted from a flow collection is correct — so that hazard is
 * gone. What remains is a house convention: frontmatter in this corpus is
 * uniformly block style, and keeping it that way keeps per-key diffs
 * line-oriented for review. The check is retained deliberately, not because
 * the parser needs it; delete it and the gate stays correct.
 * @param {string} frontmatter
 * @returns {{ keys: Set<string>, counts: Map<string, number>, flow: string[], yamlErrors: string[] }}
 */
function frontmatterShape(frontmatter) {
	/** @type {Set<string>} */
	const keys = new Set();
	/** Entries per sequence, by the path of the key holding it. */
	/** @type {Map<string, number>} */
	const counts = new Map();
	/** Paths at which a flow collection was found — reported, not rejected by the parser. */
	/** @type {string[]} */
	const flow = [];

	const doc = parseDocument(frontmatter, { keepSourceTokens: false });
	const yamlErrors = doc.errors.map((error) => error.message.split("\n")[0]);
	if (yamlErrors.length > 0) return { keys, counts, flow, yamlErrors };

	/** @param {unknown} node @param {string} prefix */
	function walk(node, prefix) {
		if (isMap(node)) {
			if (node.flow) flow.push(prefix || "(document root)");
			for (const pair of node.items) {
				const name = String(pair.key?.value ?? "");
				const keyPath = prefix ? `${prefix}.${name}` : name;
				keys.add(keyPath);
				walk(pair.value, keyPath);
			}
		} else if (isSeq(node)) {
			const sequence = prefix || "(document root)";
			if (node.flow) flow.push(sequence);
			counts.set(sequence, node.items.length);
			// Every entry contributes its keys under the same `[]` prefix, so entry
			// order never matters; the count above is what notices a lost entry.
			for (const item of node.items) walk(item, `${prefix}[]`);
		}
		// Scalars (including block scalars) are leaves: nothing to record.
	}
	walk(doc.contents, "");
	return { keys, counts, flow, yamlErrors };
}

/**
 * Parse a page body into an mdast tree.
 *
 * `.mdx` gets the MDX extensions, `.md` does not — that mirrors how Astro
 * treats the two, and it matters: a `<Component />` in a plain `.md` file is
 * raw HTML, not an invocation, and counting it as one would report a mismatch
 * against a page that renders nothing.
 * @param {string} body
 * @param {string} extension
 * @returns {import("mdast").Root}
 */
function parseBody(body, extension) {
	return extension === ".mdx"
		? fromMarkdown(body, {
				extensions: [mdxjs()],
				mdastExtensions: [mdxFromMarkdown()],
			})
		: fromMarkdown(body);
}

/**
 * Walk every node of an mdast tree in document order.
 * @param {object} tree
 * @param {(node: any) => void} visit
 */
function walkTree(tree, visit) {
	/** @param {any} node */
	function step(node) {
		visit(node);
		if (Array.isArray(node.children))
			for (const child of node.children) step(child);
		// MDX attribute values can hold whole markdown trees in principle; they
		// hold expressions here, and expressions are not content. Not descended.
	}
	step(tree);
}

/**
 * Collect the sequence of heading levels in a page, e.g. `[2, 3, 3, 2]`.
 * Heading text is ignored — it is translated by definition; the shape of the
 * outline is what has to match.
 *
 * ATX (`## x`) and setext (`x` over `===`) are both `heading` nodes with a
 * `depth`, so both count without either being special-cased, and a thematic
 * break is a `thematicBreak` node rather than something that has to be told
 * apart from a setext underline by hand. Headings written inside a code fence
 * or a comment are not `heading` nodes at all, so they cannot leak in.
 * @param {object} tree
 * @returns {number[]}
 */
function headingLevels(tree) {
	/** @type {number[]} */
	const levels = [];
	walkTree(tree, (node) => {
		if (node.type === "heading") levels.push(node.depth);
	});
	return levels;
}

/**
 * Collect the MDX component invocations in a page, as a multiset keyed by
 * component name plus its identifying attribute.
 *
 * Heading outlines cannot see these. A page can keep its `## Frequently asked
 * questions` heading in both locales while one of them loses the
 * `<Home section="faq" />` underneath it — the outline still matches, every
 * gate stays green, and a whole section (here, a live rich-results surface)
 * silently disappears from that locale. The same holds for a dropped
 * `<ConfigOption path="…" />` or `<RuleSet scope="…" />`.
 *
 * Only the identifying attribute is compared, never free text: `title` and
 * friends are translated by definition.
 *
 * The tree does the hard parts. A component named inside inline code or inside
 * a comment is not a JSX node, so it is excluded without any stripping pass —
 * which is what retires the two sanitisation defects this file used to carry.
 * An invocation Prettier wrapped across several lines is one node, so line
 * layout cannot change the key either.
 * @param {object} tree
 * @returns {Map<string, number>}
 */
function componentCalls(tree) {
	/** @type {Map<string, number>} */
	const calls = new Map();
	walkTree(tree, (node) => {
		if (node.type !== "mdxJsxFlowElement" && node.type !== "mdxJsxTextElement")
			return;
		// A fragment (`<>`) has a null name and identifies nothing.
		if (typeof node.name !== "string") return;
		// MDX makes a node of every JSX element, raw HTML included, so the
		// capitalised-name convention is what still separates a component from
		// markup. `<details>` and `<summary>` are used as plain HTML in this
		// corpus, and counting `<br />` and friends would make prose-level layout
		// differences — which are allowed to differ per locale — fail this gate.
		if (!/^[A-Z]/.test(node.name)) return;
		let key = node.name;
		for (const attribute of IDENTIFYING_ATTRIBUTES) {
			const found = (node.attributes ?? []).find(
				(candidate) =>
					candidate.type === "mdxJsxAttribute" && candidate.name === attribute,
			);
			if (found === undefined) continue;
			// A literal value is a string. An expression (`path={slug}`) arrives as a
			// node carrying its own source, which is still a stable identity — the
			// old regex saw only quoted values and silently fell back to a bare name.
			// Whitespace inside an expression is collapsed so that the key does not
			// depend on how Prettier happened to wrap it — a translated sibling
			// attribute can change the line width and rewrap the expression in one
			// locale only, which must not read as a different instance.
			const value =
				typeof found.value === "string"
					? found.value
					: typeof found.value?.value === "string"
						? `{${found.value.value.replace(/\s+/g, " ").trim()}}`
						: null;
			if (value === null) continue; // Valueless attribute identifies nothing.
			key = `${node.name}[${attribute}=${value}]`;
			break;
		}
		calls.set(key, (calls.get(key) ?? 0) + 1);
	});
	return calls;
}

/**
 * Report a fenced code block or an HTML comment that is never closed.
 *
 * Markdown does not treat these as errors: an unclosed construct simply runs to
 * end of file, swallowing every heading and component after it. The tree is
 * therefore correct while the outline is a truncation the author did not mean,
 * and two pages can agree on a truncated outline while differing after it. The
 * caller fails such a page instead of comparing it.
 *
 * This is the one place that still reads source text, because "was a closing
 * delimiter written" is not a question the tree answers — the node's range is
 * the same either way. The range itself comes from the parser.
 *
 * Note on `--!>`: HTML accepts it as a comment terminator, CommonMark does not.
 * An HTML block ends only at a line containing `-->`, so a comment closed with
 * `--!>` really does swallow the rest of the document — verified against this
 * same parser. The old code asserted the opposite (its fixture claimed such a
 * comment was closed) and would have counted headings that do not render. It is
 * reported as unterminated here, which is what the renderer actually does.
 * @param {string} body
 * @param {object} tree
 * @returns {string | null}
 */
function unterminatedConstruct(body, tree) {
	/** @type {string | null} */
	let found = null;
	walkTree(tree, (node) => {
		if (found !== null || node.position === undefined) return;
		const raw = body.slice(
			node.position.start.offset,
			node.position.end.offset,
		);
		if (node.type === "code") {
			const lines = raw.split("\n");
			const opening = /^[ \t]*(`{3,}|~{3,})/.exec(lines[0]);
			if (opening === null) return; // Indented code block: nothing to close.
			const marker = opening[1][0];
			const closing = new RegExp(
				`^[ \\t]*\\${marker}{${opening[1].length},}[ \\t]*$`,
			);
			if (lines.length < 2 || !closing.test(lines[lines.length - 1])) {
				found = "code fence";
			}
		} else if (node.type === "html") {
			const opened = raw.lastIndexOf("<!--");
			if (opened !== -1 && !raw.slice(opened + 4).includes("-->")) {
				found = "HTML comment";
			}
		}
	});
	return found;
}

/**
 * @param {string} relativePath page path relative to DOCS_DIR
 * @returns {{ keys: Set<string>, counts: Map<string, number>, flow: string[], yamlErrors: string[], levels: number[], components: Map<string, number>, unterminated: string | null, parseError: string | null }}
 */
function readPage(relativePath) {
	const source = readFileSync(path.join(DOCS_DIR, relativePath), "utf8");
	const { frontmatter, body } = splitFrontmatter(source);
	const shape =
		frontmatter === null
			? { keys: new Set(), counts: new Map(), flow: [], yamlErrors: [] }
			: frontmatterShape(frontmatter);

	let tree;
	try {
		tree = parseBody(body, path.extname(relativePath));
	} catch (error) {
		// MDX is a real grammar and rejects invalid syntax — notably `<!-- -->`,
		// which MDX has no notion of. A page that does not parse cannot be
		// compared, and would not build either; report it rather than guess.
		const place = error.line === undefined ? "" : ` (line ${error.line})`;
		return {
			...shape,
			levels: [],
			components: new Map(),
			unterminated: null,
			parseError: `${error.reason ?? error.message}${place}`,
		};
	}

	return {
		...shape,
		levels: headingLevels(tree),
		components: componentCalls(tree),
		unterminated: unterminatedConstruct(body, tree),
		parseError: null,
	};
}

/** @param {Set<string>} a @param {Set<string>} b @returns {string[]} */
function missingFrom(a, b) {
	return [...a].filter((key) => !b.has(key)).sort();
}

// ---------------------------------------------------------------------------
// Fixtures.
//
// Every blind spot this checker has had was invisible in the corpus: no page
// uses flow style, a setext heading or a sequence of bare scalars, so a checker
// that stops seeing one of them reports a pass rather than a failure, and the
// corpus run proves nothing about it. These fixtures are the only thing that
// does, so they run on every invocation instead of behind a flag no CI job
// calls — they cost a few milliseconds and no I/O.
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

/** @param {string} source @param {string} [extension] */
function pageOf(source, extension = ".mdx") {
	const { body } = splitFrontmatter(source);
	const tree = parseBody(body, extension);
	return {
		levels: headingLevels(tree),
		components: componentCalls(tree),
		unterminated: unterminatedConstruct(body, tree),
	};
}

/** @param {string} source @param {string} [extension] @returns {string} */
function outlineOf(source, extension = ".mdx") {
	return pageOf(source, extension).levels.join(",");
}

/** @param {Map<string, number>} calls @returns {string} */
function callList(calls) {
	return [...calls]
		.map(([key, count]) => `${key}x${count}`)
		.sort()
		.join(" ");
}

/** @type {[string, () => void][]} */
const SELF_TESTS = [
	// -- frontmatter shape ---------------------------------------------------
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
		"flow-style collections are reported at their path",
		() => {
			const shape = shapeOf(`---
title: T
tags: [a, b, c]
sidebar: { order: 3 }
list:
  - [nested, flow]
---
`);
			expect(
				shape.flow.join(",") === "tags,sidebar,list[]",
				`flow: ${shape.flow.join(",")}`,
			);
			// Reported, but read correctly all the same — the parser is not blind
			// inside a flow collection the way the old scanner was.
			expect(shape.keys.has("sidebar.order"), "flow mapping key not read");
			expect(
				shape.counts.get("tags") === 3,
				`tags = ${shape.counts.get("tags")}`,
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
		"malformed YAML is reported rather than mis-shaped",
		() => {
			const shape = shapeOf(`---
title: T
hero:
   tagline: x
  actions: y
---
`);
			expect(shape.yamlErrors.length > 0, "bad YAML parsed clean");
		},
	],
	// -- heading outline -----------------------------------------------------
	[
		"setext and ATX headings are both counted",
		() => {
			const levels = outlineOf(`---
title: T
---

Level one
=========

Body text.

Level two
---

## ATX two
`);
			expect(levels === "1,2,2", `levels: [${levels}]`);
		},
	],
	[
		"rules that are not setext underlines stay invisible",
		() => {
			const levels = outlineOf(`---
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
			expect(levels === "1", `levels: [${levels}]`);
		},
	],
	[
		"headings inside a code fence are not counted",
		() => {
			const page = pageOf(`---
title: T
---

## Real

\`\`\`yaml
# not a heading
Underlined
---
<Home section="ghost" />
\`\`\`

### After
`);
			expect(page.levels.join(",") === "2,3", `levels: [${page.levels}]`);
			expect(page.unterminated === null, `unterminated: ${page.unterminated}`);
			expect(
				callList(page.components) === "",
				`components: ${callList(page.components)}`,
			);
		},
	],
	[
		"an unclosed code fence is reported",
		() => {
			const page = pageOf(`---
title: T
---

## Real

\`\`\`text
never closed
## swallowed
`);
			expect(
				page.unterminated === "code fence",
				`unterminated: ${page.unterminated}`,
			);
			expect(page.levels.join(",") === "2", `levels: [${page.levels}]`);
		},
	],
	[
		"a longer fence inside a block does not close it",
		() => {
			const page = pageOf(`---
title: T
---

\`\`\`\`md
\`\`\`
## inner
\`\`\`
\`\`\`\`

## After
`);
			expect(page.levels.join(",") === "2", `levels: [${page.levels}]`);
			expect(page.unterminated === null, `unterminated: ${page.unterminated}`);
		},
	],
	[
		"headings inside an MDX comment are not counted",
		() => {
			const page = pageOf(`---
title: T
---

{/* a note
## hidden
<Home section="ghost" />
*/}

## Visible
`);
			expect(page.levels.join(",") === "2", `levels: [${page.levels}]`);
			expect(
				callList(page.components) === "",
				`components: ${callList(page.components)}`,
			);
		},
	],
	[
		"headings inside an HTML comment are not counted (.md)",
		() => {
			const page = pageOf(
				`---
title: T
---

<!-- a note
## hidden
<Home section="ghost" />
-->

## Visible
`,
				".md",
			);
			expect(page.levels.join(",") === "2", `levels: [${page.levels}]`);
			expect(page.unterminated === null, `unterminated: ${page.unterminated}`);
		},
	],
	[
		"a nested HTML comment cannot leak a component (.md)",
		() => {
			// The old chained-.replace() stripper left a bare `<!--` behind here and
			// walked straight past the component. The parser has no such seam.
			const page = pageOf(
				`---
title: T
---

<!--<!-- x -->

## Visible
`,
				".md",
			);
			expect(
				callList(page.components) === "",
				`components: ${callList(page.components)}`,
			);
		},
	],
	[
		"an HTML comment closed only with --!> is reported, not trusted (.md)",
		() => {
			// CommonMark ends an HTML block at `-->` alone, so this really does
			// swallow the rest of the file; the old fixture claimed otherwise.
			const page = pageOf(
				`---
title: T
---

<!-- a note
## hidden
--!>

## Visible
`,
				".md",
			);
			expect(
				page.unterminated === "HTML comment",
				`unterminated: ${page.unterminated}`,
			);
			expect(page.levels.join(",") === "", `levels: [${page.levels}]`);
		},
	],
	[
		"an HTML comment in MDX is a parse error, not a comment",
		() => {
			let threw = false;
			try {
				pageOf(`---
title: T
---

<!-- MDX has no HTML comments -->
`);
			} catch {
				threw = true;
			}
			expect(threw, "MDX accepted an HTML comment");
		},
	],
	// -- component invocations ----------------------------------------------
	[
		"components are keyed by their identifying attribute",
		() => {
			const page = pageOf(`---
title: T
---

<Home section="faq" />
<Home section="faq" />
<Home section="why" />
<ConfigOption path="mikrotik.address" />
<RuleSet scope="input" />
<Badge text="translated" />
`);
			expect(
				callList(page.components) ===
					"Badgex1 ConfigOption[path=mikrotik.address]x1 Home[section=faq]x2 Home[section=why]x1 RuleSet[scope=input]x1",
				`components: ${callList(page.components)}`,
			);
		},
	],
	[
		"an invocation wrapped across lines keys the same as a one-liner",
		() => {
			const wrapped = pageOf(`---
title: T
---

<ConfigOption
  path="mikrotik.address"
  title="A long translated title that made Prettier wrap this"
/>
`);
			const oneLine = pageOf(`---
title: T
---

<ConfigOption path="mikrotik.address" title="Corto" />
`);
			expect(
				callList(wrapped.components) === callList(oneLine.components),
				`${callList(wrapped.components)} vs ${callList(oneLine.components)}`,
			);
		},
	],
	[
		"a component named in inline code is not an invocation, at any tick count",
		() => {
			// Defect #3: a one-character delimiter closed a ``double-backtick`` span
			// at its first tick and leaked the rest of the line to the scan.
			const page = pageOf(`---
title: T
---

Use \`<Home section="ghost" />\` to render it.

Or \`\`<ConfigOption path="ghost" /> and a \` tick\`\` inline.

<Home section="real" />
`);
			expect(
				callList(page.components) === "Home[section=real]x1",
				`components: ${callList(page.components)}`,
			);
		},
	],
	[
		"nested and text-level components are both counted",
		() => {
			const page = pageOf(`---
title: T
---

<Tabs>
  <TabItem label="One">
    <ConfigOption path="a.b" />
  </TabItem>
</Tabs>

Heading with a badge <VersionBadge /> inline.
`);
			expect(
				callList(page.components) ===
					"ConfigOption[path=a.b]x1 TabItemx1 Tabsx1 VersionBadgex1",
				`components: ${callList(page.components)}`,
			);
		},
	],
	[
		"an expression-valued identifying attribute still keys the instance",
		() => {
			const page = pageOf(`---
title: T
---

<ConfigOption path={"a.b"} />
`);
			expect(
				callList(page.components) === `ConfigOption[path={"a.b"}]x1`,
				`components: ${callList(page.components)}`,
			);
		},
	],
	[
		"components in a plain .md page are markup, not invocations",
		() => {
			const page = pageOf(
				`---
title: T
---

<Home section="faq" />

## Visible
`,
				".md",
			);
			expect(
				callList(page.components) === "",
				`components: ${callList(page.components)}`,
			);
			expect(page.levels.join(",") === "2", `levels: [${page.levels}]`);
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
/** @type {string[]} */ const componentMismatches = [];
/** @type {string[]} */ const unreadableOutlines = [];
/** @type {string[]} */ const unreadableFrontmatter = [];
/** @type {string[]} */ const unparseablePages = [];

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

		// A page that does not parse has no outline and no components to compare.
		// Reported once, here; the structural comparisons below are then skipped so
		// a parse failure does not also masquerade as "every heading disappeared".
		if (english.parseError !== null) {
			unparseablePages.push(`${page} — ${english.parseError}`);
		}
		if (translated.parseError !== null) {
			unparseablePages.push(`${locale}/${page} — ${translated.parseError}`);
		}
		const bodiesComparable =
			english.parseError === null && translated.parseError === null;

		// An unclosed fence or comment hides every heading after it, so the outline
		// compared below would be a truncation — and two pages can agree on a
		// truncated outline while differing after it. Fail the page instead.
		if (english.unterminated !== null) {
			unreadableOutlines.push(`${page} — unterminated ${english.unterminated}`);
		}
		if (translated.unterminated !== null) {
			unreadableOutlines.push(
				`${locale}/${page} — unterminated ${translated.unterminated}`,
			);
		}

		// Malformed YAML yields no shape at all; flow style yields a correct shape
		// that this project has decided not to accept. Both are reported rather
		// than compared, so neither can turn into a confusing key-path diff.
		for (const [label, shape] of [
			[page, english],
			[`${locale}/${page}`, translated],
		]) {
			if (shape.yamlErrors.length > 0) {
				unreadableFrontmatter.push(`${label} — ${shape.yamlErrors.join("; ")}`);
			}
			if (shape.flow.length > 0) {
				unreadableFrontmatter.push(
					`${label} — flow style at: ${shape.flow.join(", ")}`,
				);
			}
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

		if (!bodiesComparable) continue;

		// A component invocation present in one locale and not the other drops a
		// whole rendered section while the heading above it survives.
		const componentKeys = [
			...new Set([
				...english.components.keys(),
				...translated.components.keys(),
			]),
		].sort();
		const componentDiff = [];
		for (const key of componentKeys) {
			const inEnglish = english.components.get(key) ?? 0;
			const inTranslated = translated.components.get(key) ?? 0;
			if (inEnglish !== inTranslated) {
				componentDiff.push(
					`${key}: ${inEnglish} in en, ${inTranslated} in ${locale}`,
				);
			}
		}
		if (componentDiff.length > 0) {
			componentMismatches.push(`${page} — ${componentDiff.join("; ")}`);
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
	"Component invocation mismatches",
	componentMismatches,
	"A component rendered in one locale and not the other drops a whole section while its heading survives.",
);
report(
	"Pages that could not be parsed",
	unparseablePages,
	"The page is not valid MDX, so it has no structure to compare (and would not build).",
);
report(
	"Outlines that could not be read",
	unreadableOutlines,
	"A code fence or HTML comment is never closed, so every heading after it is invisible to this check.",
);
report(
	"Frontmatter that could not be read",
	unreadableFrontmatter,
	"Frontmatter must be valid YAML in block style (one key or `- ` entry per line).",
);

const failures =
	missingTranslations.length +
	orphanTranslations.length +
	frontmatterMismatches.length +
	headingMismatches.length +
	componentMismatches.length +
	unparseablePages.length +
	unreadableOutlines.length +
	unreadableFrontmatter.length;

if (failures > 0) {
	console.error(
		`\n✗ i18n parity: ${failures} problem(s) across ${englishPages.length} English pages.`,
	);
	process.exit(1);
}

// Deliberately states the scope. This gate compares page set, frontmatter key
// shape, heading outline and component invocations — NOT body prose, table rows
// or code block contents. A stale translation of a paragraph whose English
// changed passes here, and it is meant to: catching that needs per-string
// provenance, not a structural diff.
console.log(
	`✓ i18n parity: ${englishPages.length} English pages, ${twinCount} twin(s) across ${LOCALES.join(", ")} — ` +
		"page set, frontmatter keys, heading outline and component invocations match (structure only; body prose is not compared).",
);
