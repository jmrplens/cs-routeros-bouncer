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
 * Plus one thing that is not a comparison at all: a component tag written in a
 * `.md` page is a hard error (5). `.md` is markdown, not MDX, so Astro emits
 * the tag as raw HTML and it renders nothing. It therefore cannot be counted as
 * an invocation, and the gate used to ignore it — which meant a `.md` page
 * could lose a whole section on both sides and stay green. Every page in this
 * corpus is `.mdx` today, so that was latent, and latent is exactly how the
 * three defects listed below got in.
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
 * MDX expressions are not mdast, and are not read as text either. An attribute
 * value (`paths={[…]}`) and a body expression (`{list.map(…)}`) each carry the
 * ESTree acorn produced for them, so a component nested inside one is found by
 * walking that tree, and the identity of an expression-valued attribute is
 * derived from it. Both used to be text: the key was the expression's source
 * with whitespace runs collapsed, which claimed to be layout-independent and
 * was not — Prettier adds a trailing comma when it breaks a literal, so one
 * invocation could key two ways; and collapsing ate whitespace *inside* string
 * literals, so two different instances could key the same. A tree has neither
 * problem, because a line break and a trailing comma are not nodes and the
 * contents of a string literal are.
 *
 * ## What still reads raw text, and why
 *
 * Three things, all deliberate:
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
 *   • Blanking HTML comments inside an `html` node when scanning a `.md` page
 *     for stray component tags. Markdown has no comment node, so a comment
 *     inside a larger html block is part of that block's text. It is a single
 *     non-greedy pass over one node's own value — not the chained `.replace()`
 *     of defect #2 — and it errs towards silence: an unclosed `<!--` blanks to
 *     the end of the node, and is separately a hard error anyway.
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
 * raw HTML, not an invocation. It renders as an unknown element (i.e. as
 * nothing), so counting it as an invocation would compare a section that does
 * not exist. `strayComponentTags` fails such a page outright instead; see there.
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
 *
 * This walks mdast only. Everything an MDX expression holds — an attribute
 * value, a `{…}` block in the body — is an ESTree, not mdast, and is reached
 * through `walkEstree` from the one visitor that needs it (`componentCalls`).
 * Heading outlines deliberately do not follow expressions: a heading cannot be
 * written inside one.
 * @param {object} tree
 * @param {(node: any) => void} visit
 */
function walkTree(tree, visit) {
	/** @param {any} node */
	function step(node) {
		visit(node);
		if (Array.isArray(node.children))
			for (const child of node.children) step(child);
	}
	step(tree);
}

// Properties of an ESTree node that carry source position or attached comments
// rather than program structure. Skipped when walking and when canonicalising,
// which is what makes both formatting-independent.
const ESTREE_NOISE = new Set([
	"start",
	"end",
	"loc",
	"range",
	"comments",
	"leadingComments",
	"trailingComments",
]);

/**
 * Walk every node of an ESTree in document order, following arrays and nested
 * objects generically so no node type has to be enumerated.
 * @param {unknown} node
 * @param {(node: any) => void} visit
 */
function walkEstree(node, visit) {
	if (Array.isArray(node)) {
		for (const item of node) walkEstree(item, visit);
		return;
	}
	if (node === null || typeof node !== "object") return;
	/** @type {any} */
	const record = node;
	if (typeof record.type === "string") visit(record);
	for (const [key, value] of Object.entries(record)) {
		if (ESTREE_NOISE.has(key)) continue;
		walkEstree(value, visit);
	}
}

/**
 * Render an ESTree `Literal` back to a canonical form.
 * String values are re-quoted from the parsed value, never from `raw`, so quote
 * style and escape spelling cannot change the key; the characters inside the
 * string are preserved exactly, because those are meaning, not formatting.
 * @param {any} node
 * @returns {string}
 */
function canonicalLiteral(node) {
	if (node.regex !== undefined && node.regex !== null) {
		return `/${node.regex.pattern}/${node.regex.flags}`;
	}
	if (node.bigint !== undefined && node.bigint !== null)
		return `${node.bigint}n`;
	return typeof node.value === "string"
		? JSON.stringify(node.value)
		: String(node.value);
}

/**
 * Canonical, formatting-independent rendering of an ESTree expression.
 *
 * This is the identity of an expression-valued attribute. It is taken from the
 * *tree*, never from the source text, and that is the whole point: the tree is
 * what Prettier is not allowed to change, whereas the source text is exactly
 * what Prettier does change.
 *
 * The previous version collapsed whitespace runs in the source text and claimed
 * that made the key wrap-independent. It did not, in either direction:
 *
 *   • it under-normalised. Prettier adds a trailing comma when it breaks a
 *     literal across lines, so `paths={["a", "b"]}` and the same attribute
 *     wrapped yield `{["a", "b"]}` and `{[ "a", "b", ]}` — two keys for one
 *     invocation, and a parity failure with nothing behind it. Comments inside
 *     the expression survived into the key for the same reason.
 *   • it over-normalised. Whitespace inside a string literal is not formatting,
 *     it is the value: `path={"a  b"}` and `path={"a b"}` are different
 *     instances and collapsed to the same key, so a real divergence passed.
 *
 * Both are gone here because a trailing comma, a line break and a comment are
 * not nodes, while the contents of a string literal are.
 *
 * Node types that carry an expression are spelled out so the key stays readable
 * in a failure report (`ConfigOption[paths={["a.b","c.d"]}]`). Anything else falls
 * through to a generic structural rendering rather than to a guess — unusual
 * syntax gets an ugly key, never a wrong or a formatting-dependent one.
 * @param {any} node
 * @returns {string}
 */
function canonicalExpression(node) {
	if (node === null || node === undefined) return "";
	switch (node.type) {
		case "Program": {
			const statement = node.body.find(
				(/** @type {any} */ entry) => entry.type === "ExpressionStatement",
			);
			return statement === undefined
				? canonicalUnknown(node)
				: canonicalExpression(statement.expression);
		}
		case "ExpressionStatement":
			return canonicalExpression(node.expression);
		// Parentheses and optional-chain wrappers are punctuation, not meaning.
		case "ParenthesizedExpression":
		case "ChainExpression":
			return canonicalExpression(node.expression);
		case "Identifier":
		case "JSXIdentifier":
			return node.name;
		case "PrivateIdentifier":
			return `#${node.name}`;
		case "Literal":
			return canonicalLiteral(node);
		case "TemplateLiteral": {
			let out = "`";
			for (const [index, quasi] of node.quasis.entries()) {
				// `value.raw` is the text between the delimiters: significant, kept.
				out += quasi.value.raw;
				if (index < node.expressions.length) {
					out += `\${${canonicalExpression(node.expressions[index])}}`;
				}
			}
			return `${out}\``;
		}
		case "TaggedTemplateExpression":
			return `${canonicalExpression(node.tag)}${canonicalExpression(node.quasi)}`;
		case "MemberExpression":
			return node.computed
				? `${canonicalExpression(node.object)}${node.optional ? "?." : ""}[${canonicalExpression(node.property)}]`
				: `${canonicalExpression(node.object)}${node.optional ? "?." : "."}${canonicalExpression(node.property)}`;
		case "ArrayExpression":
			return `[${node.elements.map((/** @type {any} */ e) => canonicalExpression(e)).join(",")}]`;
		case "ObjectExpression":
			return `{${node.properties.map((/** @type {any} */ p) => canonicalExpression(p)).join(",")}}`;
		case "Property":
			return node.computed
				? `[${canonicalExpression(node.key)}]:${canonicalExpression(node.value)}`
				: `${canonicalExpression(node.key)}:${canonicalExpression(node.value)}`;
		case "SpreadElement":
		case "RestElement":
			return `...${canonicalExpression(node.argument)}`;
		case "CallExpression":
			return `${canonicalExpression(node.callee)}${node.optional ? "?." : ""}(${node.arguments.map((/** @type {any} */ a) => canonicalExpression(a)).join(",")})`;
		case "NewExpression":
			return `new ${canonicalExpression(node.callee)}(${node.arguments.map((/** @type {any} */ a) => canonicalExpression(a)).join(",")})`;
		case "UnaryExpression":
			return `${node.operator}${canonicalExpression(node.argument)}`;
		case "BinaryExpression":
		case "LogicalExpression":
			return `(${canonicalExpression(node.left)}${node.operator}${canonicalExpression(node.right)})`;
		case "ConditionalExpression":
			return `(${canonicalExpression(node.test)}?${canonicalExpression(node.consequent)}:${canonicalExpression(node.alternate)})`;
		case "SequenceExpression":
			return `(${node.expressions.map((/** @type {any} */ e) => canonicalExpression(e)).join(",")})`;
		case "JSXExpressionContainer":
			return `{${canonicalExpression(node.expression)}}`;
		case "JSXEmptyExpression":
			return "";
		default:
			return canonicalUnknown(node);
	}
}

/**
 * Structural rendering for an ESTree node this file does not spell out. Own
 * properties are sorted so the result cannot depend on property order, and the
 * position and comment fields are dropped so it cannot depend on layout.
 * @param {any} node
 * @returns {string}
 */
function canonicalUnknown(node) {
	const parts = Object.keys(node)
		.filter((key) => key !== "type" && !ESTREE_NOISE.has(key))
		.sort()
		.map((key) => `${key}=${canonicalValue(node[key])}`);
	return `${node.type}(${parts.join(",")})`;
}

/** @param {unknown} value @returns {string} */
function canonicalValue(value) {
	if (Array.isArray(value)) {
		return `[${value.map((item) => canonicalValue(item)).join(",")}]`;
	}
	if (typeof value === "bigint") return `${value}n`;
	if (value !== null && typeof value === "object") {
		/** @type {any} */
		const record = value;
		if (typeof record.type === "string") return canonicalExpression(record);
		return `{${Object.keys(record)
			.filter((key) => !ESTREE_NOISE.has(key))
			.sort()
			.map((key) => `${key}=${canonicalValue(record[key])}`)
			.join(",")}}`;
	}
	return String(JSON.stringify(value));
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
 *
 * Invocations inside MDX expressions are counted too, and key identically to
 * the same invocation written at the top level. Two places hold them:
 * `<Card body={<Home section="x" />} />`, where the component lives in an
 * attribute value, and `{list.map((x) => <Home section={x} />)}`, where it lives
 * in a body expression. Neither is mdast — both are ESTrees hanging off
 * `data.estree` — so both are reached with `walkEstree` rather than `walkTree`.
 * An MDX `{/* … *\/}` comment is an expression whose ESTree has an empty body,
 * so nothing inside one is reachable and nothing inside one is counted.
 * @param {object} tree
 * @returns {Map<string, number>}
 */
function componentCalls(tree) {
	/** @type {Map<string, number>} */
	const calls = new Map();
	/** @param {string} key */
	const record = (key) => calls.set(key, (calls.get(key) ?? 0) + 1);

	walkTree(tree, (node) => {
		if (
			node.type === "mdxFlowExpression" ||
			node.type === "mdxTextExpression" ||
			node.type === "mdxjsEsm"
		) {
			collectJsxCalls(node.data?.estree, record);
			return;
		}
		if (node.type !== "mdxJsxFlowElement" && node.type !== "mdxJsxTextElement")
			return;

		// Attribute values first: they are counted whatever the element itself is,
		// because `<div style={<Home />}>` is still a lost section.
		for (const attribute of node.attributes ?? []) {
			// `mdxJsxAttribute` holds its expression under `value.data`;
			// `mdxJsxExpressionAttribute` (`{...props}`) holds it under `data`.
			collectJsxCalls(attribute.value?.data?.estree, record);
			collectJsxCalls(attribute.data?.estree, record);
		}

		// A fragment (`<>`) has a null name and identifies nothing.
		if (typeof node.name !== "string") return;
		// MDX makes a node of every JSX element, raw HTML included, so the
		// capitalised-name convention is what still separates a component from
		// markup. `<details>` and `<summary>` are used as plain HTML in this
		// corpus, and counting `<br />` and friends would make prose-level layout
		// differences — which are allowed to differ per locale — fail this gate.
		if (!/^[A-Z]/.test(node.name)) return;
		record(
			componentKey(node.name, (attribute) =>
				mdastAttributeValue(node, attribute),
			),
		);
	});
	return calls;
}

/**
 * Count every capitalised JSX element inside an ESTree, at any depth: nested in
 * an attribute of another element, returned from a callback, inside a ternary.
 * `walkEstree` is generic, so no expression shape has to be anticipated.
 * @param {unknown} estree
 * @param {(key: string) => void} record
 */
function collectJsxCalls(estree, record) {
	if (estree === null || estree === undefined) return;
	walkEstree(estree, (node) => {
		if (node.type !== "JSXElement") return;
		const name = jsxElementName(node);
		if (name === null || !/^[A-Z]/.test(name)) return;
		record(
			componentKey(name, (attribute) => jsxAttributeValue(node, attribute)),
		);
	});
}

/**
 * The name of an ESTree `JSXElement`, or null for a shape that names nothing.
 * @param {any} node
 * @returns {string | null}
 */
function jsxElementName(node) {
	/** @param {any} name @returns {string | null} */
	function nameOf(name) {
		if (name === null || name === undefined) return null;
		if (name.type === "JSXIdentifier") return name.name;
		if (name.type === "JSXMemberExpression") {
			const object = nameOf(name.object);
			const property = nameOf(name.property);
			return object === null || property === null
				? null
				: `${object}.${property}`;
		}
		if (name.type === "JSXNamespacedName") {
			return `${name.namespace?.name}:${name.name?.name}`;
		}
		return null;
	}
	return nameOf(node.openingElement?.name);
}

/**
 * A marker for an identifying attribute written with no value at all.
 *
 * Distinct from `null`, which means the attribute is absent. Without the
 * distinction `<Aside note />` and `<Aside />` produce the same key, so a twin
 * that dropped the flag compares equal — the gate's job is to notice exactly
 * that kind of quiet divergence.
 */
const VALUELESS = Symbol("valueless");

/**
 * The bare string an expression denotes, when it denotes one and nothing else.
 *
 * `path="a.b"`, `path={"a.b"}` and ``path={`a.b`}`` are the same invocation
 * written three ways. Keying them apart makes the gate report a mismatch it
 * invented, which is worse than a miss: it trains the reader to distrust it.
 * Anything with moving parts — an identifier, a call, a template with a
 * substitution — is left to `canonicalExpression`, since those really can
 * differ between twins.
 * @param {any} node an ESTree node, or a Program wrapping one.
 * @returns {string | null}
 */
function stringLiteralValue(node) {
	if (node === null || node === undefined) return null;
	switch (node.type) {
		case "Program": {
			const statement = node.body?.find(
				(/** @type {any} */ entry) => entry.type === "ExpressionStatement",
			);
			return statement === undefined
				? null
				: stringLiteralValue(statement.expression);
		}
		case "ExpressionStatement":
			return stringLiteralValue(node.expression);
		case "ParenthesizedExpression":
			return stringLiteralValue(node.expression);
		case "Literal":
			return typeof node.value === "string" ? node.value : null;
		case "TemplateLiteral": {
			// Only a template with no substitutions is a fixed string.
			if (node.expressions?.length > 0) return null;
			const quasi = node.quasis?.[0];
			if (quasi === undefined) return null;
			return quasi.value?.cooked ?? quasi.value?.raw ?? null;
		}
		default:
			return null;
	}
}

/**
 * Build the key for one invocation: the component name, plus the first
 * identifying attribute it carries. Shared by the mdast and the ESTree side so
 * the *same* invocation keys the same wherever it was written — an attribute
 * expression counted differently from a top-level tag would be a mismatch this
 * gate invented.
 * @param {string} name
 * @param {(attribute: string) => string | symbol | null} valueOf
 * @returns {string}
 */
function componentKey(name, valueOf) {
	for (const attribute of IDENTIFYING_ATTRIBUTES) {
		const value = valueOf(attribute);
		if (value === null) continue; // Absent: identifies nothing.
		// A valueless attribute keys as `name[attr]`, which no valued attribute
		// can collide with — `name[attr=true]` would collide with the literal
		// string "true".
		if (value === VALUELESS) return `${name}[${attribute}]`;
		return `${name}[${attribute}=${value}]`;
	}
	return name;
}

/**
 * Read one identifying attribute off an mdast JSX element.
 * A literal value is a plain string. An expression (`path={slug}`) arrives as a
 * node carrying its own ESTree, canonicalised so the key is what the expression
 * *is* rather than how it was laid out.
 * @param {any} node
 * @param {string} attribute
 * @returns {string | symbol | null}
 */
function mdastAttributeValue(node, attribute) {
	const found = (node.attributes ?? []).find(
		(/** @type {any} */ candidate) =>
			candidate.type === "mdxJsxAttribute" && candidate.name === attribute,
	);
	if (found === undefined) return null;
	if (found.value === null || found.value === undefined) return VALUELESS;
	if (typeof found.value === "string") return found.value;
	const estree = found.value?.data?.estree;
	if (estree === null || estree === undefined) return null;
	const literal = stringLiteralValue(estree);
	if (literal !== null) return literal;
	return `{${canonicalExpression(estree)}}`;
}

/**
 * Read one identifying attribute off an ESTree `JSXElement`. A string literal
 * yields its bare value, exactly as the mdast side does, so the two agree.
 * @param {any} node
 * @param {string} attribute
 * @returns {string | symbol | null}
 */
function jsxAttributeValue(node, attribute) {
	const found = (node.openingElement?.attributes ?? []).find(
		(/** @type {any} */ candidate) =>
			candidate.type === "JSXAttribute" && candidate.name?.name === attribute,
	);
	if (found === undefined) return null;
	const value = found.value;
	if (value === null || value === undefined) return VALUELESS;
	if (value.type === "Literal") {
		return typeof value.value === "string"
			? value.value
			: canonicalLiteral(value);
	}
	if (value.type === "JSXExpressionContainer") {
		if (value.expression?.type === "JSXEmptyExpression") return null;
		const literal = stringLiteralValue(value.expression);
		if (literal !== null) return literal;
		return `{${canonicalExpression(value.expression)}}`;
	}
	return null;
}

/**
 * Report component-looking tags written in a plain `.md` page.
 *
 * A `.md` page is markdown, not MDX: Astro passes `<Home section="faq" />`
 * through as raw HTML, the browser makes an unknown element of it, and nothing
 * renders. So it cannot be counted as an invocation — but it must not be
 * ignored either, which is what this gate used to do. Every page in the corpus
 * is `.mdx` today, so a `.md` page carrying a component tag would have been
 * invisible on both sides: no component counted, no mismatch, green gate,
 * missing section. It is a hard error instead — the page is broken in that
 * locale whether or not its twin agrees.
 *
 * Only `html` nodes are looked at, so a tag inside a code fence, an indented
 * block or an inline code span is a `code`/`inlineCode` node and cannot reach
 * here — the parser owns those boundaries, as everywhere else in this file.
 *
 * What is textual is one thing: markdown has no comment node, so an HTML
 * comment *inside* an html block (`<div>` … `<!-- <Home /> -->` … `</div>`) is
 * part of that node's value. Comment spans are blanked with a single
 * non-greedy pass — not the chained `.replace()` that once left a bare `<!--`
 * behind — and an unclosed `<!--` blanks to end of node, which is conservative
 * (a component after it is not reported) and already a hard error by way of
 * `unterminatedConstruct`.
 * @param {object} tree
 * @returns {string[]}
 */
function strayComponentTags(tree) {
	/** @type {Set<string>} */
	const names = new Set();
	walkTree(tree, (node) => {
		if (node.type !== "html" || typeof node.value !== "string") return;
		const visible = node.value.replace(/<!--[\s\S]*?(?:-->|$)/g, " ");
		// JSX identifiers admit `-` (`<Foo-Bar />`), so leaving it out did not
		// miss the tag — it reported it as `Foo`, naming a component that does
		// not exist and sending the reader looking for it.
		for (const match of visible.matchAll(/<\/?([A-Z][A-Za-z0-9_.-]*)/g)) {
			names.add(match[1]);
		}
	});
	return [...names].sort();
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
 * @returns {{ keys: Set<string>, counts: Map<string, number>, flow: string[], yamlErrors: string[], levels: number[], components: Map<string, number>, strayComponents: string[], unterminated: string | null, parseError: string | null }}
 */
function readPage(relativePath) {
	const source = readFileSync(path.join(DOCS_DIR, relativePath), "utf8");
	const { frontmatter, body } = splitFrontmatter(source);
	const extension = path.extname(relativePath);
	const shape =
		frontmatter === null
			? { keys: new Set(), counts: new Map(), flow: [], yamlErrors: [] }
			: frontmatterShape(frontmatter);

	let tree;
	try {
		tree = parseBody(body, extension);
	} catch (error) {
		// MDX is a real grammar and rejects invalid syntax — notably `<!-- -->`,
		// which MDX has no notion of. A page that does not parse cannot be
		// compared, and would not build either; report it rather than guess.
		const place = error.line === undefined ? "" : ` (line ${error.line})`;
		return {
			...shape,
			levels: [],
			components: new Map(),
			strayComponents: [],
			unterminated: null,
			parseError: `${error.reason ?? error.message}${place}`,
		};
	}

	return {
		...shape,
		levels: headingLevels(tree),
		components: componentCalls(tree),
		// Only `.md` can carry one: in `.mdx` the same tag is a real invocation,
		// counted above.
		strayComponents: extension === ".md" ? strayComponentTags(tree) : [],
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
		strayComponents: extension === ".md" ? strayComponentTags(tree) : [],
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
		"a fixed string keys the same however it was written",
		() => {
			// `"a.b"`, `{"a.b"}` and a substitution-free template are one
			// invocation written three ways. Keying them apart made the gate
			// report a mismatch of its own making between twins that agreed.
			const page = pageOf(`---
title: T
---

<ConfigOption path="a.b" />
<ConfigOption path={"a.b"} />
<ConfigOption path={\`a.b\`} />
`);
			expect(
				callList(page.components) === `ConfigOption[path=a.b]x3`,
				`components: ${callList(page.components)}`,
			);
		},
	],
	[
		"an expression with moving parts still keys as an expression",
		() => {
			// The converse of the test above: these really can differ between
			// twins, so they must not collapse onto the identifier's name.
			const page = pageOf(`---
title: T
---

<ConfigOption path={slug} />
<ConfigOption path={\`a.\${slug}\`} />
`);
			expect(
				callList(page.components) ===
					"ConfigOption[path={`a.${slug}`}]x1 ConfigOption[path={slug}]x1",
				`components: ${callList(page.components)}`,
			);
		},
	],
	[
		"a valueless identifying attribute is not the same as an absent one",
		() => {
			// `<Home section />` and `<Home />` used to key identically, so a twin
			// that dropped the flag compared equal.
			const page = pageOf(`---
title: T
---

<Home section />
<Home />
`);
			expect(
				callList(page.components) === "Home[section]x1 Homex1",
				`components: ${callList(page.components)}`,
			);
		},
	],
	[
		"an expression key does not depend on how Prettier wrapped it",
		() => {
			// Prettier adds a trailing comma when it breaks a literal across lines.
			// Collapsing whitespace in the source text — what this used to do — left
			// that comma in the key, so one invocation keyed two ways and parity
			// failed with nothing behind it.
			const inline = pageOf(`---
title: T
---

<ConfigOption paths={["a.b", "c.d"]} title="Short" />
`);
			const broken = pageOf(`---
title: T
---

<ConfigOption
  paths={[
    "a.b",
    "c.d",
  ]}
  title="Un titulo traducido lo bastante largo como para partir la etiqueta"
/>
`);
			expect(
				callList(inline.components) === `ConfigOption[paths={["a.b","c.d"]}]x1`,
				`inline: ${callList(inline.components)}`,
			);
			expect(
				callList(inline.components) === callList(broken.components),
				`${callList(inline.components)} vs ${callList(broken.components)}`,
			);
		},
	],
	[
		"whitespace inside a string literal is meaning, not layout",
		() => {
			// The mirror of the case above: collapsing the source text merged two
			// genuinely different instances into one key, so a real divergence
			// between the locales passed silently.
			const wide = pageOf(`---
title: T
---

<ConfigOption path={"a  b"} />
`);
			const narrow = pageOf(`---
title: T
---

<ConfigOption path={"a b"} />
`);
			expect(
				callList(wide.components) !== callList(narrow.components),
				`both keyed as ${callList(wide.components)}`,
			);
		},
	],
	[
		"a comment inside an expression does not change the key",
		() => {
			const commented = pageOf(`---
title: T
---

<ConfigOption path={/* which one */ slug} />
`);
			const plain = pageOf(`---
title: T
---

<ConfigOption path={slug} />
`);
			expect(
				callList(commented.components) === "ConfigOption[path={slug}]x1",
				`components: ${callList(commented.components)}`,
			);
			expect(
				callList(commented.components) === callList(plain.components),
				`${callList(commented.components)} vs ${callList(plain.components)}`,
			);
		},
	],
	[
		"a component nested in an attribute expression is counted",
		() => {
			// The AST rewrite lost this: walkTree stopped at the mdast element and
			// never entered the attribute, so the page yielded `Card` alone and a
			// locale that dropped the nested invocation compared equal.
			const page = pageOf(`---
title: T
---

<Card body={<Home section="x" />} />
`);
			expect(
				callList(page.components) === "Cardx1 Home[section=x]x1",
				`components: ${callList(page.components)}`,
			);
		},
	],
	[
		"a nested invocation keys the same as the same tag written at top level",
		() => {
			const nested = pageOf(`---
title: T
---

<Card body={<Home section="faq" />} />
`);
			const top = pageOf(`---
title: T
---

<Home section="faq" />
`);
			expect(
				nested.components.get("Home[section=faq]") === 1,
				`nested: ${callList(nested.components)}`,
			);
			expect(
				top.components.get("Home[section=faq]") === 1,
				`top: ${callList(top.components)}`,
			);
		},
	],
	[
		"components nested several expressions deep are all counted",
		() => {
			const page = pageOf(`---
title: T
---

<Card body={<Wrapper slot={<Home section={"deep"} />} />} />
`);
			expect(
				callList(page.components) === "Cardx1 Home[section=deep]x1 Wrapperx1",
				`components: ${callList(page.components)}`,
			);
		},
	],
	[
		"components inside a body expression are counted",
		() => {
			const page = pageOf(`---
title: T
---

{sections.map((section) => (
  <Home section={section} />
))}

Inline {<VersionBadge />} too.
`);
			expect(
				callList(page.components) ===
					"Home[section={section}]x1 VersionBadgex1",
				`components: ${callList(page.components)}`,
			);
		},
	],
	[
		"lowercase tags nested in an expression stay excluded",
		() => {
			const page = pageOf(`---
title: T
---

<Card body={<span>x</span>} />
`);
			expect(
				callList(page.components) === "Cardx1",
				`components: ${callList(page.components)}`,
			);
		},
	],
	// -- component tags in a .md page ----------------------------------------
	[
		"components in a plain .md page are markup, and a hard error",
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
			// Not counted: a .md page really does render nothing here, so comparing
			// it as an invocation would compare a section that does not exist.
			expect(
				callList(page.components) === "",
				`components: ${callList(page.components)}`,
			);
			expect(
				page.strayComponents.join(",") === "Home",
				`stray: [${page.strayComponents}]`,
			);
			expect(page.levels.join(",") === "2", `levels: [${page.levels}]`);
		},
	],
	[
		"a hyphenated component keeps its whole name in the report",
		() => {
			// JSX identifiers admit `-`. Reported as `Foo` instead of `Foo-Bar`,
			// the message names a component that does not exist and the reader
			// greps for the wrong thing.
			const page = pageOf(
				`---
title: T
---

<Rule-Set scope="input" />
`,
				".md",
			);
			expect(
				page.strayComponents.join(",") === "Rule-Set",
				`stray: [${page.strayComponents}]`,
			);
		},
	],
	[
		"an inline component tag in a .md paragraph is caught too",
		() => {
			const page = pageOf(
				`---
title: T
---

Text with <VersionBadge /> in the middle of a sentence.
`,
				".md",
			);
			expect(
				page.strayComponents.join(",") === "VersionBadge",
				`stray: [${page.strayComponents}]`,
			);
		},
	],
	[
		"a closing tag alone still reports the component in a .md page",
		() => {
			const page = pageOf(
				`---
title: T
---

<Tabs>

text

</Tabs>
`,
				".md",
			);
			expect(
				page.strayComponents.join(",") === "Tabs",
				`stray: [${page.strayComponents}]`,
			);
		},
	],
	[
		"plain HTML in a .md page is not a stray component",
		() => {
			const page = pageOf(
				`---
title: T
---

<details>
<summary>x</summary>
</details>

Text with a <br /> in it.
`,
				".md",
			);
			expect(
				page.strayComponents.length === 0,
				`stray: [${page.strayComponents}]`,
			);
		},
	],
	[
		"a commented-out component in a .md page is not reported",
		() => {
			const page = pageOf(
				`---
title: T
---

<!-- <Home section="faq" /> -->

<div>
  <!-- <ConfigOption path="a.b" /> -->
</div>

## Visible
`,
				".md",
			);
			expect(
				page.strayComponents.length === 0,
				`stray: [${page.strayComponents}]`,
			);
			expect(page.unterminated === null, `unterminated: ${page.unterminated}`);
		},
	],
	[
		"a component beside a comment in the same .md html block is still caught",
		() => {
			const page = pageOf(
				`---
title: T
---

<div>
  <!-- a note -->
  <Home section="faq" />
</div>
`,
				".md",
			);
			expect(
				page.strayComponents.join(",") === "Home",
				`stray: [${page.strayComponents}]`,
			);
		},
	],
	[
		"a component in a .md code block or code span is not a stray tag",
		() => {
			const page = pageOf(
				`---
title: T
---

Use \`<Home section="ghost" />\` to render it.

\`\`\`mdx
<ConfigOption path="ghost" />
\`\`\`

    <RuleSet scope="ghost" />
`,
				".md",
			);
			expect(
				page.strayComponents.length === 0,
				`stray: [${page.strayComponents}]`,
			);
		},
	],
	[
		"a .mdx page never reports stray tags — they are real invocations there",
		() => {
			const page = pageOf(`---
title: T
---

<Home section="faq" />
`);
			expect(
				page.strayComponents.length === 0,
				`stray: [${page.strayComponents}]`,
			);
			expect(
				callList(page.components) === "Home[section=faq]x1",
				`components: ${callList(page.components)}`,
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
/** @type {string[]} */ const componentMismatches = [];
/** @type {string[]} */ const unreadableOutlines = [];
/** @type {string[]} */ const unreadableFrontmatter = [];
/** @type {string[]} */ const unparseablePages = [];
/** @type {string[]} */ const strayComponentPages = [];

const englishSet = new Set(englishPages);
/** @type {Map<string, ReturnType<typeof readPage>>} */
const pageCache = new Map();

/** @param {string} relativePath @returns {ReturnType<typeof readPage>} */
function read(relativePath) {
	let page = pageCache.get(relativePath);
	if (page === undefined) {
		page = readPage(relativePath);
		pageCache.set(relativePath, page);
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

		const english = read(page);
		const translated = read(`${locale}/${page}`);

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
		// that this project has decided not to accept. Both are reported here; the
		// first also suppresses the diff below, for the reason given there.
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

		// Only the YAML errors suppress the diff. `frontmatterShape` returns empty
		// keys and counts for malformed YAML, so comparing anyway reports every
		// key as missing on one side and extra on the other — a wall of noise
		// stacked on top of the parse error that actually explains it. Flow style
		// is different: it yields a correct shape this project simply declines to
		// accept, so those pages are still worth diffing.
		const frontmatterComparable =
			english.yamlErrors.length === 0 && translated.yamlErrors.length === 0;

		const onlyEnglish = frontmatterComparable
			? missingFrom(english.keys, translated.keys)
			: [];
		const onlyTranslated = frontmatterComparable
			? missingFrom(translated.keys, english.keys)
			: [];
		const details = [];
		if (onlyEnglish.length > 0) {
			details.push(`missing in ${locale}: ${onlyEnglish.join(", ")}`);
		}
		if (onlyTranslated.length > 0) {
			details.push(`extra in ${locale}: ${onlyTranslated.join(", ")}`);
		}
		const sequences = frontmatterComparable
			? [
					...new Set([...english.counts.keys(), ...translated.counts.keys()]),
				].sort()
			: [];
		for (const sequence of sequences) {
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

		// Only compare outlines that are trustworthy. An unterminated fence or
		// comment hides every heading after it, so the levels array is a
		// prefix of the real one — and two pages can agree on a truncated
		// prefix while differing after it, or disagree only because one side
		// truncated. Either way the comparison says nothing, and reporting it
		// on top of the unterminated-construct failure sends the reader
		// looking for a section that is not missing. The page already fails.
		const outlineIsReadable =
			english.unterminated === null && translated.unterminated === null;
		if (
			outlineIsReadable &&
			english.levels.join(",") !== translated.levels.join(",")
		) {
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

// A component tag in a `.md` page renders as nothing, so it is a defect in that
// one page rather than a disagreement between twins — nothing a comparison
// could ever surface. Checked over every page, twinned or not, so an
// untranslated page or an orphaned translation is still covered. `read` is
// cached, so the twins compared above are not parsed twice.
for (const page of [
	...englishPages,
	...LOCALES.flatMap((locale) =>
		listPages(path.join(DOCS_DIR, locale)).map((entry) => `${locale}/${entry}`),
	),
]) {
	const stray = read(page).strayComponents;
	if (stray.length > 0) {
		strayComponentPages.push(
			`${page} — ${stray.map((name) => `<${name}>`).join(", ")}`,
		);
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
	"Component tags in a .md page",
	strayComponentPages,
	"A .md page is markdown, not MDX: the tag is emitted as raw HTML and renders nothing. Rename the page to .mdx (and import the component), or remove the tag.",
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
	strayComponentPages.length +
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
		"page set, frontmatter keys, heading outline and component invocations match " +
		"(invocations counted inside MDX attribute and body expressions too; a component tag in a .md page is a hard error). " +
		"Structure only; body prose is not compared.",
);
