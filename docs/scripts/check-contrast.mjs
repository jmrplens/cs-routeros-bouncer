#!/usr/bin/env node
/**
 * Gates the colour contrast of the Starlight theme in `src/styles/`.
 *
 * The palette lives in `theme.css`, but the *pairs* it renders as are decided
 * by a mix of the project's own rules and Starlight's. Every pair below was
 * read out of one or the other and carries the citation in `where`; none of
 * them is a combination that never reaches the screen. Only the pairing is
 * hard-coded — the colours are always resolved from the sheets, so the gate
 * follows the palette when it moves.
 *
 * The sheets are not listed here: they are read out of the `customCss` array in
 * `astro.config.mjs`, in registration order, so the gate measures exactly what
 * Starlight loads and a sheet added there can never quietly escape it.
 *
 * Thresholds (WCAG 2.2 AA):
 *   4.5 : 1  normal text                                     — 1.4.3
 *   3   : 1  large text (>= 24px, or >= 18.66px bold)        — 1.4.3
 *   3   : 1  focus indicators and other UI state information — 1.4.11, 2.4.11
 *
 * Usage:
 *   node scripts/check-contrast.mjs   # report every pair, exit 1 on any FAIL
 */
import { readFileSync } from "node:fs";
import process from "node:process";

const CONFIG = new URL("../astro.config.mjs", import.meta.url);

/* ------------------------------------------------------------------
   1. STYLESHEET PARSING
   ------------------------------------------------------------------ */

/** Removes `/* … *\/` comments. The sheets have no comment-like string literals. */
function stripComments(text) {
	return text.replaceAll(/\/\*[\s\S]*?\*\//g, "");
}

/**
 * Splits a stylesheet into `{ selector, atRule, body }` blocks, descending into
 * at-rules. Blocks nested in an at-rule keep the condition they sit under, so
 * the palette can ignore them: `@media (prefers-contrast: more)` is an opt-in
 * override, not the cascade the site renders by default.
 */
function parseBlocks(text, atRule = null, out = []) {
	let index = 0;
	while (index < text.length) {
		const open = text.indexOf("{", index);
		if (open === -1) break;
		const prelude = text.slice(index, open).trim();
		let depth = 1;
		let cursor = open + 1;
		while (cursor < text.length && depth > 0) {
			if (text[cursor] === "{") depth += 1;
			else if (text[cursor] === "}") depth -= 1;
			cursor += 1;
		}
		const body = text.slice(open + 1, cursor - 1);
		if (prelude.startsWith("@")) parseBlocks(body, prelude, out);
		else out.push({ selector: prelude.replaceAll(/\s+/g, " "), atRule, body });
		index = cursor;
	}
	return out;
}

/** Splits on top-level (paren-depth 0) separators, so `color-mix(a, b)` survives. */
function splitTopLevel(text, separator) {
	const parts = [];
	let depth = 0;
	let start = 0;
	for (let index = 0; index < text.length; index += 1) {
		const char = text[index];
		if (char === "(") depth += 1;
		else if (char === ")") depth -= 1;
		else if (char === separator && depth === 0) {
			parts.push(text.slice(start, index));
			start = index + 1;
		}
	}
	parts.push(text.slice(start));
	return parts;
}

/** Custom-property declarations of one block, as `--token` → raw value. */
function customProperties(body) {
	const declarations = new Map();
	for (const declaration of splitTopLevel(body, ";")) {
		const colon = declaration.indexOf(":");
		if (colon === -1) continue;
		const name = declaration.slice(0, colon).trim();
		if (!name.startsWith("--")) continue;
		declarations.set(name, declaration.slice(colon + 1).trim());
	}
	return declarations;
}

/**
 * The stylesheets Starlight loads, in registration order, read out of the
 * `customCss` array in `astro.config.mjs` rather than restated here — a second
 * list would be one more thing to forget to update. Only quoted `.css` paths
 * are collected, so the comments inside that array are ignored.
 */
function registeredSheets(configSource) {
	const array = /customCss:\s*\[([\s\S]*?)\]/.exec(configSource);
	if (array === null) {
		throw new Error("no `customCss` array found in astro.config.mjs");
	}
	const paths = [...array[1].matchAll(/"([^"]+\.css)"/g)].map(
		(match) => match[1],
	);
	if (paths.length === 0) {
		throw new Error(
			"the `customCss` array in astro.config.mjs lists no sheets",
		);
	}
	return paths;
}

let sheets;
try {
	sheets = registeredSheets(readFileSync(CONFIG, "utf8")).map((path) => ({
		path,
		source: readFileSync(new URL(`../${path}`, import.meta.url), "utf8"),
	}));
} catch (error) {
	// A raw ENOENT stack trace tells a CI reader nothing about the cause.
	console.error(`✗ cannot read the registered stylesheets: ${error.message}`);
	process.exit(1);
}

// Concatenated in registration order, which is the order the cascade sees them.
const blocks = parseBlocks(
	stripComments(sheets.map((sheet) => sheet.source).join("\n")),
);

/** Merges every unconditional block matching `selector`, in source order. */
function tokensOf(selector) {
	const tokens = new Map();
	for (const block of blocks) {
		if (block.atRule !== null || block.selector !== selector) continue;
		for (const [name, value] of customProperties(block.body)) {
			tokens.set(name, value);
		}
	}
	return tokens;
}

/*
 * `:root` carries the dark palette — Starlight's default — and
 * `:root[data-theme="light"]` overrides it. The effective light palette is
 * therefore base + overrides; the effective dark palette is the base alone.
 */
const base = tokensOf(":root");
const PALETTES = {
	dark: base,
	light: new Map([...base, ...tokensOf(':root[data-theme="light"]')]),
};

/** At-rule blocks that redefine tokens, reported but deliberately not gated. */
const conditionalTokenBlocks = blocks.filter(
	(block) => block.atRule !== null && customProperties(block.body).size > 0,
);

/* ------------------------------------------------------------------
   2. COLOUR RESOLUTION
   ------------------------------------------------------------------ */

const KEYWORDS = {
	white: { r: 255, g: 255, b: 255, a: 1 },
	black: { r: 0, g: 0, b: 0, a: 1 },
	transparent: { r: 0, g: 0, b: 0, a: 0 },
};

/** Index of the `)` closing the `(` at `open`. */
function matchParen(text, open) {
	let depth = 0;
	for (let index = open; index < text.length; index += 1) {
		if (text[index] === "(") depth += 1;
		else if (text[index] === ")") {
			depth -= 1;
			if (depth === 0) return index;
		}
	}
	throw new Error(`unbalanced parentheses in: ${text}`);
}

/** Substitutes every `var(--token[, fallback])` with the value it resolves to. */
function expandVars(value, tokens, seen = []) {
	let out = "";
	let index = 0;
	while (index < value.length) {
		if (!value.startsWith("var(", index)) {
			out += value[index];
			index += 1;
			continue;
		}
		const close = matchParen(value, index + 3);
		const [rawName, ...rest] = splitTopLevel(
			value.slice(index + 4, close),
			",",
		);
		const name = rawName.trim();
		if (seen.includes(name)) {
			throw new Error(
				`circular var() reference: ${[...seen, name].join(" → ")}`,
			);
		}
		const fallback = rest.join(",").trim();
		const resolved = tokens.get(name) ?? (fallback || null);
		if (resolved === null) throw new Error(`undefined token ${name}`);
		out += expandVars(resolved, tokens, [...seen, name]);
		index = close + 1;
	}
	return out;
}

function clampByte(value) {
	return Math.min(255, Math.max(0, value));
}

/** Parses one colour component of `color-mix()`: a colour plus optional weight. */
function mixOperand(text, tokens) {
	const parts = text.trim().split(/\s+/);
	const last = parts.at(-1);
	if (last.endsWith("%")) {
		return {
			color: parseColor(parts.slice(0, -1).join(" "), tokens),
			weight: Number.parseFloat(last) / 100,
		};
	}
	return { color: parseColor(text, tokens), weight: null };
}

/** Resolves a CSS colour value to `{ r, g, b, a }` with channels in 0–255. */
function parseColor(value, tokens) {
	const text = expandVars(String(value), tokens).trim();

	if (text.toLowerCase() in KEYWORDS)
		return { ...KEYWORDS[text.toLowerCase()] };

	if (text.startsWith("#")) {
		const hex = text.slice(1);
		const wide = hex.length > 4;
		const size = wide ? 2 : 1;
		const channel = (position) => {
			const slice = hex.slice(position * size, position * size + size);
			return Number.parseInt(wide ? slice : slice + slice, 16);
		};
		if (![3, 4, 6, 8].includes(hex.length)) {
			throw new Error(`unsupported hex colour: ${text}`);
		}
		return {
			r: channel(0),
			g: channel(1),
			b: channel(2),
			a: hex.length === 4 || hex.length === 8 ? channel(3) / 255 : 1,
		};
	}

	const call = /^([a-z-]+)\(/i.exec(text);
	if (!call) throw new Error(`unsupported colour value: ${text}`);
	const inner = text.slice(
		call[0].length - 1 + 1,
		matchParen(text, call[0].length - 1),
	);

	if (call[1] === "rgb" || call[1] === "rgba") {
		const parts = splitTopLevel(inner, ",")
			.flatMap((part) => part.trim().split(/[\s/]+/))
			.filter(Boolean);
		const [r, g, b, alpha = "1"] = parts;
		return {
			r: clampByte(Number.parseFloat(r)),
			g: clampByte(Number.parseFloat(g)),
			b: clampByte(Number.parseFloat(b)),
			a: alpha.endsWith("%")
				? Number.parseFloat(alpha) / 100
				: Number.parseFloat(alpha),
		};
	}

	if (call[1] === "color-mix") {
		const [space, first, second] = splitTopLevel(inner, ",");
		if (space.trim() !== "in srgb") {
			throw new Error(`only \`in srgb\` color-mix() is supported: ${text}`);
		}
		const a = mixOperand(first, tokens);
		const b = mixOperand(second, tokens);
		// CSS Color 5 normalisation: a missing weight is the remainder, and two
		// missing weights split evenly.
		const weightA = a.weight ?? (b.weight === null ? 0.5 : 1 - b.weight);
		const weightB = b.weight ?? 1 - weightA;
		const total = weightA + weightB;
		const mix = (channel) =>
			(a.color[channel] * a.color.a * weightA +
				b.color[channel] * b.color.a * weightB) /
			total;
		const alpha = (a.color.a * weightA + b.color.a * weightB) / total;
		return {
			r: alpha === 0 ? 0 : mix("r") / alpha,
			g: alpha === 0 ? 0 : mix("g") / alpha,
			b: alpha === 0 ? 0 : mix("b") / alpha,
			a: alpha,
		};
	}

	throw new Error(`unsupported colour function: ${text}`);
}

/** Paints `top` over `bottom`, source-over. `bottom` must be opaque. */
function paintOver(top, bottom) {
	return {
		r: top.r * top.a + bottom.r * (1 - top.a),
		g: top.g * top.a + bottom.g * (1 - top.a),
		b: top.b * top.a + bottom.b * (1 - top.a),
		a: 1,
	};
}

/** Flattens a stack of layers given back-to-front; the first must be opaque. */
function flatten(layers) {
	if (layers[0].a !== 1) throw new Error("the bottom layer must be opaque");
	return layers.reduce((bottom, top) => paintOver(top, bottom));
}

function toHex({ r, g, b }) {
	return `#${[r, g, b]
		.map((channel) => Math.round(channel).toString(16).padStart(2, "0"))
		.join("")}`;
}

/* ------------------------------------------------------------------
   3. WCAG RELATIVE LUMINANCE  (WCAG 2.2, "relative luminance")
   ------------------------------------------------------------------ */

/** sRGB → linear-light, on the 0–1 scale WCAG defines. */
function linearise(channel) {
	const c = channel / 255;
	return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

function relativeLuminance({ r, g, b }) {
	return 0.2126 * linearise(r) + 0.7152 * linearise(g) + 0.0722 * linearise(b);
}

/** (L1 + 0.05) / (L2 + 0.05), lighter over darker. */
function contrastRatio(foreground, background) {
	const [lighter, darker] = [
		relativeLuminance(foreground),
		relativeLuminance(background),
	].sort((a, b) => b - a);
	return (lighter + 0.05) / (darker + 0.05);
}

/* ------------------------------------------------------------------
   4. THE PAIRS THIS SITE ACTUALLY RENDERS
   ------------------------------------------------------------------ */

const NORMAL_TEXT = 4.5;
const LARGE_TEXT = 3;
const NON_TEXT = 3;

const PAGE_BG = "var(--sl-color-black)";
const TEXT = "var(--sl-color-gray-2)"; // Starlight: --sl-color-text
const HEADING = "var(--sl-color-white)";
const ACCENT = "var(--sl-color-text-accent)";

/**
 * `.flow-step` background. One declaration now covers both themes, because
 * `--rb-surface-raised` is restated in each theme block instead of the card
 * improvising a `color-mix()` in one and a literal white in the other.
 */
const FLOW_STEP_BG = sourced(".flow-step", "background");

/**
 * Starlight asides: `--sl-color-<hue>-high` title over `--sl-color-<hue>-low`.
 * theme.css points red / green / orange at the drop / allow / warn status axis
 * and blue / purple at the informational hues, so these pairs are what actually
 * gates the status ramp. Each variant also prints its name as the aside title,
 * which is the redundancy rule the axis is documented under.
 */
const ASIDE_HUES = [
	["note", "blue"],
	["tip", "purple"],
	["caution", "orange"],
	["danger", "red"],
];

/**
 * Starlight badges: `#fff` text over `--sl-color-<hue>-low` in dark and
 * `--sl-color-<hue>-high` in light (user-components/Badge.astro:27-58).
 */
const BADGE_HUES = [
	["default", "accent"],
	["note", "blue"],
	["danger", "red"],
	["success", "green"],
	["caution", "orange"],
	["tip", "purple"],
];

const PAIRS = [
	{
		label: "body copy on the page background",
		where: "starlight/style/props.css — --sl-color-text on --sl-color-bg",
		fg: TEXT,
		bg: [PAGE_BG],
		minimum: NORMAL_TEXT,
	},
	{
		label: "markdown headings on the page background",
		where: "starlight/style/markdown.css — h1–h6 from the --sl-text-h* ladder",
		fg: HEADING,
		bg: [PAGE_BG],
		minimum: NORMAL_TEXT,
	},
	{
		label: "links in prose on the page background",
		where: "starlight/style/markdown.css — a { color: --sl-color-text-accent }",
		fg: ACCENT,
		bg: [PAGE_BG],
		minimum: NORMAL_TEXT,
	},
	{
		label: "muted meta text (footer links, “Edit page”)",
		where:
			"starlight/components/Footer.astro + EditLink.astro — --sl-color-gray-3",
		fg: "var(--sl-color-gray-3)",
		bg: [PAGE_BG],
		minimum: NORMAL_TEXT,
	},
	{
		label: "hero title on the page background",
		where: "chrome.css — .hero h1 (60px, 600) → large text",
		fg: HEADING,
		bg: [PAGE_BG],
		minimum: LARGE_TEXT,
	},
	{
		label: "hero tagline on the page background",
		where: "chrome.css — .hero .tagline (19px, 400)",
		fg: TEXT,
		bg: [PAGE_BG],
		minimum: NORMAL_TEXT,
	},
	{
		label: "hero primary call-to-action label on its button",
		where: "chrome.css — .hero .actions a.primary { background, color }",
		// Starlight's own LinkButton paints .primary labels --sl-color-black; the
		// sheet overrides that. Delete the override and this must measure the
		// framework value and fail, not keep reporting the override's colour.
		fg: sourced(".hero .actions a.primary", "color", "var(--sl-color-black)"),
		bg: [sourced(".hero .actions a.primary", "background")],
		minimum: NORMAL_TEXT,
	},
	{
		label: "hero primary call-to-action label, hover",
		where: "chrome.css — .hero .actions a.primary:hover",
		fg: sourced(".hero .actions a.primary", "color", "var(--sl-color-black)"),
		bg: [sourced(".hero .actions a.primary:hover", "background")],
		minimum: NORMAL_TEXT,
	},
	{
		label: "skip-to-content link label",
		where: "a11y.css — .skip-link:focus",
		fg: sourced(".skip-link:focus", "color"),
		bg: [sourced(".skip-link:focus", "background")],
		minimum: NORMAL_TEXT,
	},
	{
		label: "inline code on its tinted background",
		where: "code.css — :not(pre) > code { background: --sl-color-accent-low }",
		fg: TEXT,
		bg: [sourced(":not(pre) > code", "background")],
		minimum: NORMAL_TEXT,
	},
	{
		label: "highlighted text in prose",
		where: "typography.css — mark { background, color }",
		fg: sourced("mark", "color"),
		bg: [sourced("mark", "background")],
		minimum: NORMAL_TEXT,
	},
	{
		// Tables are styled once now, under .sl-markdown-content — the second,
		// bare `table`/`th` rule set that used to shadow it is gone, and so is
		// the pair that measured it.
		label: "table header text",
		where: "tables.css — .sl-markdown-content th",
		fg: HEADING,
		bg: [sourced(".sl-markdown-content th", "background")],
		minimum: NORMAL_TEXT,
	},
	{
		label: "table body text on a hovered row",
		where: "tables.css — .sl-markdown-content tr:hover td",
		fg: TEXT,
		bg: [PAGE_BG, sourced(".sl-markdown-content tr:hover td", "background")],
		minimum: NORMAL_TEXT,
	},
	{
		label: "current sidebar entry label on its filled pill",
		where:
			"starlight/components/SidebarSublist.astro — text-invert on text-accent",
		fg: { dark: "var(--sl-color-accent-low)", light: "var(--sl-color-black)" },
		bg: [ACCENT],
		minimum: NORMAL_TEXT,
	},
	{
		label: "flow-step title on the step card",
		where: "home.css — .flow-step__title (15px, 700)",
		fg: TEXT,
		bg: [FLOW_STEP_BG],
		minimum: NORMAL_TEXT,
	},
	{
		label: "flow-step description on the step card",
		where: "home.css — .flow-step__desc (12.8px, 400), landing page",
		fg: "var(--sl-color-gray-3)",
		bg: [FLOW_STEP_BG],
		minimum: NORMAL_TEXT,
	},
	{
		// The `$` is the signal that this is a shell frame; it replaced the three
		// fake traffic lights, so it has to be readable rather than decorative.
		label: "terminal prompt glyph in a code frame",
		where:
			"code.css — .expressive-code .frame.is-terminal .ec-line .code::before",
		fg: sourced(
			".expressive-code .frame.is-terminal .ec-line .code::before",
			"color",
		),
		bg: ["var(--rb-code-bg)"],
		minimum: NORMAL_TEXT,
	},
	{
		label: "code-block copy-button glyph",
		where: "code.css — .expressive-code .copy button::after on .copy",
		fg: sourced(".expressive-code .copy button::after", "background-color"),
		bg: [sourced(".expressive-code .copy", "background-color")],
		minimum: NON_TEXT,
	},
	{
		label: "focus indicator against the page background",
		where: "a11y.css — :focus-visible { outline: 2px solid ... }",
		fg: ACCENT,
		bg: [PAGE_BG],
		minimum: NON_TEXT,
	},
	...ASIDE_HUES.flatMap(([variant, hue]) => [
		{
			label: `aside body text (${variant})`,
			where: "starlight/style/asides.css — --sl-color-white on the aside tint",
			fg: HEADING,
			bg: [`var(--sl-color-${hue}-low)`],
			minimum: NORMAL_TEXT,
		},
		{
			label: `aside title and links (${variant})`,
			where: "starlight/style/asides.css — <hue>-high on <hue>-low (18px, 600)",
			fg: `var(--sl-color-${hue}-high)`,
			bg: [`var(--sl-color-${hue}-low)`],
			minimum: NORMAL_TEXT,
		},
	]),
	...BADGE_HUES.map(([variant, hue]) => ({
		label: `badge label (${variant})`,
		where:
			"starlight/user-components/Badge.astro — #fff on the variant fill (13px)",
		fg: "#ffffff",
		bg: [
			{
				dark: `var(--sl-color-${hue}-low)`,
				light: `var(--sl-color-${hue}-high)`,
			},
		],
		minimum: NORMAL_TEXT,
	})),

	/*
	 * Measured and printed, but not gated. Each of these is either exempt under
	 * WCAG 1.4.3 "Incidental" or is decoration that 1.4.11 does not reach — the
	 * information it carries is also carried by something that is gated above.
	 */
	{
		label: "flow-step ordinal glyph on its tinted tile",
		where:
			"home.css — .flow-step__icon, aria-hidden decoration; 1.4.3 Incidental",
		fg: sourced(".flow-step__icon", "color"),
		bg: [FLOW_STEP_BG, sourced(".flow-step__icon", "background")],
		minimum: null,
	},
	{
		label: "card and flow-step hairline on the page background",
		where: "home.css — .flow-step border; decorative boundary, outside 1.4.11",
		fg: "var(--rb-border)",
		bg: [PAGE_BG],
		minimum: null,
	},
	{
		label: "code-frame hairline on the frame background",
		where: "code.css — .expressive-code .frame border; decorative boundary",
		fg: "var(--rb-code-border)",
		bg: ["var(--rb-code-bg)"],
		minimum: null,
	},
];

/* ------------------------------------------------------------------
   5. LIGHT / DARK TOKEN SYMMETRY
   ------------------------------------------------------------------ */

/*
 * A colour token that exists for one theme and not the other is a defect on its
 * own: whatever consumes it falls back to whatever else is around, or to
 * nothing, and that is how a hairline ships invisible. Only the light theme can
 * be short a token here, because `:root` is the base both themes inherit — a
 * token the light block never restates is not missing, it is shared, and those
 * are listed separately so a reviewer can confirm sharing was the intent. The
 * one documented exception below is upstream's, not ours.
 */
const KNOWN_ASYMMETRY = new Map([
	[
		"--sl-color-gray-7",
		"light-only upstream too (starlight/style/props.css), and its dark-mode " +
			"consumers pass a fallback — LinkCard.astro uses " +
			"var(--sl-color-gray-7, var(--sl-color-gray-6))",
	],
]);

/** True for values that name a colour, including bare `r, g, b` channel triplets. */
function isColorToken(value, tokens) {
	if (/^\s*\d+\s*,\s*\d+\s*,\s*\d+\s*$/.test(value)) return true;
	try {
		parseColor(value, tokens);
		return true;
	} catch {
		return false;
	}
}

/* ------------------------------------------------------------------
   6. REPORT
   ------------------------------------------------------------------ */

/**
 * Reads a declaration straight out of the stylesheet instead of restating its
 * value here.
 *
 * A pair that inlines `fg: "#ffffff"` cannot notice when the rule producing that
 * white is deleted — the gate keeps measuring a colour the page no longer paints.
 * That is the exact failure mode this whole script exists to prevent, so any
 * value the sheet actually declares is cited by selector and property.
 *
 * `fallback` is what the framework supplies when the local declaration is gone.
 * Passing it means deleting the override makes the gate measure the REAL
 * resulting colour and fail, rather than silently keeping the old number.
 * Omit it and a missing declaration is itself a hard failure.
 *
 * @param {string} selector exact selector text, as normalised by parseBlocks
 * @param {string} property e.g. "color" or "background"
 * @param {string} [fallback] value that applies when the declaration is absent
 */
function sourced(selector, property, fallback) {
	return { __sourced: true, selector, property, fallback };
}

/** Last declaration of `property` in the block(s) matching `selector`, or null. */
function declarationOf(selector, property) {
	let found = null;
	for (const block of blocks) {
		if (block.selector !== selector) continue;
		for (const declaration of splitTopLevel(block.body, ";")) {
			const colon = declaration.indexOf(":");
			if (colon === -1) continue;
			if (declaration.slice(0, colon).trim() !== property) continue;
			found = declaration.slice(colon + 1).trim();
		}
	}
	return found;
}

/** Resolves a sourced() reference against the sheet; throws if it cannot. */
function resolveSourced(value) {
	const declared = declarationOf(value.selector, value.property);
	if (declared !== null) return declared;
	if (value.fallback !== undefined) return value.fallback;
	throw new Error(
		`no \`${value.property}\` declaration on \`${value.selector}\` — ` +
			"the rule this pair measures was renamed or removed",
	);
}

/** Picks the value for `theme` from either a plain value or a per-theme record. */
function forTheme(value, theme) {
	if (typeof value === "object" && value !== null && !Array.isArray(value)) {
		if (value.__sourced === true) return resolveSourced(value);
		const picked = value[theme];
		return typeof picked === "object" &&
			picked !== null &&
			picked.__sourced === true
			? resolveSourced(picked)
			: picked;
	}
	return value;
}

let failures = 0;

console.log("src/styles — colour contrast gate (WCAG 2.2 AA)");
console.log(`${sheets.map((sheet) => sheet.path).join("\n")}\n`);

for (const theme of ["dark", "light"]) {
	const tokens = PALETTES[theme];
	console.log(`${theme.toUpperCase()} theme`);
	for (const pair of PAIRS) {
		let foreground;
		let background;
		let ratio;
		try {
			foreground = parseColor(forTheme(pair.fg, theme), tokens);
			background = flatten(
				pair.bg.map((layer) => parseColor(forTheme(layer, theme), tokens)),
			);
			ratio = contrastRatio(
				foreground.a === 1 ? foreground : paintOver(foreground, background),
				background,
			);
		} catch (error) {
			// A pair that no longer resolves is a failure, not a crash: the sheet
			// moved out from under the gate and someone has to look at it.
			failures += 1;
			console.log(`  FAIL  unresolved  ${pair.label}`);
			console.log(`          ${error.message} — ${pair.where}`);
			continue;
		}
		const measured = `${ratio.toFixed(2)}:1`.padStart(8);
		if (pair.minimum === null) {
			console.log(
				`  INFO  ${measured}  (not gated)  ${pair.label}\n` +
					`                             ${pair.where}`,
			);
			continue;
		}
		const passed = ratio >= pair.minimum;
		if (!passed) failures += 1;
		console.log(
			`  ${passed ? "PASS" : "FAIL"}  ${measured}  ` +
				`(min ${pair.minimum.toFixed(1)})  ${pair.label}`,
		);
		if (!passed) {
			console.log(
				`          ${toHex(foreground)} on ${toHex(background)} — ${pair.where}`,
			);
		}
	}
	console.log("");
}

console.log("Light / dark token symmetry");
// Compare the DECLARED blocks, not the resolved palettes. The light palette is
// built as {...dark, ...lightOverrides} — the cascade, reproduced — so every
// dark token is present in it by inheritance. Diffing the resolved maps can
// therefore only ever catch a light-ONLY token, and silently misses the
// dangerous direction: a colour declared on the bare `:root` (dark) and never
// restated for light keeps its dark value on a white page. That is precisely
// the near-invisible-hairline failure this check exists to prevent.
const darkDeclared = tokensOf(":root");
const lightDeclared = tokensOf(':root[data-theme="light"]');

/** Colour tokens declared in a block, ignoring theme-agnostic ones. */
function declaredColorTokens(declared, resolved) {
	return new Set(
		[...declared.keys()].filter((name) => {
			const value = resolved.get(name);
			return value !== undefined && isColorToken(value, resolved);
		}),
	);
}

const darkColors = declaredColorTokens(darkDeclared, PALETTES.dark);
const lightColors = declaredColorTokens(lightDeclared, PALETTES.light);
const lopsided = [...new Set([...darkColors, ...lightColors])]
	.filter((name) => darkColors.has(name) !== lightColors.has(name))
	.sort();
if (lopsided.length === 0) {
	console.log("  PASS  every colour token is declared in both theme blocks");
}
for (const name of lopsided) {
	const only = darkColors.has(name) ? "dark" : "light";
	const reason = KNOWN_ASYMMETRY.get(name);
	if (reason) {
		console.log(`  KNOWN ${name} is ${only}-only — ${reason}`);
		continue;
	}
	failures += 1;
	console.log(
		`  FAIL  ${name} is declared for ${only} only` +
			(only === "dark"
				? ` — it keeps its dark value (${PALETTES.dark.get(name)}) on a light page`
				: ""),
	);
}

// Non-colour tokens (radius, font stacks) legitimately live in one block.
const sharedNonColor = [...darkDeclared.keys()]
	.filter((name) => !darkColors.has(name) && !lightDeclared.has(name))
	.sort();
if (sharedNonColor.length > 0) {
	console.log("  INFO  theme-agnostic, declared once:");
	for (const name of sharedNonColor) {
		console.log(`          ${name}: ${base.get(name)}`);
	}
}

if (conditionalTokenBlocks.length > 0) {
	console.log("\nNot gated — tokens redefined inside an at-rule");
	for (const block of conditionalTokenBlocks) {
		console.log(`  ${block.atRule} { ${block.selector} }`);
	}
}

if (failures > 0) {
	console.error(
		`\n✗ ${failures} contrast ${failures === 1 ? "failure" : "failures"} in ` +
			"the registered stylesheets",
	);
	process.exit(1);
}
console.log("\n✓ Every gated pair clears its WCAG 2.2 AA threshold.");
