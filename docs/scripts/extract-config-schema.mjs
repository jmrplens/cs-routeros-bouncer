#!/usr/bin/env node
/**
 * Extracts the configuration reference metadata from the Go struct that
 * actually defines it, so the docs stop re-typing it.
 *
 * `internal/config/config.go` is the single source of truth for every
 * configuration key: the `yaml:` tags give the key paths, `v.SetDefault(...)`
 * gives the defaults, the `envBindings` map plus `bindEnvAliases(...)` give the
 * environment variables, and `Validate()` decides which keys are required.
 * Before this script the docs restated all of that by hand — 55 `**Env:** … ·
 * **Default:** …` lines in English, 55 more in Spanish, and the quick-reference
 * tables in `configuration/index.mdx` a third time. It drifted: `mikrotik.address`
 * and `mikrotik.username` were documented with defaults the binary never had.
 *
 * The contract is a committed generated artefact, not a build-time parse:
 *   - `node scripts/extract-config-schema.mjs` rewrites `src/data/config-schema.json`;
 *   - `node scripts/extract-config-schema.mjs --check` exits 1 when the
 *     committed file differs from a fresh extraction (wired into `analyze`);
 *   - the Astro build only ever reads the JSON. It never parses Go.
 *
 * The output is run through Prettier with the repository's own configuration so
 * the committed artefact is byte-identical to what `format:check` expects, and
 * so `--check` compares the same bytes it would write.
 *
 * Deliberately regex-based rather than a Go parser: the shapes it has to read
 * are a struct-tag list, a map literal, and a set of one-line calls, all of
 * which are gofmt-stable. Every assumption it makes is asserted — a parse that
 * silently degrades would emit a thin-but-valid schema and the `--check` gate
 * would pass over it, which is the vacuous-gate failure this project has
 * already been bitten by. See `assertNonVacuous`.
 *
 * Usage:
 *   node scripts/extract-config-schema.mjs           # regenerate the artefact
 *   node scripts/extract-config-schema.mjs --check   # 0 when in sync, 1 when stale
 */
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { format, resolveConfig } from "prettier";

const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));
const GO_SOURCE = fileURLToPath(
	new URL("../../internal/config/config.go", import.meta.url),
);
const OUTPUT_FILE = fileURLToPath(
	new URL("../src/data/config-schema.json", import.meta.url),
);
const ROOT_STRUCT = "Config";

/**
 * Keys that must survive any refactor of `config.go`. If the parser ever stops
 * recognising the file's shape it will produce a schema that is structurally
 * valid but missing most of it; asserting on load-bearing keys turns that into
 * a loud failure instead of a green build over an empty reference.
 */
const CANARY_KEYS = [
	"crowdsec.api_url",
	"crowdsec.api_key",
	"mikrotik.address",
	"mikrotik.pool_size",
	"firewall.ipv4.address_list",
	"firewall.deny_action",
	"firewall.rule_placement.strategy",
	"logging.level",
	"metrics.listen_port",
];

/** Every top-level section the reference is expected to document. */
const REQUIRED_SECTIONS = [
	"crowdsec",
	"mikrotik",
	"firewall",
	"logging",
	"metrics",
];

/** Floor on the number of extracted keys, well below the real count. */
// The real extraction currently yields 93 keys. The floor sits just under that
// rather than at a comfortable distance: a floor far below reality is not a
// guard at all — deleting a whole nested struct dropped 8 keys and still
// cleared a floor of 60. Raise this deliberately when keys are added.
const MINIMUM_OPTIONS = 90;
/** Leaf keys that must carry a resolved default for the schema to mean anything. */
const MINIMUM_DEFAULTS = 45;

/**
 * Reads `config.go`, failing loudly rather than returning an empty string.
 * @returns {string}
 */
function readGoSource() {
	let source;
	try {
		source = readFileSync(GO_SOURCE, "utf-8");
	} catch (error) {
		throw new Error(
			`Cannot read the Go configuration source at ${GO_SOURCE}. It is resolved ` +
				`relative to this script, so the docs directory must sit inside the ` +
				`repository checkout.`,
			{ cause: error },
		);
	}
	if (!source.includes(`type ${ROOT_STRUCT} struct`)) {
		throw new Error(
			`${GO_SOURCE} does not declare "type ${ROOT_STRUCT} struct". The extractor ` +
				`walks the configuration tree from that type; refusing to emit a schema ` +
				`it cannot anchor.`,
		);
	}
	return source;
}

/**
 * Collects the string constants declared in `const ( ... )` blocks, including
 * the ones defined by concatenating earlier constants.
 * @param {string} source
 * @returns {Map<string, string>}
 */
function parseConstants(source) {
	/** @type {Map<string, string>} */
	const raw = new Map();
	for (const block of source.matchAll(/^const \(\n([\s\S]*?)^\)$/gm)) {
		for (const line of block[1].split("\n")) {
			const match = line.match(/^\t(\w+)\s*=\s*(.+?)\s*$/);
			if (match) raw.set(match[1], match[2]);
		}
	}
	/** @type {Map<string, string>} */
	const resolved = new Map();
	// Constants may reference each other, so resolve to a fixed point rather
	// than assuming declaration order.
	for (let pass = 0; pass < raw.size + 1; pass += 1) {
		let progressed = false;
		for (const [name, expression] of raw) {
			if (resolved.has(name)) continue;
			const value = evaluateStringExpression(expression, resolved);
			if (value !== undefined) {
				resolved.set(name, value);
				progressed = true;
			}
		}
		if (!progressed) break;
	}
	return resolved;
}

/**
 * Evaluates a Go string expression built from literals and known constants,
 * e.g. `rulePlacementConfigPath + ".position"`.
 * @param {string} expression
 * @param {Map<string, string>} constants
 * @returns {string | undefined} `undefined` when a term cannot be resolved.
 */
function evaluateStringExpression(expression, constants) {
	const terms = expression.split("+").map((term) => term.trim());
	let value = "";
	for (const term of terms) {
		const literal = term.match(/^"((?:[^"\\]|\\.)*)"$/);
		if (literal) {
			value += literal[1];
			continue;
		}
		if (constants.has(term)) {
			value += /** @type {string} */ (constants.get(term));
			continue;
		}
		return undefined;
	}
	return value;
}

/**
 * @typedef {object} GoField
 * @property {string} name Go field name.
 * @property {string} yaml YAML key segment.
 * @property {string} goType Declared Go type, pointers and slices included.
 * @property {string} doc Doc comment above the field, joined into one line.
 */

/**
 * Parses every `type X struct { ... }` declaration into its yaml-tagged fields.
 * @param {string} source
 * @returns {Map<string, GoField[]>}
 */
function parseStructs(source) {
	/** @type {Map<string, GoField[]>} */
	const structs = new Map();
	for (const match of source.matchAll(
		/^type (\w+) struct \{\n([\s\S]*?)^\}$/gm,
	)) {
		const [, typeName, body] = match;
		/** @type {GoField[]} */
		const fields = [];
		/** @type {string[]} */
		let pendingDoc = [];
		for (const line of body.split("\n")) {
			const comment = line.match(/^\t\/\/ ?(.*)$/);
			if (comment) {
				pendingDoc.push(comment[1].trim());
				continue;
			}
			const field = line.match(/^\t(\w+)\s+(\S+)\s+`(.+)`\s*$/);
			if (field) {
				const [, name, goType, tags] = field;
				const yamlTag = tags.match(/yaml:"([^",]+)/);
				if (yamlTag) {
					fields.push({
						name,
						yaml: yamlTag[1],
						goType,
						doc: pendingDoc.join(" ").trim(),
					});
				}
			}
			pendingDoc = [];
		}
		structs.set(typeName, fields);
	}
	return structs;
}

/**
 * Reads the `v.SetDefault("key", value)` calls.
 * @param {string} source
 * @param {Map<string, string>} constants
 * @returns {Map<string, unknown>}
 */
function parseDefaults(source, constants) {
	/** @type {Map<string, unknown>} */
	const defaults = new Map();
	for (const match of source.matchAll(
		/v\.SetDefault\(\s*(.+?),\s*(.+?),?\s*\)\n/g,
	)) {
		const key = evaluateStringExpression(match[1], constants);
		if (key === undefined) {
			throw new Error(`Unresolved v.SetDefault key expression: ${match[1]}`);
		}
		defaults.set(key, parseGoLiteral(match[2]));
	}
	return defaults;
}

/**
 * Converts a Go literal used as a default into its JSON equivalent.
 * @param {string} literal
 * @returns {unknown}
 */
function parseGoLiteral(literal) {
	const trimmed = literal.trim();
	const stringLiteral = trimmed.match(/^"((?:[^"\\]|\\.)*)"$/);
	if (stringLiteral) return stringLiteral[1];
	if (trimmed === "true") return true;
	if (trimmed === "false") return false;
	if (/^-?\d+$/.test(trimmed)) return Number(trimmed);
	const sliceLiteral = trimmed.match(/^\[\]string\{(.*)\}$/);
	if (sliceLiteral) {
		return sliceLiteral[1]
			.split(",")
			.map((item) => item.trim())
			.filter((item) => item.length > 0)
			.map((item) => {
				const value = item.match(/^"((?:[^"\\]|\\.)*)"$/);
				if (!value) throw new Error(`Unsupported slice element: ${item}`);
				return value[1];
			});
	}
	throw new Error(`Unsupported default literal: ${literal}`);
}

/**
 * Reads both environment-variable binding forms: the `envBindings` map literal
 * and the `bindEnvAliases(v, key, primary, ...aliases)` calls.
 * @param {string} source
 * @param {Map<string, string>} constants
 * @returns {Map<string, {env: string, aliases: string[]}>}
 */
function parseEnvBindings(source, constants) {
	/** @type {Map<string, {env: string, aliases: string[]}>} */
	const bindings = new Map();

	const mapLiteral = source.match(
		/envBindings := map\[string\]string\{\n([\s\S]*?)^\t\}$/m,
	);
	if (!mapLiteral) {
		throw new Error(
			"Could not find the `envBindings := map[string]string{` literal in config.go.",
		);
	}
	for (const line of mapLiteral[1].split("\n")) {
		const entry = line.match(/^\t\t(.+?):\s+"([A-Z0-9_]+)",$/);
		if (!entry) continue;
		const key = evaluateStringExpression(entry[1], constants);
		if (key === undefined) {
			throw new Error(`Unresolved envBindings key expression: ${entry[1]}`);
		}
		bindings.set(key, { env: entry[2], aliases: [] });
	}

	for (const call of source.matchAll(/^\tbindEnvAliases\(v, (.+)\)$/gm)) {
		const parts = splitTopLevelArguments(call[1]);
		const key = evaluateStringExpression(parts[0], constants);
		if (key === undefined) {
			throw new Error(`Unresolved bindEnvAliases key expression: ${parts[0]}`);
		}
		const envNames = parts.slice(1).map((part) => {
			const value = evaluateStringExpression(part, constants);
			if (value === undefined) {
				throw new Error(`Unresolved bindEnvAliases env expression: ${part}`);
			}
			return value;
		});
		bindings.set(key, { env: envNames[0], aliases: envNames.slice(1) });
	}

	return bindings;
}

/**
 * Splits a Go argument list on commas that are not inside a string literal.
 * @param {string} argumentList
 * @returns {string[]}
 */
function splitTopLevelArguments(argumentList) {
	/** @type {string[]} */
	const parts = [];
	let current = "";
	let inString = false;
	for (let index = 0; index < argumentList.length; index += 1) {
		const character = argumentList[index];
		if (character === '"' && argumentList[index - 1] !== "\\")
			inString = !inString;
		if (character === "," && !inString) {
			parts.push(current.trim());
			current = "";
			continue;
		}
		current += character;
	}
	if (current.trim()) parts.push(current.trim());
	return parts;
}

/**
 * Keys `Validate()` rejects when empty, read from its error messages.
 * @param {string} source
 * @returns {Set<string>}
 */
function parseRequiredKeys(source) {
	/** @type {Set<string>} */
	const required = new Set();
	for (const match of source.matchAll(
		/"([a-z0-9_]+(?:\.[a-z0-9_]+)+) is required"/g,
	)) {
		required.add(match[1]);
	}
	return required;
}

/**
 * Requirements `Validate()` states against a runtime-built path, such as
 * `"%s.comment is required when strategy=%q"`. The path is not knowable from
 * the literal, so these are matched by leaf name and only accepted when exactly
 * one struct in the file declares that leaf — an ambiguous leaf is reported as
 * needing hand-authored prose instead of being guessed onto a key.
 * @param {string} source
 * @returns {Map<string, string>} leaf yaml name -> condition text
 */
function parseConditionalRequirements(source, constants) {
	/** @type {Map<string, string>} */
	const conditions = new Map();
	// The condition's VALUE lives in the fmt.Errorf argument that fills the
	// verb, not in the format string. Stripping the verb and stopping there
	// emitted `strategy=` — a condition with its only informative half removed,
	// which reads like a real value to anyone who does not open config.go.
	for (const match of source.matchAll(
		/"%s\.(\w+) is required when ([^"]+)"([^)\n]*)\)/g,
	)) {
		const [, field, template, argumentTail] = match;
		const verb = /%[qsv]/.exec(template);
		if (!verb) {
			conditions.set(field, template.trim());
			continue;
		}
		// The last argument is the one filling the trailing verb.
		const args = argumentTail
			.split(",")
			.map((a) => a.trim())
			.filter(Boolean);
		const last = args.at(-1);
		const resolved = last && constants.get(last);
		if (resolved !== undefined) {
			conditions.set(field, template.replace(/%[qsv]/, resolved).trim());
			continue;
		}
		// A runtime variable: say what the condition depends on rather than
		// publishing a truncated equality with nothing on its right-hand side.
		conditions.set(
			field,
			`the configured ${template.replace(/\s*=?\s*%[qsv]/, "").trim()} requires it`,
		);
	}
	return conditions;
}

/**
 * Reads per-type field defaults out of the zero-argument constructors that
 * supply them, e.g. `defaultStructuredRulePlacement()`.
 *
 * Not every default reaches Viper: `firewall.rule_placement`'s sub-keys are
 * defaulted by the placement parser and by the normalisation `Validate()` runs
 * (`normalizedRulePlacementStrategy` returns `defaultStructuredRulePlacement().Strategy`),
 * never by a `v.SetDefault` call. Reading the constructor keeps those three
 * keys' documented defaults derived instead of hand-written.
 *
 * @param {string} source
 * @param {Map<string, string>} constants
 * @param {Map<string, GoField[]>} structs
 * @returns {Map<string, Map<string, unknown>>} Go type -> yaml leaf -> default
 */
function parseStructLiteralDefaults(source, constants, structs) {
	/** @type {Map<string, Map<string, unknown>>} */
	const byType = new Map();
	for (const match of source.matchAll(
		/^func \w+\(\) (\w+) \{\n\treturn \1\{\n([\s\S]*?)^\t\}$/gm,
	)) {
		const [, typeName, body] = match;
		const fields = structs.get(typeName);
		if (!fields) continue;
		/** @type {Map<string, unknown>} */
		const defaults = byType.get(typeName) ?? new Map();
		for (const line of body.split("\n")) {
			const assignment = line.match(/^\t\t(\w+):\s+(.+?),\s*$/);
			if (!assignment) continue;
			const field = fields.find(
				(candidate) => candidate.name === assignment[1],
			);
			if (!field) continue;
			const literal = evaluateStringExpression(assignment[2], constants);
			defaults.set(
				field.yaml,
				literal === undefined ? parseGoLiteral(assignment[2]) : literal,
			);
		}
		if (defaults.size > 0) byType.set(typeName, defaults);
	}
	return byType;
}

/**
 * Maps a Go type onto the vocabulary the documentation uses.
 * @param {string} goType
 * @param {Map<string, GoField[]>} structs
 * @returns {string}
 */
function describeType(goType, structs) {
	const base = goType.replace(/^\*/, "");
	if (base === "time.Duration") return "duration";
	if (base === "[]string") return "list of strings";
	if (base === "string") return "string";
	if (base === "bool") return "boolean";
	if (base === "int") return "integer";
	if (structs.has(base)) return "object";
	return base;
}

/**
 * The value a key takes when nothing sets it. Only meaningful for kinds whose
 * Go zero value is a value a user would recognise; pointers, strings, slices
 * and nested objects report "no default" instead of a fabricated one.
 * @param {string} goType
 * @param {Map<string, GoField[]>} structs
 * @returns {{value: unknown, kind: "zero" | "none"}}
 */
function zeroValueDefault(goType, structs) {
	if (goType.startsWith("*")) return { value: null, kind: "none" };
	const described = describeType(goType, structs);
	if (described === "boolean") return { value: false, kind: "zero" };
	if (described === "integer") return { value: 0, kind: "zero" };
	// A nil slice and an empty one are the same thing to every consumer of these
	// keys (they are all filters where "empty" means "no filtering"), so the
	// documented default is the empty list rather than "unset".
	if (described === "list of strings") return { value: [], kind: "zero" };
	return { value: null, kind: "none" };
}

/**
 * Walks the configuration tree from `Config`, emitting one entry per YAML key.
 *
 * `RulePlacementConfig` nests itself (`filter` and `raw` override the parent),
 * so recursion stops when a type reappears on its own path. The key is still
 * emitted — dropping it would hide documented options — but is marked as
 * needing hand-authored prose, because "inherits every unspecified field from
 * the enclosing placement" is a semantic no struct tag states.
 *
 * @param {object} inputs
 * @param {Map<string, GoField[]>} inputs.structs
 * @param {Map<string, unknown>} inputs.defaults
 * @param {Map<string, {env: string, aliases: string[]}>} inputs.envBindings
 * @param {Set<string>} inputs.requiredKeys
 * @param {Map<string, string>} inputs.conditionalRequirements
 * @param {Set<string>} inputs.ambiguousLeaves
 * @param {Map<string, Map<string, unknown>>} inputs.structLiteralDefaults
 * @returns {Record<string, object>}
 */
function walkConfig(inputs) {
	const {
		structs,
		defaults,
		envBindings,
		requiredKeys,
		conditionalRequirements,
		ambiguousLeaves,
		structLiteralDefaults,
	} = inputs;
	/** @type {Record<string, object>} */
	const options = {};

	/**
	 * @param {string} typeName
	 * @param {string} prefix
	 * @param {string[]} ancestorTypes
	 */
	function visit(typeName, prefix, ancestorTypes) {
		for (const field of structs.get(typeName) ?? []) {
			const keyPath = prefix ? `${prefix}.${field.yaml}` : field.yaml;
			const baseType = field.goType.replace(/^\*/, "");
			const isStruct = structs.has(baseType);
			const isRecursive = isStruct && ancestorTypes.includes(baseType);
			const binding = envBindings.get(keyPath);
			const hasExplicitDefault = defaults.has(keyPath);
			const typeDefaults = structLiteralDefaults.get(typeName);
			const hasTypeDefault =
				!hasExplicitDefault && typeDefaults?.has(field.yaml) === true;
			const zero = zeroValueDefault(field.goType, structs);

			/** @type {"required" | "conditional" | "optional"} */
			let requirement = "optional";
			/** @type {string | null} */
			let requirementCondition = null;
			if (requiredKeys.has(keyPath)) {
				requirement = "required";
			} else if (
				conditionalRequirements.has(field.yaml) &&
				!ambiguousLeaves.has(field.yaml)
			) {
				requirement = "conditional";
				requirementCondition = conditionalRequirements.get(field.yaml) ?? null;
			}

			/** @type {string | null} */
			let needsProse = null;
			if (isRecursive) {
				needsProse =
					"Self-referential override object: its inheritance semantics are not " +
					"expressed by any struct tag, default, or validation message.";
			} else if (
				conditionalRequirements.has(field.yaml) &&
				ambiguousLeaves.has(field.yaml)
			) {
				needsProse =
					`Validation states a conditional requirement for the "${field.yaml}" ` +
					"leaf, but more than one struct declares that key, so it cannot be " +
					"attributed to this path with certainty.";
			}

			options[keyPath] = {
				path: keyPath,
				type: describeType(field.goType, structs),
				section: isStruct && !binding && !hasExplicitDefault,
				env: binding?.env ?? null,
				envAliases: binding?.aliases ?? [],
				requirement,
				requirementCondition,
				default: hasExplicitDefault
					? defaults.get(keyPath)
					: hasTypeDefault
						? typeDefaults?.get(field.yaml)
						: zero.value,
				defaultSource: hasExplicitDefault
					? "explicit"
					: hasTypeDefault
						? "struct-default"
						: zero.kind,
				doc: field.doc,
				needsProse,
			};

			if (isStruct && !isRecursive) {
				visit(baseType, keyPath, [...ancestorTypes, baseType]);
			}
		}
	}

	visit(ROOT_STRUCT, "", [ROOT_STRUCT]);
	return options;
}

/**
 * Refuses to emit a schema that is structurally valid but empty of meaning.
 * @param {Record<string, object>} options
 */
/**
 * Per-protocol rule-placement keys are OVERRIDES, not independently defaulted
 * settings. `mergeRulePlacement` (config.go:271) copies a field from the
 * protocol block onto the global one only when the protocol value is non-zero,
 * so an unset `firewall.ipv4.rule_placement.strategy` resolves to whatever
 * `firewall.rule_placement.strategy` holds — NOT to the struct constructor's
 * "top". Emitting the constructor value as a flat default tells an operator
 * that leaving the key unset yields "top", which is false whenever the global
 * placement says anything else. That is precisely the phantom-default class of
 * error this artefact exists to eliminate, so it is rewritten here rather than
 * left for a reader to disbelieve.
 * @param {Record<string, object>} options
 */
function markInheritedOverrides(options) {
	const pattern = /^firewall\.ipv[46]\.rule_placement\.(.+)$/;
	for (const [keyPath, option] of Object.entries(options)) {
		const match = pattern.exec(keyPath);
		if (!match) continue;
		option.inheritsFrom = `firewall.rule_placement.${match[1]}`;
		option.default = null;
		option.defaultSource = "inherited";
	}
}

function assertNonVacuous(options) {
	const keys = Object.keys(options);
	if (keys.length < MINIMUM_OPTIONS) {
		throw new Error(
			`Extracted only ${keys.length} configuration keys from config.go, expected ` +
				`at least ${MINIMUM_OPTIONS}. The parser is out of step with the Go source; ` +
				`refusing to write a schema that would pass --check while documenting nothing.`,
		);
	}
	// A key count alone is not enough. Deleting every v.SetDefault() line still
	// produced 93 keys — each carrying no default, which the docs would then
	// render as though the binary genuinely had none. Guard the metadata that
	// makes the artefact worth anything, not merely its shape.
	const leaves = Object.values(options).filter(
		(option) => option && option.type !== "section",
	);
	// An inherited override carries resolved metadata too — it just resolves to
	// another key rather than to a literal. Both count as "the extraction worked".
	const withDefault = leaves.filter(
		(option) =>
			(option.default !== undefined && option.default !== null) ||
			option.inheritsFrom,
	);
	if (leaves.length > 0 && withDefault.length < MINIMUM_DEFAULTS) {
		throw new Error(
			`Only ${withDefault.length} of ${leaves.length} leaf keys carry a default, ` +
				`expected at least ${MINIMUM_DEFAULTS}. The defaults are read from the ` +
				`v.SetDefault() calls in config.go — if those moved, the schema would ` +
				`document every key as having no default. Refusing to write it.`,
		);
	}

	const missingSections = REQUIRED_SECTIONS.filter(
		(section) => !keys.some((key) => key === section),
	);
	if (missingSections.length > 0) {
		throw new Error(
			`Extraction is missing top-level section(s): ${missingSections.join(", ")}.`,
		);
	}
	const missingCanaries = CANARY_KEYS.filter((key) => !(key in options));
	if (missingCanaries.length > 0) {
		throw new Error(
			`Extraction is missing load-bearing key(s): ${missingCanaries.join(", ")}.`,
		);
	}
	const withEnv = keys.filter((key) => options[key].env !== null);
	if (withEnv.length < 50) {
		throw new Error(
			`Only ${withEnv.length} keys resolved an environment variable; the ` +
				"envBindings parse has degraded.",
		);
	}
}

/**
 * Builds the artefact and formats it exactly as `format:check` expects.
 * @returns {Promise<string>}
 */
async function buildSchema() {
	const source = readGoSource();
	const constants = parseConstants(source);
	const structs = parseStructs(source);
	const defaults = parseDefaults(source, constants);
	const envBindings = parseEnvBindings(source, constants);
	const requiredKeys = parseRequiredKeys(source);
	const conditionalRequirements = parseConditionalRequirements(
		source,
		constants,
	);
	const structLiteralDefaults = parseStructLiteralDefaults(
		source,
		constants,
		structs,
	);

	// A conditional requirement is only attributable to a key when exactly one
	// struct declares that yaml leaf.
	/** @type {Set<string>} */
	const ambiguousLeaves = new Set();
	for (const leaf of conditionalRequirements.keys()) {
		const declaringTypes = [...structs.entries()].filter(([, fields]) =>
			fields.some((field) => field.yaml === leaf),
		);
		if (declaringTypes.length !== 1) ambiguousLeaves.add(leaf);
	}

	const options = walkConfig({
		structs,
		defaults,
		envBindings,
		requiredKeys,
		conditionalRequirements,
		ambiguousLeaves,
		structLiteralDefaults,
	});
	markInheritedOverrides(options);
	assertNonVacuous(options);

	const artefact = {
		$comment:
			"GENERATED FILE — do not edit by hand. Regenerate with " +
			"`pnpm --filter docs run config:extract`; `config:check` fails the build " +
			"when this file and internal/config/config.go disagree.",
		source: path.relative(REPO_ROOT, GO_SOURCE).split(path.sep).join("/"),
		generator: "docs/scripts/extract-config-schema.mjs",
		options,
	};

	const prettierOptions = await resolveConfig(OUTPUT_FILE, {
		editorconfig: true,
	});
	return format(JSON.stringify(artefact, null, "\t"), {
		...prettierOptions,
		filepath: OUTPUT_FILE,
		parser: "json",
	});
}

/**
 * Reports the first line where the committed artefact and a fresh extraction
 * diverge, so a failing gate says what changed rather than only that it did.
 * @param {string} committed
 * @param {string} fresh
 * @returns {string}
 */
function describeFirstDifference(committed, fresh) {
	const committedLines = committed.split("\n");
	const freshLines = fresh.split("\n");
	const length = Math.max(committedLines.length, freshLines.length);
	for (let index = 0; index < length; index += 1) {
		if (committedLines[index] !== freshLines[index]) {
			return (
				`  first difference at line ${index + 1}:\n` +
				`    committed: ${committedLines[index] ?? "<end of file>"}\n` +
				`    extracted: ${freshLines[index] ?? "<end of file>"}`
			);
		}
	}
	return "  (files differ only in trailing content)";
}

async function main() {
	const checkOnly = process.argv.includes("--check");
	const fresh = await buildSchema();
	const relativeOutput = path
		.relative(REPO_ROOT, OUTPUT_FILE)
		.split(path.sep)
		.join("/");

	if (!checkOnly) {
		writeFileSync(OUTPUT_FILE, fresh);
		const count = Object.keys(JSON.parse(fresh).options).length;
		console.log(`✓ ${relativeOutput}: ${count} configuration keys extracted.`);
		return;
	}

	let committed;
	try {
		committed = readFileSync(OUTPUT_FILE, "utf-8");
	} catch {
		console.error(
			`✗ ${relativeOutput} is missing. Run \`pnpm run config:extract\` and commit it.`,
		);
		process.exitCode = 1;
		return;
	}
	if (committed !== fresh) {
		console.error(
			`✗ ${relativeOutput} is out of date with internal/config/config.go.\n` +
				describeFirstDifference(committed, fresh) +
				"\n  Run `pnpm run config:extract` and commit the result.",
		);
		process.exitCode = 1;
		return;
	}
	console.log(`✓ ${relativeOutput} matches internal/config/config.go.`);
}

await main();
