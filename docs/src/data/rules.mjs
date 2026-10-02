/**
 * The firewall rules this daemon writes to RouterOS — one module, rendered by
 * `src/components/RuleSet.astro` on the English page, on its Spanish twin, and
 * on the landing page.
 *
 * WHY THIS FILE EXISTS
 *
 * The same four-to-seven rules used to be described in three unconnected
 * places: a prose list in `architecture/firewall-rules.mdx`, a second one in
 * its Spanish twin, and a `<details>` listing in `configuration/firewall.mdx`.
 * All three omitted the passthrough counting rules, which `metrics.track_processed`
 * creates BY DEFAULT — so a stock installation puts eight rules on the router
 * while the documented listing accounted for four of them, and the two the
 * reader had never seen match no address list at all and read, on the router,
 * like somebody's forgotten scratch rule.
 *
 * SOURCE OF TRUTH — every field below was read out of the Go, not the README:
 *
 *   internal/manager/manager.go
 *     createFilterChainRules()   filter block, in emission order
 *     createRawChainRules()      raw block, in emission order
 *     inputWhitelistRule()       the accept rule, and its `connection-state`
 *     filterInputRule()          the filter deny rule
 *     outputRule()               the output block
 *     processedCountingRule()    the passthrough rules — chain, action, comment, nothing else
 *     rawDenyAction()            `reject` becomes `drop` in raw
 *     applyInputRuleOptions()    in-interface / in-interface-list
 *     applyRejectOptions()       reject-with
 *     buildRuleComment()         the comment string, exactly
 *     ruleSignature              the fixed `@cs-routeros-bouncer` suffix
 *   internal/routeros/firewall.go
 *     firewallRuleAttrs()        which attributes are sent, and which are omitted when empty
 *   internal/config/config.go
 *     setDefaults()              every default quoted in `settingDefault` below
 *
 * Cross-checked against the live router this repository's author runs, whose
 * `/ip firewall filter`, `/ip firewall raw`, `/ipv6 firewall filter` and
 * `/ipv6 firewall raw` menus carry exactly the eight rules `defaultRules`
 * expands to, comments and all.
 *
 * WHAT IS TRANSLATED
 *
 * Nothing structural. `i18n.en` / `i18n.es` carry the human gloss — a name and
 * a sentence of purpose, kept in `rule-glosses.mjs` — and every chain, action, attribute, setting path and
 * comment string is rendered from the same fields in both locales. A rule
 * cannot therefore be right in one language and wrong in the other.
 */

import { RULE_GLOSSES } from "./rule-glosses.mjs";

/**
 * The fixed, non-configurable suffix on every comment the bouncer writes
 * (manager.go, `ruleSignature`). Cleanup after a crash searches for this, not
 * for the prefix, which is why it cannot be configured away.
 */
export const RULE_SIGNATURE = "@cs-routeros-bouncer";

/** `firewall.comment_prefix` default (config.go). */
export const DEFAULT_COMMENT_PREFIX = "crowdsec-bouncer";

/**
 * `firewall.ipv4.address_list` / `firewall.ipv6.address_list` defaults.
 * Both protocol families are enabled by default, so both lists exist in a
 * stock installation.
 */
export const DEFAULT_ADDRESS_LISTS = {
	v4: "crowdsec-banned",
	v6: "crowdsec6-banned",
};

/**
 * `firewall.block_input.whitelist` has NO default — the accept rules only
 * exist once an operator names a list. This is the placeholder used when
 * rendering those rules, and it is illustrative, never a value the daemon
 * assumes.
 */
export const SAMPLE_WHITELIST_LIST = "crowdsec-whitelist";

/**
 * Protocol families, in the order `enabledProtos()` returns them.
 * @type {("v4" | "v6")[]}
 */
export const FAMILIES = ["v4", "v6"];

/**
 * @typedef {"v4" | "v6"} Family
 *
 * @typedef {object} RuleMatch
 * The address-list matcher the rule carries, or `null` for a rule that matches
 * no list at all.
 * @property {"src-address-list" | "dst-address-list"} attribute
 * @property {"banned" | "whitelist"} kind
 *   `banned` resolves per family from {@link DEFAULT_ADDRESS_LISTS};
 *   `whitelist` has no default and renders {@link SAMPLE_WHITELIST_LIST}.
 *
 * @typedef {object} OptionalAttribute
 * A RouterOS attribute the rule carries only when a setting is non-empty —
 * `firewallRuleAttrs()` omits every empty value rather than sending a blank.
 * @property {string} attribute RouterOS attribute name.
 * @property {string} setting Configuration path that fills it.
 *
 * @typedef {object} RuleGloss
 * @property {string} name Short human name for the rule.
 * @property {string} purpose One sentence: what it is for.
 * @property {string} [note] One sentence of non-obvious behaviour, when there is any.
 *
 * @typedef {object} ManagedRule
 * @property {string} id Stable key; also the anchor and the React-style list key.
 * @property {"filter" | "raw"} table RouterOS firewall menu.
 * @property {string} chain Chain in the stock configuration.
 * @property {string | null} chainSetting
 *   Setting that decides the chain(s) — one copy of the rule per entry in it.
 *   `null` for the output block, whose chain is fixed.
 * @property {"whitelist" | "counting" | "input" | "output"} direction
 *   Fourth segment of the comment (`buildRuleComment`).
 * @property {string} action RouterOS action in the stock configuration.
 * @property {string | null} actionSetting Setting that decides the action, when configurable.
 * @property {RuleMatch | null} match
 * @property {boolean} createdByDefault True when a stock configuration writes it.
 * @property {string} enabledBy Setting that gates the rule's existence.
 * @property {string} settingDefault That setting's default, verbatim from `setDefaults()`.
 * @property {OptionalAttribute[]} optionalAttributes
 * @property {{ en: RuleGloss, es: RuleGloss }} i18n
 */

/* ------------------------------------------------------------------
   Shared attribute sets

   Every managed rule draws its optional attributes from the same few
   sets. Naming them once is not merely shorter: it makes the difference
   between two rules visible as a difference in composition, instead of
   leaving a reader to diff two twenty-line literals to find the one
   entry that changed.
   ------------------------------------------------------------------ */

/** Interface narrowing, available to every input-side rule. */
const INPUT_INTERFACE_ATTRS = [
	{ attribute: "in-interface", setting: "firewall.block_input.interface" },
	{
		attribute: "in-interface-list",
		setting: "firewall.block_input.interface_list",
	},
];

/**
 * Rule logging. `firewall.log` gates emission; the prefix value comes from
 * `firewall.log_prefix`, resolved per table by `resolveLogPrefix`.
 */
const LOG_ATTRS = [
	{ attribute: "log", setting: "firewall.log" },
	{ attribute: "log-prefix", setting: "firewall.log_prefix" },
];

/** Only the filter table sees conntrack, so only filter rules take this. */
const CONNECTION_STATE_ATTR = {
	attribute: "connection-state",
	setting: "firewall.filter.connection_state",
};

/** Present only when `firewall.deny_action` is `reject`. */
const REJECT_WITH_ATTR = {
	attribute: "reject-with",
	setting: "firewall.reject_with",
};

/* ------------------------------------------------------------------
   The input-side block

   `createFilterChainRules()` and `createRawChainRules()` in
   internal/manager build the SAME ordered block — whitelist, counting,
   deny — differing only in which table they write to, which setting
   names the chains, which setting enables them, and the handful of
   attributes only the filter table can carry. Building both blocks from
   one function keeps that symmetry visible here as well; writing them
   out twice invited the two copies to drift, and made the real
   differences hard to spot among twenty identical lines.
   ------------------------------------------------------------------ */

/** @type {(spec: {
 *   table: string, chain: string, chainSetting: string,
 *   denyEnabledBy: string, connectionState: boolean, rejectWith: boolean,
 * }) => ManagedRule[]} */
function inputSideBlock({
	table,
	chain,
	chainSetting,
	denyEnabledBy,
	connectionState,
	rejectWith,
}) {
	const where = { table, chain, chainSetting };
	// Only the filter table sees conntrack, and only it can reject: rawDenyAction()
	// coerces reject to drop because the raw table has no conntrack to reject from.
	const stateAttr = connectionState ? [CONNECTION_STATE_ATTR] : [];
	const rejectAttr = rejectWith ? [REJECT_WITH_ATTR] : [];

	return [
		{
			...where,
			id: `${table}-whitelist`,
			direction: "whitelist",
			action: "accept",
			actionSetting: null,
			match: { attribute: "src-address-list", kind: "whitelist" },
			createdByDefault: false,
			enabledBy: "firewall.block_input.whitelist",
			settingDefault: "unset",
			optionalAttributes: [
				...stateAttr,
				...INPUT_INTERFACE_ATTRS,
				...LOG_ATTRS,
			],
			i18n: RULE_GLOSSES[`${table}-whitelist`],
		},
		{
			...where,
			id: `${table}-counting`,
			direction: "counting",
			action: "passthrough",
			actionSetting: null,
			match: null,
			createdByDefault: true,
			enabledBy: "metrics.track_processed",
			settingDefault: "true",
			optionalAttributes: [...INPUT_INTERFACE_ATTRS],
			i18n: RULE_GLOSSES[`${table}-counting`],
		},
		{
			...where,
			id: `${table}-deny`,
			direction: "input",
			action: "drop",
			actionSetting: "firewall.deny_action",
			match: { attribute: "src-address-list", kind: "banned" },
			createdByDefault: true,
			enabledBy: denyEnabledBy,
			settingDefault: "true",
			optionalAttributes: [
				...stateAttr,
				...INPUT_INTERFACE_ATTRS,
				...rejectAttr,
				...LOG_ATTRS,
			],
			i18n: RULE_GLOSSES[`${table}-deny`],
		},
	];
}

/** @type {ManagedRule[]} */
export const managedRules = [
	...inputSideBlock({
		table: "filter",
		chain: "input",
		chainSetting: "firewall.filter.chains",
		denyEnabledBy: "firewall.filter.enabled",
		connectionState: true,
		rejectWith: true,
	}),
	...inputSideBlock({
		table: "raw",
		chain: "prerouting",
		chainSetting: "firewall.raw.chains",
		denyEnabledBy: "firewall.raw.enabled",
		connectionState: false,
		rejectWith: false,
	}),
	{
		id: "filter-output",
		table: "filter",
		chain: "output",
		chainSetting: null,
		direction: "output",
		action: "drop",
		actionSetting: "firewall.deny_action",
		match: { attribute: "dst-address-list", kind: "banned" },
		createdByDefault: false,
		enabledBy: "firewall.block_output.enabled",
		settingDefault: "false",
		optionalAttributes: [
			{
				attribute: "src-address (negated)",
				setting: "firewall.block_output.passthrough_v4",
			},
			{
				attribute: "src-address-list (negated)",
				setting: "firewall.block_output.passthrough_v4_list",
			},
			{
				attribute: "out-interface",
				setting: "firewall.block_output.interface",
			},
			{
				attribute: "out-interface-list",
				setting: "firewall.block_output.interface_list",
			},
			REJECT_WITH_ATTR,
			...LOG_ATTRS,
		],
		i18n: RULE_GLOSSES["filter-output"],
	},
];

/** The rules a stock configuration writes, in the order the daemon creates them. */
export const defaultRules = managedRules.filter(
	(rule) => rule.createdByDefault,
);

/**
 * The passthrough rules `metrics.track_processed` creates. Exported by name
 * because they are the ones every earlier listing left out.
 */
export const countingRules = managedRules.filter(
	(rule) => rule.direction === "counting",
);

/**
 * How many rules land on the router for a given set of rule kinds, counting
 * both protocol families — `enabledProtos()` walks IPv4 and IPv6 and creates
 * the whole set for each.
 * @param {ManagedRule[]} [rules] Defaults to {@link defaultRules}.
 * @returns {number}
 */
export function ruleCount(rules = defaultRules) {
	return rules.length * FAMILIES.length;
}

/**
 * RouterOS menu path for a rule in one protocol family.
 * @param {ManagedRule} rule
 * @param {Family} family
 * @returns {string}
 */
export function menuPath(rule, family) {
	return `${family === "v6" ? "/ipv6" : "/ip"}/firewall/${rule.table}`;
}

/**
 * The address list the rule matches, or `null` when it matches none.
 * @param {ManagedRule} rule
 * @param {Family} family
 * @returns {string | null}
 */
export function addressListName(rule, family) {
	if (rule.match === null) return null;
	return rule.match.kind === "banned"
		? DEFAULT_ADDRESS_LISTS[family]
		: SAMPLE_WHITELIST_LIST;
}

/**
 * The comment the daemon writes, exactly — `buildRuleComment()` in manager.go
 * is `<prefix>:<table>-<chain>-<direction>-<family> <signature>`.
 * @param {ManagedRule} rule
 * @param {Family} family
 * @param {string} [prefix]
 * @returns {string}
 */
export function ruleComment(rule, family, prefix = DEFAULT_COMMENT_PREFIX) {
	return `${prefix}:${rule.table}-${rule.chain}-${rule.direction}-${family} ${RULE_SIGNATURE}`;
}

/**
 * The rule as a RouterOS `add` command, carrying only the attributes the
 * daemon actually sends for it under a stock configuration plus whatever
 * setting the rule itself is gated on. Optional attributes are deliberately
 * left out — they are listed separately, with the setting that adds each.
 * @param {ManagedRule} rule
 * @param {Family} family
 * @param {string} [prefix]
 * @returns {string}
 */
export function ruleCommand(rule, family, prefix = DEFAULT_COMMENT_PREFIX) {
	const parts = [
		`${menuPath(rule, family)} add`,
		`chain=${rule.chain}`,
		`action=${rule.action}`,
	];
	const list = addressListName(rule, family);
	if (rule.match !== null && list !== null) {
		parts.push(`${rule.match.attribute}=${list}`);
	}
	parts.push(`comment="${ruleComment(rule, family, prefix)}"`);
	return parts.join(" ");
}

/**
 * The human gloss for one locale, falling back to English for any locale the
 * module has not been translated into.
 * @param {ManagedRule} rule
 * @param {string} locale
 * @returns {RuleGloss}
 */
export function ruleGloss(rule, locale) {
	return locale === "es" ? rule.i18n.es : rule.i18n.en;
}

/**
 * What the daemon does NOT touch, which is as load-bearing as what it writes.
 *
 * `Shutdown()` calls `removeFirewallRules()` and nothing else: every rule above
 * is deleted, and not one address-list entry is. Entries are left to expire on
 * the MikroTik timeout they were written with — and `decisionTimeout()` returns
 * an empty string for any decision whose duration is zero or negative, which
 * `AddAddress()` then omits from the request, so RouterOS stores that entry with
 * no timeout at all. Those entries never expire on their own.
 */
export const addressListLifecycle = {
	/** Rules are removed on SIGTERM/SIGINT; address-list entries are not. */
	rulesRemovedOnShutdown: true,
	addressEntriesRemovedOnShutdown: false,
	/** Entries carry the CrowdSec decision duration as their RouterOS timeout. */
	timeoutSource: "CrowdSec decision duration",
	/** A decision with no positive duration produces an entry with no timeout. */
	entriesWithoutTimeout: "decisions whose duration is zero or negative",
	i18n: {
		en: {
			title: "What the daemon leaves behind",
			body: "Shutdown removes every rule above and no address-list entry. Entries expire on their own MikroTik timeout, which is the CrowdSec decision duration; protection therefore outlives the daemon by whatever is left of it.",
			caveat:
				"A decision whose duration resolves to zero or less — CrowdSec does emit negative remaining durations — is written with no timeout at all, so that entry stays on the router until something removes it: the next reconciliation, or you. A decision carrying no duration field is discarded earlier and never reaches the router.",
		},
		es: {
			title: "Lo que el daemon deja atrás",
			body: "Al apagarse elimina todas las reglas anteriores y ninguna entrada de las address-lists. Las entradas expiran por su propio timeout de MikroTik, que es la duración de la decisión de CrowdSec; la protección, por tanto, sobrevive al daemon lo que quede de ella.",
			caveat:
				"Una decisión cuya duración resuelve a cero o menos —CrowdSec sí emite duraciones restantes negativas— se escribe sin timeout alguno, así que esa entrada permanece en el router hasta que algo la elimine: la siguiente reconciliación, o tú. Una decisión que no trae campo de duración se descarta antes y nunca llega al router.",
		},
	},
};
