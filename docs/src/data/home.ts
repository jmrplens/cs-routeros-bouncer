/**
 * The landing page, as one typed content contract.
 *
 * WHY THIS FILE EXISTS
 *
 * `index.mdx` and `es/index.mdx` used to be parallel hand-written twins: the
 * same four flow steps, the same feature cards, the same five FAQ entries and
 * the same four link cards, authored twice. The FAQ was worse than twice — each
 * answer existed FOUR times, once in the JSON-LD `mainEntity` and once in the
 * visible `<details>`, in each of the two files. Nothing compared those copies,
 * so the machine-readable answer and the human one were free to disagree, and
 * a section added to one locale simply never appeared in the other.
 *
 * Now both locales are values of the same {@link HomeContent} type. `astro
 * check` runs in the `analyze` chain, so structural parity is a compile-time
 * test that costs nothing: add a card to `en` and not to `es` and the build
 * fails with the missing property — in the editor, before that.
 *
 * WHERE DRIFT CAN STILL HIDE
 *
 * Two places, both deliberate, both narrowed as far as they go:
 *
 *   1. OPTIONAL FIELDS. A field marked `?` is a field TypeScript will not make
 *      you fill in, so one locale may carry it where its twin does not. Exactly
 *      two exist here — {@link DisclosureFact.link} and {@link Requirement.note}
 *      — and each is optional because the *content* is genuinely per-item, not
 *      to make authoring easier. Do not add a third without the same argument.
 *      Anything that must exist in both locales stays required even when it is
 *      a nuisance to translate; that nuisance is the test doing its job.
 *
 *   2. THE `##` HEADINGS. They stay in the MDX, as prose, because Starlight
 *      builds the "On this page" table of contents from the markdown AST — a
 *      heading emitted by a component is invisible to it, and moving them here
 *      would silently empty the landing's ToC. `scripts/check-i18n-parity.mjs`
 *      compares the heading *sequence* of every twin pair, so a section added
 *      to one side still fails a gate; only the heading text itself is
 *      unguarded, and that is the one string on the page a reader can check
 *      against the section sitting under it.
 *
 * NO HAND-TYPED FACTS
 *
 * Every version, count, measurement and default below is interpolated from the
 * module that derives it — `repo-stats.mjs` (go.mod, .goreleaser.yaml, the
 * README tables, git), `rules.mjs` (manager.go) and `config-schema.json`
 * (config.go). A literal number in this file is a bug: it means a fact was
 * copied instead of read, and the copy will outlive the thing it came from.
 */
import schema from "./config-schema.json";
import {
	banLatency,
	crowdsecMinVersion,
	goVersionMajorMinor,
	releasePlatforms,
	routerosGeneration,
	supportedDecisionTypes,
} from "./repo-stats.mjs";
import { DEFAULT_ADDRESS_LISTS, defaultRules, ruleCount } from "./rules.mjs";

/* ------------------------------------------------------------------
   1. DERIVED VALUES
   Each names the module it comes from, so a reader can check any of
   them without leaving this file.
   ------------------------------------------------------------------ */

const options = schema.options as Record<string, { default: unknown }>;

/**
 * A configuration default, read from the schema `extract-config-schema.mjs`
 * extracts out of `internal/config/config.go`. Throws on an unknown key rather
 * than rendering `undefined`: a setting renamed in Go should break this build,
 * not publish a blank.
 */
function configDefault(path: string): string {
	const option = options[path];
	if (option === undefined) {
		throw new Error(
			`src/data/home.ts: no configuration key "${path}" in config-schema.json — ` +
				"it was renamed or removed in internal/config/config.go. Re-run " +
				"`pnpm run config:extract`, then update the landing copy that cites it.",
		);
	}
	return String(option.default);
}

/**
 * Asserts a configuration default is still the one a sentence below asserts in
 * words. Some claims cannot be interpolated — "no origin is filtered out" is
 * the English for `[]`, and no template literal renders that. So the sentence
 * stays prose and this holds it to the schema: change the default in Go and the
 * build stops here, with the sentence that has to be rewritten.
 */
function assertConfigDefault(path: string, expected: unknown, claim: string) {
	const actual = options[path]?.default;
	if (JSON.stringify(actual) !== JSON.stringify(expected)) {
		throw new Error(
			`src/data/home.ts: the landing states "${claim}", which assumes ` +
				`${path} defaults to ${JSON.stringify(expected)}; config-schema.json ` +
				`now says ${JSON.stringify(actual)}. Rewrite the sentence, then this check.`,
		);
	}
}

/** `firewall.rule_placement.strategy` — `top`, i.e. above your own rules. */
const placementDefault = configDefault("firewall.rule_placement.strategy");

/** How many rules a stock configuration puts on the router: kinds × families. */
const stockRuleCount = ruleCount(defaultRules);
/** How many rule *kinds* that is, before the IPv4/IPv6 doubling. */
const stockRuleKinds = defaultRules.length;

/**
 * The decision type enforced out of the box.
 *
 * Both locales set this inside a sentence written in the singular ("… is the
 * only one enforced by default"). Joining a longer list would render a list
 * inside that sentence and no gate would notice, so the cardinality is asserted
 * rather than assumed — the default is now operator-configurable, which makes
 * the schema default the only thing holding the prose up.
 */
if (supportedDecisionTypes.length !== 1) {
	throw new Error(
		`The landing copy states one enforced decision type, but the schema default ` +
			`for crowdsec.supported_decisions_types is [${supportedDecisionTypes.join(", ")}]. ` +
			`Rewrite the "One decision type" fact in both locales before changing that default.`,
	);
}
const implementedDecisionType = supportedDecisionTypes[0];

/**
 * The RouterOS API service ports.
 *
 * The one pair of numbers on this page that is NOT derived, and the reason is
 * that nothing in this repository asserts them: they are MikroTik's own fixed
 * service ports, not a default this project sets. `mikrotik.address` is a
 * host:port string with no default at all, and neither number appears anywhere
 * in `internal/`, so there is nothing to read them out of.
 *
 * They are therefore stated once, here, and interpolated into both the
 * requirements list and the FAQ answer that cite them — which buys the property
 * that actually mattered: the two cannot disagree, and neither can the English
 * page and its Spanish twin.
 */
const ROUTEROS_API_PORTS = { plain: 8728, tls: 8729 };

/** "16 prebuilt binaries across 4 operating systems" — see the note in repo-stats.mjs. */
const binaryCount = releasePlatforms.binaryCount;
const operatingSystemCount = releasePlatforms.operatingSystems.length;

assertConfigDefault(
	"crowdsec.origins",
	[],
	"crowdsec.origins is empty by default, so no origin is filtered out",
);
// Deliberately NOT guarded against crowdsec.supported_decisions_types. That key
// is declared, defaulted and mapped to CROWDSEC_DECISIONS_TYPES, and then read by
// nothing: the Local API query hardcodes `type=ban` (internal/crowdsec/stream.go).
// Asserting the claim against that key would have been a tautology — both sides
// read the same generated schema entry — and would have implied the setting is
// load-bearing when it is inert.

/* ------------------------------------------------------------------
   2. THE CONTRACT
   ------------------------------------------------------------------ */

/** A link that travels with the sentence it belongs to. */
export interface Link {
	text: string;
	href: string;
}

/**
 * A run of prose, or a fragment to set in `<code>`.
 *
 * The datasheet copy has to name settings and address lists mid-sentence, and
 * these strings are rendered as text, not as markdown — a backtick in one would
 * publish as a backtick. Splitting the sentence is more typing than a markdown
 * convention would be, and it buys the thing a convention cannot: both locales
 * are forced to spell out which fragment is a literal, so a setting path cannot
 * end up styled as code on one page and as prose on the other.
 */
export type Segment = string | { code: string };

/**
 * One step of the "how it works" strip. The ordinal is the array index and is
 * never a field — a hand-numbered step is a step that can be numbered twice.
 */
export interface FlowStep {
	title: string;
	description: string;
}

/** One feature card. No icon field by design: see the note on {@link HomeContent.why}. */
export interface WhyCard {
	title: string;
	body: string;
}

/**
 * One line of the disclosure block's limits column: a short label and the flat
 * statement under it.
 */
export interface DisclosureFact {
	/** Two to six words, plain. Rendered as the `<dt>`. */
	term: string;
	/** The statement itself. One or two sentences, no hedging, no apology. */
	detail: Segment[];
	/**
	 * OPTIONAL BY DESIGN (1 of 2). Some limits have a page carrying the whole
	 * story and some are complete in two sentences; forcing a link on the
	 * latter would mean inventing a destination. A locale may therefore link a
	 * fact its twin does not — the only asymmetry this field permits, and it
	 * changes no statement.
	 */
	link?: Link;
}

/** The disclosure block — "What it writes to your router". */
export interface DisclosureSection {
	/** The paragraph that opens the block: enforcement, not decision-making. */
	lead: string;
	/** The first panel: the literal rules, rendered from `rules.mjs`. */
	writes: {
		title: string;
		/** Sentence above the rule listing. */
		caption: string;
		/** Sentence below it, about the address lists and the counting rules. */
		footnote: Segment[];
	};
	/** The second panel: the limits. */
	limits: {
		title: string;
		facts: DisclosureFact[];
	};
}

/** One requirement, as a term and its detail. */
export interface Requirement {
	term: string;
	detail: string;
	/**
	 * OPTIONAL BY DESIGN (2 of 2). A parenthetical only some requirements have —
	 * the API port pair, for instance. It sits on the same item in both locales
	 * today; nothing enforces that and nothing needs to, because the requirement
	 * itself is in `detail`.
	 */
	note?: string;
}

/**
 * One FAQ entry. This single array renders the visible `<details>` AND the
 * `FAQPage` JSON-LD, so the two cannot disagree — which is the whole point.
 * `answer` is therefore plain prose: no markdown, no markup, no segments,
 * because the structured-data copy is emitted as a bare string.
 */
export interface FaqEntry {
	question: string;
	answer: string;
}

/** One card in the "explore the docs" grid. */
export interface ExploreLink {
	title: string;
	description: string;
	href: string;
}

export interface HomeContent {
	/** Drives `ruleGloss()`, `addressListLifecycle.i18n` and the JSON-LD `inLanguage`. */
	locale: "en" | "es";
	flow: FlowStep[];
	/**
	 * The feature cards. Deliberately no icon field: the page used to pass
	 * Starlight's stock icon names for concepts they did not describe
	 * (`icon="random"` for "Self-Healing State"), which is decoration that
	 * misinforms. The section rules and the ordinals carry the structure now.
	 */
	why: {
		lead: string;
		link: Link;
		cards: WhyCard[];
	};
	disclosure: DisclosureSection;
	requirements: Requirement[];
	faq: FaqEntry[];
	explore: ExploreLink[];
}

/* ------------------------------------------------------------------
   3. ENGLISH
   ------------------------------------------------------------------ */

export const en: HomeContent = {
	locale: "en",
	flow: [
		{
			title: "CrowdSec decides",
			description: "The Local API holds a decision about an address.",
		},
		{
			title: "The bouncer syncs",
			description: "It reads new decisions and expires the ones that ended.",
		},
		{
			title: "RouterOS enforces",
			description:
				"Addresses land on a firewall address list the managed rules match.",
		},
		{
			title: "You watch it",
			description:
				"Prometheus metrics, a health endpoint and a Grafana dashboard.",
		},
	],
	why: {
		lead: "Most MikroTik bouncers regenerate an address list from a scheduled script. This one keeps a session open and applies each CrowdSec decision as a single call to",
		link: {
			text: "the RouterOS API",
			href: "https://help.mikrotik.com/docs/spaces/ROS/pages/47579160/API",
		},
		cards: [
			{
				title: "No manual router commands",
				body: `It writes the ${stockRuleCount} rules a stock configuration needs when it starts and removes them when it stops. You configure the bouncer, not the router.`,
			},
			{
				title: `Per-decision writes (${banLatency.label}/op)`,
				body: `One address added on ban, one removed on unban, at roughly ${banLatency.min}–${banLatency.max} ${banLatency.unit} each. No bulk re-upload, no duplicates.`,
			},
			{
				title: "Reconciliation, not hope",
				body: "At startup and on an interval it compares the Local API against what is actually on the router, then adds what is missing and removes what is stale.",
			},
			{
				title: "Observable while it runs",
				body: "Prometheus metrics for decisions, RouterOS CPU and dropped traffic; structured logs; a health endpoint; a Grafana dashboard in the repository.",
			},
			{
				title: "One binary, MIT-licensed",
				body: `Built with Go ${goVersionMajorMinor} and published as ${binaryCount} prebuilt binaries across ${operatingSystemCount} operating systems, plus multi-architecture Docker images.`,
			},
		],
	},
	disclosure: {
		lead: "CrowdSec decides which addresses are hostile. This bouncer enforces that decision and does nothing else — no detection, no scoring, no opinion of its own. Enforcing means writing to a production firewall, so here is the whole of what it writes, and the whole of what it will not clean up for you.",
		writes: {
			title: "What it writes",
			caption: `A stock configuration puts ${stockRuleCount} rules on the router: ${stockRuleKinds} kinds, one set per protocol family. These, verbatim.`,
			footnote: [
				"Banned addresses go on ",
				{ code: DEFAULT_ADDRESS_LISTS.v4 },
				" and ",
				{ code: DEFAULT_ADDRESS_LISTS.v6 },
				". The two passthrough rules match no address list and take no decision; they count the packets the block evaluates, which is what makes “evaluated” and “dropped” two separate numbers in the metrics.",
			],
		},
		limits: {
			title: "What it does not do",
			facts: [
				{
					term: "It enforces; it does not decide",
					detail: [
						"Every ban comes from CrowdSec. Take CrowdSec away and this has nothing to write: no scenarios, no scoring, no address of its own.",
					],
					link: {
						text: "How a decision becomes a rule",
						href: "/cs-routeros-bouncer/architecture/decisions/",
					},
				},
				{
					term: "One decision type, not four",
					detail: [
						"Of the CrowdSec decision types, ",
						{ code: implementedDecisionType },
						" is the only one enforced by default. The bouncer has exactly one action — put the address on a list the firewall drops — so a captcha decision could be listed in ",
						{ code: "crowdsec.supported_decisions_types" },
						" but would be enforced as a block, which is not what a captcha means. The setting is there for custom decision types that do mean \u201cblock\u201d.",
					],
					link: {
						text: "How decisions are processed",
						href: "/cs-routeros-bouncer/architecture/decisions/",
					},
				},
				{
					term: "The rules go in at the top",
					detail: [
						"By default the managed block is inserted at the top of every chain it touches, above your existing rules: ",
						{ code: "firewall.rule_placement.strategy" },
						" is ",
						{ code: placementDefault },
						" by default. For an operator whose ruleset is ordered deliberately this is the most consequential thing the bouncer does to it — so it is worth saying that placement is the most configurable thing here, not the least: five strategies (",
						{ code: "top" },
						", ",
						{ code: "bottom" },
						", ",
						{ code: "before_comment" },
						", ",
						{ code: "after_comment" },
						", ",
						{ code: "position" },
						"), each overridable per table and per protocol family, with a fallback for when the anchor rule is missing.",
					],
					link: {
						text: "Rule placement",
						href: "/cs-routeros-bouncer/configuration/firewall/",
					},
				},
				{
					term: "The first sync is a bulk import",
					detail: [
						"The first reconciliation pulls every active decision the Local API holds, CrowdSec's CAPI community blocklists included: ",
						{ code: "crowdsec.origins" },
						" is empty by default, so no origin is filtered out. That is tens of thousands of addresses written in one pass, and on a small router you will watch it happen in the CPU graph.",
					],
					link: {
						text: "CAPI blocklists",
						href: "/cs-routeros-bouncer/configuration/capi-blocklists/",
					},
				},
				{
					term: "Every reconciliation pass costs the router CPU",
					detail: [
						"Not only at startup, and not only when there is drift to repair: the pass runs on every ",
						{ code: "crowdsec.reconciliation_interval" },
						" tick and re-reads the whole address list each time, because RouterOS evaluates address-list queries with an unindexed linear scan. Measured on an RB5009 holding 21,600 entries: a CPU transient peaking at 29–34% against a 7% baseline, lasting about six seconds, in 11 of 11 consecutive cycles. At the default 15-minute interval that is four transients an hour.",
						" Your own monitoring may well not show it — the standard SNMP ",
						{ code: "hrProcessorLoad" },
						" OID reports a one-minute average, which flattens a six-second spike to roughly 9%.",
					],
					link: {
						text: "Performance tuning",
						href: "/cs-routeros-bouncer/configuration/performance-tuning/",
					},
				},
			],
		},
	},
	requirements: [
		{
			term: `CrowdSec ${crowdsecMinVersion}+`,
			detail: "with the Local API reachable from the host running the bouncer",
		},
		{
			term: `MikroTik RouterOS ${routerosGeneration}`,
			detail: "with the API service enabled",
			note: `port ${ROUTEROS_API_PORTS.plain}, or ${ROUTEROS_API_PORTS.tls} for TLS`,
		},
		{
			term: "A dedicated RouterOS API user",
			detail:
				"with permission to read and write firewall rules and address lists",
		},
	],
	faq: [
		{
			question: "What is cs-routeros-bouncer?",
			answer:
				"cs-routeros-bouncer is a free, open-source CrowdSec bouncer for MikroTik RouterOS. It syncs CrowdSec ban/unban decisions into RouterOS firewall rules (filter and raw, IPv4 and IPv6) through the RouterOS API, with startup and periodic reconciliation, Prometheus metrics, and safe rule cleanup.",
		},
		{
			question: "Which CrowdSec and RouterOS versions does it support?",
			answer: `It requires CrowdSec ${crowdsecMinVersion}+ with the Local API (LAPI) reachable from the bouncer host, and MikroTik RouterOS ${routerosGeneration} with the API service enabled (port ${ROUTEROS_API_PORTS.plain}, or ${ROUTEROS_API_PORTS.tls} for TLS), using a dedicated RouterOS API user with the appropriate permissions.`,
		},
		{
			question: "Is cs-routeros-bouncer free and open source?",
			answer:
				"Yes. cs-routeros-bouncer is MIT-licensed, written in Go, distributed as a single static binary, with the full source on GitHub and no paid tier.",
		},
		{
			question: "Does cs-routeros-bouncer support IPv6?",
			answer:
				"Yes. Each RouterOS rule type it manages (filter input, raw prerouting, and optional filter output) has an IPv6 equivalent, and IPv4/IPv6 rule placement can be configured together or overridden independently per protocol.",
		},
		{
			question:
				"How is cs-routeros-bouncer different from address-list or script-based CrowdSec bouncers for MikroTik?",
			answer: `cs-routeros-bouncer talks to the RouterOS API directly and applies each ban or unban as an individual real-time call (about ${banLatency.min}–${banLatency.max} ${banLatency.unit}), instead of periodically regenerating address lists via scheduled scripts. It also runs startup and periodic reconciliation against MikroTik's actual state, so drift is repaired automatically.`,
		},
	],
	explore: [
		{
			title: "Quick Start",
			description: "Get up and running in 5 minutes with Docker or systemd.",
			href: "/cs-routeros-bouncer/getting-started/quickstart/",
		},
		{
			title: "Configuration Reference",
			description: "All configuration options explained with examples.",
			href: "/cs-routeros-bouncer/configuration/",
		},
		{
			title: "Monitoring & Metrics",
			description: "Prometheus metrics, Grafana dashboard, and health checks.",
			href: "/cs-routeros-bouncer/monitoring/prometheus/",
		},
		{
			title: "Troubleshooting",
			description: "Common issues and their solutions.",
			href: "/cs-routeros-bouncer/troubleshooting/",
		},
	],
};

/* ------------------------------------------------------------------
   4. SPANISH
   The same type, therefore the same sections in the same order. Only
   the prose is translated: every version, count, default and
   address-list name is the same interpolation as above.
   ------------------------------------------------------------------ */

export const es: HomeContent = {
	locale: "es",
	flow: [
		{
			title: "CrowdSec decide",
			description: "La Local API tiene una decisión sobre una dirección.",
		},
		{
			title: "El bouncer sincroniza",
			description:
				"Lee las decisiones nuevas y da por vencidas las que terminaron.",
		},
		{
			title: "RouterOS la aplica",
			description:
				"Las direcciones llegan a una address-list que las reglas gestionadas usan.",
		},
		{
			title: "Tú lo vigilas",
			description:
				"Métricas de Prometheus, endpoint de salud y panel de Grafana.",
		},
	],
	why: {
		lead: "La mayoría de los bouncers para MikroTik regeneran una address-list desde un script programado. Este mantiene abierta una sesión y aplica cada decisión de CrowdSec como una sola llamada a",
		link: {
			text: "la API de RouterOS",
			href: "https://help.mikrotik.com/docs/spaces/ROS/pages/47579160/API",
		},
		cards: [
			{
				title: "Ningún comando manual en el router",
				body: `Escribe las ${stockRuleCount} reglas que necesita una configuración de partida al arrancar y las elimina al parar. Configuras el bouncer, no el router.`,
			},
			{
				title: `Una escritura por decisión (${banLatency.label}/op)`,
				body: `Una dirección añadida al banear y una eliminada al desbanear, en torno a ${banLatency.min}–${banLatency.max} ${banLatency.unit} cada una. Sin recargas masivas y sin duplicados.`,
			},
			{
				title: "Reconciliación, no confianza",
				body: "Al arrancar y de forma periódica compara la Local API con lo que hay realmente en el router; después añade lo que falta y elimina lo obsoleto.",
			},
			{
				title: "Observable mientras funciona",
				body: "Métricas de Prometheus de decisiones, CPU de RouterOS y tráfico descartado; logs estructurados; endpoint de salud; panel de Grafana en el repositorio.",
			},
			{
				title: "Un binario, licencia MIT",
				body: `Compilado con Go ${goVersionMajorMinor} y publicado como ${binaryCount} binarios precompilados para ${operatingSystemCount} sistemas operativos, más imágenes Docker multiarquitectura.`,
			},
		],
	},
	disclosure: {
		lead: "CrowdSec decide qué direcciones son hostiles. Este bouncer aplica esa decisión y nada más: no tiene detección, ni puntuación, ni criterio propio. Aplicarla significa escribir en un firewall en producción, así que aquí está todo lo que escribe y todo lo que no va a limpiar por ti.",
		writes: {
			title: "Lo que escribe",
			caption: `Una configuración de partida deja ${stockRuleCount} reglas en el router: ${stockRuleKinds} tipos, un juego por familia de protocolo. Estas, literalmente.`,
			footnote: [
				"Las direcciones baneadas van a ",
				{ code: DEFAULT_ADDRESS_LISTS.v4 },
				" y ",
				{ code: DEFAULT_ADDRESS_LISTS.v6 },
				". Las dos reglas passthrough no coinciden con ninguna address-list ni toman ninguna decisión; cuentan los paquetes que evalúa el bloque, que es lo que hace que «evaluados» y «descartados» sean dos cifras distintas en las métricas.",
			],
		},
		limits: {
			title: "Lo que no hace",
			facts: [
				{
					term: "Aplica; no decide",
					detail: [
						"Todos los baneos vienen de CrowdSec. Sin CrowdSec no tiene nada que escribir: ni escenarios, ni puntuación, ni direcciones propias.",
					],
					link: {
						text: "Cómo una decisión se convierte en regla",
						href: "/cs-routeros-bouncer/es/architecture/decisions/",
					},
				},
				{
					term: "Un tipo de decisión, no cuatro",
					detail: [
						"De los tipos de decisión de CrowdSec, ",
						{ code: implementedDecisionType },
						" es el único que se aplica por defecto. El bouncer tiene exactamente una acción —poner la dirección en una lista que el firewall descarta— así que una decisión de captcha podría listarse en ",
						{ code: "crowdsec.supported_decisions_types" },
						" pero se aplicaría como bloqueo, que no es lo que significa un captcha. El ajuste está para tipos personalizados que sí signifiquen \u201cbloquear\u201d.",
					],
					link: {
						text: "Cómo se procesan las decisiones",
						href: "/cs-routeros-bouncer/es/architecture/decisions/",
					},
				},
				{
					term: "Las reglas entran arriba del todo",
					detail: [
						"Por defecto el bloque gestionado se inserta en lo alto de cada chain que toca, por encima de tus reglas existentes: ",
						{ code: "firewall.rule_placement.strategy" },
						" vale ",
						{ code: placementDefault },
						" por defecto. Para quien tiene su conjunto de reglas ordenado a conciencia esto es lo más determinante que le hace el bouncer, así que conviene decir que la ubicación es lo más configurable de todo esto, no lo menos: cinco estrategias (",
						{ code: "top" },
						", ",
						{ code: "bottom" },
						", ",
						{ code: "before_comment" },
						", ",
						{ code: "after_comment" },
						", ",
						{ code: "position" },
						"), cada una redefinible por tabla y por familia de protocolo, con un fallback para cuando la regla ancla no existe.",
					],
					link: {
						text: "Ubicación de las reglas",
						href: "/cs-routeros-bouncer/es/configuration/firewall/",
					},
				},
				{
					term: "La primera sincronización es una importación masiva",
					detail: [
						"La primera reconciliación se trae todas las decisiones activas que tiene la Local API, incluidas las listas de bloqueo comunitarias CAPI de CrowdSec: ",
						{ code: "crowdsec.origins" },
						" está vacío por defecto, así que no se filtra ningún origen. Son decenas de miles de direcciones escritas de una sola vez, y en un router pequeño lo vas a ver pasar en la gráfica de CPU.",
					],
					link: {
						text: "Listas de bloqueo CAPI",
						href: "/cs-routeros-bouncer/es/configuration/capi-blocklists/",
					},
				},
				{
					term: "Cada pasada de reconciliación cuesta CPU del router",
					detail: [
						"No solo al arrancar, ni solo cuando hay desviación que reparar: la pasada corre en cada tick de ",
						{ code: "crowdsec.reconciliation_interval" },
						" y vuelve a leer la lista de direcciones entera, porque RouterOS resuelve las consultas de address-list con un escaneo lineal sin índice. Medido en un RB5009 con 21.600 entradas: un transitorio con pico del 29-34% sobre una base del 7%, de unos seis segundos, en 11 de 11 ciclos consecutivos. Con el intervalo por defecto de 15 minutos son cuatro transitorios por hora.",
						" Es probable que tu monitorización no lo vea: el OID SNMP estándar ",
						{ code: "hrProcessorLoad" },
						" reporta una media de un minuto, que aplana un pico de seis segundos hasta un 9% aproximado.",
					],
					link: {
						text: "Ajuste de rendimiento",
						href: "/cs-routeros-bouncer/es/configuration/performance-tuning/",
					},
				},
			],
		},
	},
	requirements: [
		{
			term: `CrowdSec ${crowdsecMinVersion}+`,
			detail: "con la Local API accesible desde el host donde corre el bouncer",
		},
		{
			term: `MikroTik RouterOS ${routerosGeneration}`,
			detail: "con el servicio API habilitado",
			note: `puerto ${ROUTEROS_API_PORTS.plain}, u ${ROUTEROS_API_PORTS.tls} para TLS`,
		},
		{
			term: "Un usuario dedicado de la API de RouterOS",
			detail:
				"con permiso para leer y escribir reglas de firewall y address-lists",
		},
	],
	faq: [
		{
			question: "¿Qué es cs-routeros-bouncer?",
			answer:
				"cs-routeros-bouncer es un bouncer de CrowdSec gratuito y de código abierto para MikroTik RouterOS. Sincroniza las decisiones de bloqueo/desbloqueo de CrowdSec con las reglas del firewall de RouterOS (filter y raw, IPv4 e IPv6) a través de la API de RouterOS, con reconciliación al inicio y periódica, métricas de Prometheus y limpieza segura de reglas.",
		},
		{
			question: "¿Qué versiones de CrowdSec y RouterOS soporta?",
			answer: `Requiere CrowdSec ${crowdsecMinVersion}+ con la Local API (LAPI) accesible desde el host del bouncer, y MikroTik RouterOS ${routerosGeneration} con el servicio API habilitado (puerto ${ROUTEROS_API_PORTS.plain}, u ${ROUTEROS_API_PORTS.tls} para TLS), usando un usuario dedicado de la API de RouterOS con los permisos apropiados.`,
		},
		{
			question: "¿Es cs-routeros-bouncer gratuito y de código abierto?",
			answer:
				"Sí. cs-routeros-bouncer tiene licencia MIT, está escrito en Go, se distribuye como un único binario estático, con el código fuente completo en GitHub y sin planes de pago.",
		},
		{
			question: "¿Soporta cs-routeros-bouncer IPv6?",
			answer:
				"Sí. Cada tipo de regla de RouterOS que gestiona (filter input, raw prerouting y opcionalmente filter output) tiene un equivalente IPv6, y la ubicación de las reglas IPv4/IPv6 puede configurarse de forma conjunta o sobrescribirse de forma independiente por protocolo.",
		},
		{
			question:
				"¿En qué se diferencia cs-routeros-bouncer de los bouncers de CrowdSec para MikroTik basados en address-list o en scripts?",
			answer: `cs-routeros-bouncer se comunica directamente con la API de RouterOS y aplica cada bloqueo o desbloqueo como una llamada individual en tiempo real (alrededor de ${banLatency.min}–${banLatency.max} ${banLatency.unit}), en lugar de regenerar periódicamente listas de direcciones mediante scripts programados. También ejecuta una reconciliación al inicio y periódica contra el estado real de MikroTik, de modo que las desviaciones se reparan automáticamente.`,
		},
	],
	explore: [
		{
			title: "Inicio rápido",
			description: "Ponlo en marcha en 5 minutos con Docker o systemd.",
			href: "/cs-routeros-bouncer/es/getting-started/quickstart/",
		},
		{
			title: "Referencia de configuración",
			description:
				"Todas las opciones de configuración explicadas con ejemplos.",
			href: "/cs-routeros-bouncer/es/configuration/",
		},
		{
			title: "Monitorización y métricas",
			description:
				"Métricas de Prometheus, panel de Grafana y comprobaciones de salud.",
			href: "/cs-routeros-bouncer/es/monitoring/prometheus/",
		},
		{
			title: "Solución de problemas",
			description: "Problemas comunes y sus soluciones.",
			href: "/cs-routeros-bouncer/es/troubleshooting/",
		},
	],
};

/** Both locales, keyed the way `Astro.url.pathname` resolves them. */
export const home: Record<"en" | "es", HomeContent> = { en, es };
