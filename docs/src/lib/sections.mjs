/**
 * The sidebar group each URL segment belongs to, per language.
 *
 * Shared because two things need it and they must agree: the breadcrumb JSON-LD
 * in `Head.astro`, and the kicker line on each page's social card. A card
 * naming a section the breadcrumb calls something else is the kind of small
 * contradiction nobody reports and everybody notices.
 */
/** @type {Record<string, Record<string, string>>} */
export const SEGMENT_LABELS = {
	en: {
		"getting-started": "Getting Started",
		configuration: "Configuration",
		architecture: "Architecture",
		monitoring: "Monitoring",
		development: "Development",
	},
	es: {
		"getting-started": "Primeros pasos",
		configuration: "Configuración",
		architecture: "Arquitectura",
		monitoring: "Monitorización",
		development: "Desarrollo",
	},
};

/** Name of the root breadcrumb, per language. */
/** @type {Record<string, string>} */
export const HOME_LABELS = {
	en: "Home",
	es: "Inicio",
};

/**
 * The kicker for a page that sits directly under the locale root.
 *
 * Not the project name: the social card already carries that on its footer
 * line, and a card whose eyebrow and footer say the same words twice reads as
 * a template someone forgot to fill in.
 */
/** @type {Record<string, string>} */
export const ROOT_KICKER = {
	en: "Documentation",
	es: "Documentación",
};

/**
 * The card path for a page, from whichever id the caller happens to hold.
 *
 * Two callers name the same page differently: the content collection calls the
 * English home page `index`, and Starlight's route for it has an empty id. They
 * agreed on every other page, so pointing each at its own id produced a working
 * site with exactly one broken card — the home page's, which is the one most
 * links point at. Normalising in one place is what keeps them from drifting
 * apart again.
 * @param {string} id
 * @returns {string}
 */
export function cardPath(id) {
	return id === "" ? "index" : id;
}
