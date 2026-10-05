/**
 * The human gloss for every rule in `rules.mjs` — a name, a sentence of
 * purpose and a note, in English and Spanish — keyed by rule id.
 *
 * Only prose lives here. Every chain, action, attribute, setting path and
 * comment string stays in `rules.mjs` and is rendered from the same fields in
 * both locales, so nothing below can make a rule right in one language and
 * wrong in the other. The entries share one shape by construction, which is
 * why sonar-project.properties keeps this file out of copy-paste detection.
 */

/** @type {Record<string, { en: import("./rules.mjs").RuleGloss, es: import("./rules.mjs").RuleGloss }>} */
export const RULE_GLOSSES = {
	"filter-whitelist": {
		en: {
			name: "Filter whitelist",
			purpose:
				"Accepts traffic from an address list you control before any bouncer rule can drop it, so a source you have vouched for is never blocked by a CrowdSec decision.",
			note: "It is first in the block on purpose: RouterOS evaluates a chain top to bottom, so an accept placed after the drop would never be reached.",
		},
		es: {
			name: "Whitelist de filter",
			purpose:
				"Acepta el tráfico de una address-list que tú controlas antes de que ninguna regla del bouncer pueda descartarlo, de modo que un origen que has avalado nunca queda bloqueado por una decisión de CrowdSec.",
			note: "Va primera en el bloque a propósito: RouterOS evalúa la chain de arriba abajo, así que un accept colocado después del drop no se alcanzaría nunca.",
		},
	},
	"filter-counting": {
		en: {
			name: "Filter counting",
			purpose:
				"Counts every packet the filter chain hands to the bouncer's block, which is what the processed byte and packet metrics report.",
			note: "It matches no address list and takes no decision — passthrough only increments counters — which is exactly why it looks like a stray rule on the router.",
		},
		es: {
			name: "Contador de filter",
			purpose:
				"Cuenta cada paquete que la chain de filter entrega al bloque del bouncer, que es lo que informan las métricas de bytes y paquetes procesados.",
			note: "No coincide con ninguna address-list ni toma ninguna decisión —passthrough solo incrementa contadores—, y por eso mismo parece una regla suelta en el router.",
		},
	},
	"filter-deny": {
		en: {
			name: "Filter deny",
			purpose:
				"Drops inbound traffic whose source address is on the banned list, after connection tracking has run.",
			note: "Set firewall.deny_action to reject and this rule rejects instead, carrying reject-with when one is configured; the IPv6 rule carries its ICMPv6 equivalent.",
		},
		es: {
			name: "Denegación de filter",
			purpose:
				"Descarta el tráfico entrante cuya dirección de origen está en la address-list de baneados, después de que se haya ejecutado el connection tracking.",
			note: "Si firewall.deny_action se establece en reject, esta regla rechaza en lugar de descartar, e incluye reject-with cuando hay uno configurado; la regla IPv6 lleva su equivalente ICMPv6.",
		},
	},
	"raw-whitelist": {
		en: {
			name: "Raw whitelist",
			purpose:
				"The same exemption as the filter whitelist, one step earlier in the pipeline, so a vouched-for source is never dropped before connection tracking either.",
			note: "The raw table has no connection tracking, so this rule never carries connection-state even when firewall.filter.connection_state is set.",
		},
		es: {
			name: "Whitelist de raw",
			purpose:
				"La misma exención que la whitelist de filter, un paso antes en la cadena de procesado, para que un origen avalado tampoco se descarte antes del connection tracking.",
			note: "La tabla raw no tiene connection tracking, así que esta regla nunca lleva connection-state aunque firewall.filter.connection_state esté configurado.",
		},
	},
	"raw-counting": {
		en: {
			name: "Raw counting",
			purpose:
				"Counts every packet the raw chain hands to the bouncer's block, feeding the same processed metrics as its filter twin.",
			note: "Like the filter counting rule it matches no address list; its counters are what makes “evaluated” and “dropped” two separate numbers.",
		},
		es: {
			name: "Contador de raw",
			purpose:
				"Cuenta cada paquete que la chain de raw entrega al bloque del bouncer y alimenta las mismas métricas de procesados que su gemela de filter.",
			note: "Igual que el contador de filter, no coincide con ninguna address-list; sus contadores son los que hacen que «evaluados» y «descartados» sean dos cifras distintas.",
		},
	},
	"raw-deny": {
		en: {
			name: "Raw deny",
			purpose:
				"Drops banned sources before connection tracking, which is the cheapest place in RouterOS to discard a flood.",
			note: "RouterOS raw rules cannot reject, so firewall.deny_action: reject is written here as drop — this is the one rule whose action does not follow that setting.",
		},
		es: {
			name: "Denegación de raw",
			purpose:
				"Descarta los orígenes baneados antes del connection tracking, que es el punto más barato de RouterOS para deshacerse de una avalancha.",
			note: "Las reglas raw de RouterOS no pueden rechazar, así que firewall.deny_action: reject se escribe aquí como drop: es la única regla cuya acción no sigue esa opción.",
		},
	},
	"filter-output": {
		en: {
			name: "Output block",
			purpose:
				"Stops the router itself from opening traffic towards a banned destination — the only rule here that matches on destination rather than source.",
			note: "Its block gets no counting rule, so output traffic never appears in the processed metrics.",
		},
		es: {
			name: "Bloqueo de output",
			purpose:
				"Impide que el propio router inicie tráfico hacia un destino baneado; es la única regla aquí que coincide por destino y no por origen.",
			note: "Su bloque no recibe regla de contador, por lo que el tráfico de salida nunca aparece en las métricas de procesados.",
		},
	},
};
