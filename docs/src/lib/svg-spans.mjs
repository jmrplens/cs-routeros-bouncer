/**
 * Strip XML comments and `<style>` blocks out of SVG source, in one pass.
 *
 * Shared because three callers need it and each one needs it for a different
 * reason: `brandSvg()` inlines the mark into a page, where a surviving
 * `<style>` would style the whole host document; `socialCard()` lifts the
 * mark's shapes into a larger drawing, where the mark's own block would sit
 * *after* the card's and win the cascade on equal specificity; and both want
 * the comments gone rather than repeated on every page.
 *
 * Not `.replaceAll()` with a lazy regex, which is what this replaced. Such a
 * pass only matches spans that are *closed*, so an unterminated `<style>` or
 * `<!--` survives untouched, and a marker sitting inside an attribute value is
 * treated as if it opened a real span. CodeQL flags that shape as incomplete
 * multi-character sanitization. Consuming each span as it is entered cannot
 * leave a partial marker behind.
 *
 * Callers are expected to assert on the result — see `assertNoSpansSurvive`.
 * This is a lexer, not a parser: it knows nothing about attribute values, so a
 * `<!--` inside one makes it swallow the rest of the file. That is deliberate.
 * Emitting a half-open span would be worse than truncating, and truncation is
 * detectable; the assertion below is what makes it loud.
 *
 * @param {string} source SVG (or any markup) to strip.
 * @returns {string} the same source with both span kinds removed.
 */
export function stripSpans(source) {
	/** @type {readonly (readonly [string, string])[]} */
	const spans = [
		["<!--", "-->"],
		["<style", "</style>"],
	];
	let out = "";
	let i = 0;
	outer: while (i < source.length) {
		for (const [open, close] of spans) {
			if (!source.startsWith(open, i)) continue;
			const end = source.indexOf(close, i + open.length);
			i = end === -1 ? source.length : end + close.length;
			continue outer;
		}
		out += source[i];
		i += 1;
	}
	return out;
}

/**
 * Throw unless `stripped` came out of `stripSpans` clean and whole.
 *
 * Checks three things a caller would otherwise have to remember: no `<style>`
 * left (the reason the strip exists), no `<!--` left (nested comments, which
 * inlined would swallow everything after them behind a comment the browser
 * never closes), and no orphaned `</style>` — which the `<style` test misses
 * because of the slash, and which only appears when a file nests one block
 * inside another.
 *
 * @param {string} stripped output of `stripSpans`.
 * @param {string} label file path or similar, for the error message.
 * @param {string} [terminator] text the result must still end with. Pass the
 *   closing tag when stripping a whole document: losing it is how a swallowed
 *   file announces itself, and without this check the truncated output looks
 *   perfectly clean to every test above.
 */
export function assertNoSpansSurvive(stripped, label, terminator) {
	if (/<\/?style\b/i.test(stripped)) {
		throw new Error(
			`${label}: a <style> element survived stripping. Inlined, it would ` +
				"style the whole host document rather than the mark.",
		);
	}
	if (stripped.includes("<!--")) {
		throw new Error(
			`${label}: an XML comment opener survived stripping, which means the ` +
				"file nests one comment inside another. Inlined, everything after " +
				"it would be swallowed by a comment the browser never closes.",
		);
	}
	if (terminator !== undefined && !stripped.endsWith(terminator)) {
		throw new Error(
			`${label}: stripping consumed the closing ${terminator}, which means an ` +
				"unterminated span — or a comment marker inside an attribute value — " +
				"swallowed the rest of the file.",
		);
	}
}
