#!/usr/bin/env node
/**
 * Every `og:image` a built page declares must exist as a file in the same build.
 *
 * The card URL is assembled in two places that hold different ids for the same
 * page — the endpoint iterates the content collection, the `Head` override sees
 * Starlight's route — and they agreed on all 56 pages but one. The result was a
 * site that built clean, validated clean, and served a broken preview image for
 * the home page, which is the URL most links point at. Nothing in the pipeline
 * looked, because nothing joined the two halves.
 *
 * This does: it reads the URLs out of the rendered HTML and asks the filesystem
 * whether each one is there. A card that is generated but unreferenced is fine
 * and not reported — a locale or a page can legitimately be dropped from the
 * navigation — but a reference with no file is always a broken preview.
 *
 * Usage: node scripts/check-social-cards.mjs
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const DOCS = fileURLToPath(new URL("..", import.meta.url));
const DIST = path.join(DOCS, "dist");
const SITE = "https://jmrplens.github.io/cs-routeros-bouncer/";

/** Every file under `dir` matching `suffix`, recursively. */
function walk(dir, suffix, out = []) {
	for (const name of readdirSync(dir)) {
		const full = path.join(dir, name);
		if (statSync(full).isDirectory()) walk(full, suffix, out);
		else if (name.endsWith(suffix)) out.push(full);
	}
	return out;
}

if (!existsSync(DIST)) {
	console.error("✗ no dist/ to check — run `pnpm build` first");
	process.exit(1);
}

const pages = walk(DIST, ".html");
if (pages.length === 0) {
	console.error("✗ dist/ holds no HTML, so this check proved nothing");
	process.exit(1);
}

const broken = [];
let checked = 0;
for (const page of pages) {
	const html = readFileSync(page, "utf8");
	for (const match of html.matchAll(
		/<meta (?:property|name)="(?:og:image|twitter:image)" content="([^"]+)"/g,
	)) {
		const url = match[1];
		if (!url.startsWith(SITE)) continue; // absolute elsewhere: not ours to check
		checked += 1;
		const file = path.join(DIST, url.slice(SITE.length));
		if (!existsSync(file)) {
			broken.push(`${path.relative(DIST, page)} → ${url.slice(SITE.length)}`);
		}
	}
}

if (checked === 0) {
	console.error(
		"✗ no social-image tags found in dist/, which means this check is " +
			"passing without measuring anything",
	);
	process.exit(1);
}

if (broken.length > 0) {
	console.error(
		`\n✗ ${broken.length} social image(s) referenced but not built`,
	);
	for (const one of [...new Set(broken)]) console.error(`    • ${one}`);
	process.exit(1);
}

console.log(
	`✓ social cards: ${checked} og:image/twitter:image references across ` +
		`${pages.length} pages all resolve to a file in dist/.`,
);
