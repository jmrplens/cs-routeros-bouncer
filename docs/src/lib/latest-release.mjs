import { execFileSync } from "node:child_process";

// The Astro CLI always runs with the docs package as its working directory
// (both `astro.config.mjs` loading and the Vite SSR build). Resolving from
// `import.meta.url` would break for bundled consumers (e.g. the Head
// override), whose chunks execute from `dist/`, so cwd is the reliable root.
const docsRoot = process.cwd();

// Check once, at module load, instead of on every call — avoids spawning a
// doomed `git` process when `git` is missing or the build runs outside a git
// checkout (e.g. some Docker/CI contexts).
let isGitAvailable = false;
try {
	execFileSync("git", ["rev-parse", "--is-inside-work-tree"], {
		cwd: docsRoot,
		stdio: "ignore",
	});
	isGitAvailable = true;
} catch {
	// No git available — getLatestRelease() falls back to the snapshot below.
}

/**
 * Resolve the latest release tag and its date from git, so build-time version
 * strings (JSON-LD `softwareVersion`, the homepage version badge) track the
 * actual latest release instead of hand-maintained literals that silently go
 * stale after every release (falls back to a known-good snapshot when git or
 * tags aren't available, e.g. building from a tarball).
 * @returns {{ version: string, date: string }}
 */
export function getLatestRelease() {
	const fallback = { version: "1.4.5", date: "2026-06-19" };
	if (!isGitAvailable) return fallback;
	try {
		const tag = execFileSync("git", ["describe", "--tags", "--abbrev=0"], {
			cwd: docsRoot,
			encoding: "utf-8",
		}).trim();
		const date = execFileSync("git", ["log", "-1", "--format=%cI", tag], {
			cwd: docsRoot,
			encoding: "utf-8",
		}).trim();
		if (!tag || !date) return fallback;
		return { version: tag.replace(/^v/, ""), date: date.slice(0, 10) };
	} catch {
		return fallback;
	}
}

/** Whether the build is running inside a git checkout with `git` available. */
export function gitAvailable() {
	return isGitAvailable;
}

/** Cache: one git spawn per content file per build, not per render. */
const firstCommitDates = new Map();

/**
 * Resolve the date a content file first entered git history, for JSON-LD
 * `datePublished`. Returns undefined for untracked files (e.g. brand-new
 * pages not yet committed) so callers can simply omit the property.
 * @param {string} relativePath path relative to the docs root, e.g. "src/content/docs/index.mdx"
 * @returns {string | undefined} ISO 8601 date
 */
export function getFirstCommitDate(relativePath) {
	if (!isGitAvailable || !relativePath) return undefined;
	if (firstCommitDates.has(relativePath)) {
		return firstCommitDates.get(relativePath);
	}
	let date;
	try {
		const output = execFileSync(
			"git",
			[
				"log",
				"--follow",
				"--diff-filter=A",
				"--format=%cI",
				"--",
				relativePath,
			],
			{ cwd: docsRoot, encoding: "utf-8" },
		).trim();
		// --follow can list several "A" commits after renames; the oldest is last.
		const lines = output.split("\n").filter(Boolean);
		date = lines.length > 0 ? lines[lines.length - 1] : undefined;
	} catch {
		date = undefined;
	}
	firstCommitDates.set(relativePath, date);
	return date;
}
