import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const docsRoot = fileURLToPath(new URL("../..", import.meta.url));

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
