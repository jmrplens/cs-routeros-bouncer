#!/usr/bin/env node
/**
 * Draws the first-reconciliation charts from the committed 10 Hz captures.
 *
 * Each capture is two CSVs in `src/data/`: `<name>.csv` (`rel_s,cpu_pct,
 * ram_used_mib`, one row per 100 ms, seconds relative to the bouncer starting)
 * and `<name>-markers.csv` (`rel_s,label,kind`, read off the bouncer's own
 * log). This script turns them into a light and a dark SVG in `src/assets/`,
 * painted from the same `theme.css` tokens the site renders with, so the
 * figures follow the palette instead of freezing a copy of it.
 *
 * The charts of one group share their axes: the three bulk-add methods are
 * drawn on the same seconds, CPU and RAM scales, so the eye compares like with
 * like.
 *
 * `<name>-background.csv` (`from_s,to_s`), when present, lists the stretches
 * the router spent on its own periodic jobs rather than on the bouncer: two of
 * them every 30 s on the router's clock, found while the bouncer was stopped.
 * Inside each stretch every sample is drawn as the mean of the samples in the
 * second either side of it, CPU and RAM alike. The capture CSV itself stays
 * raw, so what was smoothed, and where, is in the repository.
 *
 * Usage:
 *   node scripts/render-perf-charts.mjs           # write the SVGs
 *   node scripts/render-perf-charts.mjs --check   # exit 1 if any is stale
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { token } from "../src/lib/brand-assets.mjs";

const DOCS = fileURLToPath(new URL("..", import.meta.url));
const DATA = path.join(DOCS, "src/data");
const ASSETS = path.join(DOCS, "src/assets");
const css = readFileSync(path.join(DOCS, "src/styles/theme.css"), "utf8");

/** The captures, grouped by the axes they share. */
const GROUPS = [
	[
		{
			name: "perf-first-reconcile-stored",
			title: "Stored /system/script (RouterOS before 7.8)",
		},
		{
			name: "perf-first-reconcile-execute",
			title: "/execute, the default on RouterOS 7.8 and later",
		},
		{
			name: "perf-first-reconcile-api",
			title: "bulk_add_method: api, one call per entry",
		},
	],
];

// Every point is the mean of this many 100 ms samples: single slices are too
// spiky to read at this width, and the text beside each chart gives the peaks.
const BIN = 5;
const W = 960;
const H = 440;
const PLOT = { left: 64, right: 888, top: 74, bottom: 382 };
const FONT = "ui-sans-serif,system-ui,sans-serif";

function palette(selector) {
	const t = (name) => token(css, selector, name);
	return {
		ground: t("rb-page"),
		ink: t("rb-heading"),
		grid: t("rb-border"),
		muted: t("rb-muted"),
		cpu: t("rb-accent"),
		ram: t("rb-status-warn"),
		kinds: {
			neutral: t("rb-muted"),
			write: t("rb-status-drop"),
			done: t("rb-status-allow"),
		},
	};
}

const THEMES = {
	light: palette(':root[data-theme="light"] {'),
	dark: palette(":root {"),
};

function readCsv(file) {
	const [header, ...rows] = readFileSync(file, "utf8").trim().split("\n");
	const keys = header.split(",");
	return rows.map((row) => {
		const cells = row.split(",");
		return Object.fromEntries(keys.map((k, i) => [k, cells[i]]));
	});
}

function load(name) {
	const samples = readCsv(path.join(DATA, `${name}.csv`)).map((r) => ({
		t: Number(r.rel_s),
		cpu: Number(r.cpu_pct),
		ram: Number(r.ram_used_mib),
	}));
	const bgFile = path.join(DATA, `${name}-background.csv`);
	const windows = existsSync(bgFile)
		? readCsv(bgFile).map((w) => [Number(w.from_s), Number(w.to_s)])
		: [];
	const inside = (t) => windows.some(([a, b]) => a <= t && t <= b);
	const smoothed = samples.map((s) => {
		const win = windows.find(([a, b]) => a <= s.t && s.t <= b);
		if (!win) return s;
		const [a, b] = win;
		const near = samples.filter(
			(n) =>
				((n.t >= a - 1 && n.t < a) || (n.t > b && n.t <= b + 1)) &&
				!inside(n.t),
		);
		const mean = (key) =>
			near.reduce((sum, n) => sum + n[key], 0) / near.length;
		return { t: s.t, cpu: mean("cpu"), ram: mean("ram") };
	});
	const points = [];
	for (let i = 0; i + BIN <= samples.length; i += BIN) {
		const bin = smoothed.slice(i, i + BIN);
		const mean = (key) => bin.reduce((sum, s) => sum + s[key], 0) / BIN;
		points.push({ t: mean("t"), cpu: mean("cpu"), ram: mean("ram") });
	}
	const markers = readCsv(path.join(DATA, `${name}-markers.csv`)).map((m) => ({
		t: Number(m.rel_s),
		label: m.label,
		kind: m.kind,
	}));
	return { points, markers };
}

function niceStep(span, targets) {
	return targets.find((step) => span / step <= 9) ?? targets.at(-1);
}

function scales(captures) {
	const pts = captures.flatMap((c) => c.points);
	const t0 = Math.floor(Math.min(...pts.map((p) => p.t)));
	const t1 = Math.ceil(Math.max(...pts.map((p) => p.t)));
	const xStep = niceStep(t1 - t0, [5, 10, 20, 30, 60]);
	const cpuStep = niceStep(Math.max(...pts.map((p) => p.cpu)), [10, 20, 25]);
	const cpuMax =
		Math.ceil(Math.max(...pts.map((p) => p.cpu)) / cpuStep) * cpuStep;
	const ramLow = Math.min(...pts.map((p) => p.ram));
	const ramHigh = Math.max(...pts.map((p) => p.ram));
	const ramStep = niceStep(ramHigh - ramLow, [5, 10, 20, 25, 50]);
	return {
		t0,
		t1,
		xStep,
		cpuMax,
		cpuStep,
		ramMin: Math.floor(ramLow / ramStep) * ramStep,
		ramMax: Math.ceil(ramHigh / ramStep) * ramStep,
		ramStep,
	};
}

const f1 = (n) => n.toFixed(1);
const esc = (s) =>
	s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");

function text(x, y, body, attrs, fill) {
	return `<text x="${x}" y="${y}" font-family="${FONT}" ${attrs} fill="${fill}">${esc(body)}</text>`;
}

function render(chart, capture, s, c) {
	const x = (t) =>
		PLOT.left + ((t - s.t0) / (s.t1 - s.t0)) * (PLOT.right - PLOT.left);
	const yCpu = (v) => PLOT.bottom - (v / s.cpuMax) * (PLOT.bottom - PLOT.top);
	const yRam = (v) =>
		PLOT.bottom -
		((v - s.ramMin) / (s.ramMax - s.ramMin)) * (PLOT.bottom - PLOT.top);
	const out = [
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(chart.title)}">`,
		`<rect width="${W}" height="${H}" fill="${c.ground}"/>`,
		text(PLOT.left, 24, chart.title, 'font-size="16" font-weight="600"', c.ink),
	];
	for (let v = 0; v <= s.cpuMax; v += s.cpuStep) {
		const y = f1(yCpu(v));
		out.push(
			`<line x1="${PLOT.left}" y1="${y}" x2="${PLOT.right}" y2="${y}" stroke="${c.grid}" stroke-width="1"/>`,
			text(
				PLOT.left - 8,
				f1(yCpu(v) + 4),
				String(v),
				'font-size="11" text-anchor="end"',
				c.cpu,
			),
		);
	}
	for (let v = s.ramMin; v <= s.ramMax; v += s.ramStep) {
		out.push(
			text(PLOT.right + 8, f1(yRam(v) + 4), String(v), 'font-size="11"', c.ram),
		);
	}
	for (let t = Math.ceil(s.t0 / s.xStep) * s.xStep; t <= s.t1; t += s.xStep) {
		out.push(
			text(
				f1(x(t)),
				400,
				String(t),
				'font-size="11" text-anchor="middle"',
				c.muted,
			),
		);
	}
	const mid = f1((PLOT.top + PLOT.bottom) / 2);
	out.push(
		text(
			16,
			mid,
			"CPU %",
			`font-size="12" transform="rotate(-90 16 ${mid})" text-anchor="middle"`,
			c.cpu,
		),
		text(
			W - 18,
			mid,
			"RAM used, MiB",
			`font-size="12" transform="rotate(90 ${W - 18} ${mid})" text-anchor="middle"`,
			c.ram,
		),
		text(
			f1((PLOT.left + PLOT.right) / 2),
			424,
			"seconds since the bouncer started",
			'font-size="12" text-anchor="middle"',
			c.muted,
		),
	);
	// Labels alternate between two rows when they would overlap.
	const rows = [-Infinity, -Infinity];
	for (const m of capture.markers) {
		const mx = x(m.t);
		const width = m.label.length * 6.2 + 12;
		const row = mx - width / 2 > rows[0] + 4 ? 0 : 1;
		rows[row] = mx + width / 2;
		const top = row === 0 ? 54 : 34;
		const color = c.kinds[m.kind] ?? c.kinds.neutral;
		out.push(
			`<line x1="${f1(mx)}" y1="${PLOT.top}" x2="${f1(mx)}" y2="${PLOT.bottom}" stroke="${color}" stroke-width="1.5" stroke-dasharray="5 4"/>`,
			`<rect x="${f1(mx - width / 2)}" y="${top}" width="${f1(width)}" height="16" rx="4" fill="${color}"/>`,
			text(
				f1(mx),
				top + 12,
				m.label,
				'font-size="11" text-anchor="middle"',
				c.ground,
			),
		);
	}
	const line = (key, y) =>
		capture.points
			.map((p, i) => `${i ? "L" : "M"}${f1(x(p.t))},${f1(y(p[key]))}`)
			.join("");
	out.push(
		`<path d="${line("ram", yRam)}" fill="none" stroke="${c.ram}" stroke-width="2.0" stroke-linejoin="round"/>`,
		`<path d="${line("cpu", yCpu)}" fill="none" stroke="${c.cpu}" stroke-width="2.5" stroke-linejoin="round"/>`,
		"</svg>",
		"",
	);
	return out.join("\n");
}

const check = process.argv.includes("--check");
const stale = [];
for (const group of GROUPS) {
	const captures = group.map((chart) => load(chart.name));
	const s = scales(captures);
	group.forEach((chart, i) => {
		for (const [theme, colors] of Object.entries(THEMES)) {
			const file = path.join(ASSETS, `${chart.name}-${theme}.svg`);
			const svg = render(chart, captures[i], s, colors);
			if (check) {
				if (!existsSync(file) || readFileSync(file, "utf8") !== svg) {
					stale.push(path.relative(DOCS, file));
				}
			} else {
				writeFileSync(file, svg);
			}
		}
	});
}
if (stale.length) {
	console.error(
		`✗ stale chart(s), run \`node scripts/render-perf-charts.mjs\`:\n  ${stale.join("\n  ")}`,
	);
	process.exit(1);
}
if (check) {
	console.log("✓ performance charts match their captures and the palette.");
}
