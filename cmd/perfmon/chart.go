package main

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// The documentation chart: CPU %% and RAM MiB on one time axis with two Y
// axes, plus dashed vertical markers at the lifecycle events. Drawn by hand
// as SVG for the same reasons the brand rasters are: mermaid's xychart has
// neither a second Y axis nor annotations, matplotlib would add a Python
// dependency whose output shifts between versions, and gonum/plot has no
// first-class secondary axis. ~200 lines of geometry buy determinism — the
// same CSV always yields byte-identical SVGs — and palette fidelity, because
// every color is read from theme.css rather than restated.

// point is one row of the committed dataset.
type point struct {
	relS   float64
	cpuPct float64
	ramMiB float64
}

// marker is one labeled vertical line.
type marker struct {
	relS  float64
	label string
}

// chartPalette carries the handful of theme tokens the chart paints with.
type chartPalette struct {
	page, grid, text, muted string
	cpu, ram                string
}

// tokensFromTheme reads the needed stops for one scheme out of theme.css,
// with the same block convention render-brand-rasters uses: dark lives on
// bare `:root`, light on `:root[data-theme="light"]`.
func tokensFromTheme(css, scheme string) (chartPalette, error) {
	selector := ":root {"
	if scheme == "light" {
		selector = `:root[data-theme="light"] {`
	}
	start := strings.Index(css, selector)
	if start < 0 {
		return chartPalette{}, fmt.Errorf("theme.css: no %q block", selector)
	}
	end := strings.Index(css[start:], "\n}")
	block := css[start : start+end]
	get := func(name string) (string, error) {
		m := regexp.MustCompile(`--` + name + `:\s*([^;]+);`).FindStringSubmatch(block)
		if m == nil {
			return "", fmt.Errorf("theme.css: %s declares no --%s", selector, name)
		}
		return strings.TrimSpace(m[1]), nil
	}
	var p chartPalette
	var err error
	read := func(dst *string, name string) {
		if err == nil {
			*dst, err = get(name)
		}
	}
	read(&p.page, "rb-page")
	read(&p.grid, "rb-border")
	read(&p.text, "rb-heading")
	read(&p.muted, "rb-muted")
	read(&p.cpu, "rb-accent")
	read(&p.ram, "rb-status-warn")
	return p, err
}

// Geometry constants. One place, so the two themes cannot drift apart.
const (
	chartW  = 960
	chartH  = 440
	padL    = 64
	padR    = 72
	padT    = 46
	padB    = 58
	plotW   = chartW - padL - padR
	plotH   = chartH - padT - padB
	fontCSS = `font-family="ui-sans-serif,system-ui,sans-serif"`
)

func xPos(t, tMin, tMax float64) float64 { return padL + (t-tMin)/(tMax-tMin)*plotW }

// renderChart draws the full figure for one palette.
func renderChart(pts []point, marks []marker, p chartPalette, title string) string {
	tMin, tMax := pts[0].relS, pts[len(pts)-1].relS
	cpuMax := 10.0
	ramMin, ramMax := math.MaxFloat64, 0.0
	for _, pt := range pts {
		cpuMax = math.Max(cpuMax, pt.cpuPct)
		ramMin = math.Min(ramMin, pt.ramMiB)
		ramMax = math.Max(ramMax, pt.ramMiB)
	}
	cpuTop := math.Ceil(cpuMax/10)*10 + 10
	ramLo := math.Floor(ramMin/5) * 5
	ramHi := math.Ceil(ramMax/5)*5 + 5

	yCPU := func(v float64) float64 { return padT + (1-v/cpuTop)*plotH }
	yRAM := func(v float64) float64 { return padT + (1-(v-ramLo)/(ramHi-ramLo))*plotH }

	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" role="img" aria-label="%s">`+"\n",
		chartW, chartH, xmlEscape(title))
	fmt.Fprintf(&sb, `<rect width="%d" height="%d" fill="%s"/>`+"\n", chartW, chartH, p.page)
	fmt.Fprintf(&sb, `<text x="%d" y="24" %s font-size="16" font-weight="600" fill="%s">%s</text>`+"\n",
		padL, fontCSS, p.text, xmlEscape(title))

	// Horizontal grid on the CPU scale, labels on both axes.
	for v := 0.0; v <= cpuTop; v += 10 {
		y := yCPU(v)
		fmt.Fprintf(&sb, `<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="%s" stroke-width="1"/>`+"\n",
			padL, y, chartW-padR, y, p.grid)
		fmt.Fprintf(&sb, `<text x="%d" y="%.1f" %s font-size="11" text-anchor="end" fill="%s">%.0f</text>`+"\n",
			padL-8, y+4, fontCSS, p.cpu, v)
	}
	for v := ramLo; v <= ramHi; v += 5 {
		fmt.Fprintf(&sb, `<text x="%d" y="%.1f" %s font-size="11" fill="%s">%.0f</text>`+"\n",
			chartW-padR+8, yRAM(v)+4, fontCSS, p.ram, v)
	}
	// X ticks every 5 s.
	for t := math.Ceil(tMin/5) * 5; t <= tMax; t += 5 {
		x := xPos(t, tMin, tMax)
		fmt.Fprintf(&sb, `<text x="%.1f" y="%d" %s font-size="11" text-anchor="middle" fill="%s">%.0f</text>`+"\n",
			x, chartH-padB+18, fontCSS, p.muted, t)
	}

	// Axis titles, each tinted like its series — the affordance that makes a
	// dual-axis chart readable at a glance.
	fmt.Fprintf(&sb, `<text x="16" y="%.1f" %s font-size="12" fill="%s" transform="rotate(-90 16 %.1f)" text-anchor="middle">CPU %%</text>`+"\n",
		padT+plotH/2.0, fontCSS, p.cpu, padT+plotH/2.0)
	fmt.Fprintf(&sb, `<text x="%d" y="%.1f" %s font-size="12" fill="%s" transform="rotate(90 %d %.1f)" text-anchor="middle">RAM used, MiB</text>`+"\n",
		chartW-18, padT+plotH/2.0, fontCSS, p.ram, chartW-18, padT+plotH/2.0)
	fmt.Fprintf(&sb, `<text x="%.1f" y="%d" %s font-size="12" text-anchor="middle" fill="%s">seconds since the bouncer started</text>`+"\n",
		padL+plotW/2.0, chartH-16, fontCSS, p.muted)

	// Event markers under the data so the series stay legible over them.
	for _, m := range marks {
		x := xPos(m.relS, tMin, tMax)
		fmt.Fprintf(&sb, `<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="%s" stroke-width="1.5" stroke-dasharray="5 4"/>`+"\n",
			x, padT, x, chartH-padB, p.muted)
		fmt.Fprintf(&sb, `<text x="%.1f" y="%d" %s font-size="11" text-anchor="middle" fill="%s">%s</text>`+"\n",
			x, padT-6, fontCSS, p.text, xmlEscape(m.label))
	}

	line := func(y func(float64) float64, val func(point) float64, color string, width float64) {
		var d strings.Builder
		for i, pt := range pts {
			cmd := 'L'
			if i == 0 {
				cmd = 'M'
			}
			fmt.Fprintf(&d, "%c%.1f,%.1f", cmd, xPos(pt.relS, tMin, tMax), y(val(pt)))
		}
		fmt.Fprintf(&sb, `<path d="%s" fill="none" stroke="%s" stroke-width="%.1f" stroke-linejoin="round"/>`+"\n",
			d.String(), color, width)
	}
	line(yRAM, func(pt point) float64 { return pt.ramMiB }, p.ram, 2)
	line(yCPU, func(pt point) float64 { return pt.cpuPct }, p.cpu, 2.5)

	sb.WriteString("</svg>\n")
	return sb.String()
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

// readDataset parses the committed CSV (rel_s,cpu_pct,ram_used_mib).
func readDataset(path string) ([]point, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the path is this CLI's own flag
	if err != nil {
		return nil, err
	}
	var pts []point
	for i, lineText := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if i == 0 {
			continue // header
		}
		f := strings.Split(lineText, ",")
		if len(f) < 3 {
			return nil, fmt.Errorf("%s:%d: want 3 fields, got %d", path, i+1, len(f))
		}
		var pt point
		if pt.relS, err = strconv.ParseFloat(f[0], 64); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		if pt.cpuPct, err = strconv.ParseFloat(f[1], 64); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		if pt.ramMiB, err = strconv.ParseFloat(f[2], 64); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		pts = append(pts, pt)
	}
	if len(pts) < 2 {
		return nil, fmt.Errorf("%s: fewer than two data rows", path)
	}
	return pts, nil
}

// readMarkers parses the committed marker list (rel_s,label).
func readMarkers(path string) ([]marker, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the path is this CLI's own flag
	if err != nil {
		return nil, err
	}
	var out []marker
	for i, lineText := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if i == 0 {
			continue
		}
		relText, label, ok := strings.Cut(lineText, ",")
		if !ok {
			return nil, fmt.Errorf("%s:%d: want rel_s,label", path, i+1)
		}
		rel, parseErr := strconv.ParseFloat(relText, 64)
		if parseErr != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, parseErr)
		}
		out = append(out, marker{relS: rel, label: strings.TrimSpace(label)})
	}
	return out, nil
}
