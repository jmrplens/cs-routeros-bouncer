package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// plotDocs regenerates the documentation's lifecycle chart pair from the
// committed dataset: one SVG per color scheme, palette read from theme.css,
// deterministic byte-for-byte so a docs gate can diff them if it ever wants
// to. Refresh the dataset itself with `perfmon capture` after a new
// measurement campaign.
func plotDocs(o options) error {
	pts, err := readDataset(o.dataCSV)
	if err != nil {
		return err
	}
	marks, err := readMarkers(o.markersCSV)
	if err != nil {
		return err
	}
	cssBytes, err := os.ReadFile(o.themeCSS) // #nosec G304 -- the path is this CLI's own flag
	if err != nil {
		return err
	}
	for _, scheme := range []string{"light", "dark"} {
		palette, paletteErr := tokensFromTheme(string(cssBytes), scheme)
		if paletteErr != nil {
			return paletteErr
		}
		svg := renderChart(pts, marks, palette, o.title)
		out := filepath.Join(o.outDir, "perf-lifecycle-"+scheme+".svg")
		if writeErr := os.WriteFile(out, []byte(svg), 0o600); writeErr != nil {
			return writeErr
		}
		fmt.Printf("  %s (%d bytes)\n", out, len(svg))
	}
	return nil
}
