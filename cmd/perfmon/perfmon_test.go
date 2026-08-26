package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// TestImageTarShape pins the docker-save layout RouterOS accepts: a manifest
// naming a config and one layer, the layer carrying /sampler, and the config
// declaring the right architecture. Built twice from the same binary it must
// be byte-identical — determinism is what lets an operator diff two installs.
func TestImageTarShape(t *testing.T) {
	binary := []byte("fake-elf")
	img1, err := imageTar(binary, "arm64")
	if err != nil {
		t.Fatal(err)
	}
	img2, _ := imageTar(binary, "arm64")
	if !bytes.Equal(img1, img2) {
		t.Fatal("image tar is not deterministic")
	}

	files := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(img1))
	for {
		hdr, nextErr := tr.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			t.Fatal(nextErr)
		}
		data, _ := io.ReadAll(tr)
		files[hdr.Name] = data
	}
	manifestRaw, ok := files["manifest.json"]
	if !ok {
		t.Fatal("no manifest.json")
	}
	var manifest []struct {
		Config string
		Layers []string
	}
	if unmarshalErr := json.Unmarshal(manifestRaw, &manifest); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if len(manifest) != 1 || len(manifest[0].Layers) != 1 {
		t.Fatalf("manifest shape: %+v", manifest)
	}
	var config struct {
		Architecture string `json:"architecture"`
	}
	if cfgErr := json.Unmarshal(files[manifest[0].Config], &config); cfgErr != nil {
		t.Fatal(cfgErr)
	}
	if config.Architecture != "arm64" {
		t.Fatalf("architecture = %q", config.Architecture)
	}
	layer := tar.NewReader(bytes.NewReader(files[manifest[0].Layers[0]]))
	lhdr, layerErr := layer.Next()
	if layerErr != nil || lhdr.Name != "sampler" {
		t.Fatalf("layer content: %v %v", lhdr, layerErr)
	}
}

// fakeRunner scripts the router: canned answers for checks, a log of writes.
type fakeRunner struct {
	present map[string]bool // step name fragment -> exists
	ran     []string
	uploads int
}

func (f *fakeRunner) run(command string) (string, error) {
	if strings.HasPrefix(command, ":put [:len") {
		for frag, ok := range f.present {
			if strings.Contains(command, frag) && ok {
				return "1\n", nil
			}
		}
		return "0\n", nil
	}
	f.ran = append(f.ran, command)
	return "", nil
}

func (f *fakeRunner) upload([]byte, string) error {
	f.uploads++
	return nil
}

// TestInstallIsIdempotent pins the promise the docs make: a second install
// creates nothing.
func TestInstallIsIdempotent(t *testing.T) {
	o, _, err := parseOptions([]string{"-router", "u@h"})
	if err != nil {
		t.Fatal(err)
	}
	empty := &fakeRunner{present: map[string]bool{}}
	created, err := install(empty, o, []byte("img"))
	if err != nil {
		t.Fatal(err)
	}
	if created != len(steps(o)) {
		t.Fatalf("fresh install created %d of %d steps", created, len(steps(o)))
	}

	full := &fakeRunner{present: map[string]bool{
		o.veth: true, o.name: true, o.ifaceList: true, o.addrList: true, o.subnet: true,
	}}
	created, err = install(full, o, []byte("img"))
	if err != nil {
		t.Fatal(err)
	}
	if created != 0 {
		t.Fatalf("second install created %d steps; want 0\nran: %v", created, full.ran)
	}
}

// TestRenderChartDeterministic pins that the same dataset and palette always
// produce identical bytes, and that the essentials are present.
func TestRenderChartDeterministic(t *testing.T) {
	pts := []point{{-5, 3, 330}, {0, 5, 349}, {10, 31, 349}, {35, 30, 348}, {45, 4, 348}}
	marks := []marker{{0, "bouncer starts"}, {35, "reconciliation complete"}}
	p := chartPalette{page: "#fff", grid: "#ddd", text: "#111", muted: "#666", cpu: "#4d4a98", ram: "#906004"}
	a := renderChart(pts, marks, p, "title & test")
	b := renderChart(pts, marks, p, "title & test")
	if a != b {
		t.Fatal("chart is not deterministic")
	}
	for _, want := range []string{"#4d4a98", "#906004", "stroke-dasharray", "title &amp; test", "reconciliation complete"} {
		if !strings.Contains(a, want) {
			t.Fatalf("chart lacks %q", want)
		}
	}
}

// TestExpandTimestamps pins the batch-expansion arithmetic: the line's
// timestamp belongs to its LAST sample.
func TestExpandTimestamps(t *testing.T) {
	ts := time.Unix(1000, 0)
	line := "CPUHR01 v=1 q=7 t=1,2,3,4,5,6,7,8,9,10 c0=0,0,0,0,0,0,0,0,0,0 c1=0,0,0,0,0,0,0,0,0,0 c2=0,0,0,0,0,0,0,0,0,0 c3=0,0,0,0,0,0,0,0,0,0 ma=700000 mf=650000"
	out := expand(ts, line, map[string]bool{})
	if len(out) != 10 {
		t.Fatalf("expanded %d samples", len(out))
	}
	if out[9].t != 1000 || out[0].t != 999.1 {
		t.Fatalf("timestamps: first=%v last=%v", out[0].t, out[9].t)
	}
	if out[4].cpu != 5 {
		t.Fatalf("sample order broken: %v", out[4].cpu)
	}
}
