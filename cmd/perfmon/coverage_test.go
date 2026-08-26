package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fixtureTheme is the minimal theme.css shape tokensFromTheme understands.
const fixtureTheme = `:root {
	--rb-page: #0e1316;
	--rb-border: #2a333a;
	--rb-heading: #f2f6f8;
	--rb-muted: #8b969d;
	--rb-accent: #807dc0;
	--rb-status-warn: #f9ab14;
}

:root[data-theme="light"] {
	--rb-page: #ffffff;
	--rb-border: #dce4e7;
	--rb-heading: #14191d;
	--rb-muted: #556069;
	--rb-accent: #4d4a98;
	--rb-status-warn: #906004;
}
`

// TestPlotDocsEndToEnd runs the real plot path over fixtures: dataset and
// markers in, two themed SVGs out, byte-identical on a second run.
func TestPlotDocsEndToEnd(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	o := options{
		dataCSV:    write("data.csv", "rel_s,cpu_pct,ram_used_mib\n-5,3,330\n0,5,349\n10,31,349\n35,30,348\n45,4,348\n"),
		markersCSV: write("markers.csv", "rel_s,label\n0,bouncer starts\n35,reconciliation complete\n"),
		themeCSS:   write("theme.css", fixtureTheme),
		outDir:     dir,
		title:      "fixture",
	}
	if err := plotDocs(o); err != nil {
		t.Fatal(err)
	}
	light1, readErr := os.ReadFile(filepath.Join(dir, "perf-lifecycle-light.svg"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	dark1, _ := os.ReadFile(filepath.Join(dir, "perf-lifecycle-dark.svg"))
	if !strings.Contains(string(light1), "#4d4a98") || !strings.Contains(string(dark1), "#807dc0") {
		t.Fatal("palettes did not reach their SVGs")
	}
	if err := plotDocs(o); err != nil {
		t.Fatal(err)
	}
	light2, _ := os.ReadFile(filepath.Join(dir, "perf-lifecycle-light.svg"))
	if string(light1) != string(light2) {
		t.Fatal("plot is not deterministic across runs")
	}
}

// TestPlotDocsRejectsBadInputs pins the loud-failure contract for the file
// formats: too few rows, malformed rows, missing tokens.
func TestPlotDocsRejectsBadInputs(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(content), 0o600)
		return p
	}
	good := options{
		dataCSV:    write("d.csv", "h\n0,1,2\n1,2,3\n"),
		markersCSV: write("m.csv", "h\n0,x\n"),
		themeCSS:   write("t.css", fixtureTheme),
		outDir:     dir,
	}
	cases := []struct {
		name   string
		mutate func(o options) options
	}{
		{"one data row", func(o options) options { o.dataCSV = write("d1.csv", "h\n0,1,2\n"); return o }},
		{"malformed data", func(o options) options { o.dataCSV = write("d2.csv", "h\nnope\n"); return o }},
		{"malformed marker", func(o options) options { o.markersCSV = write("m1.csv", "h\nnope\n"); return o }},
		{"missing token", func(o options) options { o.themeCSS = write("t1.css", ":root {\n--rb-page: #fff;\n}\n"); return o }},
	}
	for _, tc := range cases {
		if err := plotDocs(tc.mutate(good)); err == nil {
			t.Fatalf("%s: want error, got none", tc.name)
		}
	}
}

// lokiFixture serves one page of CPUHR01 lines the way Loki does.
func lokiFixture(t *testing.T, lines [][2]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"result": []map[string]any{{"values": lines}},
			},
		})
	}))
}

// TestCaptureAgainstFixture exercises the whole pull path: HTTP, pagination
// cutoff, expansion and ordering.
func TestCaptureAgainstFixture(t *testing.T) {
	base := time.Now().Truncate(time.Second)
	line := func(q int, ts time.Time) [2]string {
		return [2]string{
			strconv.FormatInt(ts.UnixNano(), 10),
			"CPUHR01 v=1 q=" + strconv.Itoa(q) +
				" t=1,2,3,4,5,6,7,8,9,10 c0=0,0,0,0,0,0,0,0,0,0 c1=0,0,0,0,0,0,0,0,0,0" +
				" c2=0,0,0,0,0,0,0,0,0,0 c3=0,0,0,0,0,0,0,0,0,0 ma=700000 mf=650000",
		}
	}
	srv := lokiFixture(t, [][2]string{line(1, base), line(2, base.Add(time.Second))})
	defer srv.Close()

	o := options{lokiBase: srv.URL, job: "cpuhr01"}
	samples, err := capture(o, base.Add(-time.Minute), base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 20 {
		t.Fatalf("got %d samples, want 20", len(samples))
	}
	for i := 1; i < len(samples); i++ {
		if samples[i].t < samples[i-1].t {
			t.Fatalf("samples out of order at %d", i)
		}
	}
}

// TestCaptureSurfacesHTTPErrors pins that a broken Loki is loud, not empty.
func TestCaptureSurfacesHTTPErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()
	_, err := capture(options{lokiBase: srv.URL, job: "x"}, time.Now().Add(-time.Minute), time.Now())
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("want HTTP 502 error, got %v", err)
	}
}

// TestUninstallRunsRemovalsInReverse pins that uninstall touches every step's
// removal and keeps going past failures.
func TestUninstallRunsRemovalsInReverse(t *testing.T) {
	o, _, err := parseOptions([]string{"-router", "u@h"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{present: map[string]bool{}}
	uninstall(f, o)
	if len(f.ran) != len(steps(o)) {
		t.Fatalf("uninstall ran %d commands, want %d", len(f.ran), len(steps(o)))
	}
	if !strings.Contains(f.ran[0], "/container/stop") {
		t.Fatalf("first removal should stop the container, got %q", f.ran[0])
	}
}

// TestWriteCSVShape pins the capture output header and row arity.
func TestWriteCSVShape(t *testing.T) {
	var sb strings.Builder
	writeCSV(&sb, []sample{{t: 1.5, cpu: 7, cores: [4]int{1, 2, 3, 4}, maKiB: 10, mfKiB: 5}})
	lines := strings.Split(strings.TrimSpace(sb.String()), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "unix_s,cpu_pct") {
		t.Fatalf("csv shape: %q", sb.String())
	}
	if lines[1] != "1.5,7,1,2,3,4,10,5" {
		t.Fatalf("row: %q", lines[1])
	}
}

// TestBuildSamplerProducesStaticELF runs the real cross-build: the test suite
// runs under the same toolchain the tool shells out to, so this is cheap and
// pins the one external dependency the installer has.
func TestBuildSamplerProducesStaticELF(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-build in -short mode")
	}
	// The build resolves ./cmd/perfmon/sampler, so run from the module root.
	wd, _ := os.Getwd()
	t.Chdir(filepath.Join(wd, "..", ".."))
	binary, err := buildSampler("linux", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if len(binary) < 1<<20 || string(binary[:4]) != "\x7fELF" {
		t.Fatalf("unexpected binary: %d bytes, magic %q", len(binary), binary[:4])
	}
}

// TestVerifyReadsFreshness pins both verdicts: fresh samples pass, an empty
// window names the firewall-membership failure mode in its error.
func TestVerifyReadsFreshness(t *testing.T) {
	base := time.Now()
	fresh := lokiFixture(t, [][2]string{{
		strconv.FormatInt(base.UnixNano(), 10),
		"CPUHR01 v=1 q=1 t=1,1,1,1,1,1,1,1,1,1 c0=0,0,0,0,0,0,0,0,0,0 c1=0,0,0,0,0,0,0,0,0,0 c2=0,0,0,0,0,0,0,0,0,0 c3=0,0,0,0,0,0,0,0,0,0 ma=1 mf=1",
	}})
	defer fresh.Close()
	if err := verify(options{lokiBase: fresh.URL, job: "cpuhr01"}); err != nil {
		t.Fatalf("fresh samples should verify: %v", err)
	}

	empty := lokiFixture(t, nil)
	defer empty.Close()
	err := verify(options{lokiBase: empty.URL, job: "cpuhr01"})
	if err == nil || !strings.Contains(err.Error(), "membership") {
		t.Fatalf("empty window should name the membership trap, got %v", err)
	}
}

// TestDispatchContract pins the CLI surface: required flags, unknown verbs,
// and the two Loki-backed verbs end to end.
func TestDispatchContract(t *testing.T) {
	if err := dispatch("install", options{}, flagSetForTest()); err == nil {
		t.Fatal("install without -router must fail")
	}
	if err := dispatch("bogus", options{}, flagSetForTest()); err == nil {
		t.Fatal("unknown verb must fail")
	}

	srv := lokiFixture(t, nil)
	defer srv.Close()
	if err := dispatch("capture", options{lokiBase: srv.URL, job: "x", minutes: 1}, flagSetForTest()); err == nil {
		t.Fatal("capture over an empty window must fail")
	}

	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(content), 0o600)
		return p
	}
	o := options{
		dataCSV:    write("d.csv", "h\n0,1,330\n1,2,331\n"),
		markersCSV: write("m.csv", "h\n0,start\n"),
		themeCSS:   write("t.css", fixtureTheme),
		outDir:     dir,
	}
	if err := dispatch("plot", o, flagSetForTest()); err != nil {
		t.Fatalf("plot over fixtures: %v", err)
	}
}

func flagSetForTest() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Usage = func() {}
	return fs
}

// TestInstallUploadsForContainerStep pins that the image travels exactly when
// the container step is the one being created.
func TestInstallUploadsForContainerStep(t *testing.T) {
	o, _, err := parseOptions([]string{"-router", "u@h"})
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{present: map[string]bool{}}
	if _, err := install(f, o, []byte("img")); err != nil {
		t.Fatal(err)
	}
	if f.uploads != 1 {
		t.Fatalf("uploads = %d, want exactly 1", f.uploads)
	}
}

// TestSSHRunnerShapesItsCommands runs the real sshRunner against a stub `ssh`
// and `scp` placed first on PATH, which covers the argument assembly and the
// upload temp-file dance without a network.
func TestSSHRunnerShapesItsCommands(t *testing.T) {
	dir := t.TempDir()
	stub := "#!/bin/sh\necho \"$@\" >> " + filepath.Join(dir, "calls.log") + "\nexit 0\n"
	for _, name := range []string{"ssh", "scp"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(stub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	r := sshRunner{target: "u@h", port: "2200", key: "/k"}
	if _, err := r.run(":put 1"); err != nil {
		t.Fatal(err)
	}
	if err := r.upload([]byte("payload"), "file.tar"); err != nil {
		t.Fatal(err)
	}
	log, logErr := os.ReadFile(filepath.Join(dir, "calls.log"))
	if logErr != nil {
		t.Fatal(logErr)
	}
	got := string(log)
	for _, want := range []string{"-p 2200", "-i /k", "u@h :put 1", "-P 2200", "u@h:file.tar"} {
		if !strings.Contains(got, want) {
			t.Fatalf("calls lack %q:\n%s", want, got)
		}
	}
}

// TestSSHRunnerSurfacesFailure pins the error path: a failing remote command
// carries its output, and firstLine trims it for the uninstall summary.
func TestSSHRunnerSurfacesFailure(t *testing.T) {
	dir := t.TempDir()
	stub := "#!/bin/sh\necho \"boom line one\"\necho \"line two\"\nexit 7\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	r := sshRunner{target: "u@h", port: "22"}
	_, err := r.run("whatever")
	if err == nil {
		t.Fatal("want error from exit 7")
	}
	if line := firstLine(err); strings.Contains(line, "line two") {
		t.Fatalf("firstLine kept more than one line: %q", line)
	}
}
