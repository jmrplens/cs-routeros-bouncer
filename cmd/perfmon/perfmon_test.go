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

// fakeRunner scripts the router. Writes are the commands that start with a
// menu path; everything else (:put, :if …) is a query and answers "1" when it
// mentions a fragment marked true. Ownership queries always carry the tag,
// so they are answered from owned when that map is set — which is how a test
// models "the effect exists, but perfmon did not create it". When owned is
// nil, everything present counts as ours.
type fakeRunner struct {
	present map[string]bool // fragment -> the effect exists (answers check)
	owned   map[string]bool // fragment -> perfmon's own object exists (answers owned); nil = same as present
	ran     []string
	uploads int
}

func (f *fakeRunner) run(command string) (string, error) {
	if strings.HasPrefix(command, "/") {
		f.ran = append(f.ran, command)
		return "", nil
	}
	table := f.present
	if f.owned != nil && strings.Contains(command, "(managed by cmd/perfmon)") {
		table = f.owned
	}
	for frag, ok := range table {
		if ok && strings.Contains(command, frag) {
			return "1\n", nil
		}
	}
	return "0\n", nil
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
		o.veth: true, o.name: true, o.ifaceList: true, o.addrList: true, o.subnet: true, o.containerIP: true,
	}}
	created, err = install(full, o, []byte("img"))
	if err != nil {
		t.Fatal(err)
	}
	if created != 0 {
		t.Fatalf("second install created %d steps; want 0\nran: %v", created, full.ran)
	}
}

// TestInstallRefusesWhatItDoesNotOwn pins the rule this tool builds on:
// ours → skip, exists-but-not-ours → refuse naming the object, absent →
// create. The reference router is exactly this case — a hand-made sampler
// on the default names — and the old behavior was to skip silently and
// then, at uninstall, delete its image file.
func TestInstallRefusesWhatItDoesNotOwn(t *testing.T) {
	o, _, err := parseOptions([]string{"-router", "u@h"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{ // present fragment -> step name the error must carry
		o.veth:          "veth interface",
		o.subnet:        "address-list membership",
		o.name + ".tar": "container " + o.name,
		o.name + "-env": "container " + o.name,
	}
	for frag, wantStep := range cases {
		f := &fakeRunner{present: map[string]bool{frag: true}, owned: map[string]bool{}}
		_, installErr := install(f, o, []byte("img"))
		if installErr == nil {
			t.Fatalf("install with foreign %q succeeded; ran %v", frag, f.ran)
		}
		if !strings.Contains(installErr.Error(), wantStep) || !strings.Contains(installErr.Error(), "not created by perfmon") {
			t.Fatalf("install with foreign %q: error does not name the collision: %v", frag, installErr)
		}
		if len(f.ran) != 0 && frag != o.veth {
			// Steps before the collision are legitimately created; nothing
			// may be created at or after it.
			for _, cmd := range f.ran {
				if strings.Contains(cmd, frag) {
					t.Fatalf("install wrote to the foreign object %q: %s", frag, cmd)
				}
			}
		}
	}
}

// TestUninstallGuardsDerivedResourcesByMarker pins that the envlist and the
// image file — the two objects that cannot carry a comment — are removed
// only inside the marker guard, that the marker is written first and
// removed last, and that with no marker uninstall touches neither.
func TestUninstallGuardsDerivedResourcesByMarker(t *testing.T) {
	o, _, err := parseOptions([]string{"-router", "u@h"})
	if err != nil {
		t.Fatal(err)
	}
	container := steps(o)[len(steps(o))-1]
	marker := `/container/envs/find list="` + o.name + `-env" name="PERFMON_TAG" value="` + tagFor(o.name) + `"`

	// create: marker before any other env entry
	if i, j := strings.Index(container.create, "name=PERFMON_TAG"), strings.Index(container.create, "name=LOKI_URL"); i < 0 || j < 0 || i > j {
		t.Fatalf("marker is not the first env entry written: %s", container.create)
	}
	// remove: guard opens, file and non-marker envs go, marker goes last
	guard := strings.Index(container.remove, `:if ([:len [`+marker+`]] > 0) do={`)
	file := strings.Index(container.remove, `/file/remove [find name="`+o.name+`.tar"]`)
	envs := strings.Index(container.remove, `/container/envs/remove [find list="`+o.name+`-env" name!="PERFMON_TAG"]`)
	last := strings.LastIndex(container.remove, `/container/envs/remove [`+marker+`]`)
	if guard < 0 || file < 0 || envs < 0 || last < 0 {
		t.Fatalf("removal lacks the guard, the file removal, the env removal or the marker removal:\n%s", container.remove)
	}
	if guard >= file || file >= envs || envs >= last {
		t.Fatalf("removal order is not guard → file → envs → marker:\n%s", container.remove)
	}
	// owned: counts the file and the envlist only under the marker
	if !strings.HasPrefix(container.owned, `:if ([:len [`+marker+`]] > 0) do={`) {
		t.Fatalf("ownership query is not marker-guarded: %s", container.owned)
	}

	// Behavior: foreign image file and envlist, no marker → uninstall does
	// not report them as leftovers, and its removals never name them
	// outside the guard (the guard is what protects them on the router).
	f := &fakeRunner{present: map[string]bool{o.name + ".tar": true, o.name + "-env": true}, owned: map[string]bool{}}
	if uninstallErr := uninstall(f, o); uninstallErr != nil {
		t.Fatalf("uninstall over foreign derived resources returned %v", uninstallErr)
	}
}

// TestUninstallSelectsOnlyWhatInstallTagged pins the containment promise:
// every removal names the exact comment install wrote, and none of them is a
// pattern. The address-list table this tool writes to is where the bouncer
// keeps its blocking state, and a `comment~` there with a colliding -name
// would have deleted it — so the test runs with the most colliding name it
// can, and inspects the commands rather than trusting their output.
func TestUninstallSelectsOnlyWhatInstallTagged(t *testing.T) {
	o, _, err := parseOptions([]string{"-router", "u@h", "-name", "bouncer"})
	if err != nil {
		t.Fatal(err)
	}
	tag := `comment="` + tagFor("bouncer") + `"`
	for _, s := range steps(o) {
		for what, cmd := range map[string]string{"remove": s.remove, "owned": s.owned} {
			if strings.Contains(cmd, "comment~") {
				t.Fatalf("%s of %q matches by pattern: %s", what, s.name, cmd)
			}
			if !strings.Contains(cmd, tag) {
				t.Fatalf("%s of %q does not select by the exact tag: %s", what, s.name, cmd)
			}
		}
		if !strings.Contains(s.create, tag) {
			t.Fatalf("create of %q does not write the tag: %s", s.name, s.create)
		}
	}
	// A bouncer entry is commented "crowdsec-bouncer|…@cs-routeros-bouncer";
	// nothing above can match it, because nothing above is a substring test.
	// What the removals do select, for the address list, is one list + one
	// address + the tag.
	last := steps(o)[3]
	want := `/ip/firewall/address-list/remove [find list="` + o.addrList + `" address="` + o.subnet + `" ` + tag + `]`
	if last.remove != want {
		t.Fatalf("address-list removal:\n got %s\nwant %s", last.remove, want)
	}
}

// TestUninstallRemovesTheImageFile pins that the tar scp'd by install is part
// of what uninstall owes the device, and part of what it verifies.
func TestUninstallRemovesTheImageFile(t *testing.T) {
	o, _, err := parseOptions([]string{"-router", "u@h"})
	if err != nil {
		t.Fatal(err)
	}
	container := steps(o)[len(steps(o))-1]
	if !strings.Contains(container.remove, `/file/remove [find name="`+o.name+`.tar"]`) {
		t.Fatalf("container removal does not delete the image file: %s", container.remove)
	}
	if !strings.Contains(container.owned, `/file/find name="`+o.name+`.tar"`) {
		t.Fatalf("container ownership check ignores the image file: %s", container.owned)
	}
}

// TestUninstallVerifiesAndFailsOnLeftovers pins that "gone" is not the last
// word: uninstall re-asks the router what install created and fails, naming
// the step, when anything is still there. A clean router yields nil.
func TestUninstallVerifiesAndFailsOnLeftovers(t *testing.T) {
	o, _, err := parseOptions([]string{"-router", "u@h"})
	if err != nil {
		t.Fatal(err)
	}
	clean := &fakeRunner{present: map[string]bool{}}
	if uninstallErr := uninstall(clean, o); uninstallErr != nil {
		t.Fatalf("clean uninstall returned %v", uninstallErr)
	}
	// Every ownership query carries the tag, and the tag carries the name;
	// marking the name present makes every step report a leftover.
	dirty := &fakeRunner{present: map[string]bool{o.name: true}}
	uninstallErr := uninstall(dirty, o)
	if uninstallErr == nil {
		t.Fatal("uninstall reported success with objects still present")
	}
	for _, s := range steps(o) {
		if !strings.Contains(uninstallErr.Error(), s.name) {
			t.Fatalf("error does not name %q: %v", s.name, uninstallErr)
		}
	}
	if len(dirty.ran) != len(steps(o)) {
		t.Fatalf("verification changed the number of removals run: %d, want %d", len(dirty.ran), len(steps(o)))
	}
}

// TestFlagsAreBounded pins that no flag interpolated into a RouterOS command
// can carry a quote, a separator, a pattern or a parent reference, and that
// the structured ones (-subnet, -loki, -port) must parse as what they are.
func TestFlagsAreBounded(t *testing.T) {
	bad := [][]string{
		{"-name", ``},
		{"-name", `a"b`},
		{"-name", `cpu.*`},
		{"-name", `a b`},
		{"-name", `x/y`},
		{"-name", `$name`},
		{"-name", `-lead`},
		{"-name", strings.Repeat("a", 33)},
		{"-veth", `v"eth`},
		{"-veth", `a;b`},
		{"-iface-list", `L AN`},
		{"-addr-list", `LANs]`},
		{"-job", `j"ob`},
		{"-host-label", `h$`},
		{"-root-dir", `../disk`},
		{"-root-dir", `disk/../x`},
		{"-root-dir", `a"b`},
		{"-root-dir", ``},
		{"-arch", `ARM 64`},
		{"-arch", ``},
		{"-port", `0`},
		{"-port", `65536`},
		{"-port", `abc`},
		{"-subnet", `10.0.0.0/24`},
		{"-subnet", `10.0.0.1/30`},
		{"-subnet", `abc`},
		{"-subnet", `fd00::/30`},
		{"-loki", `ftp://x`},
		{"-loki", `http://`},
		{"-loki", `http://h:1/path`},
		{"-loki", `h:1`},
	}
	for _, args := range bad {
		if _, _, err := parseOptions(append([]string{"-router", "u@h"}, args...)); err == nil {
			t.Fatalf("%v was accepted", args)
		}
	}
	good := [][]string{
		{"-name", `cpuhr01`},
		{"-name", `a`},
		{"-name", `mon-2.b_c`},
		{"-name", strings.Repeat("a", 32)},
		{"-veth", `veth-cpuhr`},
		{"-iface-list", `LAN`},
		{"-addr-list", `LANs`},
		{"-job", `cpuhr01`},
		{"-host-label", `rb5009`},
		{"-root-dir", `tmpfs`},
		{"-root-dir", `disk1/perf.mon`},
		{"-arch", `arm64`},
		{"-port", `2200`},
		{"-subnet", `172.30.9.0/30`},
		{"-loki", `https://loki.example:3100/`},
	}
	for _, args := range good {
		if _, _, err := parseOptions(append([]string{"-router", "u@h"}, args...)); err != nil {
			t.Fatalf("%v was rejected: %v", args, err)
		}
	}
}

// TestDerivedAddressesAndLokiHost pins what the structured flags turn into:
// the two ends of the /30 and the NAT rule's destination host.
func TestDerivedAddressesAndLokiHost(t *testing.T) {
	o, _, err := parseOptions([]string{"-router", "u@h", "-subnet", "10.9.8.4/30", "-loki", "https://loki.example:3100/"})
	if err != nil {
		t.Fatal(err)
	}
	if o.gatewayIP != "10.9.8.5" || o.containerIP != "10.9.8.6" {
		t.Fatalf("derived /30 ends: gateway %s container %s", o.gatewayIP, o.containerIP)
	}
	if o.lokiHost != "loki.example" || o.lokiBase != "https://loki.example:3100" || o.lokiPushURL() != "https://loki.example:3100/loki/api/v1/push" {
		t.Fatalf("loki: host %s base %s push %s", o.lokiHost, o.lokiBase, o.lokiPushURL())
	}
}

// TestRenderChartDeterministic pins that the same dataset and palette always
// produce identical bytes, and that the essentials are present.
func TestRenderChartDeterministic(t *testing.T) {
	pts := []point{{-5, 3, 330}, {0, 5, 349}, {10, 31, 349}, {35, 30, 348}, {45, 4, 348}}
	marks := []marker{{0, "bouncer starts", "neutral"}, {35, "reconciliation complete", "done"}}
	p := chartPalette{page: "#fff", grid: "#ddd", text: "#111", muted: "#666", cpu: "#4d4a98", ram: "#906004", markNeutral: "#666", markWrite: "#b3352f", markDone: "#257a38"}
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
