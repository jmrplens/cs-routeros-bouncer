// Command perfmon installs, verifies and harvests the high-resolution router
// monitor used for the performance numbers in the documentation.
//
// The monitor is a 6 MiB scratch container running ON the RouterOS device,
// sampling the shared kernel's /proc/stat and /proc/meminfo at 10 Hz and
// pushing one batched line per second straight to Loki. RouterOS's own
// cpu-load metric updates once per second; this is the only way to see below
// that. Per-process attribution is not possible from the container (own PID
// namespace).
//
// Usage:
//
//	go run ./cmd/perfmon install   [flags]   deploy container + network, verify
//	go run ./cmd/perfmon verify    [flags]   check fresh samples reach Loki
//	go run ./cmd/perfmon capture   [flags]   pull a window from Loki as CSV
//	go run ./cmd/perfmon plot      [flags]   pull a window and emit mermaid charts
//	go run ./cmd/perfmon uninstall [flags]   remove everything install created
//
// Requirements: ssh and scp on PATH with key access to the router, the
// container package enabled on the device, and a Loki instance the router can
// reach. Everything install creates is tagged with the container name in its
// comment; uninstall removes exactly that set. The container's root lives on
// the router's tmpfs, so it does NOT survive a reboot — rerun install (it is
// idempotent and fast) after one.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type options struct {
	router     string // user@host for ssh
	port       string
	key        string
	name       string
	veth       string
	subnet     string // x.y.z.0/30
	ifaceList  string
	addrList   string
	rootDir    string
	lokiBase   string // http://host:port
	lokiHost   string // host part, for the NAT rule
	job        string
	hostLabel  string
	arch       string
	minutes    float64
	dataCSV    string
	markersCSV string
	themeCSS   string
	outDir     string
	title      string

	containerIP string
	gatewayIP   string
}

func (o options) lokiPushURL() string { return o.lokiBase + "/loki/api/v1/push" }

func parseOptions(args []string) (options, *flag.FlagSet, error) {
	fs := flag.NewFlagSet("perfmon", flag.ContinueOnError)
	o := options{}
	fs.StringVar(&o.router, "router", "", "ssh target for the router, user@host (required)")
	fs.StringVar(&o.port, "port", "22", "ssh port on the router")
	fs.StringVar(&o.key, "key", "", "ssh identity file (default: ssh agent / config)")
	fs.StringVar(&o.name, "name", "cpuhr01", "container name; tags every object created")
	fs.StringVar(&o.veth, "veth", "veth-cpuhr", "veth interface name on the router")
	fs.StringVar(&o.subnet, "subnet", "172.30.9.0/30", "point-to-point /30 for the container") // NOSONAR S1313 -- a documented default the operator overrides
	fs.StringVar(&o.ifaceList, "iface-list", "LAN", "interface list the veth must join (raw drop-the-rest trap)")
	fs.StringVar(&o.addrList, "addr-list", "LANs", "address list the subnet must join (raw drop-local trap)")
	fs.StringVar(&o.rootDir, "root-dir", "tmpfs", "router disk for the container root (tmpfs = wiped on reboot)")
	fs.StringVar(&o.lokiBase, "loki", "http://192.168.0.40:50104", "Loki base URL, reachable from the router") // NOSONAR S1313 -- ditto
	fs.StringVar(&o.job, "job", "cpuhr01", "Loki job label the sampler pushes under")
	fs.StringVar(&o.hostLabel, "host-label", "rb5009", "Loki host label")
	fs.StringVar(&o.arch, "arch", "arm64", "router CPU architecture (GOARCH)")
	fs.Float64Var(&o.minutes, "minutes", 5, "capture window, minutes back from now")
	fs.StringVar(&o.dataCSV, "data", "docs/src/data/perf-lifecycle.csv", "plot: dataset to draw")
	fs.StringVar(&o.markersCSV, "markers", "docs/src/data/perf-lifecycle-markers.csv", "plot: event markers")
	fs.StringVar(&o.themeCSS, "theme", "docs/src/styles/theme.css", "plot: stylesheet the palettes are read from")
	fs.StringVar(&o.outDir, "out", "docs/src/assets", "plot: directory for the generated SVGs")
	fs.StringVar(&o.title, "title", "First reconciliation on an RB5009 — 22,000 entries, sampled at 100 ms", "plot: chart title")
	if err := fs.Parse(args); err != nil {
		return o, fs, err
	}

	// Derive the two host addresses of the /30: .1 router side, .2 container.
	base, _, ok := strings.Cut(o.subnet, "/")
	if !ok {
		return o, fs, fmt.Errorf("-subnet must be CIDR, got %q", o.subnet)
	}
	octets := strings.Split(base, ".")
	if len(octets) != 4 {
		return o, fs, fmt.Errorf("-subnet must be IPv4, got %q", o.subnet)
	}
	prefix := strings.Join(octets[:3], ".")
	o.gatewayIP = prefix + ".1"
	o.containerIP = prefix + ".2"

	hostPart := strings.TrimPrefix(o.lokiBase, "http://")
	hostPart = strings.TrimPrefix(hostPart, "https://")
	o.lokiHost, _, _ = strings.Cut(hostPart, ":")
	return o, fs, nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	verb := os.Args[1]
	o, fs, err := parseOptions(os.Args[2:])
	if err != nil {
		os.Exit(2)
	}
	if dispatchErr := dispatch(verb, o, fs); dispatchErr != nil {
		fmt.Fprintln(os.Stderr, "perfmon:", dispatchErr)
		os.Exit(1)
	}
}

func dispatch(verb string, o options, fs *flag.FlagSet) error {
	needsRouter := verb == "install" || verb == "uninstall"
	if needsRouter && o.router == "" {
		fs.Usage()
		return fmt.Errorf("-router is required for %s", verb)
	}
	r := sshRunner{target: o.router, port: o.port, key: o.key}

	switch verb {
	case "install":
		fmt.Println("building sampler for linux/" + o.arch)
		binary, err := buildSampler("linux", o.arch)
		if err != nil {
			return err
		}
		image, tarErr := imageTar(binary, o.arch)
		if tarErr != nil {
			return tarErr
		}
		created, err := install(r, o, image)
		if err != nil {
			return err
		}
		fmt.Printf("install done (%d step(s) created); waiting for first samples\n", created)
		time.Sleep(15 * time.Second)
		return verify(o)
	case "uninstall":
		uninstall(r, o)
		return nil
	case "verify":
		return verify(o)
	case "capture":
		to := time.Now()
		from := to.Add(-time.Duration(o.minutes * float64(time.Minute)))
		samples, err := capture(o, from, to)
		if err != nil {
			return err
		}
		if len(samples) == 0 {
			return errors.New("no samples in the window")
		}
		writeCSV(os.Stdout, samples)
		return nil
	case "plot":
		return plotDocs(o)
	default:
		usage()
		return fmt.Errorf("unknown verb %q", verb)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: perfmon <install|verify|capture|plot|uninstall> [flags]  (-h for flags)")
}
