// Command perfmon installs, verifies and harvests the high-resolution router
// monitor used for the performance numbers in the documentation.
//
// The monitor is a 6 MiB scratch container running ON the RouterOS device,
// sampling the shared kernel's /proc/stat at 10 Hz — and /proc/meminfo once
// per batch, so memory is a 1 Hz series — and pushing one batched line per
// second straight to Loki. RouterOS's own cpu-load metric updates once per
// second; this is the only way to see below that. Per-process attribution is
// not possible from the container (own PID namespace).
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
// reach. Everything install creates carries one exact comment tag; uninstall
// removes exactly that set — matched by the tag, never by pattern — plus the
// uploaded image file, then re-runs its ownership checks and fails if anything
// remains. The container's root lives on the router's tmpfs by default and it
// is registered with start-on-boot=no, so it does NOT survive a reboot —
// rerun install (it is idempotent and fast) after one.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Every string flag below is interpolated verbatim into RouterOS commands
// that run over the operator's own admin ssh session, so there is no
// privilege boundary for a crafted value to cross — but a quote or a
// semicolon in one turns a clear failure into a confusing RouterOS syntax
// error, or a selector into something wider than intended. The flags are
// therefore bounded to what RouterOS object names and paths can carry, and
// the tool fails fast, before the first command, on anything else.
var (
	// validName bounds -name, which also becomes the envlist name, the
	// image file name and the root-dir leaf.
	validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`)
	// validObjectName bounds RouterOS object and list names: -veth,
	// -iface-list, -addr-list, and the Loki labels -job and -host-label.
	validObjectName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	// validRootDir bounds -root-dir: a disk name or a slash-separated path
	// on the router, no quotes, no parent references.
	validRootDir = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./-]{0,63}$`)
	// validArch bounds -arch to what GOARCH and the image manifest accept.
	validArch = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
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
	fs.StringVar(&o.name, "name", "cpuhr01", "container name; tags every object created (letters, digits, - _ .)")
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

	if err := validateFlags(o); err != nil {
		return o, fs, err
	}
	return deriveEndpoints(o, fs)
}

// validateFlags bounds every value that is interpolated into a RouterOS
// command; see the regexps above for why.
func validateFlags(o options) error {
	if !validName.MatchString(o.name) {
		return fmt.Errorf("-name must match %s, got %q", validName, o.name)
	}
	for flagName, value := range map[string]string{
		"-veth": o.veth, "-iface-list": o.ifaceList, "-addr-list": o.addrList,
		"-job": o.job, "-host-label": o.hostLabel,
	} {
		if !validObjectName.MatchString(value) {
			return fmt.Errorf("%s must match %s, got %q", flagName, validObjectName, value)
		}
	}
	if !validRootDir.MatchString(o.rootDir) || slices.Contains(strings.Split(o.rootDir, "/"), "..") {
		return fmt.Errorf("-root-dir must match %s with no \"..\" segment, got %q", validRootDir, o.rootDir)
	}
	if !validArch.MatchString(o.arch) {
		return fmt.Errorf("-arch must match %s, got %q", validArch, o.arch)
	}
	if port, err := strconv.Atoi(o.port); err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("-port must be 1-65535, got %q", o.port)
	}
	return nil
}

// deriveEndpoints turns the structured flags into what the commands need:
// the two ends of the /30 and the Loki host the NAT rule names.
func deriveEndpoints(o options, fs *flag.FlagSet) (options, *flag.FlagSet, error) {
	// The /30 is the whole point-to-point link: .1 router side, .2 container.
	// Anything but an IPv4 /30 cannot yield those two addresses.
	ip, network, err := net.ParseCIDR(o.subnet)
	if err != nil || ip.To4() == nil {
		return o, fs, fmt.Errorf("-subnet must be an IPv4 CIDR, got %q", o.subnet)
	}
	if ones, _ := network.Mask.Size(); ones != 30 {
		return o, fs, fmt.Errorf("-subnet must be a /30, got %q", o.subnet)
	}
	if !ip.Equal(network.IP) {
		return o, fs, fmt.Errorf("-subnet must be the network address, got %q (network %s)", o.subnet, network)
	}
	base := network.IP.To4()
	o.subnet = network.String()
	o.gatewayIP = net.IPv4(base[0], base[1], base[2], base[3]+1).String()
	o.containerIP = net.IPv4(base[0], base[1], base[2], base[3]+2).String()

	// The Loki base is both the URL the sampler pushes to and the host the
	// NAT rule names; it must parse as one, with a scheme and a host.
	u, err := url.Parse(o.lokiBase)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
		return o, fs, fmt.Errorf("-loki must be http(s)://host[:port] with no path, got %q", o.lokiBase)
	}
	o.lokiBase = u.Scheme + "://" + u.Host
	o.lokiHost = u.Hostname()
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
		return uninstall(r, o)
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
