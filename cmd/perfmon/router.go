package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
)

// runner executes one RouterOS CLI command and returns its output. The real
// implementation shells out to the system ssh; tests substitute a fake to
// exercise the idempotency decisions without a router.
type runner interface {
	run(command string) (string, error)
	upload(local []byte, remoteName string) error
}

type sshRunner struct {
	target string // user@host
	port   string
	key    string
}

func (r sshRunner) base() []string {
	args := []string{"-p", r.port, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"}
	if r.key != "" {
		args = append(args, "-i", r.key)
	}
	return args
}

func (r sshRunner) run(command string) (string, error) {
	args := append(r.base(), r.target, command)
	// #nosec G204 -- invoking the system ssh with operator-supplied flags is
	// this tool's whole transport; there is no injection surface beyond what
	// the operator already controls. (Sonar S4036 objects to PATH lookup for
	// the same reason; a developer tool resolving ssh from PATH is intended.)
	out, err := exec.CommandContext(context.Background(), "ssh", args...).CombinedOutput() // NOSONAR --
	if err != nil {
		return string(out), fmt.Errorf("ssh %q: %w\n%s", command, err, out)
	}
	return string(out), nil
}

func (r sshRunner) upload(data []byte, remoteName string) error {
	tmp, err := os.CreateTemp("", "perfmon-upload-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, writeErr := tmp.Write(data); writeErr != nil {
		return writeErr
	}
	if closeErr := tmp.Close(); closeErr != nil {
		return closeErr
	}
	args := []string{"-P", r.port, "-o", "BatchMode=yes"}
	if r.key != "" {
		args = append(args, "-i", r.key)
	}
	args = append(args, tmp.Name(), r.target+":"+remoteName)
	// #nosec G204 -- same reasoning as run: scp is the transport.
	if out, scpErr := exec.CommandContext(context.Background(), "scp", args...).CombinedOutput(); scpErr != nil { // NOSONAR --
		return fmt.Errorf("scp %s: %w\n%s", remoteName, scpErr, out)
	}
	return nil
}

// step is one install action with three questions and two verbs. Install
// asks owned first: ours already → skip. Then check: exists but not ours →
// refuse, naming the object, because perfmon does not build on objects it
// does not own and will not later remove. Neither → create. Uninstall runs
// remove in reverse order, then asks owned for every step and refuses to
// report success while any count is non-zero.
//
// owned selects only what install itself created, by the exact comment tag
// it wrote, and remove uses that same selector — which is what keeps
// uninstall from touching a hand-made setup, or anything else that happens
// to share a substring with the container name. The address-list table this
// tool writes to is the one the bouncer keeps its blocking state in; a
// pattern match there is not an option. check asks the broader question —
// does the EFFECT exist, however it got there — and its only job is to
// detect a collision with something that is not ours.
type step struct {
	name   string
	check  string // RouterOS expression printing a count; "0" means the effect is absent
	create string
	owned  string // RouterOS expression printing how many objects install created still exist
	remove string
}

// tagFor is the exact comment every object install creates carries, and the
// only thing uninstall matches on.
func tagFor(name string) string {
	return name + ": high-resolution monitor (managed by cmd/perfmon)"
}

// markerName is the environment entry that signs the envlist. Neither
// /container/envs nor /file carries a comment, so ownership of the two
// resources the container step derives — the envlist and the uploaded image
// — is established by this entry holding the exact tag, and the image is
// considered ours only while the marker exists.
const markerName = "PERFMON_TAG"

// steps returns the install plan for the given options. Every object it
// creates carries tagFor(o.name) in its comment, verbatim, and every remove
// selects by that exact comment together with the identity its check used —
// nothing else on the router is touched.
func steps(o options) []step {
	tag := tagFor(o.name)
	byTag := ` comment="` + tag + `"`
	envList := o.name + "-env"
	imageFile := o.name + ".tar"
	marker := `[/container/envs/find list="` + envList + `" name="` + markerName + `" value="` + tag + `"]`
	return []step{
		{
			name:   "veth interface " + o.veth,
			check:  `:put [:len [/interface/veth/find name="` + o.veth + `"]]`,
			create: `/interface/veth/add name="` + o.veth + `" address=` + o.containerIP + `/30 gateway=` + o.gatewayIP + byTag,
			owned:  `:put [:len [/interface/veth/find name="` + o.veth + `"` + byTag + `]]`,
			remove: `/interface/veth/remove [find name="` + o.veth + `"` + byTag + `]`,
		},
		{
			name:   "router address " + o.gatewayIP,
			check:  `:put [:len [/ip/address/find interface="` + o.veth + `"]]`,
			create: `/ip/address/add address=` + o.gatewayIP + `/30 interface="` + o.veth + `"` + byTag,
			owned:  `:put [:len [/ip/address/find interface="` + o.veth + `"` + byTag + `]]`,
			remove: `/ip/address/remove [find interface="` + o.veth + `"` + byTag + `]`,
		},
		{
			// Without this, the defconf raw rule `drop the rest
			// (in-interface-list=!LAN)` silently eats every packet the
			// container sends. Found the hard way; the method note in
			// docs/src/content/docs/development/benchmarking.mdx records
			// both traps.
			name:   "interface-list membership " + o.ifaceList,
			check:  `:put [:len [/interface/list/member/find interface="` + o.veth + `" list="` + o.ifaceList + `"]]`,
			create: `/interface/list/member/add list="` + o.ifaceList + `" interface="` + o.veth + `"` + byTag,
			owned:  `:put [:len [/interface/list/member/find interface="` + o.veth + `" list="` + o.ifaceList + `"` + byTag + `]]`,
			remove: `/interface/list/member/remove [find interface="` + o.veth + `" list="` + o.ifaceList + `"` + byTag + `]`,
		},
		{
			// The sibling trap: `drop local if not from default IP range`
			// matches src outside the LANs address list.
			name:   "address-list membership " + o.addrList,
			check:  `:put [:len [/ip/firewall/address-list/find list="` + o.addrList + `" address="` + o.subnet + `"]]`,
			create: `/ip/firewall/address-list/add list="` + o.addrList + `" address=` + o.subnet + byTag,
			owned:  `:put [:len [/ip/firewall/address-list/find list="` + o.addrList + `" address="` + o.subnet + `"` + byTag + `]]`,
			remove: `/ip/firewall/address-list/remove [find list="` + o.addrList + `" address="` + o.subnet + `"` + byTag + `]`,
		},
		{
			// In a find, an address attribute only matches when quoted:
			// unquoted, RouterOS parses it as an ip and the comparison with
			// the stored prefix comes back empty (verified on 7.24.1).
			name:   "srcnat masquerade to Loki",
			check:  `:put [:len [/ip/firewall/nat/find chain=srcnat src-address="` + o.containerIP + `"]]`,
			create: `/ip/firewall/nat/add chain=srcnat src-address=` + o.containerIP + ` dst-address=` + o.lokiHost + ` action=masquerade` + byTag,
			owned:  `:put [:len [/ip/firewall/nat/find chain=srcnat src-address="` + o.containerIP + `"` + byTag + `]]`,
			remove: `/ip/firewall/nat/remove [find chain=srcnat src-address="` + o.containerIP + `"` + byTag + `]`,
		},
		{
			// The image file is uploaded by install right before this step
			// runs, and RouterOS keeps it on flash after extracting it; it is
			// part of what uninstall owes the device. The marker is written
			// first and removed last, so a removal that fails half-way leaves
			// the envlist and the image counted as ours, and uninstall says
			// so instead of reporting clean.
			name: "container " + o.name,
			check: `:put ([:len [/container/find file="` + imageFile + `"]] + ` +
				`[:len [/container/envs/find list="` + envList + `"]] + ` +
				`[:len [/file/find name="` + imageFile + `"]])`,
			create: `/container/envs/add list="` + envList + `" name=` + markerName + ` value="` + tag + `"; ` +
				`/container/envs/add list="` + envList + `" name=LOKI_URL value="` + o.lokiPushURL() + `"; ` +
				`/container/envs/add list="` + envList + `" name=HOST_NAME value="` + o.hostLabel + `"; ` +
				`/container/add file=` + imageFile + ` interface="` + o.veth + `" root-dir=` + o.rootDir + `/` + o.name +
				` envlist="` + envList + `" logging=yes start-on-boot=no` + byTag + `; ` +
				`:delay 6s; /container/start [find` + byTag + `]`,
			owned: `:if ([:len ` + marker + `] > 0) do={ ` +
				`:put ([:len [/container/find` + byTag + `]] + ` +
				`[:len [/container/envs/find list="` + envList + `"]] + ` +
				`[:len [/file/find name="` + imageFile + `"]]) ` +
				`} else={ :put [:len [/container/find` + byTag + `]] }`,
			remove: `/container/stop [find` + byTag + `]; :delay 4s; ` +
				`/container/remove [find` + byTag + `]; ` +
				`:if ([:len ` + marker + `] > 0) do={ ` +
				`/file/remove [find name="` + imageFile + `"]; ` +
				`/container/envs/remove [find list="` + envList + `" name!="` + markerName + `"]; ` +
				`/container/envs/remove ` + marker + ` }`,
		},
	}
}

// install walks the plan, creating what is missing and refusing what is
// present but not ours. The container step uploads the image first. It
// returns how many steps it created.
func install(r runner, o options, image []byte) (int, error) {
	created := 0
	for _, s := range steps(o) {
		out, err := r.run(s.owned)
		if err != nil {
			return created, fmt.Errorf("check ownership of %s: %w", s.name, err)
		}
		if strings.TrimSpace(out) != "0" {
			fmt.Printf("  ok    %s (already present)\n", s.name)
			continue
		}
		out, err = r.run(s.check)
		if err != nil {
			return created, fmt.Errorf("check %s: %w", s.name, err)
		}
		if strings.TrimSpace(out) != "0" {
			return created, fmt.Errorf("%s exists on the router and was not created by perfmon (no ownership tag); "+
				"pick another -name/-veth/-subnet, or remove it by hand if it is yours", s.name)
		}
		if strings.HasPrefix(s.name, "container ") {
			fmt.Printf("  up    uploading image (%d KiB)\n", len(image)/1024)
			if upErr := r.upload(image, o.name+".tar"); upErr != nil {
				return created, upErr
			}
		}
		if _, createErr := r.run(s.create); createErr != nil {
			return created, fmt.Errorf("create %s: %w", s.name, createErr)
		}
		fmt.Printf("  new   %s\n", s.name)
		created++
	}
	return created, nil
}

// uninstall removes everything install created, newest first, ignoring what
// is already gone — then asks the router, step by step, whether anything
// install created is still there, and returns an error naming what is. A
// removal that printed nothing is not evidence; the count is.
func uninstall(r runner, o options) error {
	plan := steps(o)
	for _, s := range slices.Backward(plan) {
		if _, err := r.run(s.remove); err != nil {
			fmt.Printf("  skip  %s (%v)\n", s.name, firstLine(err))
			continue
		}
		fmt.Printf("  gone  %s\n", s.name)
	}
	var left []string
	for _, s := range plan {
		out, err := r.run(s.owned)
		if err != nil {
			return fmt.Errorf("verify %s: %w", s.name, err)
		}
		if strings.TrimSpace(out) != "0" {
			left = append(left, s.name)
		}
	}
	if len(left) > 0 {
		return fmt.Errorf("uninstall left %d object(s) behind: %s", len(left), strings.Join(left, "; "))
	}
	fmt.Println("uninstall verified: nothing perfmon created remains on the router")
	return nil
}

func firstLine(err error) string {
	msg := err.Error()
	if before, _, ok := strings.Cut(msg, "\n"); ok {
		return before
	}
	return msg
}
