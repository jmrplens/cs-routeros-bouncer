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
	out, err := exec.CommandContext(context.Background(), "ssh", args...).CombinedOutput() //NOSONAR
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
	if out, scpErr := exec.CommandContext(context.Background(), "scp", args...).CombinedOutput(); scpErr != nil { //NOSONAR
		return fmt.Errorf("scp %s: %w\n%s", remoteName, scpErr, out)
	}
	return nil
}

// step is one idempotent install action: skip when check finds it, create
// otherwise. Uninstall runs remove in reverse order for the steps that have
// one.
type step struct {
	name   string
	check  string // RouterOS expression printing a count; "0" means absent
	create string
	remove string
}

// steps returns the install plan for the given options. Every object it
// creates carries the container name in its comment, which is what remove
// matches on — nothing else on the router is touched.
func steps(o options) []step {
	tag := o.name + ": high-resolution monitor (managed by cmd/perfmon)"
	return []step{
		{
			name:   "veth interface " + o.veth,
			check:  `:put [:len [/interface/veth/find name="` + o.veth + `"]]`,
			create: `/interface/veth/add name="` + o.veth + `" address=` + o.containerIP + `/30 gateway=` + o.gatewayIP + ` comment="` + tag + `"`,
			remove: `/interface/veth/remove [find name="` + o.veth + `"]`,
		},
		{
			name:   "router address " + o.gatewayIP,
			check:  `:put [:len [/ip/address/find interface="` + o.veth + `"]]`,
			create: `/ip/address/add address=` + o.gatewayIP + `/30 interface="` + o.veth + `" comment="` + tag + `"`,
			remove: `/ip/address/remove [find interface="` + o.veth + `"]`,
		},
		{
			// Without this, the defconf raw rule `drop the rest
			// (in-interface-list=!LAN)` silently eats every packet the
			// container sends. Found the hard way; see docs/perfmon.
			name:   "interface-list membership " + o.ifaceList,
			check:  `:put [:len [/interface/list/member/find interface="` + o.veth + `" list="` + o.ifaceList + `"]]`,
			create: `/interface/list/member/add list="` + o.ifaceList + `" interface="` + o.veth + `" comment="` + tag + `"`,
			remove: `/interface/list/member/remove [find interface="` + o.veth + `"]`,
		},
		{
			// The sibling trap: `drop local if not from default IP range`
			// matches src outside the LANs address list.
			name:   "address-list membership " + o.addrList,
			check:  `:put [:len [/ip/firewall/address-list/find list="` + o.addrList + `" address="` + o.subnet + `"]]`,
			create: `/ip/firewall/address-list/add list="` + o.addrList + `" address=` + o.subnet + ` comment="` + tag + `"`,
			remove: `/ip/firewall/address-list/remove [find comment~"` + o.name + `"]`,
		},
		{
			name:   "srcnat masquerade to Loki",
			check:  `:put [:len [/ip/firewall/nat/find comment~"` + o.name + `"]]`,
			create: `/ip/firewall/nat/add chain=srcnat src-address=` + o.containerIP + ` dst-address=` + o.lokiHost + ` action=masquerade comment="` + tag + `"`,
			remove: `/ip/firewall/nat/remove [find comment~"` + o.name + `"]`,
		},
		{
			name:  "container " + o.name,
			check: `:put [:len [/container/find comment~"` + o.name + `"]]`,
			create: `/container/envs/add list="` + o.name + `-env" name=LOKI_URL value="` + o.lokiPushURL() + `"; ` +
				`/container/envs/add list="` + o.name + `-env" name=HOST_NAME value="` + o.hostLabel + `"; ` +
				`/container/add file=` + o.name + `.tar interface="` + o.veth + `" root-dir=` + o.rootDir + `/` + o.name +
				` envlist="` + o.name + `-env" logging=yes start-on-boot=no comment="` + tag + `"; ` +
				`:delay 6s; /container/start [find comment~"` + o.name + `"]`,
			remove: `/container/stop [find comment~"` + o.name + `"]; :delay 4s; ` +
				`/container/remove [find comment~"` + o.name + `"]; ` +
				`/container/envs/remove [find list="` + o.name + `-env"]`,
		},
	}
}

// install walks the plan, creating what is missing. The container step uploads
// the image first. It returns how many steps it created.
func install(r runner, o options, image []byte) (int, error) {
	created := 0
	for _, s := range steps(o) {
		out, err := r.run(s.check)
		if err != nil {
			return created, fmt.Errorf("check %s: %w", s.name, err)
		}
		if strings.TrimSpace(out) != "0" {
			fmt.Printf("  ok    %s (already present)\n", s.name)
			continue
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

// uninstall removes everything install created, newest first, and ignores
// what is already gone.
func uninstall(r runner, o options) {
	plan := steps(o)
	for _, s := range slices.Backward(plan) {
		if s.remove == "" {
			continue
		}
		if _, err := r.run(s.remove); err != nil {
			fmt.Printf("  skip  %s (%v)\n", s.name, firstLine(err))
			continue
		}
		fmt.Printf("  gone  %s\n", s.name)
	}
}

func firstLine(err error) string {
	msg := err.Error()
	if before, _, ok := strings.Cut(msg, "\n"); ok {
		return before
	}
	return msg
}
