// Command sampler reads the router's real per-core CPU and memory at 10 Hz and
// pushes one line per second to Loki. It runs as a container ON the RouterOS
// device: the kernel is shared, so /proc/stat exposes the true per-core
// jiffies — the only sub-second source the system has, since RouterOS's own
// cpu-load updates once per second. /proc/meminfo is global too. Per-process
// data is NOT available: the container has its own PID namespace.
//
// Each second it emits one line carrying ten 100 ms samples:
//
//	CPUHR01 v=1 q=<seq> t=<total%>,... c0=... c1=... c2=... c3=... ma=<KiB> mf=<KiB>
//
// A failed push is dropped, deliberately: a monitor that buffers without bound
// eventually becomes the load it was built to watch.
//
// Configuration is by environment, set through the container's envlist:
//
//	LOKI_URL  push endpoint (default http://192.168.0.40:50104/loki/api/v1/push)
//	JOB_NAME  Loki job label (default cpuhr01)
//	HOST_NAME Loki host label (default rb5009)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	interval = 100 * time.Millisecond
	batch    = 10
	nCores   = 4
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type cpuTicks struct{ busy, total uint64 }

// readStat returns aggregate and per-core tick counters.
func readStat() (total cpuTicks, cores [nCores]cpuTicks, err error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return total, cores, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		var vals [8]uint64
		for i := range 8 {
			vals[i], _ = strconv.ParseUint(f[i+1], 10, 64)
		}
		// user nice system idle iowait irq softirq steal
		idle := vals[3] + vals[4]
		var sum uint64
		for _, v := range vals {
			sum += v
		}
		t := cpuTicks{busy: sum - idle, total: sum}
		switch f[0] {
		case "cpu":
			total = t
		default:
			if n, convErr := strconv.Atoi(f[0][3:]); convErr == nil && n < nCores {
				cores[n] = t
			}
		}
	}
	return total, cores, nil
}

func readMem() (avail, free uint64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemAvailable:":
			avail = v
		case "MemFree:":
			free = v
		}
	}
	return avail, free
}

// pct converts the delta between two readings into a busy percentage.
func pct(prev, cur cpuTicks) (busyPct int) {
	dt := cur.total - prev.total
	if dt == 0 {
		return 0
	}
	// The quotient is 0..100 by construction; the conversion cannot overflow.
	return int((cur.busy - prev.busy) * 100 / dt) // #nosec G115 -- the quotient is 0..100 by construction
}

func push(client *http.Client, url, job, host, line string, ts time.Time) {
	payload := map[string]any{
		"streams": []map[string]any{{
			"stream": map[string]string{"job": job, "host": host},
			"values": [][2]string{{strconv.FormatInt(ts.UnixNano(), 10), line}},
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		return
	}
	req, reqErr := http.NewRequestWithContext(context.Background(),
		http.MethodPost, url, bytes.NewReader(body))
	if reqErr != nil {
		fmt.Fprintln(os.Stderr, "push:", reqErr)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "push:", err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		fmt.Fprintln(os.Stderr, "push: HTTP", resp.StatusCode)
	}
}

func main() {
	lokiURL := env("LOKI_URL", "http://192.168.0.40:50104/loki/api/v1/push")
	job := env("JOB_NAME", "cpuhr01")
	host := env("HOST_NAME", "rb5009")

	client := &http.Client{Timeout: 3 * time.Second}
	prevTot, prevCores, err := readStat()
	if err != nil {
		fmt.Fprintln(os.Stderr, "stat:", err)
		os.Exit(1)
	}

	var sb strings.Builder
	tot := make([]string, 0, batch)
	var cores [nCores][]string
	for i := range cores {
		cores[i] = make([]string, 0, batch)
	}
	seq := 0
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for range tick.C {
		curTot, curCores, statErr := readStat()
		if statErr != nil {
			continue
		}
		tot = append(tot, strconv.Itoa(pct(prevTot, curTot)))
		for i := range curCores {
			cores[i] = append(cores[i], strconv.Itoa(pct(prevCores[i], curCores[i])))
		}
		prevTot, prevCores = curTot, curCores
		if len(tot) < batch {
			continue
		}
		avail, free := readMem()
		seq++
		sb.Reset()
		fmt.Fprintf(&sb, "CPUHR01 v=1 q=%d t=%s", seq, strings.Join(tot, ","))
		for i := range cores {
			fmt.Fprintf(&sb, " c%d=%s", i, strings.Join(cores[i], ","))
		}
		fmt.Fprintf(&sb, " ma=%d mf=%d", avail, free)
		push(client, lokiURL, job, host, sb.String(), time.Now())
		tot = tot[:0]
		for i := range cores {
			cores[i] = cores[i][:0]
		}
	}
}
