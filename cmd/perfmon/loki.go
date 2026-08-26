package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var lineRE = regexp.MustCompile(
	`CPUHR01 v=1 q=(\d+) t=([\d,]+) c0=([\d,]+) c1=([\d,]+) c2=([\d,]+) c3=([\d,]+) ma=(\d+) mf=(\d+)`,
)

// sample is one 100 ms reading reconstructed from a batched line.
type sample struct {
	t     float64 // unix seconds
	cpu   int
	cores [4]int
	maKiB int
	mfKiB int
}

// verify asks Loki for the most recent sampler line and reports how fresh it
// is. This is the install's acceptance test: network misconfiguration on the
// router (the firewall-list traps above) presents as a running container whose
// pushes silently go nowhere.
func verify(o options) error {
	now := time.Now()
	samples, err := capture(o, now.Add(-2*time.Minute), now)
	if err != nil {
		return err
	}
	if len(samples) == 0 {
		return fmt.Errorf("no %s lines reached Loki in the last two minutes — the container may be running with its pushes dropped; check the interface-list and address-list memberships", o.job)
	}
	age := now.Sub(time.Unix(int64(samples[len(samples)-1].t), 0))
	fmt.Printf("  ok    %d samples in the last two minutes, newest %s old\n", len(samples), age.Round(time.Second))
	return nil
}

// capture pulls the [from, to] window from Loki and expands each batched line
// back into its ten 100 ms samples.
func capture(o options, from, to time.Time) ([]sample, error) {
	var out []sample
	seen := map[string]bool{}
	cursor := from
	client := &http.Client{Timeout: 30 * time.Second}
	for cursor.Before(to) {
		q := url.Values{
			"query":     {`{job="` + o.job + `"}`},
			"start":     {strconv.FormatInt(cursor.UnixNano(), 10)},
			"end":       {strconv.FormatInt(to.UnixNano(), 10)},
			"limit":     {"5000"},
			"direction": {"forward"},
		}
		req, reqErr := http.NewRequestWithContext(context.Background(),
			http.MethodGet, o.lokiBase+"/loki/api/v1/query_range?"+q.Encode(), http.NoBody)
		if reqErr != nil {
			return nil, reqErr
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("loki: HTTP %d: %s", resp.StatusCode, firstBytes(body))
		}
		var payload struct {
			Data struct {
				Result []struct {
					Values [][2]string `json:"values"`
				} `json:"result"`
			} `json:"data"`
		}
		if unmarshalErr := json.Unmarshal(body, &payload); unmarshalErr != nil {
			return nil, unmarshalErr
		}
		batch := 0
		var last time.Time
		for _, res := range payload.Data.Result {
			for _, v := range res.Values {
				ns, _ := strconv.ParseInt(v[0], 10, 64)
				ts := time.Unix(0, ns)
				if ts.After(last) {
					last = ts
				}
				batch++
				out = append(out, expand(ts, v[1], seen)...)
			}
		}
		if batch == 0 || !last.After(cursor) {
			break
		}
		cursor = last.Add(time.Millisecond)
		if batch < 5000 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].t < out[j].t })
	return out, nil
}

// expand turns one batched line into its constituent samples. The line's
// timestamp marks the LAST sample of the batch; sample k of n sits at
// ts-(n-1-k)*100ms. The seen set drops replays across paginated queries.
func expand(ts time.Time, line string, seen map[string]bool) []sample {
	m := lineRE.FindStringSubmatch(line)
	if len(m) < 9 || seen[m[1]] {
		return nil
	}
	seen[m[1]] = true
	tot := splitInts(m[2])
	cores := [4][]int{splitInts(m[3]), splitInts(m[4]), splitInts(m[5]), splitInts(m[6])}
	ma, _ := strconv.Atoi(m[7])
	mf, _ := strconv.Atoi(m[8])
	n := len(tot)
	out := make([]sample, 0, n)
	for k := range n {
		s := sample{
			t:     float64(ts.UnixNano())/1e9 - float64(n-1-k)*0.1,
			cpu:   tot[k],
			maKiB: ma, mfKiB: mf,
		}
		for c := range cores {
			if k < len(cores[c]) {
				s.cores[c] = cores[c][k]
			}
		}
		out = append(out, s)
	}
	return out
}

func splitInts(csv string) []int {
	parts := strings.Split(csv, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		v, _ := strconv.Atoi(p)
		out = append(out, v)
	}
	return out
}

func firstBytes(b []byte) string {
	const limit = 160
	if len(b) > limit {
		b = b[:limit]
	}
	return string(b)
}

// writeCSV emits the samples in a spreadsheet-ready shape.
func writeCSV(w io.Writer, samples []sample) {
	fmt.Fprintln(w, "unix_s,cpu_pct,core0,core1,core2,core3,mem_avail_kib,mem_free_kib")
	for _, s := range samples {
		fmt.Fprintf(w, "%.1f,%d,%d,%d,%d,%d,%d,%d\n",
			s.t, s.cpu, s.cores[0], s.cores[1], s.cores[2], s.cores[3], s.maKiB, s.mfKiB)
	}
}
