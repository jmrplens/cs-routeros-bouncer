package routeros

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// bulkScriptName is the temporary script used for bulk operations.
const bulkScriptName = "crowdsec-bulk-import"

// systemScriptPath is the RouterOS menu used to create and execute temporary scripts.
const systemScriptPath = "/system/script"

// bulkDoneMarker starts the line a bulk script prints last, followed by the
// positions of the adds it could not make, as "1,5,". Output without it means
// the run stopped early.
const bulkDoneMarker = "crowdsec-bulk-done:"

// bulkChunkSize limits addresses per script to keep the script source a
// reasonable single API word.
//
// Measured, not estimated: 100 entries build a 21.6 KB script with this
// project's real comment format (75 bytes) and 14.7 KB with a minimal one —
// the previous "≈ 12 KB" was low by roughly half. The "~32 KB safe limit" it
// cited does not exist either: the wire format encodes a word length in up to
// five bytes, and this client's own guard is maxWordLength = 16 MiB
// (proto/reader.go), whose comment already names bulk script sources as the
// traffic it expects.
//
// The real constraint is not message size either. It is the trade between
// amortizing four round trips per chunk (find, add, run, remove) and the length
// of one non-interruptible script run on the router — and that trade has been
// swept against the live device: five interleaved rounds of 4,000 entries at
// 50 / 100 / 250 / 500 / 1000, medians 4.36 s to 5.78 s across the whole 20×
// range.
//
// The sweep's real result is that it cannot resolve one. Within a single chunk
// size the interquartile range reaches 2.55 s, while the spread between sizes
// is 1.43 s — the noise on one arm is larger than the difference between arms.
// Which size looks best even depends on the estimator: median and minimum pick
// 1,000, the mean picks 100. A two-term fit is correspondingly ill-conditioned;
// the per-entry coefficient lands near 1.2–1.3 ms and is stable because it
// dominates, but the per-chunk term is anywhere from ~1 to ~10 ms depending on
// the round, which for a 22,000-entry import is somewhere between 0.2 s and
// 2.3 s of scaffolding against ~27 s of insertion.
//
// Either way the conclusion is the same and does not depend on pinning the
// coefficient down: inserting rows dominates, and no chunk size in this range
// changes the import enough to measure reliably. So 100 stays — deep in the
// flat region, and short enough to keep a single script run interruptible.
//
// With /execute (RouterOS 7.8rc1 and later, see runChunk) a chunk is one round
// trip instead of four, which only flattens this further. The cap that matters
// there is RouterOS's own: an executed script "can not be larger than 64kB",
// and 100 entries stay far below it.
const bulkChunkSize = 100

// executeMaxScriptBytes is the largest script /execute takes, per the RouterOS
// scripting manual. A bigger one goes through a stored /system/script instead.
const executeMaxScriptBytes = 64 * 1024

// BulkAddAddresses adds many addresses through RouterOS scripts of up to
// bulkChunkSize adds each (runChunk), so a chunk costs the same few round trips
// however many entries it holds. An entry the script reports as not added, and
// every entry of a chunk whose run failed, gets an add of its own (addEach);
// a duplicate the router already holds is then refreshed and counts as added,
// the duplicates of every chunk looked up together at the end
// (settleDuplicates), and failed holds what the retry could not add either. A
// stored script cannot report back, so its chunk counts every entry as added.
// Once ctx is done no further chunk runs, and its entries are failed too.
// Each chunk waits on the client's pacer first (Pacer.Block).
func (c *Client) BulkAddAddresses(ctx context.Context, proto, list string, entries []BulkEntry) (added int, failed []BulkEntry, err error) {
	if len(entries) == 0 {
		return 0, nil, nil
	}

	total := 0
	var dups []*BulkEntry
	var errs []error
	for start := 0; start < len(entries); start += bulkChunkSize {
		if ctxErr := ctx.Err(); ctxErr != nil {
			failed = append(failed, entries[start:]...)
			errs = append(errs, ctxErr)
			break
		}
		if paceErr := c.pacer.Block(ctx); paceErr != nil {
			failed = append(failed, entries[start:]...)
			errs = append(errs, paceErr)
			break
		}
		end := min(start+bulkChunkSize, len(entries))
		chunk := entries[start:end]

		var retry []*BulkEntry
		failedAt, scriptErr := c.runChunk(buildBulkAddScript(proto, list, chunk))
		if scriptErr != nil {
			log.Warn().Err(scriptErr).Int("chunk_size", len(chunk)).Msg("bulk script failed, falling back to individual adds")
			for i := range chunk {
				retry = append(retry, &chunk[i])
			}
		} else {
			positions := recordedPositions(len(chunk), failedAt)
			total += len(chunk) - len(positions)
			for _, i := range positions {
				retry = append(retry, &chunk[i])
			}
		}
		retryAdded, retryFailed, retryDups, retryErrs := c.addEach(ctx, proto, list, retry)
		total += retryAdded
		failed = append(failed, retryFailed...)
		dups = append(dups, retryDups...)
		errs = append(errs, retryErrs...)
	}

	// The duplicates of every chunk together: each lookup walks the whole
	// list, and duplicates spread over many chunks would cost one each.
	refreshed, dupFailed, dupErrs := c.settleDuplicates(ctx, proto, list, dups)
	total += refreshed
	failed = append(failed, dupFailed...)
	errs = append(errs, dupErrs...)

	return total, failed, joinAddErrors(errs)
}

// AddAddressesEach adds entries with one API call each, never through a
// script: the bulk_add_method "api" without a connection pool. It counts every
// entry the router accepts, and every one it already had and the bouncer
// owns, whose timeout and comment it refreshes, as AddAddress does, but
// finding those with one lookup per batch (refreshDuplicates), and returns the
// entries whose add failed. It sets ID on every entry it adds or refreshes.
// Once ctx is done it adds no more, and the entries left, and the duplicates
// not yet refreshed, are failed too.
func (c *Client) AddAddressesEach(ctx context.Context, proto, list string, chunk []BulkEntry) (added int, failed []BulkEntry, err error) {
	ptrs := make([]*BulkEntry, len(chunk))
	for i := range chunk {
		ptrs[i] = &chunk[i]
	}
	added, failed, dups, errs := c.addEach(ctx, proto, list, ptrs)
	refreshed, dupFailed, dupErrs := c.settleDuplicates(ctx, proto, list, dups)
	added += refreshed
	failed = append(failed, dupFailed...)
	errs = append(errs, dupErrs...)
	if len(errs) == 0 {
		return added, nil, nil
	}
	return added, failed, joinAddErrors(errs)
}

// addEach sends one add per entry and sets ID on each one the router accepts.
// It hands back the duplicates, for settleDuplicates, instead of looking each
// one up. Once ctx is done it adds no more, and the entries left are failed.
// Each add waits on the client's pacer (Pacer.Entry).
func (c *Client) addEach(ctx context.Context, proto, list string, entries []*BulkEntry) (added int, failed []BulkEntry, dups []*BulkEntry, errs []error) {
	for i, entry := range entries {
		if ctxErr := ctx.Err(); ctxErr != nil {
			for _, e := range entries[i:] {
				failed = append(failed, *e)
			}
			errs = append(errs, ctxErr)
			break
		}
		release, paceErr := c.pacer.Entry(ctx)
		if paceErr != nil {
			for _, e := range entries[i:] {
				failed = append(failed, *e)
			}
			errs = append(errs, paceErr)
			break
		}
		id, duplicate, addErr := c.addAddressOnce(proto, list, entry.Address, entry.Timeout, entry.Comment)
		release()
		switch {
		case duplicate:
			dups = append(dups, entry)
		case addErr != nil:
			errs = append(errs, addErr)
			failed = append(failed, *entry)
		default:
			entry.ID = id
			added++
		}
	}
	return added, failed, dups, errs
}

// settleDuplicates refreshes dups with refreshDuplicates. Once ctx is done it
// leaves them, failed, for the next pass: each lookup walks the whole list,
// and a shutdown should not wait for it.
func (c *Client) settleDuplicates(ctx context.Context, proto, list string, dups []*BulkEntry) (refreshed int, failed []BulkEntry, errs []error) {
	if len(dups) == 0 {
		return 0, nil, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		for _, e := range dups {
			failed = append(failed, *e)
		}
		return 0, failed, []error{ctxErr}
	}
	return c.refreshDuplicates(ctx, proto, list, dups)
}

// joinAddErrors sums up the errors of a run of adds, nil for none.
func joinAddErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%d add errors (last: %w)", len(errs), errs[len(errs)-1])
}

// BulkEntry represents an address to add in bulk.
type BulkEntry struct {
	Address string
	Timeout string
	Comment string
	// ID is the RouterOS id of the entry, set by the per-entry adds
	// (AddAddressesEach, Pool.AddAddresses); a script cannot report it.
	ID string
}

// quoteScript escapes a value for interpolation into a double-quoted RouterOS
// script string.
//
// The `$` is the one that matters and the one that was missing. RouterOS
// expands `$name` INSIDE double quotes at script-parse time, and a name the
// generated script never declares expands to nothing — so the text is deleted
// rather than mangled, silently. Verified on RouterOS 7.24.1: a comment sent as
// `cs$bouncer|crowdsec|sshd-bf` arrives as `cs|crowdsec|sshd-bf`.
//
// That is not cosmetic where the destroyed text is the operator's
// `firewall.comment_prefix`: entries then count as foreign, so reconciliation
// neither removes them nor adds their addresses again, and no unban removes
// them either — they stay until their timeout, with nothing in any log to say
// why.
//
// Order is load-bearing: backslashes first, so the escapes added below are not
// doubled by it.
func quoteScript(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "$", "\\$")
	return value
}

// buildBulkAddScript generates a RouterOS script that adds addresses and
// prints bulkDoneMarker with the positions of the adds that failed last.
func buildBulkAddScript(proto, list string, entries []BulkEntry) string {
	prefix := "/ip"
	if proto == "ipv6" {
		prefix = "/ipv6"
	}

	var sb strings.Builder
	sb.WriteString(":local failed \"\"\n")

	for i, e := range entries {
		addr := NormalizeAddress(e.Address, proto)

		sb.WriteString(":do {\n")
		fmt.Fprintf(&sb, "  %s/firewall/address-list/add list=\"%s\" address=\"%s\" comment=\"%s\"",
			prefix, quoteScript(list), quoteScript(addr), quoteScript(e.Comment))
		if e.Timeout != "" {
			fmt.Fprintf(&sb, " timeout=\"%s\"", quoteScript(e.Timeout))
		}
		fmt.Fprintf(&sb, "\n} on-error={ :set failed ($failed . \"%d,\") }\n", i)
	}

	fmt.Fprintf(&sb, ":put (\"%s\" . $failed)\n", bulkDoneMarker)
	return sb.String()
}

// errExecuteUnsupported marks a router without /execute or its as-string
// parameter, as opposed to an error inside the script or any other trap.
var errExecuteUnsupported = errors.New("routeros does not support /execute as-string")

// runChunk runs one bulk-add script and returns the positions of the adds it
// reported as failed. On RouterOS 7.8rc1 and later it goes through /execute
// with as-string: a single API call that runs the script synchronously and
// hands back its :put output, so the failed adds are known and no script is
// stored — nothing reaches the configuration or the router log,
// where a stored script's creation is logged with its whole source. Older
// routers, a script over the /execute size limit, and a router that turns out
// to lack /execute as-string get the stored /system/script of runBulkScript;
// the last is remembered for the rest of the client's life.
func (c *Client) runChunk(source string) (failedAt []int, err error) {
	if len(source) <= executeMaxScriptBytes && c.executeSupported() {
		failedAt, err = c.runExecuteScript(source)
		if !errors.Is(err, errExecuteUnsupported) {
			return failedAt, err
		}
		c.runnerMu.Lock()
		c.useExecute = false
		c.runnerMu.Unlock()
		log.Warn().Err(err).Msg("RouterOS lacks /execute as-string; bulk adds use a stored /system/script from now on")
	}
	return nil, c.runBulkScript(source)
}

// executeSupported reports whether bulk-add scripts go through /execute. It
// reads the router's version on first use; a failed read is retried on the
// next chunk rather than settling on the slower runner for good.
func (c *Client) executeSupported() bool {
	c.runnerMu.Lock()
	defer c.runnerMu.Unlock()
	if !c.runnerKnown {
		sr, err := c.GetSystemResources()
		if err != nil {
			log.Warn().Err(err).Msg("could not read the RouterOS version; this bulk chunk uses a stored /system/script")
			return false
		}
		c.runnerKnown = true
		c.useExecute = executeAsStringSupported(sr.Version)
		runner := "stored /system/script"
		if c.useExecute {
			runner = "/execute as-string"
		}
		log.Info().Str("routeros", sr.Version).Str("runner", runner).Msg("bulk add script runner")
	}
	return c.useExecute
}

// routerOSVersion matches the leading release in /system/resource's version,
// such as "7.24.4 (stable)", "7.8rc1 (testing)" or "7.25beta3 (development)".
var routerOSVersion = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.\d+)?(beta|rc)?`)

// executeAsStringSupported reports whether a RouterOS version takes the
// as-string parameter of :execute. It arrived in 7.8rc1 ("console - added
// "as-string" parameter to the ":execute" command"); 7.8beta2 and beta3 do not
// have it. A version it cannot read counts as older.
func executeAsStringSupported(version string) bool {
	m := routerOSVersion.FindStringSubmatch(strings.TrimSpace(version))
	if m == nil {
		return false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	switch {
	case major != 7:
		return major > 7
	case minor != 8:
		return minor > 8
	default:
		return m[3] != "beta"
	}
}

// runExecuteScript runs source through /execute with as-string and returns
// the positions its final :put printed. A device error saying the router lacks
// the command or its parameter is errExecuteUnsupported; any other error, and
// output parseBulkOutput cannot read, fails only this chunk, which
// BulkAddAddresses then retries entry by entry.
func (c *Client) runExecuteScript(source string) ([]int, error) {
	start := time.Now()
	reply, err := c.Run("/execute", "=script="+source, "=as-string=")
	if err != nil {
		if isDeviceError(err) && executeUnsupported(err) {
			return nil, fmt.Errorf("%w: %w", errExecuteUnsupported, err)
		}
		return nil, fmt.Errorf("execute bulk script: %w", err)
	}
	ret := ""
	if reply != nil && reply.Done != nil {
		ret = reply.Done.Map["ret"]
	}
	failedAt, err := parseBulkOutput(ret)
	if err != nil {
		return nil, fmt.Errorf("execute bulk script: %w", err)
	}
	log.Debug().Dur("elapsed", time.Since(start)).Int("failed", len(failedAt)).Msg("bulk script executed")
	return failedAt, nil
}

// parseBulkOutput reads the positions from the last line of a bulk script's
// output. An :error or a syntax error inside the script comes back as output
// text, not as an API error, so output whose last line does not start with
// bulkDoneMarker is an error.
func parseBulkOutput(out string) ([]int, error) {
	out = strings.TrimRight(out, "\r\n")
	last := out[strings.LastIndexAny(out, "\r\n")+1:]
	positions, ok := strings.CutPrefix(last, bulkDoneMarker)
	if !ok {
		if len(out) > 200 {
			out = out[:200] + "…"
		}
		return nil, fmt.Errorf("script stopped early: %q", out)
	}
	var failedAt []int
	for field := range strings.SplitSeq(positions, ",") {
		if field == "" {
			continue
		}
		i, convErr := strconv.Atoi(field)
		if convErr != nil {
			return nil, fmt.Errorf("script output: %q is not a position", field)
		}
		failedAt = append(failedAt, i)
	}
	return failedAt, nil
}

// recordedPositions returns the recorded positions of a chunk of n entries,
// each once and in order; a position outside the chunk is ignored.
func recordedPositions(n int, positions []int) []int {
	recorded := make([]bool, n)
	for _, i := range positions {
		if i >= 0 && i < n {
			recorded[i] = true
		}
	}
	var out []int
	for i, ok := range recorded {
		if ok {
			out = append(out, i)
		}
	}
	return out
}

// executeUnsupported reports whether a device error from /execute says the
// router does not have it. RouterOS 7.24.4 answers an unknown parameter with
// "unknown parameter <name>" and an unknown command with "no such command";
// any other trap, "not enough permissions (9)" among them, is about this call
// and leaves /execute in use.
func executeUnsupported(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unknown parameter") || strings.Contains(msg, "no such command")
}

// runBulkScript creates, executes, and cleans up a temporary RouterOS script.
// A script run this way returns no output over the API, so the adds it could
// not make stay unknown.
func (c *Client) runBulkScript(source string) error {
	// Remove any existing script with same name
	existing, err := c.Find(systemScriptPath, []string{"?name=" + bulkScriptName}, []string{".id"})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("find existing bulk script: %w", err)
	}
	if err == nil {
		if removeErr := c.Remove(systemScriptPath, existing[".id"]); removeErr != nil {
			return fmt.Errorf("remove existing bulk script: %w", removeErr)
		}
	}

	// Create script
	scriptID, err := c.Add(systemScriptPath, map[string]string{
		"name":   bulkScriptName,
		"source": source,
	})
	if err != nil {
		return fmt.Errorf("create bulk script: %w", err)
	}

	// Execute
	start := time.Now()
	_, err = c.Run("/system/script/run", "=number="+scriptID)
	elapsed := time.Since(start)

	// Clean up script regardless of execution result
	_ = c.Remove(systemScriptPath, scriptID)

	if err != nil {
		return fmt.Errorf("run bulk script: %w", err)
	}

	log.Debug().Dur("elapsed", elapsed).Msg("bulk script executed")
	return nil
}

// RemoveAddresses removes multiple address-list entries by their IDs.
// Uses individual remove calls but can be parallelized via the pool.
func (c *Client) RemoveAddresses(proto string, ids []string) (removed int, errs []error) {
	path := addressListPath(proto)
	for _, id := range ids {
		if err := c.Remove(path, id); err != nil {
			if errors.Is(err, ErrNotFound) {
				// Already expired — harmless
				continue
			}
			errs = append(errs, fmt.Errorf("remove %s: %w", id, err))
		} else {
			removed++
		}
	}
	return removed, errs
}
