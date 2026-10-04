package routeros

import (
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
// however many entries it holds. failed holds the entries of failed chunks that
// the per-entry retry could not add either. Through /execute the count is the
// script's own, without the entries it skipped; a stored script cannot report
// one, so its chunk counts every entry as added.
func (c *Client) BulkAddAddresses(proto, list string, entries []BulkEntry) (added int, failed []BulkEntry, err error) {
	if len(entries) == 0 {
		return 0, nil, nil
	}

	total := 0
	for start := 0; start < len(entries); start += bulkChunkSize {
		end := min(start+bulkChunkSize, len(entries))
		chunk := entries[start:end]

		script := buildBulkAddScript(proto, list, chunk)

		n, scriptErr := c.runChunk(script)
		if scriptErr != nil {
			log.Warn().Err(scriptErr).Int("chunk_size", len(chunk)).Msg("bulk script failed, falling back to individual adds")
			fallbackAdded, fallbackFailed, fallbackErr := c.AddAddressesEach(proto, list, chunk)
			total += fallbackAdded
			failed = append(failed, fallbackFailed...)
			if fallbackErr != nil {
				err = fallbackErr
			}
			continue
		}
		total += n
	}

	return total, failed, err
}

// AddAddressesEach adds entries with one AddAddress call each, never through a
// script: the bulk_add_method "api" without a connection pool, and the retry
// of a failed script chunk. It counts every entry AddAddress accepts, including
// one the router already had, whose timeout and comment AddAddress refreshes,
// and returns the entries whose add failed. It sets ID on every entry it adds.
func (c *Client) AddAddressesEach(proto, list string, chunk []BulkEntry) (added int, failed []BulkEntry, err error) {
	var fallbackErrs []error
	for i := range chunk {
		entry := &chunk[i]
		id, addErr := c.AddAddress(proto, list, entry.Address, entry.Timeout, entry.Comment)
		if addErr != nil {
			if !isDuplicateEntryError(addErr) {
				fallbackErrs = append(fallbackErrs, addErr)
				failed = append(failed, *entry)
			}
			continue
		}
		entry.ID = id
		added++
	}
	if len(fallbackErrs) == 0 {
		return added, nil, nil
	}
	return added, failed, fmt.Errorf("%d add errors (last: %w)", len(fallbackErrs), fallbackErrs[len(fallbackErrs)-1])
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

// buildBulkAddScript generates a RouterOS script that adds addresses.
func buildBulkAddScript(proto, list string, entries []BulkEntry) string {
	prefix := "/ip"
	if proto == "ipv6" {
		prefix = "/ipv6"
	}

	var sb strings.Builder
	sb.WriteString(":local count 0\n")

	for _, e := range entries {
		addr := NormalizeAddress(e.Address, proto)

		sb.WriteString(":do {\n")
		fmt.Fprintf(&sb, "  %s/firewall/address-list/add list=\"%s\" address=\"%s\" comment=\"%s\"",
			prefix, quoteScript(list), quoteScript(addr), quoteScript(e.Comment))
		if e.Timeout != "" {
			fmt.Fprintf(&sb, " timeout=\"%s\"", quoteScript(e.Timeout))
		}
		sb.WriteString("\n  :set count ($count + 1)\n")
		sb.WriteString("} on-error={}\n") // silently skip duplicates
	}

	sb.WriteString(":put $count\n")
	return sb.String()
}

// errExecuteRejected marks a device error from /execute itself, as opposed to
// an error inside the script: the router does not take the command.
var errExecuteRejected = errors.New("routeros rejected /execute as-string")

// runChunk runs one bulk-add script. On RouterOS 7.8rc1 and later it goes
// through /execute with as-string: a single API call that runs the script
// synchronously and hands back its :put output, so the count is exact and no
// script is stored — nothing reaches the configuration or the router log,
// where a stored script's creation is logged with its whole source. Older
// routers, a script over the /execute size limit, and a router that refuses
// /execute get the stored /system/script of runBulkScript; a refusal is
// remembered for the rest of the client's life.
func (c *Client) runChunk(source string) (int, error) {
	if len(source) <= executeMaxScriptBytes && c.executeSupported() {
		n, err := c.runExecuteScript(source)
		if !errors.Is(err, errExecuteRejected) {
			return n, err
		}
		c.runnerMu.Lock()
		c.useExecute = false
		c.runnerMu.Unlock()
		log.Warn().Err(err).Msg("RouterOS refused /execute as-string; bulk adds use a stored /system/script from now on")
	}
	return c.runBulkScript(source)
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
// the count its final :put printed. A device error on the command itself is
// errExecuteRejected; anything but a number in the output is an error inside
// the script — an :error comes back there as text, not as an API error — and
// fails the chunk so BulkAddAddresses retries it entry by entry.
func (c *Client) runExecuteScript(source string) (int, error) {
	start := time.Now()
	reply, err := c.Run("/execute", "=script="+source, "=as-string=")
	if err != nil {
		if isDeviceError(err) {
			return 0, fmt.Errorf("%w: %w", errExecuteRejected, err)
		}
		return 0, fmt.Errorf("execute bulk script: %w", err)
	}
	ret := ""
	if reply != nil && reply.Done != nil {
		ret = strings.TrimSpace(reply.Done.Map["ret"])
	}
	n, convErr := strconv.Atoi(ret)
	if convErr != nil {
		if len(ret) > 200 {
			ret = ret[:200] + "…"
		}
		return 0, fmt.Errorf("execute bulk script: output %q is not a count", ret)
	}
	log.Debug().Dur("elapsed", time.Since(start)).Int("added", n).Msg("bulk script executed")
	return n, nil
}

// runBulkScript creates, executes, and cleans up a temporary RouterOS script.
// Returns the number of addresses added (parsed from script output).
func (c *Client) runBulkScript(source string) (int, error) {
	// Remove any existing script with same name
	existing, err := c.Find(systemScriptPath, []string{"?name=" + bulkScriptName}, []string{".id"})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return 0, fmt.Errorf("find existing bulk script: %w", err)
	}
	if err == nil {
		if removeErr := c.Remove(systemScriptPath, existing[".id"]); removeErr != nil {
			return 0, fmt.Errorf("remove existing bulk script: %w", removeErr)
		}
	}

	// Create script
	scriptID, err := c.Add(systemScriptPath, map[string]string{
		"name":   bulkScriptName,
		"source": source,
	})
	if err != nil {
		return 0, fmt.Errorf("create bulk script: %w", err)
	}

	// Execute
	start := time.Now()
	_, err = c.Run("/system/script/run", "=number="+scriptID)
	elapsed := time.Since(start)

	// Clean up script regardless of execution result
	_ = c.Remove(systemScriptPath, scriptID)

	if err != nil {
		return 0, fmt.Errorf("run bulk script: %w", err)
	}

	log.Debug().Dur("elapsed", elapsed).Msg("bulk script executed")

	// We can't reliably get the :put output via API, so we estimate
	// based on the number of entries (errors are silently skipped by on-error={})
	return len(strings.Split(source, "address-list/add")) - 1, nil
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
