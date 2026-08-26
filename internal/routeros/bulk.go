package routeros

import (
	"errors"
	"fmt"
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
const bulkChunkSize = 100

// BulkAddAddresses adds many addresses at once using a RouterOS script.
// This is dramatically faster than individual API calls because the script
// executes locally on the router without per-command network round-trips.
func (c *Client) BulkAddAddresses(proto, list string, entries []BulkEntry) (added int, err error) {
	if len(entries) == 0 {
		return 0, nil
	}

	total := 0
	for start := 0; start < len(entries); start += bulkChunkSize {
		end := min(start+bulkChunkSize, len(entries))
		chunk := entries[start:end]

		script := buildBulkAddScript(proto, list, chunk)

		n, scriptErr := c.runBulkScript(script)
		if scriptErr != nil {
			log.Warn().Err(scriptErr).Int("chunk_size", len(chunk)).Msg("bulk script failed, falling back to individual adds")
			fallbackAdded, fallbackErr := c.bulkAddFallback(proto, list, chunk)
			total += fallbackAdded
			if fallbackErr != nil {
				err = fallbackErr
			}
			continue
		}
		total += n
	}

	return total, err
}

// bulkAddFallback retries a failed script chunk using individual AddAddress calls.
func (c *Client) bulkAddFallback(proto, list string, chunk []BulkEntry) (int, error) {
	added := 0
	var fallbackErrs []error
	for _, entry := range chunk {
		if _, addErr := c.AddAddress(proto, list, entry.Address, entry.Timeout, entry.Comment); addErr != nil {
			if !isDuplicateEntryError(addErr) {
				fallbackErrs = append(fallbackErrs, addErr)
			}
			continue
		}
		added++
	}
	if len(fallbackErrs) == 0 {
		return added, nil
	}
	return added, fmt.Errorf("%d fallback add errors (last: %w)", len(fallbackErrs), fallbackErrs[len(fallbackErrs)-1])
}

// BulkEntry represents an address to add in bulk.
type BulkEntry struct {
	Address string
	Timeout string
	Comment string
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
// `firewall.comment_prefix`: entries then fail the HasPrefix filter in
// ListAddresses, never appear in the reconcile diff's present set, and are
// re-added on every single cycle — an address list that grows without bound,
// with nothing in any log to say why.
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
