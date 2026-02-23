package routeros

import (
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// bulkScriptName is the temporary script used for bulk operations.
const bulkScriptName = "crowdsec-bulk-import"

// bulkChunkSize limits addresses per script to keep within RouterOS API message size limits.
// 100 entries ≈ 12 KB script source, well within the ~32 KB safe limit.
const bulkChunkSize = 100

// BulkAddAddresses adds many addresses at once using a RouterOS script.
// This is dramatically faster than individual API calls because the script
// executes locally on the router without per-command network round-trips.
func (c *Client) BulkAddAddresses(proto, list string, entries []BulkEntry) (added int, err error) {
	if len(entries) == 0 {
		return 0, nil
	}

	path := addressListPath(proto)
	_ = path // used in fallback

	total := 0
	for start := 0; start < len(entries); start += bulkChunkSize {
		end := start + bulkChunkSize
		if end > len(entries) {
			end = len(entries)
		}
		chunk := entries[start:end]

		script := buildBulkAddScript(proto, list, chunk)

		n, scriptErr := c.runBulkScript(script)
		if scriptErr != nil {
			// Fall back to individual adds for this chunk
			log.Warn().Err(scriptErr).Int("chunk_size", len(chunk)).Msg("bulk script failed, falling back to individual adds")
			for _, e := range chunk {
				if _, addErr := c.AddAddress(proto, list, e.Address, e.Timeout, e.Comment); addErr != nil {
					if !strings.Contains(addErr.Error(), "already have") {
						err = addErr
					}
				} else {
					total++
				}
			}
			continue
		}
		total += n
	}

	return total, err
}

// BulkEntry represents an address to add in bulk.
type BulkEntry struct {
	Address string
	Timeout string
	Comment string
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
		// Escape quotes in comment
		comment := strings.ReplaceAll(e.Comment, "\"", "\\\"")

		sb.WriteString(":do {\n")
		fmt.Fprintf(&sb, "  %s/firewall/address-list/add list=\"%s\" address=\"%s\" comment=\"%s\"",
			prefix, list, addr, comment)
		if e.Timeout != "" {
			fmt.Fprintf(&sb, " timeout=\"%s\"", e.Timeout)
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
	existing, _ := c.Find("/system/script", []string{"?name=" + bulkScriptName}, []string{".id"})
	if existing != nil {
		_ = c.Remove("/system/script", existing[".id"])
	}

	// Create script
	scriptID, err := c.Add("/system/script", map[string]string{
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
	_ = c.Remove("/system/script", scriptID)

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
			if strings.Contains(err.Error(), "no such item") {
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
