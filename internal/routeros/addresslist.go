package routeros

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/rs/zerolog/log"
)

// isDuplicateEntryError returns true when the error is a RouterOS DeviceError
// indicating that the resource already exists ("already have such entry").
func isDuplicateEntryError(err error) bool {
	return errors.Is(err, ErrAddressDuplicate) || isDeviceError(err) && strings.Contains(err.Error(), "already have such entry")
}

// AddressEntry represents an entry in a MikroTik address list.
type AddressEntry struct {
	ID      string // MikroTik .id (e.g., "*1A3B")
	Address string
	List    string
	Timeout string
	Comment string
}

// protoPrefix returns the RouterOS path prefix for the given protocol.
func protoPrefix(proto string) string {
	if proto == "ipv6" {
		return "/ipv6"
	}
	return "/ip"
}

// addressListPath returns the full path for address-list operations.
func addressListPath(proto string) string {
	return protoPrefix(proto) + "/firewall/address-list"
}

// NormalizeAddress returns address in the form RouterOS stores and lists it,
// so a decision and the entry it became compare equal: a prefix with its host
// bits cleared (198.51.100.7/24 is listed as 198.51.100.0/24), an IPv4 /32 as
// the bare address, an IPv6 address lowercase and compressed, with /128 when
// it has no prefix length, and an IPv4 address embedded in IPv6 in hex except
// in the ::ffff: form. Any other form never matched its entry: the
// reconciliation removed and added it again on every pass. An IPv4-mapped
// address (::ffff:192.0.2.1), which CrowdSec gives proto ip, becomes the
// plain IPv4 address: the IPv4 list refuses the mapped form. An address
// netip cannot parse keeps the old handling, /128 added to an IPv6 one.
func NormalizeAddress(address, proto string) string {
	if prefix, err := netip.ParsePrefix(address); err == nil {
		prefix = prefix.Masked()
		if proto != "ipv6" && prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		if prefix.Addr().Is4() && prefix.Bits() == 32 {
			return prefix.Addr().String()
		}
		return prefix.String()
	}
	if addr, err := netip.ParseAddr(address); err == nil && addr.Zone() == "" {
		if proto != "ipv6" {
			addr = addr.Unmap()
		}
		if addr.Is4() {
			return addr.String()
		}
		return addr.String() + "/128"
	}
	if proto == "ipv6" && !strings.Contains(address, "/") {
		return address + "/128"
	}
	return address
}

// DetectProto detects whether an address is IPv4 or IPv6.
func DetectProto(address string) string {
	if strings.Contains(address, ":") {
		return "ipv6"
	}
	return "ip"
}

// AddAddress adds an IP address to a MikroTik address list with a timeout.
// Returns the MikroTik .id of the created entry. An entry the router already
// holds is looked up and, when it is the bouncer's, refreshed with the timeout
// and comment, and its id returned.
func (c *Client) AddAddress(proto, list, address, timeout, comment string) (string, error) {
	address = NormalizeAddress(address, proto)
	id, duplicate, err := c.addAddressOnce(proto, list, address, timeout, comment)
	if duplicate {
		return c.updateDuplicateAddress(addressListPath(proto), proto, list, address, timeout, comment)
	}
	return id, err
}

// addAddressOnce sends one address-list add. An entry the router already
// holds comes back as duplicate, with no error, for the caller to refresh:
// updateDuplicateAddress for one add, refreshDuplicates for many.
func (c *Client) addAddressOnce(proto, list, address, timeout, comment string) (id string, duplicate bool, err error) {
	address = NormalizeAddress(address, proto)

	attrs := map[string]string{
		"list":    list,
		"address": address,
		"comment": comment,
	}
	if timeout != "" {
		attrs["timeout"] = timeout
	}

	path := addressListPath(proto)

	log.Debug().
		Str("proto", proto).
		Str("list", list).
		Str("address", address).
		Str("timeout", timeout).
		Msg("adding address to list")

	id, err = c.Add(path, attrs)
	if err != nil {
		if isDuplicateEntryError(err) {
			return "", true, nil
		}
		if isTrapError(err) {
			return "", false, fmt.Errorf("add address %s to %s: %w: %w", address, list, ErrAddRefused, err)
		}
		return "", false, fmt.Errorf("add address %s to %s: %w", address, list, err)
	}

	return id, false, nil
}

// duplicateLookupBatch is how many duplicate addresses refreshDuplicates finds
// with one lookup. RouterOS walks the whole list for a query on it, whatever
// the query matches: on a virtual RouterOS 7.24.4 holding 60,000 entries, one
// address took 1.0 s to find and 100 OR'd in one query 6.3 s, against 102 s
// one at a time.
const duplicateLookupBatch = 100

// refreshDuplicates settles adds the router answered as duplicates, as
// AddAddress does for one: it finds their entries, duplicateLookupBatch per
// lookup, and refreshes the timeout and comment of each one the bouncer owns.
// It sets ID on every entry it refreshed and returns how many, and the entries
// it could not refresh with why: no entry found
// (ErrDuplicateReportedButNotFound), a foreign one (ErrForeignEntry), or a
// failed lookup or update.
func (c *Client) refreshDuplicates(proto, list string, dups []*BulkEntry) (refreshed int, failed []BulkEntry, errs []error) {
	path := addressListPath(proto)
	for start := 0; start < len(dups); start += duplicateLookupBatch {
		batch := dups[start:min(start+duplicateLookupBatch, len(dups))]
		addrs := make([]string, len(batch))
		for i, e := range batch {
			addrs[i] = NormalizeAddress(e.Address, proto)
		}
		found, err := c.findAddresses(proto, list, addrs)
		if err != nil {
			for _, e := range batch {
				failed = append(failed, *e)
			}
			errs = append(errs, fmt.Errorf("refresh %d duplicate entries in %s: %w", len(batch), list, err))
			continue
		}
		for i, e := range batch {
			existing, ok := found[addrs[i]]
			switch {
			case !ok:
				err = fmt.Errorf("add address %s to %s: %w", addrs[i], list, ErrDuplicateReportedButNotFound)
			case !OwnedComment(existing.Comment, c.ownerPrefix):
				err = fmt.Errorf("add address %s to %s: %w", addrs[i], list, ErrForeignEntry)
			default:
				err = nil
				if attrs := duplicateAddressUpdateAttrs(e.Timeout, e.Comment); len(attrs) > 0 {
					if setErr := c.Set(path, existing.ID, attrs); setErr != nil {
						err = fmt.Errorf("add address %s to %s: duplicate entry and update failed: %w", addrs[i], list, setErr)
					}
				}
			}
			if err != nil {
				failed = append(failed, *e)
				errs = append(errs, err)
				continue
			}
			e.ID = existing.ID
			refreshed++
		}
	}
	return refreshed, failed, errs
}

// findAddresses looks up the entries of list holding any of addrs, which must
// be normalized, in one query, and returns them by address.
func (c *Client) findAddresses(proto, list string, addrs []string) (map[string]AddressEntry, error) {
	query := make([]string, 0, len(addrs)+2)
	query = append(query, "?list="+list)
	for _, a := range addrs {
		query = append(query, "?address="+a)
	}
	if len(addrs) > 1 {
		// OR the address conditions together, then AND the result with the list.
		query = append(query, "?#"+strings.Repeat("|", len(addrs)-1)+"&")
	}
	results, err := c.Print(addressListPath(proto), query, []string{".id", "address", "comment"})
	if err != nil {
		return nil, fmt.Errorf("find %d addresses in %s: %w", len(addrs), list, err)
	}
	found := make(map[string]AddressEntry, len(results))
	for _, r := range results {
		found[r["address"]] = AddressEntry{ID: r[".id"], Address: r["address"], List: list, Comment: r["comment"]}
	}
	return found, nil
}

// OwnedComment reports whether an address-list comment belongs to the owner
// prefix: the comment is the prefix, or continues it with "|" or a space, as
// the comments the bouncer writes do. A longer prefix is someone else's. An
// empty prefix owns every comment.
func OwnedComment(comment, prefix string) bool {
	if prefix == "" || comment == prefix {
		return true
	}
	return strings.HasPrefix(comment, prefix+"|") || strings.HasPrefix(comment, prefix+" ")
}

// updateDuplicateAddress refreshes timeout/comment on an existing RouterOS entry.
func (c *Client) updateDuplicateAddress(path, proto, list, address, timeout, comment string) (string, error) {
	existing, findErr := c.FindAddress(proto, list, address)
	if errors.Is(findErr, ErrNotFound) {
		return "", fmt.Errorf("add address %s to %s: %w", address, list, ErrDuplicateReportedButNotFound)
	}
	if findErr != nil {
		return "", fmt.Errorf("add address %s to %s: duplicate entry and lookup failed: %w", address, list, findErr)
	}
	if !OwnedComment(existing.Comment, c.ownerPrefix) {
		return "", fmt.Errorf("add address %s to %s: %w", address, list, ErrForeignEntry)
	}

	updateAttrs := duplicateAddressUpdateAttrs(timeout, comment)
	if len(updateAttrs) == 0 {
		log.Debug().Str("address", address).Str("list", list).Msg("address already exists, no update needed")
		return existing.ID, nil
	}

	if updErr := c.Set(path, existing.ID, updateAttrs); updErr != nil {
		return "", fmt.Errorf("add address %s to %s: duplicate entry and update failed: %w", address, list, updErr)
	}
	log.Debug().Str("address", address).Str("list", list).Msg("address already exists, updated existing entry")
	return existing.ID, nil
}

// duplicateAddressUpdateAttrs builds the non-empty fields used to refresh duplicates.
func duplicateAddressUpdateAttrs(timeout, comment string) map[string]string {
	updateAttrs := make(map[string]string)
	if timeout != "" {
		updateAttrs["timeout"] = timeout
	}
	if comment != "" {
		updateAttrs["comment"] = comment
	}
	return updateAttrs
}

// RemoveAddress removes an address-list entry by its MikroTik .id.
func (c *Client) RemoveAddress(proto, id string) error {
	path := addressListPath(proto)

	log.Debug().
		Str("proto", proto).
		Str("id", id).
		Msg("removing address from list")

	return c.Remove(path, id)
}

// ListAddresses returns all address-list entries matching the given list name and comment prefix.
// An empty prefix returns every entry of the list. Once ctx is done the
// listing ends at once with ctx's error.
func (c *Client) ListAddresses(ctx context.Context, proto, list, commentPrefix string) ([]AddressEntry, error) {
	path := addressListPath(proto)

	query := []string{"?list=" + list}
	// Three properties, not five. `list` is whatever we just queried for, so
	// asking the router to echo it back 22,000 times is pure cost; `timeout` is
	// never read off an entry that came FROM the router — the reconcile diff
	// feeds the removal path, which uses `.ID` alone, while every entry that
	// carries a timeout into a write is one the bouncer built itself.
	//
	// Measured against a live RB5009 holding 22,037 entries: the five-property
	// print takes 2.24 s and the three-property one 1.78 s, so this is 0.46 s
	// off a 2.17 s reconciliation. The saving is not only transfer — a
	// count-only print of the same list still costs 1.18 s, which is the floor
	// for traversing the records, and the rest scales with what each row has to
	// serialize.
	proplist := []string{".id", "address", "comment"}

	results, err := c.PrintContext(ctx, path, query, proplist)
	if err != nil {
		return nil, fmt.Errorf("list addresses for %s: %w", list, err)
	}

	var entries []AddressEntry
	for _, r := range results {
		comment := r["comment"]
		if commentPrefix != "" && !strings.HasPrefix(comment, commentPrefix) {
			continue
		}
		entries = append(entries, AddressEntry{
			ID:      r[".id"],
			Address: r["address"],
			// Not from the wire: the query pinned it, so this is the same value
			// without the 22,000 round-trip copies of it.
			List:    list,
			Comment: r["comment"],
		})
	}

	return entries, nil
}

// FindAddress finds a specific address in a list.
func (c *Client) FindAddress(proto, list, address string) (*AddressEntry, error) {
	address = NormalizeAddress(address, proto)
	path := addressListPath(proto)

	query := []string{"?list=" + list, "?address=" + address}
	proplist := []string{".id", "address", "list", "timeout", "comment"}

	result, err := c.Find(path, query, proplist)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find address %s in %s: %w", address, list, err)
	}

	return &AddressEntry{
		ID:      result[".id"],
		Address: result["address"],
		List:    result["list"],
		Timeout: result["timeout"],
		Comment: result["comment"],
	}, nil
}

// UpdateAddressTimeout updates the timeout of an existing address-list entry.
func (c *Client) UpdateAddressTimeout(proto, id, timeout string) error {
	path := addressListPath(proto)

	return c.Set(path, id, map[string]string{"timeout": timeout})
}
