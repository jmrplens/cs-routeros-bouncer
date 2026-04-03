package routeros

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
)

// isDuplicateEntryError returns true when the error indicates that the
// resource already exists on the RouterOS device ("already have such entry").
func isDuplicateEntryError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already have such entry")
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

// NormalizeAddress prepares an address for MikroTik.
// For IPv6 single addresses, appends /128 if no prefix length is present.
func NormalizeAddress(address string, proto string) string {
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
// Returns the MikroTik .id of the created entry.
func (c *Client) AddAddress(proto, list, address, timeout, comment string) (string, error) {
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

	id, err := c.Add(path, attrs)
	if err != nil {
		// If the address already exists, find it and update the timeout instead.
		if isDuplicateEntryError(err) {
			log.Debug().
				Str("address", address).
				Str("list", list).
				Msg("address already exists, updating timeout")

			existing, findErr := c.FindAddress(proto, list, address)
			if findErr != nil {
				return "", fmt.Errorf("add address %s to %s: duplicate entry and lookup failed: %w", address, list, findErr)
			}
			if existing == nil {
				return "", fmt.Errorf("add address %s to %s: duplicate entry but could not find it", address, list)
			}

			if timeout != "" {
				if updErr := c.UpdateAddressTimeout(proto, existing.ID, timeout); updErr != nil {
					return "", fmt.Errorf("add address %s to %s: duplicate entry and timeout update failed: %w", address, list, updErr)
				}
			}
			return existing.ID, nil
		}
		return "", fmt.Errorf("add address %s to %s: %w", address, list, err)
	}

	return id, nil
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
func (c *Client) ListAddresses(proto, list, commentPrefix string) ([]AddressEntry, error) {
	path := addressListPath(proto)

	query := []string{"?list=" + list}
	proplist := []string{".id", "address", "list", "timeout", "comment"}

	results, err := c.Print(path, query, proplist)
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
			List:    r["list"],
			Timeout: r["timeout"],
			Comment: r["comment"],
		})
	}

	return entries, nil
}

// FindAddress finds a specific address in a list. Returns nil if not found.
func (c *Client) FindAddress(proto, list, address string) (*AddressEntry, error) {
	address = NormalizeAddress(address, proto)
	path := addressListPath(proto)

	query := []string{"?list=" + list, "?address=" + address}
	proplist := []string{".id", "address", "list", "timeout", "comment"}

	result, err := c.Find(path, query, proplist)
	if err != nil {
		return nil, fmt.Errorf("find address %s in %s: %w", address, list, err)
	}

	if result == nil {
		return nil, nil
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
