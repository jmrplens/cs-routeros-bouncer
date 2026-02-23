// Package config provides YAML and environment variable based configuration
// loading and validation for the cs-routeros-bouncer.
//
// Configuration is loaded via Viper with support for YAML files, environment
// variable overrides (prefixed with CS_ROUTEROS_BOUNCER_), and sensible
// defaults. The package validates required fields (API keys, router address)
// and enforces that at least one protocol (IPv4 or IPv6) is enabled.
package config
