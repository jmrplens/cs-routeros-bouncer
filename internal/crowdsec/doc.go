// Package crowdsec provides a streaming client for the CrowdSec Local API (LAPI).
//
// It wraps the official go-cs-bouncer StreamBouncer to deliver parsed ban and
// unban decisions over a Go channel. The package handles connection lifecycle,
// TLS configuration, origin and scope filtering, and graceful shutdown.
package crowdsec
