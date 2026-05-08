//go:build integration

// Package integration contains live integration tests for Docker images and
// MikroTik RouterOS API behavior.
//
// These tests are excluded from the default test suite and must be run with the
// integration build tag. The RouterOS tests load connection settings through
// the same config package used by the command, then exercise the high-level
// routeros client against a real router or lab instance.
package integration
