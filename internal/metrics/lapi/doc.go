// Copyright (c) 2025 jmrplens
// SPDX-License-Identifier: MIT

// Package lapi provides CrowdSec LAPI usage metrics integration.
//
// It uses the go-cs-bouncer MetricsProvider to periodically report bouncer
// metrics to the CrowdSec LAPI /v1/usage-metrics endpoint.
//
// The provider sends three metric types per the CrowdSec bouncer spec:
//   - active_decisions: current count of active decisions by origin and ip_type
//   - dropped: bytes and packets blocked by drop/reject rules as ip_type deltas
//   - processed: total bytes and packets through bouncer rules as ip_type deltas
//
// The metrics update path gathers data from the parent metrics package, and
// [Provider.SetCounterCollector] lets the manager refresh MikroTik firewall
// counters just before each LAPI push.
package lapi
