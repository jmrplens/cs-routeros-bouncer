// Package manager implements the central orchestrator that connects the CrowdSec
// decision stream to MikroTik RouterOS.
//
// On startup the manager:
//  1. Connects to the RouterOS API and creates firewall rules (filter + raw).
//  2. Starts the CrowdSec stream and collects initial decisions.
//  3. Reconciles the router's address lists with the expected CrowdSec state,
//     adding missing entries and removing stale ones.
//  4. Processes live ban/unban decisions as they arrive.
//
// On shutdown, firewall rules are removed. Address list entries are left to
// expire via their MikroTik timeout, ensuring no traffic is allowed prematurely.
package manager
