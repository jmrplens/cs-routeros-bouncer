#!/usr/bin/env bash
# router-perf-query.sh — read a RouterOS device's kernel telemetry back out of
# the InfluxDB 3 database that `mikroscope forward` writes to.
#
# This repository does not ship a router instrumentation tool any more. It was
# removed in favour of mikroscope (https://jmrp.io/docs/mikroscope/), which runs
# the sampler on the router and forwards to InfluxDB. This script is the
# read-back side: it answers "what did the router's CPU do between these two
# times" without deploying anything.
#
# MAINTAINER / OPERATOR TOOL. It talks to *your* InfluxDB, not to any service
# this project runs. It is useful to anyone who runs mikroscope themselves —
# the schema is mikroscope's, not ours — and useless without such a store.
#
# No credentials are committed. Everything comes from the environment:
#
#   export MIKROSCOPE_INFLUX_URL=http://influx.example:8181
#   export MIKROSCOPE_INFLUX_TOKEN=...      # never echo this, never log it
#   export MIKROSCOPE_INFLUX_DB=mikroscope  # optional, this is the default
#   export MIKROSCOPE_HOST_TAG=rb5009       # optional, the `host` tag to filter
#
# The first two are the same variable names mikroscope's own collector uses
# (see mikroscope's .env.example), so a machine already running the collector
# needs no new configuration.
#
# Usage:
#   router-perf-query.sh cpu       <from> <to> [bin]   per-core + all-core busy %
#   router-perf-query.sh cpu-raw   <from> <to>         native-rate per-core busy %
#   router-perf-query.sh mem       <from> <to> [bin]   used / free / anon MiB
#   router-perf-query.sh softnet   <from> <to> [bin]   packets, drops, time squeezes
#   router-perf-query.sh observer  <from> <to>         the agent's own cost
#   router-perf-query.sh continuity <from> <to>        holes and restarts in the window
#   router-perf-query.sh window    <from> <to> [bin]   all of the above, joined
#   router-perf-query.sh conntrack <from> <to> [bin]   connection-table occupancy
#   router-perf-query.sh hottest   <from> <to> [n]     the n busiest seconds
#   router-perf-query.sh sql       <sql>               run a statement verbatim
#
# <from> and <to> are SQL timestamp literals. Bare literals are UTC:
#   2026-09-25T13:10:00Z   2026-09-25T13:10:20Z
#   2026-09-25T15:10:00+02:00
# Relative forms work too and are passed through:
#   "now() - INTERVAL '10 minutes'"   now()
#
# [bin] is a date_bin interval, default '1 second'. Use '100 milliseconds' for
# the native rate, '1 minute' for a long window.
#
# Output is CSV on stdout, so it pipes into anything. FORMAT=json for JSON.
#
# Read §1 of the schema notes before trusting a number from this script. Two
# traps in particular:
#   * mikroscope_softnet.{processed,dropped,time_squeeze} and
#     mikroscope_self.cpu_us are PER-SAMPLE DELTAS. This script SUMs them.
#     max()-min() is wrong by four orders of magnitude and looks plausible.
#   * a complete 1 s CPU bin holds exactly 40 rows (4 cores x 10 Hz). Partial
#     bins at a window edge average over less than a second; `cpu` reports the
#     row count so you can see it, and `hottest` filters on it.
#
# A single per-core sample at 10 Hz resolves to steps of about 10 percentage
# points, because USER_HZ is 100 and a 100 ms tick holds ~10 jiffies. Read
# `cpu-raw` as jiffy counts, not as measurements to two figures; a 1 s bin sums
# ~400 jiffies and is good to about 0.25 pp.

set -euo pipefail

readonly PROG=${0##*/}

die() { printf '%s: %s\n' "$PROG" "$*" >&2; exit 2; }

usage() {
	sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; $d'
	exit "${1:-2}"
}

# --- configuration -----------------------------------------------------------

url=${MIKROSCOPE_INFLUX_URL:-}
token=${MIKROSCOPE_INFLUX_TOKEN:-}
db=${MIKROSCOPE_INFLUX_DB:-mikroscope}
host_tag=${MIKROSCOPE_HOST_TAG:-}
format=${FORMAT:-csv}

require_config() {
	[ -n "$url" ] || die "MIKROSCOPE_INFLUX_URL is not set (e.g. http://influx.example:8181)"
	[ -n "$token" ] || die "MIKROSCOPE_INFLUX_TOKEN is not set"
	command -v curl >/dev/null 2>&1 || die "curl is not on PATH"
	# mikroscope's collector accepts a URL that already carries a write path;
	# strip anything after the authority so we can append the query path.
	case $url in
	*://*) url=${url%%/api/*} ;;
	*) die "MIKROSCOPE_INFLUX_URL must include a scheme: $url" ;;
	esac
	url=${url%/}
}

# host_filter emits the `host = '...'` conjunct, or nothing when
# MIKROSCOPE_HOST_TAG is unset (one-device store).
host_filter() {
	[ -n "$host_tag" ] || return 0
	printf " AND host = '%s'" "$host_tag"
}

# run sends one statement. The token goes in a header, never in the URL, so it
# does not reach a proxy access log.
run() {
	require_config
	curl -sS --fail-with-body \
		-H "Authorization: Bearer $token" \
		--get "$url/api/v3/query_sql" \
		--data-urlencode "db=$db" \
		--data-urlencode "q=$1" \
		--data-urlencode "format=$format"
}

# ts renders a <from>/<to> argument. A bare literal becomes a timestamp
# literal; anything containing '(' is assumed to be an expression such as
# now() - INTERVAL '5 minutes' and is passed through untouched.
ts() {
	case $1 in
	*'('*) printf '%s' "$1" ;;
	*) printf "timestamp '%s'" "$1" ;;
	esac
}

need_range() {
	[ "$1" -ge 2 ] || die "this subcommand needs <from> and <to>; see $PROG --help"
}

# --- subcommands -------------------------------------------------------------

q_cpu() {
	local from=$1 to=$2 bin=${3:-1 second}
	cat <<-SQL
	SELECT date_bin(INTERVAL '$bin', time) AS bin,
	       round(avg(CASE WHEN cpu='0' THEN busy_ratio END)*100, 2) AS cpu0_pct,
	       round(avg(CASE WHEN cpu='1' THEN busy_ratio END)*100, 2) AS cpu1_pct,
	       round(avg(CASE WHEN cpu='2' THEN busy_ratio END)*100, 2) AS cpu2_pct,
	       round(avg(CASE WHEN cpu='3' THEN busy_ratio END)*100, 2) AS cpu3_pct,
	       round(avg(busy_ratio)*100, 2) AS all_pct,
	       round(max(busy_ratio)*100, 1) AS hottest_core_pct,
	       count(*) AS rows_in_bin
	FROM mikroscope_cpu
	WHERE time >= $(ts "$from") AND time < $(ts "$to")$(host_filter)
	GROUP BY bin ORDER BY bin
	SQL
}

q_cpu_raw() {
	local from=$1 to=$2
	cat <<-SQL
	SELECT time,
	       round(max(CASE WHEN cpu='0' THEN busy_ratio END)*100, 1) AS cpu0_pct,
	       round(max(CASE WHEN cpu='1' THEN busy_ratio END)*100, 1) AS cpu1_pct,
	       round(max(CASE WHEN cpu='2' THEN busy_ratio END)*100, 1) AS cpu2_pct,
	       round(max(CASE WHEN cpu='3' THEN busy_ratio END)*100, 1) AS cpu3_pct,
	       round(avg(busy_ratio)*100, 1) AS all_pct,
	       max(dt_ns) AS dt_ns
	FROM mikroscope_cpu
	WHERE time >= $(ts "$from") AND time < $(ts "$to")$(host_filter)
	GROUP BY time ORDER BY time
	SQL
}

q_mem() {
	local from=$1 to=$2 bin=${3:-1 second}
	cat <<-SQL
	SELECT date_bin(INTERVAL '$bin', time) AS bin,
	       round(avg(total_kb - available_kb)/1024.0, 2) AS used_mib,
	       round(avg(available_kb)/1024.0, 2) AS available_mib,
	       round(avg(anon_kb)/1024.0, 2) AS anon_mib,
	       round(avg(slab_kb)/1024.0, 2) AS slab_mib,
	       round(stddev((CAST(total_kb AS BIGINT) - CAST(available_kb AS BIGINT))/1024.0), 3) AS used_sd_mib,
	       round(max(total_kb)/1024.0, 1) AS total_mib,
	       count(*) AS rows_in_bin
	FROM mikroscope_mem
	WHERE time >= $(ts "$from") AND time < $(ts "$to")$(host_filter)
	GROUP BY bin ORDER BY bin
	SQL
}

q_softnet() {
	# processed/dropped/time_squeeze are per-sample deltas: SUM, never max-min.
	local from=$1 to=$2 bin=${3:-1 second}
	cat <<-SQL
	SELECT date_bin(INTERVAL '$bin', time) AS bin, cpu,
	       sum(processed) AS processed, sum(dropped) AS dropped,
	       sum(time_squeeze) AS time_squeezes, count(*) AS rows_in_bin
	FROM mikroscope_softnet
	WHERE time >= $(ts "$from") AND time < $(ts "$to")$(host_filter)
	GROUP BY bin, cpu ORDER BY bin, cpu
	SQL
}

q_observer() {
	# cpu_us is a per-tick delta in microseconds. Its sum over the window,
	# divided by the window's own measured wall time (from dt_ns, not from the
	# requested range, so a hole does not inflate the share), is the agent's
	# share of ONE core.
	local from=$1 to=$2
	cat <<-SQL
	SELECT count(*) AS samples,
	       round(sum(cpu_us)/1e6, 3) AS agent_cpu_s,
	       round(sum(s.dt_ns)/1e9, 1) AS measured_window_s,
	       round(sum(cpu_us)*1e3 / nullif(sum(s.dt_ns), 0) * 100, 3) AS pct_of_one_core,
	       round(avg(cpu_us), 1) AS cpu_us_per_sample_avg,
	       round(approx_percentile_cont(cpu_us, 0.95), 0) AS cpu_us_p95,
	       max(cpu_us) AS cpu_us_max,
	       round(avg(rss)/1048576.0, 2) AS rss_mib_avg,
	       round(max(rss)/1048576.0, 2) AS rss_mib_max,
	       round(max(cgroup_mem)/1048576.0, 2) AS cgroup_mem_mib_max,
	       round(avg(read_ns)/1e6, 3) AS read_ms_avg,
	       round(approx_percentile_cont(read_ns, 0.99)/1e6, 3) AS read_ms_p99,
	       round(max(read_ns)/1e6, 3) AS read_ms_max,
	       sum(throttled) AS throttle_events, sum(throttled_us) AS throttled_us,
	       sum(resets) AS agent_resets, sum(oom_kill) AS oom_kills,
	       sum(kmsg_dropped) AS kmsg_dropped
	FROM mikroscope_self AS f
	JOIN mikroscope_sample AS s ON s.time = f.time
	WHERE f.time >= $(ts "$from") AND f.time < $(ts "$to")
	SQL
}

q_continuity() {
	# seq is UInt64 and resets to 0 when the agent restarts, so subtracting
	# without the BIGINT cast wraps to ~1.8e19 instead of going negative.
	local from=$1 to=$2
	cat <<-SQL
	WITH d AS (
	  SELECT time,
	         CAST(seq AS BIGINT) - LAG(CAST(seq AS BIGINT)) OVER (ORDER BY time) AS dseq,
	         dt_ns
	  FROM mikroscope_sample
	  WHERE time >= $(ts "$from") AND time < $(ts "$to")$(host_filter)
	)
	SELECT count(*) AS deltas,
	       sum(CASE WHEN dseq = 1 THEN 1 ELSE 0 END) AS continuous,
	       sum(CASE WHEN dseq > 1 THEN 1 ELSE 0 END) AS holes,
	       sum(CASE WHEN dseq < 0 THEN 1 ELSE 0 END) AS agent_restarts,
	       coalesce(sum(CASE WHEN dseq > 1 THEN dseq - 1 ELSE 0 END), 0) AS ticks_missing,
	       round(avg(dt_ns)/1e6, 2) AS dt_ms_avg,
	       round(approx_percentile_cont(dt_ns, 0.99)/1e6, 2) AS dt_ms_p99,
	       round(max(dt_ns)/1e6, 2) AS dt_ms_max
	FROM d WHERE dseq IS NOT NULL
	SQL
}

q_conntrack() {
	local from=$1 to=$2 bin=${3:-1 minute}
	cat <<-SQL
	SELECT date_bin(INTERVAL '$bin', time) AS bin,
	       min(entries) AS min_entries, round(avg(entries), 1) AS avg_entries,
	       max(entries) AS max_entries, count(*) AS rows_in_bin
	FROM mikroscope_api_conntrack
	WHERE time >= $(ts "$from") AND time < $(ts "$to")$(host_filter)
	GROUP BY bin ORDER BY bin
	SQL
}

q_hottest() {
	local from=$1 to=$2 n=${3:-10}
	case $n in
	*[!0-9]* | '') die "hottest: <n> must be a whole number, got '$n'" ;;
	esac
	cat <<-SQL
	SELECT date_bin(INTERVAL '1 second', time) AS sec,
	       round(avg(busy_ratio)*100, 2) AS all_pct,
	       round(max(busy_ratio)*100, 1) AS hottest_core_pct
	FROM mikroscope_cpu
	WHERE time >= $(ts "$from") AND time < $(ts "$to")$(host_filter)
	GROUP BY sec HAVING count(*) = 40
	ORDER BY all_pct DESC LIMIT $n
	SQL
}

q_window() {
	local from=$1 to=$2 bin=${3:-1 second}
	local f t
	f=$(ts "$from")
	t=$(ts "$to")
	cat <<-SQL
	WITH c AS (
	  SELECT date_bin(INTERVAL '$bin', time) AS bin,
	         avg(busy_ratio)*100 AS all_pct, max(busy_ratio)*100 AS hottest_core_pct,
	         count(*) AS cpu_rows
	  FROM mikroscope_cpu WHERE time >= $f AND time < $t$(host_filter) GROUP BY bin),
	m AS (
	  SELECT date_bin(INTERVAL '$bin', time) AS bin,
	         avg(total_kb - available_kb)/1024.0 AS used_mib, avg(anon_kb)/1024.0 AS anon_mib
	  FROM mikroscope_mem WHERE time >= $f AND time < $t$(host_filter) GROUP BY bin),
	n AS (
	  SELECT date_bin(INTERVAL '$bin', time) AS bin,
	         sum(processed) AS pkts, sum(dropped) AS drops, sum(time_squeeze) AS squeezes
	  FROM mikroscope_softnet WHERE time >= $f AND time < $t$(host_filter) GROUP BY bin),
	s AS (
	  SELECT date_bin(INTERVAL '$bin', s2.time) AS bin,
	         sum(f2.cpu_us) AS obs_cpu_us, sum(s2.dt_ns) AS obs_dt_ns
	  FROM mikroscope_self AS f2
	  JOIN mikroscope_sample AS s2 ON s2.time = f2.time
	  WHERE f2.time >= $f AND f2.time < $t GROUP BY bin),
	l AS (
	  SELECT date_bin(INTERVAL '$bin', time) AS bin, avg(load1) AS load1
	  FROM mikroscope_load WHERE time >= $f AND time < $t$(host_filter) GROUP BY bin)
	SELECT c.bin,
	       round(c.all_pct, 2) AS all_pct,
	       round(c.hottest_core_pct, 1) AS hottest_core_pct,
	       round(m.used_mib, 2) AS used_mib,
	       round(m.anon_mib, 2) AS anon_mib,
	       n.pkts, n.drops, n.squeezes,
	       round(l.load1, 2) AS load1,
	       round(s.obs_cpu_us * 1e3 / nullif(s.obs_dt_ns, 0) * 100, 2) AS observer_pct_of_core,
	       c.cpu_rows
	FROM c
	JOIN m ON c.bin = m.bin
	JOIN n ON c.bin = n.bin
	JOIN s ON c.bin = s.bin
	JOIN l ON c.bin = l.bin
	ORDER BY c.bin
	SQL
}

# --- dispatch ----------------------------------------------------------------

[ $# -ge 1 ] || usage 2
sub=$1
shift

case $sub in
-h | --help | help) usage 0 ;;
sql)
	[ $# -eq 1 ] || die "sql: expected exactly one statement"
	run "$1"
	;;
cpu | cpu-raw | mem | softnet | observer | continuity | conntrack | hottest | window)
	need_range $#
	# Build the statement first so that a validation failure inside the
	# builder exits with its own status rather than the subshell's.
	case $sub in
	cpu) sql=$(q_cpu "$@") ;;
	cpu-raw) sql=$(q_cpu_raw "$1" "$2") ;;
	mem) sql=$(q_mem "$@") ;;
	softnet) sql=$(q_softnet "$@") ;;
	observer) sql=$(q_observer "$1" "$2") ;;
	continuity) sql=$(q_continuity "$1" "$2") ;;
	conntrack) sql=$(q_conntrack "$@") ;;
	hottest) sql=$(q_hottest "$@") ;;
	window) sql=$(q_window "$@") ;;
	esac
	run "$sql"
	;;
*) die "unknown subcommand '$sub'; see $PROG --help" ;;
esac
