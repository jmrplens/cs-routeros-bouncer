# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`crowdsec.supported_decisions_types` does something now** — it was declared, defaulted, mapped to `CROWDSEC_DECISIONS_TYPES` and read by nothing, while `parseDecision` hardcoded `ban`. CrowdSec's decision type is a free string (only `ban` is a defined constant, and `cscli decisions add --type anything` is accepted), so a scenario emitting a custom type can now be enforced by naming it here. Verified against a live Local API: `type=ban` returns 22,368 decisions, `type=throttle` returns the probe, `type=ban,throttle` returns **zero** — the parameter matches exactly and is not a list — and omitting it returns every type. So the default `["ban"]` keeps its server-side filter and costs nothing, and only a widened set falls back to fetching everything and filtering locally
- **The landing page is rebuilt from a typed content contract, with a disclosure block** — `index.mdx` and its Spanish twin were parallel hand-written files in which every FAQ answer existed four times over. Both locales now satisfy one `HomeContent` interface and render from `src/data/home.ts`, and the FAQ structured data is generated from the same array as the visible answers, so the machine-readable and human-readable text cannot drift apart. The new "What it writes to your router" section states the limits on the front page: it enforces decisions rather than making them, `ban` is the only decision type and that is hardcoded rather than configurable, the managed block goes in at the top of each chain by default (of five placement strategies, each overridable per table and protocol family), the first sync imports every active decision including CAPI blocklists, address-list entries outlive shutdown, and every reconciliation pass costs the router CPU — measured on an RB5009 with 21,600 entries as a transient peaking at 29–34% against a 7% baseline for about six seconds, in 11 of 11 consecutive cycles
- **The firewall rules the daemon writes are single-sourced** (`src/data/rules.mjs`, rendered by `RuleSet.astro`) — the reference page and the landing now render from one module read directly from `internal/manager`. This corrected a long-standing undercount: a stock configuration writes **eight** rules, not four. The two passthrough counting rules created by `metrics.track_processed` were absent from every listing on the site, and they are created even when `metrics.enabled` is false, since `processedCountingRule()` reads `TrackProcessed` alone. Verified byte-for-byte against a production RB5009
- **`logging.file` is implemented** — the key was parsed and read by nothing. When set, log lines now go to **both** stderr and the file, so `journalctl` and `docker logs` keep working; the file is an addition, not a redirection. Opened append (a restart never discards ban history) with mode `0640`, since log lines record the IP addresses of banned clients. Parent directories are deliberately not created, and a failure to open is a **startup error** naming the path and the OS error rather than a silent fallback to stderr — a log file you configured and did not get is worse than no log file. There is no built-in rotation and the handle is held for the process lifetime, which the documentation now states along with the `copytruncate` caveat
- **The configuration reference is generated from the Go struct** — `docs/scripts/extract-config-schema.mjs` reads `internal/config/config.go` and emits `docs/src/data/config-schema.json`, a committed artefact the docs build renders through a new `ConfigOption` component. The docs build never parses Go; `--check` regenerates and fails on any diff, and runs first in the `analyze` chain so CI catches drift. This retires 110 hand-typed `Env`/`Default` lines across both locales, the surface that had already published defaults the binary did not have
- **The token layer** — `custom.css` (681 lines, with three ways of drawing a card and five theme blocks gated on an attribute that only exists after client JS runs) is replaced by seven single-concern sheets. Dark lives on bare `:root` and light on `:root[data-theme="light"]`, with every colour token restated in both. The heading ladder is now monotonic at every viewport width — `h3` used to render smaller than `h4`, and the first fix left `h5`/`h6` below body copy. Project tokens take an `--rb-` prefix; the framework's `--sl-` names only ever receive values

### Security

- **Go 1.26.5** — bumped the Go toolchain (go directive, CI and Docker build image) from 1.26.4 to 1.26.5 to fix a Go standard library vulnerability reported by govulncheck: GO-2026-5856 (`crypto/tls`, Encrypted Client Hello privacy leak)
- **`gosec` 2.28.0** — the security scanner now detects AWS temporary access keys under `G101`, and carries false-positive fixes for `G115` (min/max) and `G404` (missing `math/rand` weak-random functions)

### Fixed

- **Every documented binary-download command 404'd** — GoReleaser embeds the version in the archive filename (`.goreleaser.yaml:77-82`), so `releases/latest/download/cs-routeros-bouncer_linux_amd64.tar.gz` could never resolve, and the architecture suffix was wrong as well (releases ship `x86_64`, not `amd64`). The install snippets now resolve the latest tag from the GitHub API first, guard against an empty result instead of requesting a malformed URL, and name the architecture list as examples rather than an exhaustive set. Two lines later, `cp cs-routeros-bouncer.yaml` also failed — the archive ships it under `config/` — which left the operator with no configuration before the systemd unit was written. Fixed in both languages and in the README
- **Documentation claims contradicted by the binary** — six statements were corrected against the Go source: the CLI reference denied the implicit `/etc/cs-routeros-bouncer/config.yaml` path that `resolveRunConfigPath` (`main.go:222-232`) actually stats on every run without `-c` (and the same behaviour was attributed to the Docker image rather than the binary); `logging.file` was documented as writing logs to a file when it is parsed at `config.go:659` and read nowhere, with all output going to stderr; `architecture/decisions.mdx` described an in-bouncer filtering pipeline that does not exist, so an operator would grep for a warning log that can never appear; bulk-add parallelism was attributed to the connection pool, which serves reconciliation removals only, contradicting `architecture/reconciliation.mdx`; `mikrotik.address` and `mikrotik.username` carried defaults the binary does not have, on the same line as a *Required* badge; and `pool_size` was described as accelerating adds
- **`lists:*` was documented as an origins wildcard and matches nothing** — `crowdsec.origins` is passed verbatim into the LAPI stream query (`internal/crowdsec/stream.go:143-144`), and the LAPI matches origin values exactly. Verified against a live LAPI: `origins=CAPI` returns 20,050 decisions while `origins=CAPI*` returns 0, so an operator following the previous advice subscribed to third-party blocklists and silently received none of them. The correct value is the literal `lists`, which is what CrowdSec assigns to every blocklist subscription regardless of the list's name (`pkg/types/constants.go`, `ListOrigin = "lists"`). Corrected in five pages plus their Spanish twins; the Prometheus `origin` label documentation also claimed a `lists:<name>` value that the bouncer cannot emit, and omitted the `reconcile` value it does
- **The recommended least-privilege router group was left in doubt** — the group denies `!policy` while the bouncer creates and runs a temporary `/system/script` per bulk chunk, which looked like it might silently degrade every reconciliation to per-address writes. It does not: RouterOS only requires `policy` to run a script whose own policy set exceeds the caller's, and a script created over the API inherits the creating user's policies. Confirmed on RouterOS 7.24.1 against a production instance whose API user holds exactly `read,write,api` — `bulk script executed` succeeds. `getting-started/router-setup.mdx` now states this positively rather than leaving the reader to guess
- **Three WCAG 2.2 AA contrast failures in the light theme** — `--sl-color-gray-3` was `#7986cb`, measuring 3.45:1 on white while `.flow-step__desc` used it as body copy on the landing page; `--sl-color-orange-high` measured 3.46:1 on its own aside fill; and the hero primary call-to-action inherited Starlight's `--sl-color-black` label, measuring 2.75:1 on the brand fill (1.43:1 on hover)

- **Duplicated decision-forwarding loops in the CrowdSec stream** — `(*Stream).Run` carried two near-identical loops for new and deleted decisions, which put it over the cognitive complexity guard. The shared body moved to `forwardBatch`, preserving the per-kind log fields and the mid-batch cancellation behaviour
- **Documentation site structured data** — the JSON-LD `Person` node shares its `@id` with the canonical entity at `https://jmrp.io/#person` but published a project-scoped `description` ("Open-source developer; author and maintainer of cs-routeros-bouncer"). Because `description` is single-valued, that contradicted the canonical node instead of enriching it. It now mirrors the canonical `description`, and the canonical `jobTitle` was added
- **`gosec` suppressions** — the two known false positives in `internal/routeros/client.go` (G402) and `internal/config/config.go` (G101) were annotated with `//nolint:gosec`, which only `golangci-lint` honours, so standalone `gosec` still reported them at default confidence. Both now use `// #nosec GXXX -- reason`, the form `gosec` understands natively and the convention already used elsewhere in the codebase

### Changed

- **The i18n parity gate now compares component invocations** — a page could keep its `## Frequently asked questions` heading in both locales while one of them lost the `<Home section="faq" />` underneath it. The heading outline still matched, every gate stayed green, and a whole section — a live rich-results surface — vanished from that locale. Proven by mutation before the fix and after it. The gate now compares the multiset of component invocations keyed by their identifying attribute, which covers `ConfigOption`, `RuleSet` and anything added later
- **Both documentation gates were failing open, and now do not** — the contrast gate's token-symmetry check compared the *resolved* palettes, but the light palette is built as `{...dark, ...lightOverrides}`, so every dark token is present in it by inheritance. It could therefore only ever catch a light-only token and was structurally blind to the dangerous direction: a colour declared on the bare `:root` and never restated for light keeps its dark value on a white page. It now compares the declared blocks. The schema extractor had the same shape of hole: deleting every `v.SetDefault()` call still produced 93 keys, each documented as having no default, and deleting a whole nested struct dropped eight keys while clearing a floor set at 60. Both are now guarded on the metadata, not just the key count, and both were mutation-tested
- **Per-protocol rule-placement keys no longer publish defaults they do not have** — `firewall.ipv4.rule_placement.*` and its IPv6 twin are overrides: `mergeRulePlacement` copies a field onto the global placement only when the protocol value is non-zero, so an unset key resolves to the global value, not to the struct constructor's. Six keys were emitted with a flat `top`/`exact` default. They now record what they inherit from, and the reference renders that

- **Two documentation CI gates** (`docs/scripts/check-i18n-parity.mjs`, `docs/scripts/check-contrast.mjs`, both wired into `pnpm analyze` so the existing CI job runs them) — the parity gate compares the page set in both directions, frontmatter key shape and heading outline across every locale mirror, and fails on an empty corpus rather than reporting a vacuous pass; its success line states that it compares structure and not body prose, so a green run does not overclaim. The contrast gate parses `custom.css` as text, reproduces the cascade to resolve both palettes, and measures the pairs the sheet actually renders against the WCAG 2.2 AA thresholds. Colours it cannot derive from a token are cited by selector and property rather than restated as literals — deleting the rule that produces one makes the gate measure the framework fallback and fail, which is how the hero call-to-action failure above was found

- **Dependencies** — updated the Go dependency closure (including `prometheus/client_golang` 1.23.2 → 1.24.1 and `golang.org/x/{crypto,net,sync,sys,text}`), refreshed the Go tool closure (`golangci-lint`, `actionlint`, `staticcheck`, `govulncheck`, `goimports`), bumped the documentation site's npm dependencies (Astro 7.0.6 → 7.1.6, Starlight, ESLint, Playwright, Prettier and the remaining dev tooling, plus `eslint-plugin-astro` 2 → 3), moved the pinned pnpm release to 11.18.0, and upgraded `actions/setup-go` and `actions/setup-node` to v7
  - `typescript` is deliberately held at 6.x: TypeScript 7's native compiler does not yet expose the programmatic API that `astro check` relies on ([withastro/roadmap#1321](https://github.com/withastro/roadmap/discussions/1321))
- **Dependencies (2026-08-13)** — updated the Go dependency closure (`go-openapi/{analysis,validate}`, `golang.org/x/{net,text}`, `google.golang.org/protobuf`, `lufia/plan9stats`, `power-devops/perfstat`), bumped the pinned pnpm release from 11.18.0 to 11.21.0, and updated the documentation site's npm dependencies (Astro 7.1.6 → 7.2.1, `@astrojs/starlight` 0.41.6 → 0.41.7, ESLint 10.8.0 → 10.8.1, `eslint-plugin-astro` 3.0.1 → 3.1.0, `globals` 17.8.0 → 17.11.0, `html-validate` 11.6.0 → 11.6.2, `typescript-eslint` 8.65.0 → 8.67.0); `typescript` stays pinned at 6.x for the same `astro check` reason as above
- **Go 1.27.0** — bumped the Go toolchain from 1.26.5 to 1.27.0 across the `go` directive, the CI `GO_VERSION`/`GOTOOLCHAIN` pair, the `golangci-lint` language target (`run.go`), the Docker build image and the documentation prerequisites. `govulncheck` reports no advisories against the new toolchain
- **CodeQL moved from default setup to an advanced workflow** (`.github/workflows/codeql.yml`) — GitHub's default setup runs the Go extractor with `GOTOOLCHAIN=local`, pinned to whatever Go the CodeQL runtime ships. With `go.mod` on 1.27.0 its autobuild failed outright: `go.mod requires go >= 1.27.0 (running go 1.26.6; GOTOOLCHAIN=local)`. The advanced workflow installs the required toolchain with `actions/setup-go` and uses `build-mode: manual` (`go mod download && go build ./...`) for Go, `build-mode: none` for `actions`, so the extractor no longer depends on the runtime's bundled Go. The matrix keeps what default setup analyzed (`actions`, `go`) and adds `javascript-typescript`, which covers the Astro/Starlight documentation site under `docs/` that default setup was not scanning. Query suite and the weekly schedule are unchanged, and default setup is disabled at the repository level so the two do not collide. Same fix as the sibling `gitlab-mcp-server` repository
- **Dependencies (2026-08-25)** — updated the Go dependency closure (`sirupsen/logrus` 1.9.4 → 1.10.1, `stretchr/testify` 1.11.1 → 1.12.1, the `go-openapi/{analysis,loads,spec,swag,validate}` tree, dropping `pmezard/go-difflib` now that testify no longer needs it), refreshed the pinned Go tools (`golangci-lint` 2.12.2 → 2.13.1, `staticcheck` 0.7.0 → 0.8.1, `govulncheck` 1.6.0 → 1.7.0, `golang.org/x/tools` 0.48.0 → 0.49.0 for `goimports` and `modernize`), moved the pinned pnpm release from 11.21.0 to 11.23.0, updated the documentation site's npm dependencies (Astro 7.2.1 → 7.2.6, `@astrojs/starlight` 0.41.7 → 0.41.8, ESLint 10.8.1 → 10.9.1, `html-validate` 11.6.2 → 11.10.0, `typescript-eslint` 8.67.0 → 8.68.0), and moved the GoReleaser runtime image to `alpine:3.24`, matching the main Dockerfile. `typescript` stays pinned at 6.x for the same `astro check` reason as above; every GitHub Action already tracked its latest release, so no workflow pins changed
- **`.golangci.yml` aligned with the sibling `gitlab-mcp-server` configuration** — adds the complexity guards (`gocyclo` 20, `gocognit` 25, `nestif` 5, `maintidx` 20) and `dupl`, the `gofumpt` and `gci` formatters, `gocritic`'s `opinionated` and `experimental` tags, `staticcheck` with no check exclusions, `gosec` in `audit` mode with only `G104` excluded, `revive` at `severity: error`, `nolintlint` with `allow-unused: false`, and the stricter `usetesting` and `perfsprint` settings. Project-specific values are kept: the `routeros` spelling exemptions, the `prealloc` linter the sibling does not run, and the local module paths. The sibling's `concurrency: 4` is deliberately not copied — it is calibrated for a 226-package tree and would only slow a repository this size

  `make fmt` now applies every configured formatter through `golangci-lint fmt` rather than `gofmt` plus `goimports` alone, which would otherwise leave `gofumpt` and `gci` drift that the lint run then rejects. `make fmt-check` reports that drift without rewriting files

- **TypeScript major updates ignored in Dependabot** — TypeScript 7 ships the native compiler, which does not yet expose the programmatic API `astro check` is built on, so major bumps fail the documentation build. Minor and patch updates to 6.x are unaffected ([withastro/roadmap#1321](https://github.com/withastro/roadmap/discussions/1321))

- **Analysis tools moved out of `go.mod`** — `golangci-lint`, `gosec`, `actionlint`, `staticcheck`, `govulncheck`, `goimports` and `modernize` are no longer tracked through a `tool` directive. They are installed as standalone binaries at versions pinned in the `Makefile` (`make tools`, `make tools-versions`), which CI installs from as the single source of truth

  A `tool` directive forces every linter and the application itself through one MVS graph, so any two tools with incompatible requirements deadlock the whole build. That was not hypothetical: `gosec` 2.28.0 and `rhysd/actionlint` 1.7.12 pull mutually exclusive `go.yaml.in/yaml/v4` revisions, and `golangci-lint` 2.12.2 pins `denis-tingaikin/go-header` at v0.5.0 while v1.0.0 breaks its API. As standalone binaries each tool resolves its own dependencies and cannot conflict. As a side effect `go.mod` drops from 305 to 81 lines and `go.sum` from 757 to 178, leaving only what the shipped binary actually links

  The earlier note in this section claiming `gosec` had to be held at 2.27.1 because "2.28.0 requires the rc.6 YAML API" was wrong: gosec never imports `go.yaml.in/yaml/v4` — its own code is on `yaml/v3` and the rc.6 entry in its `go.mod` is indirect and unused. `gosec` is now on 2.28.0

## [1.4.5] - 2026-06-20

### Fixed

- **Grafana "Reconciliation Duration" panel** — the panel graphed the histogram `crowdsec_bouncer_operation_duration_seconds_sum` (a monotonic cumulative counter) and therefore showed the lifetime total of all reconcile durations instead of the most recent cycle. A new `crowdsec_bouncer_last_operation_duration_seconds` gauge now records the duration of the most recent operation, and the panel queries it ([#44](https://github.com/jmrplens/cs-routeros-bouncer/issues/44))

### Security

- **Go 1.26.4** — bumped the Go toolchain (go directive, CI and Docker build image) from 1.26.3 to 1.26.4 to fix two Go standard library vulnerabilities reported by govulncheck: GO-2026-5039 (`net/textproto`) and GO-2026-5037 (`crypto/x509`)

### Changed

- **Dependencies** — updated the Go build/test dependency closure (including `golang.org/x/crypto`, `golang.org/x/net`, `golang.org/x/sys`, `golang.org/x/text` and `prometheus/common`), bumped the Docker base image to `alpine:3.24`, and refreshed the documentation site's npm dependencies (Astro, Starlight, sharp and dev tooling)

### Added

- **`crowdsec_bouncer_last_operation_duration_seconds`** — new per-operation gauge exposing the duration of the most recent operation (add, remove, reconcile, …), complementing the existing latency histogram

## [1.4.4] - 2026-05-14

### Fixed

- **Docker env-only startup** — Docker images no longer force `-c /etc/cs-routeros-bouncer/config.yaml`; deployments configured only with environment variables now start without requiring a mounted config file ([#33](https://github.com/jmrplens/cs-routeros-bouncer/issues/33))
- **Legacy Compose command compatibility** — `command: sh -c ...` wrappers that were ignored by the image entrypoint before `1.4.2` are tolerated again, avoiding `unexpected argument "sh"` for existing Docker Compose deployments ([#33](https://github.com/jmrplens/cs-routeros-bouncer/issues/33))

### Changed

- **Docker examples** — Compose examples now document environment variables as the default configuration path and describe `/etc/cs-routeros-bouncer/config.yaml` as an optional auto-loaded mount
- **Release preparation** — active version references, issue templates, build examples, metric examples, and version-sensitive tests now point at `1.4.4`; the `v1.4.4` tag is intentionally left for the release merge

## [1.4.3] - 2026-05-09

### Added

- **Documentation refresh** — added dedicated CAPI blocklists, performance tuning, benchmarking, testing guide, and CLI reference pages, and expanded setup, architecture, monitoring, and troubleshooting guidance

### Fixed

- **CLI run-mode flag handling** — implicit run mode now rejects unknown flags and unexpected positional arguments before loading configuration, while `--version` continues to exit cleanly
- **Safe uninstall purge** — `uninstall -purge` now refuses empty, root, current-directory, and top-level config paths before running systemd or removal actions

### Changed

- **Docs UI and examples** — refreshed the Astro/Starlight documentation header, logo assets, code block styling, configuration examples, and CrowdSec origin guidance, including explicit `lists:*` documentation
- **Release preparation** — active version references, issue templates, build examples, metric examples, and version-sensitive tests now point at `1.4.3`; the `v1.4.3` tag is intentionally left for the release merge
- **Coverage audit** — benchmark runner, RouterOS pool, firewall placement, Logrus adapter, and manager polling/removal paths now use focused unit tests, raising aggregate Go coverage from 88.9% to 94.2%

## [1.4.1] - 2026-05-08

### Added

- **Periodic reconciliation** — active CrowdSec decisions are reconciled against MikroTik address lists every `crowdsec.reconciliation_interval` (default `15m`, `0` disables, minimum `1m`) so router-side timeout or manual drift is repaired without waiting for a restart
- **Extended static analysis** — `make analyze` now includes `modernize` and `gosec`, and the documentation workspace now runs Astro type checks, ESLint, Prettier, build validation, and HTML validation through pnpm

### Fixed

- **Sustained RouterOS CPU/API churn on duplicate ban decisions** — cached duplicate bans now skip RouterOS API writes entirely, and RouterOS device errors continue to be treated as command conflicts rather than transport failures. This prevents repeated duplicate add attempts and reconnect churn during steady-state operation ([#22](https://github.com/jmrplens/cs-routeros-bouncer/issues/22))
- **Functional tests with CAPI origins** — integrity and bulk tests now compare against the bouncer's configured `crowdsec.origins`, avoiding false local-only failures when production config includes CAPI
- **Functional reconciliation wait** — test helpers no longer use a `journalctl | grep -q` pipeline that could miss completion markers under `pipefail` with verbose logs

### Changed

- **Release preparation** — active version references, issue templates, build examples, metric examples, and version-sensitive tests now point at `1.4.1`; the `v1.4.1` tag is intentionally left for the release merge
- **Tooling and dependencies** — Go tooling now targets the project `go.mod` version (`1.26.3`) via `GOTOOLCHAIN`, and the documentation stack has been refreshed to the Astro 6 / Starlight 0.39 / TypeScript 6 / pnpm 10 generation
- **Go lint policy** — golangci-lint rules have been tightened with `nilnil`, stale exclusions were removed, and not-found RouterOS paths now use explicit errors instead of `nil, nil` results
- **GitHub Pages deployment** — docs publishing now runs only when Astro documentation inputs change, avoiding unrelated Pages deploys
- **Documentation** — clarified that reconciliation can temporarily raise Router CPU when it performs add/remove work. Sustained high RouterOS CPU after reconciliation is not expected from address-list entries simply remaining in memory
- **Benchmarks** — refreshed RB5009/RouterOS 7.22.1 CAPI measurements: ~28,700 decisions reconcile in ~58s wall-clock with ~35–36s of RouterOS bulk work, and no-drift periodic reconciliation settles around ~3–4s
- **Systemd unit** — setup now installs `TimeoutStopSec=90` to avoid killing graceful shutdown during large-list churn

## [1.3.4] - 2026-04-04

### Added

- **RouterOS system metrics** — Prometheus gauges for CPU load (`routeros_cpu_load`), used/total memory (`routeros_memory_used_bytes`, `routeros_memory_total_bytes`), and CPU temperature (`routeros_cpu_temperature_celsius`). Polled via RouterOS API at configurable `metrics.routeros_poll_interval` (default `30s`, `0` to disable)
- **LAPI usage metrics** — reports active decisions (per-origin and per-IP-type) and dropped traffic (bytes/packets delta) to CrowdSec LAPI `/v1/usage-metrics` endpoint
  - Per-origin decision counts (e.g., `crowdsec`, `cscli`, `CAPI`)
  - Per-IP-type decision counts (`ipv4`, `ipv6`)
  - Firewall dropped bytes and packets read from MikroTik rule counters (delta between pushes)
  - Configurable interval via `crowdsec.lapi_metrics_interval` (default `15m`, `0` to disable)
- **CrowdSec SDK version metadata** — bouncer now reports correct version to CrowdSec LAPI via `go-cs-lib/version.Version` ldflags
- **Input interface filtering** — restrict firewall rules to a specific interface or interface-list via `firewall.block_input.interface` / `firewall.block_input.interface_list`
- **Connection pool auto-capping** — automatically reduces `pool_size` if it would exceed RouterOS `max-sessions` limit
- **Comprehensive unit test suite**:
  - `internal/manager` — 90.3% coverage with mock-based CrowdSecStream and RouterOSClient interfaces
  - `internal/routeros` — 93.0% coverage with MockConn and extracted RouterConn interface
  - `internal/crowdsec` — 93.4% coverage with BouncerEngine interface and mock-based stream tests
  - `internal/metrics/lapi` — 71.8% coverage (metricsUpdater 100%, SDK wiring excluded)
- **Rule signature** (`@cs-routeros-bouncer`) — fixed, non-configurable identifier appended to every firewall rule comment for crash-safe cleanup
- **Stale rule cleanup** — `cleanupStaleRules()` on startup removes orphaned firewall rules from previous runs (e.g., after config change or crash)
- **Firewall customization features**:
  - **Output passthrough** — exclude local IPs from output blocking via `passthrough_v4`/`passthrough_v6` or address lists (`passthrough_v4_list`/`passthrough_v6_list`)
  - **Connection-state filter** — restrict filter rules to specific connection states (e.g., `new`) via `firewall.filter.connection_state`
  - **Hierarchical log-prefix** — configurable log prefix at global, per-table, and per-direction levels
  - **Input whitelist** — accept rule for whitelisted address list before drop rule via `firewall.block_input.whitelist`
  - **Reject-with** — configurable ICMP reject type when `deny_action: reject` via `firewall.reject_with`
- **Functional test suite** — 60 black-box tests in 9 groups (t1–t9) validating the compiled binary against real MikroTik hardware via SSH, SNMP, cscli, and Prometheus
- **Prometheus metrics expanded** — 3 new metrics: `crowdsec_bouncer_dropped_bytes_total`, `crowdsec_bouncer_dropped_packets_total`, `crowdsec_bouncer_active_decisions_by_origin` (total now 11)

### Fixed

- **Infinite reconnect loop on duplicate entries** — the bouncer no longer treats RouterOS device errors (like "already have such entry") as connection failures. Duplicate entries are now handled gracefully by finding and updating the existing entry's timeout and comment ([#14](https://github.com/jmrplens/cs-routeros-bouncer/issues/14))
- **Docker health check fails when metrics are disabled** — the `/health` endpoint now always starts regardless of the `metrics.enabled` setting, so container health checks work out of the box ([#16](https://github.com/jmrplens/cs-routeros-bouncer/issues/16))
- **Firewall rule placement** — iterate all chain positions when dynamic/builtin rules occupy top slots
- **Incorrect language attribution in README** — fixed acknowledgments section that incorrectly described cs-mikrotik-bouncer and cs-mikrotik-bouncer-alt as Python projects when they are Go projects ([#15](https://github.com/jmrplens/cs-routeros-bouncer/issues/15))
- **Health/metrics server startup** — the listener is now bound synchronously so address-in-use errors are caught immediately at startup instead of silently failing in a background goroutine
- **Empty version in LAPI metadata** — added `go-cs-lib/version.Version` ldflags to Makefile, Dockerfile, and `.goreleaser.yaml`

### Changed

- **LAPI metrics format** — migrated from single `active_decisions` total to per-origin and per-IP-type breakdown with dropped traffic deltas
- **metricsUpdater** — refactored from package-level function to `Provider` method for `CounterCollector` support

## [0.1.0] - 2025-07-22

### Added

- **CrowdSec integration**: Stream-based bouncer connecting to CrowdSec LAPI for real-time ban/unban decisions
- **RouterOS API client**: Persistent connection with auto-reconnect, TLS support, and mutex-safe concurrent access
- **Automatic firewall rule management**: Creates filter and raw rules on startup, removes them on shutdown
  - IPv4 filter (`/ip/firewall/filter`) and raw (`/ip/firewall/raw`) chains
  - IPv6 filter (`/ipv6/firewall/filter`) and raw (`/ipv6/firewall/raw`) chains
  - Configurable deny action (`drop` or `reject`)
  - Move-based rule placement at top of chain with builtin rule fallback
- **Individual IP management**: Adds IPs on ban, removes on unban — no bulk re-upload, no duplicates
  - Optimistic-add pattern (~1ms per IP vs ~400ms with lookup-first)
  - Named address lists: `crowdsec-banned` (IPv4), `crowdsec6-banned` (IPv6)
  - Comment-based resource identification (`crowdsec-bouncer:` prefix)
- **Startup reconciliation**: On start/restart, compares CrowdSec decisions with MikroTik address lists
  - Adds missing IPs that should be blocked
  - Removes stale IPs that are no longer in CrowdSec decisions
- **IPv4 and IPv6 support**: Independently toggleable per protocol
- **Input and output blocking**: Output blocking optional with configurable interface or interface-list
- **Decision origin filtering**: Configure `crowdsec.origins` to sync only local decisions or include CAPI community blocklists
- **Prometheus metrics**: 8 metrics exposed at `/metrics` endpoint
  - Active decisions gauge, total decisions counter, error counter
  - Operation duration histogram, connection status, build info
- **Health endpoint**: HTTP `/health` with RouterOS connection status and version info
- **Configuration**: YAML config file with environment variable overrides (Viper-based)
- **Structured logging**: Zerolog-based JSON/console logging with configurable level
- **Docker support**: Multi-arch Docker images (amd64, arm64) with minimal scratch-based image
- **Binary releases**: Cross-compiled binaries for Linux (amd64, arm64, armv7), macOS, and Windows via GoReleaser
- **Systemd support**: Example unit file and install/uninstall Makefile targets
- **CI/CD**: GitHub Actions for lint, test, build, Docker build, and automated releases

### Performance

- Single IPv4 add: ~1 ms (optimistic-add pattern)
- Single IPv6 add: ~8 ms
- **Bulk add** (script-based, chunks of 100): ~168 IPs/s for local (~1,500 IPs in ~9 s), ~147 IPs/s for CAPI (~25,000 IPs in ~2 min 50 s)
- **Mass removal** (parallel, 4 connections): ~105 removes/s (~23,500 IPs in ~3 min 45 s)
- **Restart with existing entries**: ~10 s for 25,000 IPs (diff-only, no bulk needed)
- Router CPU peak during reconciliation: 14% (local), 23% (CAPI 25k)
- Steady-state router CPU in the original benchmark environment: 8–11% (local-only), 15–20% (with CAPI)
