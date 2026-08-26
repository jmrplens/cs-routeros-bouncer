# rosapi — vendored RouterOS API client

Vendored copy of [`github.com/go-routeros/routeros/v3`](https://github.com/go-routeros/routeros)
at **v3.0.1** (upstream commit of 2025-02-16), MIT licensed — see `LICENSE`.

## Why vendored

Upstream is effectively unmaintained: the last commit predates this copy by
eighteen months, and the pull requests and issues filed against the async mode
in mid-2026 (#31–#34) have had no maintainer response. No maintained alternative
exists — `swoga/go-routeros` is a copy that only receives dependabot bumps for
its GitHub Actions, and `jda/routeros-api-go` stopped in 2016. Vendoring keeps
the code buildable forever and lets this repo fix and prune what it uses.

## Local changes relative to upstream v3.0.1

1. **The async/listen mode is removed** (`async.go`, `listen.go`,
   `chan_reply.go`, their tests, and the async branch of `RunArgsContext`).
   The bouncer's `RouterConn` interface exposes `RunArgs` and `Close` only;
   nothing in this repository ever called `Async()`, `Listen()`, or the
   context-cancelling run variants. The sentence-kind constants that lived in
   `listen.go` moved to `reply.go`, which is what consumes them.

2. **`proto.ctxReader`/`ctxWriter` read and write directly** instead of
   dispatching every call to a fresh goroutine with a channel and a copy
   buffer. Upstream's dispatch existed to let `Cancel()` interrupt an in-flight
   read — and only the removed async mode ever called `Cancel()`. At this
   bouncer's production scale (22k address-list entries fetched every cycle)
   the goroutine-per-Read layer cost ~294,000 goroutine spawns, ~62 MB of
   garbage and ~76% of all allocations per reconcile cycle. The rewrite was
   validated against the pristine upstream with a differential test: SHA-256
   fingerprint over all 22,037 parsed sentences identical, error shapes
   identical (`io.ErrUnexpectedEOF` on truncation, `*DeviceError` on `!trap`),
   and upstream's own suite green under `go test -race`. The committed
   `proto/reader_shape_test.go` pins that behaviour.

3. **The pre-6.43 MD5 challenge login is removed.** The two-stage login only
   exists before RouterOS 6.43 (2018), the bouncer documents 7.x as its floor,
   and answering the challenge means hashing the password with MD5 — flagged,
   rightly, by every scanner that reads it. A router that sends a `ret`
   challenge now gets `ErrLegacyLoginUnsupported` instead of an MD5 answer.

4. **`TestRunAsync` and the listen-mode tests are removed** with the mode; the
   pre-6.43 login tests assert the rejection instead of the handshake. The
   rest of upstream's test suite is kept and passing.

When comparing against upstream, diff against the `v3.0.1` tag, not master.
