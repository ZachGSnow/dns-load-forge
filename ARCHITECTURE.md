# DNS Load Forge - Architecture

How the pieces fit together, and why the awkward decisions went the way they did.
The README is the operator's guide; this is for whoever has to change the code.

## Module map

```
src/dnsloadforge/
  __main__.py        enables python -m dnsloadforge
  cli.py             argument parsing, preflight, console reporting, command dispatch
  spec.py            THE CONTRACT: vocabulary, dataclasses, snapshot JSON schema
  targets.py         named targets: address + the rules that decide what counts as a failure
  compare.py         reduce a finished run to comparable numbers; console comparison table
  packets.py         DNS wire codec (encode query, encode response, decode) - pure
  domainlist.py      fetch/parse/cache the GitHub domain lists; categories + weights
  curated.py         built-in enterprise + borderline domains (always available offline)
  sources.json       the data-driven source table
  profiles.py        the 10,000-worker office model (roles, mixes, hot sets, arrivals)
  engine.py          asyncio sender: pacing, bursts, in-flight budget, classification
  stats.py           aggregation, rolling windows, percentiles, findings, verdict
  server.py          stdlib HTTP + SSE dashboard, run/compare control, list jobs, request screening
  mockappliance.py   simulated filtering appliance, 7 scenarios, standalone CLI
  dashboard/index.html  the entire front end, one self-contained file (themes are CSS tokens)
scripts/
  Invoke-DnsLoadForge.ps1   PowerShell front end
  New-LabSourceIPs.ps1      create/remove the source-IP pool (elevated)
  Get-DnsLoadForgeCapture.ps1  pktmon wire capture + reconcile (elevated)
tests/                     270 tests; no network required
runs/                      per-query record logs (gitignored)
lists/cache/               fetched domain lists in a checkout (gitignored); a pip install uses
                           %LOCALAPPDATA%\dnsloadforge or ~/.cache/dnsloadforge instead
                           (override with $DNSLOADFORGE_CACHE)
targets.example.json       a starting point for your own targets
```

`spec.py` is a leaf module that imports nothing else from the package, and every other
module agrees on the names it defines. Changing a `Category` value or a `QueryRecord`
field means updating `stats.py`, `server.py` and `dashboard/index.html` together - the
snapshot schema is documented in a comment block at the bottom of `spec.py`, and the
dashboard is written against exactly that.

## Data flow

```
sources.json
    |
    v
domainlist.load_catalogue
    |-- _resolve_overlaps              one category per domain
    |-- _resolve_subdomain_conflicts   popularity under a blocked tree
    v
DomainCatalogue (9 weighted pools)
    |
    v
profiles.PersonaModel (10,000 personas)
    |   roles, mixes, hot sets, DGA probes
    v
engine.DnsLoadEngine  <--  Target.apply(RunConfig)  (scoring rules)
    |
    |   asyncio UDP queries
    v
the target (appliance or public resolver)
    |
    |   responses
    v
classify() -> Outcome   (expectations, sinkhole networks, neutral names)
    |
    v
stats.StatsAggregator
    |
    +--> snapshot() --> server.py --> dashboard
    |                      |
    |                      v
    +--> RecordLog ------> /api/run/export.*
         (CSV/JSONL on disk)
```

## Key decisions

### Why Python for the hot path

10,000 workers at realistic peak means ~10,000 queries per second sustained. A
PowerShell runspace pool is a poor fit for that: runspaces are heavyweight, the socket
APIs are awkward, and 10,000 of them would exhaust 16 GB of RAM before sending a
packet. Python's `asyncio` reaches the target in one process on this hardware, and the
package has **no third-party dependencies**, so it runs on a freshly imaged box with
nothing but Python installed. The PowerShell scripts are the front end for the
repository's everyday workflow; the load generation is not.

### One event loop, not 10,000 timers

Each persona's lookups are an independent Poisson process, but the engine does not run
10,000 of them. A superposition of independent Poisson processes is itself Poisson, so
the engine draws **one** inter-arrival time for the whole office and then picks who acted
in proportion to their rate. Identical mathematics, O(1) per arrival, and the only reason
10,000 personas fit in one process. When the target rate exceeds what the machine
delivers, the pacer simply stops sleeping and falls behind - reported as unanswered
queries rather than papered over.

### Two clocks, because one is a lie

`--qps` means *queries* per second, so the pacer's rate is derived as
`target * Σ(w_i/b_i) / Σw_i` - pages per second, where `b_i` is the role's mean burst
size. Dividing by the office *page* total instead of the rate-weight total is off by the
mean burst size (~5x), which is exactly the bug that shipped in the first draft and was
caught by measuring achieved throughput against the target. `RunResult.achieved_qps`
divides by the **sending** window (`send_started_at`/`send_ended_at`), not the whole run,
so the drain at the end does not deflate the number.

### One aggregator, per-shard counters

`threads > 1` shards personas, sockets and the target rate across event loops that all
report into one locked `StatsAggregator`. The engine therefore keeps its **own**
sent/received/timeout counters for `RunResult`: reading them back from the shared
aggregator made every shard claim credit for the whole office, so a 2-thread run reported
double the load it generated.

### Received excludes timeouts

`totals.received` counts answers. A timeout is a completed query but not a received one,
and counting it as received would leave the received-qps line flat while the appliance
dropped every packet - the exact failure the tool exists to expose. Timeouts and
generator errors get their own per-second buckets, and the two groups use different
denominators on the dashboard: wire rcodes are a share of responses *received*, the
timeout/error sentinels a share of queries *sent*, since they never arrived.

### Percentiles from histograms

At 10,000 qps a 60-second run is 600,000 queries; storing every latency to sort later
would cost hundreds of megabytes for a number nobody reads past the millisecond. Each
latency goes into one of 19 buckets (fine-grained below 100 ms, where filtered-DNS
latency actually lives) and a percentile is reported as the **upper** bound of its
bucket - a mild over-estimate rather than a flattering one. Per-domain latency uses a
coarser 8-bucket histogram because it has to exist for tens of thousands of domains at
once, capped at 100,000 tracked domains. An infinite overflow bucket is reported as the
boundary below it, never as `Infinity`, because `Infinity` is not valid JSON and would
blank the entire dashboard payload.

### Targets carry their own rulebook

One rulebook cannot judge every resolver, and the first public-resolver run proved it:
OpenDNS answers a blocked name with an address on its block page (`146.112.61.x`), not
NXDOMAIN, so every block scored as a leak; reverse-DNS and `corp.local` lookups came
back NXDOMAIN, which is correct on a public resolver, and scored as outages. A `Target`
therefore bundles an address with three scoring inputs, and `Target.apply()` stamps them
onto a copy of the `RunConfig`:

* `blocks` - the categories it should block. The rest are sent anyway (they are realistic
  traffic) but their expectation becomes `unknown`: reported, never judged.
* `sinkhole_ips` / `sinkhole_cidrs` - what "blocked" looks like for this target.
  `SinkholeSet` checks exact addresses first (a hash hit) and only parses networks on a miss.
* `kind` - `public` excuses NXDOMAIN for internal-only names (`*.local`, `*.corp`, ...) and
  applies the 100 qps limit; `appliance` expects AD names to resolve.

NXDOMAIN for a reverse (`*.arpa`) name is neutral for every target: most addresses have no
PTR record, and the answer says nothing about the filter. The expectations reach both
`classify()` (per query) and `StatsAggregator.set_expectations()` (verdict and
by-category table), set in one place - the engine's constructor - so the two can never
disagree about what "blocked" means.

### Comparison runs

A start request may name several targets. `RunController._supervise` runs them one after
another on the same seed with a short cooldown, giving each a fresh `StatsAggregator`, and
condenses each finished run with `compare.summarise_run` into `history`. Running them
*sequentially* is deliberate: in parallel they would share one CPU and one NIC, so the
generator would become the variable being measured. A comparison needs a finite duration,
and a stop cancels the targets that have not yet run.

### Dashboard request screening

The dashboard can start load tests and has no login, so `_Handler._screen` refuses what a
web page in another tab could send: a cross-origin `Origin`, a cross-site
`Sec-Fetch-Site`, a non-JSON `Content-Type` (which keeps simple-request CSRF out), and -
when bound to loopback - any `Host` that is not localhost (DNS rebinding). A refusal closes
the connection, because the unread request body would otherwise be parsed as the next
request on a keep-alive socket. Binding beyond loopback needs `--allow-remote-dashboard`.

### List maintenance runs on a job thread, never during a run

Refreshing or toggling a source re-parses lists of up to a million names. That shares the
sender's interpreter, so doing it mid-run would distort the latency being measured; the
controller refuses it while a run is in progress (and refuses a run while a job is active).
A refresh fetches each source with `refresh_source` (one dead list never stops the rest),
then rebuilds the catalogue from the cache and swaps it in atomically - a run holds its
own reference, so it never sees a half-built catalogue. Disabled sources are stored in
`disabled.json` beside the cache, keeping `sources.json` read-only.

### Verdict precedence

The order in `StatsAggregator._verdict_locked` encodes what an operator needs to know
first:

1. **idle** - nothing ran.
2. **unknown** - under 200 completed queries; a verdict from a handful of packets is
   noise dressed as analysis.
3. **degraded / "answered none"** - no point reporting a false-positive rate against a
   resolver that never spoke.
4. **passthrough** - *a rate, not a zero*. If fewer than 20% of known-bad queries were
   blocked, the policy is not being applied. Requiring exactly zero blocked sounds
   stricter but is brittle: an appliance that intercepts only one query type can block a
   token few names while letting the traffic through, and "policy not applied" is the
   finding that changes what the operator does next.
5. **degraded / failing under load** - >5% loss or SERVFAIL. Capacity, not policy.
6. **degraded / false positives** - the expensive failure, ranked above leaks because a
   blocked sign-in endpoint is a ticket and a leaked ad domain is not.
7. **degraded / false negatives** - leaking known-bad.
8. **baseline** - nothing is expected to be blocked for this target (an unfiltered
   resolver used as a control), so "filtering correctly" would claim something the run
   never tested.
9. **filtering** - nothing to report.

`borderline` traffic never produces a false positive or negative: those categories exist
because the lists genuinely disagree, so the tool reports what happened without judging.

### Themes

Every colour in `dashboard/index.html` is a CSS variable, and a theme is one
`:root[data-theme="..."]` block redefining them. Tints (alert glows, chips, button fills)
use `color-mix()` over the tokens, so they follow the active palette. Canvas cannot read
CSS, so `syncChartColors()` copies the chart colours out of the active theme on every
change. The selection is remembered in `localStorage` (wrapped in try/catch) and applied by
an inline script before first paint.

### The snapshot contract

The dashboard renders one JSON object produced by `StatsAggregator.snapshot()`. Its
schema is documented at the bottom of `spec.py` and is the only interface between
backend and frontend - the front end is one self-contained HTML file with hand-drawn
canvas charts, no framework, no build step and no external requests, so it works on an
air-gapped segment. All dynamic strings go through `textContent`; a hostile hostname off
the wire cannot inject markup. Payloads are serialised with `allow_nan=False` and fall
back to a sanitiser, so a non-finite number can never produce invalid JSON.

### Failures the code is built to have

* **Source-IP pool addresses that do not exist.** Discovered at bind time and reported
  with the command that creates them, rather than as an `errno`.
* **ICMP port-unreachable.** A connected UDP socket surfaces it as `error_received`;
  every outstanding query on that socket is attributed at once instead of waiting out
  the timeout, so a wrong port is visible in seconds.
* **A malformed response.** Cannot be attributed to a query without a transaction ID, so
  it is counted separately (`malformed`) rather than silently dropped.
* **An in-flight cap.** Hitting `max_inflight` *drops* and counts queries instead of
  queueing without bound and reporting a rate never achieved. A nonzero drop count means
  the generator, not the appliance, is the bottleneck.
* **A dead source list.** Every fetch is individually guarded; one retired URL cannot
  fail a run.

## Extending it

* **A new target**: add it to `targets.json` (or `BUILTIN_TARGETS` in `targets.py` for a
  preset). Declare `blocks` honestly; a target that blocks nothing should say `[]`.
* **A new theme**: copy any `:root[data-theme]` block in `dashboard/index.html`, change the
  tokens, and add its id to the `THEMES` array in the page script. Check
  text contrast (4.5:1 against both panel surfaces) before shipping it.

* **A new domain source**: add an entry to `sources.json`. `format` selects the parser
  (`hosts`, `plain`, `rank_csv`); `ranked` marks a popularity list so its order drives
  sampling weights.
* **A new role**: add a `Role` to `ROLES` in `profiles.py`. Headcounts should keep
  summing to 10,000, and `_normalise` will scale the mixes for you.
* **A new mock behaviour**: add a preset to `_SCENARIO_PRESETS` in `mockappliance.py`
  and a name to `SCENARIOS`. Presets are defaults; explicit keyword arguments always win.
* **A new reported statistic**: add it to `_snapshot_locked`, document it in the schema
  comment in `spec.py`, and render it.
* **More throughput**: raise `--threads`. Sharding splits personas, sockets and the rate
  evenly, and the per-shard identity in `RunEngine._prepare_shard` is the only place that
  needs to stay consistent.
