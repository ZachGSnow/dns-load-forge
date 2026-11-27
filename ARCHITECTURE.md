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
  transports.py      TCP, DoT and DoH: one-shot probes, and the connection pools a run sends through
  stats.py           aggregation, rolling windows, percentiles, findings, verdict
  server.py          stdlib HTTP + SSE dashboard, run/compare control, list jobs, request screening
  mockappliance.py   simulated filtering appliance, 8 scenarios, standalone CLI
  checks.py          deployment checks: identity, bypass, canaries, DNSSEC, SafeSearch
  dashboard/index.html  the front end: built from web/ into one self-contained file
  dashboard/THIRD_PARTY_NOTICES.txt  licenses of the libraries bundled into that page
web/                       the dashboard's source: React, Tailwind CSS, shadcn/ui, Recharts
  src/lib/schema.ts        the snapshot contract on the TypeScript side
  src/index.css            every theme, as CSS variables
  scripts/postbuild.mjs    keeps the built page ASCII and free of external references
scripts/
  Invoke-DnsLoadForge.ps1   PowerShell front end
  New-LabSourceIPs.ps1      create/remove the source-IP pool (elevated)
  Get-DnsLoadForgeCapture.ps1  pktmon wire capture + reconcile (elevated)
tests/                     369 tests; no network required
runs/                      per-query record logs (gitignored)
lists/cache/               fetched domain lists in a checkout (gitignored); a pip install uses
                           %LOCALAPPDATA%\dnsloadforge or ~/.cache/dnsloadforge instead
                           (override with $DNSLOADFORGE_CACHE)
targets.example.json       a starting point for your own targets
```

`spec.py` is a leaf module that imports nothing else from the package, and every other
module agrees on the names it defines. Changing a `Category` value or a `QueryRecord`
field means updating `stats.py`, `server.py` and `web/src/lib/schema.ts` together (then
rebuilding the page) - the snapshot schema is documented in a comment block at the bottom
of `spec.py`, and the dashboard is written against exactly that.

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
engine.DnsLoadEngine  <--  Target.apply(RunConfig)  (scoring rules, transport)
    |
    |   asyncio queries: a UDP socket, or a TCP / DoT / DoH connection pool
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
so the drain at the end does not deflate the number. The dashboard's per-second rates
come only from **finished** seconds: the bucket still filling, and the run's first bucket
(which starts mid-second), would show a healthy generator at a fraction of its rate.

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

Two more inputs reach `classify()` from the wire. An **Extended DNS Error** in the policy
range (4 Forged Answer, 15 Blocked, 16 Censored, 17 Filtered, 18 Prohibited) is the filter
saying it applied a policy, so it is a block whatever the answer looks like; filters do
not agree on which code a block gets, so all five count. And the **address hints in
HTTPS/SVCB records** are passed in with the A/AAAA addresses, because a browser connects to
them directly: a block-listed name whose HTTPS answer carries real hints has leaked. The
engine also names the mechanism behind each block (`block_signal()`: NXDOMAIN, REFUSED,
sinkhole, no records, an unlisted address known only by its EDE), which is what the
dashboard and the comparison show as "blocks with".

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

### Every transport through one engine

TCP, DNS over TLS and DNS over HTTPS reuse everything the UDP path has -- pacing,
classification, the sweeper, the statistics -- because a connection pool in
`transports.py` stands exactly where the UDP socket stood: the same `pending` table keyed
by transaction ID, the same `transport.sendto(packet)`, the same `_handle_response`. The
engine asks one new question, `room()`, before each burst, so a pool that is out of
connections drops queries the way the in-flight budget does instead of queueing them.

* **Connections open before the first query.** A handshake is set-up, not latency, and
  counting it would make an encrypted transport look slower than it is.
* **TCP and DoT pipeline and match by ID.** Quad9, Google and Cloudflare all answered a
  pipelined batch out of order when it was checked, so nothing may assume order.
* **DoH sends one request per connection at a time.** HTTP/1.1 answers strictly in order,
  so a pipeline would let one slow lookup hold up the rest. A page load fires up to
  `MAX_BURST` (24) lookups at once, so a pool starts with room for a whole burst and grows
  when it runs short; four connections dropped a third of a 20-qps run against real DoH
  services, every drop inside a burst.
* **A close is not a failure.** Servers retire connections as a matter of course (idle
  timeouts, recycling, `Connection: close`), and a resolver library re-sends what was
  waiting, so the pool re-sends each stranded query once on another connection; the
  query's latency keeps counting from its first send. A connection counts as lost only
  when a close cost queries or came with an error, or when it stopped answering for twice
  the timeout.
* **HTTP/1.1 only.** HTTP/2 is not in the standard library. A service that insists on it
  answers 505 (Quad9 does), which the preflight probe explains.
* **The mock has no certificate.** The standard library cannot make one, and a key in the
  repository would be a key in the repository, so the mock speaks TCP (on its UDP port,
  as a real server does) and DoH over plain HTTP. The TLS layer was verified live against
  Quad9, Google, Cloudflare and OpenDNS, and the code that is TLS-specific -- the context
  and the wording of certificate errors -- is small and tested directly.

### Deployment checks are single queries with evidence

`checks.py` is deliberately not part of the load path. Each check sends a handful of
queries through an injectable `ask()` function (tests replace it with a fake resolver, so
every pass, warn and fail path runs without the network) and returns a `CheckResult` that
carries its evidence: every query, its answer, EDE and NSID. The expected answers are
external facts that drift -- vendors rename test domains and move block pages -- so they
were verified live and dated, and the evidence is always shown rather than only a verdict.
Two lessons from that verification are encoded: Umbrella's test names resolve to
146.112.59.12 on an unfiltered resolver, inside the same network as its block pages, so
only the exact block-page addresses count; and a resolver that answers every name with
the same address makes a SafeSearch comparison meaningless, so that is reported as
inconclusive. The dashboard runs the checks on a background thread and refuses them
during a load run, because a few dozen extra queries are exactly the noise a latency
measurement must not contain.

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
9. **unknown / filtering not tested** - blocking is expected but no block-listed query was
   sent, which is what empty or never-fetched block lists produce. "Filtering correctly, 0
   block-listed queries were refused" would certify a test that never ran.
10. **filtering** - nothing to report.

`borderline` traffic never produces a false positive or negative: those categories exist
because the lists genuinely disagree, so the tool reports what happened without judging.

### Themes

Every colour is a CSS variable in `web/src/index.css`: shadcn/ui's token names
(`--background`, `--card`, `--primary`, ...) plus the tool's own meanings (`--ok`,
`--warn`, `--bad`, `--fp`, `--fn`) and chart series. Light is `:root`, Dark is `.dark`, and
each palette is one `.dark[data-theme="..."]` block, so every component follows whichever
is active. `npm test` parses those blocks and checks text and status colours for 4.5:1
contrast on both the page and card surfaces. The selection is remembered in
`localStorage` under the original key (a palette chosen in the old dashboard carries over)
and applied by an inline script before first paint.

### The snapshot contract

The dashboard renders one JSON object produced by `StatsAggregator.snapshot()`. Its
schema is documented at the bottom of `spec.py`, mirrored in `web/src/lib/schema.ts`, and
is the only interface between backend and frontend. Every field is optional on the
TypeScript side, because the page and the server can be different versions.

### One file, no network, no Node at run time

The front end is a React app built with shadcn/ui components and Recharts, but it ships
as **one** self-contained HTML file: Vite inlines the scripts, styles and the Latin subset
of the Geist fonts, and `web/scripts/postbuild.mjs` fails the build if the result refers
to anything outside itself or contains a non-ASCII character. The built page is
committed, so installing and running the tool needs Python only; Node is needed only to
change the page, and CI rebuilds it and fails if the committed copy is stale.

The server sends the page with a Content-Security-Policy built from the SHA-256 of each
inline script (`dashboard_csp()`), so the browser itself refuses any other script and any
connection to anywhere but this server, and `frame-ancestors 'none'` stops another site
framing the Start button. Browsers normalise line endings before hashing a script, and a
Windows checkout may store the page with CRLF, so the hashes are taken after the same
normalisation (and `.gitattributes` pins the page to LF anyway). Values from the network
are rendered as React text, never HTML: a hostile hostname off the wire cannot inject
markup. Payloads are serialised with `allow_nan=False` and fall back to a sanitiser, so a
non-finite number can never produce invalid JSON.

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
* **A certificate this machine cannot check yet.** Windows downloads root certificates the
  first time something needs one, and Python only sees roots already downloaded, so a
  perfectly valid DoT or DoH server can fail verification on a fresh machine (it did, for
  SSL.com and IdenTrust roots). The error says so and names the fix instead of reporting
  a bare OpenSSL code.
* **A server that hangs up mid-pipeline.** The queries it stranded are re-sent once and
  then fail as errors at once, rather than waiting out the timeout.

## Extending it

* **A new target**: add it to `targets.json` (or `BUILTIN_TARGETS` in `targets.py` for a
  preset). Declare `blocks` honestly; a target that blocks nothing should say `[]`.
* **A new theme**: copy a `.dark[data-theme="..."]` block in `web/src/index.css`, change
  the tokens, add it to `THEMES` in `web/src/lib/themes.ts` and to the palette list in
  `web/index.html`'s pre-paint script, then run `npm test` (contrast) and `npm run build`.
* **A new dashboard panel**: add the fields it reads to `web/src/lib/schema.ts`, build it
  from the components in `web/src/components/ui`, and rebuild the page.

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
