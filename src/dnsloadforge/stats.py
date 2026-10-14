"""Aggregation, rolling windows, percentiles and the run verdict.

The engine generates a record per query; this module is the only thing that
decides what those records *mean*.  It is deliberately the most carefully written
part of the package, because everything the operator concludes about the
appliance comes out of here.

Two design points worth stating up front:

**Percentiles come from histograms, not from stored samples.**  At 10,000 qps a
60-second run is 600,000 queries; keeping every latency to sort later would cost
hundreds of megabytes for a number nobody reads to more than a millisecond of
precision.  Instead each latency is dropped into one of
:data:`spec.LATENCY_BUCKETS_MS` and a percentile is reported as the upper bound of
the bucket it lands in.  The bucket list is fine-grained below 100ms, which is
where essentially all filtered-DNS latency lives, so in practice the reported
p95 is accurate to a few milliseconds and is always a mild over-estimate rather
than a flattering one.

**The verdict is computed, not guessed.**  ``snapshot()["verdict"]`` compares what
happened against what each category was supposed to do, and refuses to draw a
conclusion until it has seen enough queries to mean anything.  A run against a
mistyped address that answered nothing must not read as "filtering works".
"""

from __future__ import annotations

import json
import math
import os
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .spec import (
    CATEGORY_EXPECTED,
    CATEGORY_LABELS,
    LATENCY_BUCKETS_MS,
    RCODE_BUCKETS,
    RCODE_ERROR,
    RCODE_TIMEOUT,
    RECORD_FIELDS,
    Category,
    Outcome,
)

__all__ = [
    "StatsAggregator",
    "RecordLog",
    "SeriesWindow",
    "percentile_from_histogram",
    "DOMAIN_LATENCY_BUCKETS_MS",
    "MIN_VERDICT_SAMPLE",
    "SERIES_SECONDS",
]

#: How many one-second buckets the dashboard's rolling chart can show (5 minutes).
SERIES_SECONDS = 300

#: Window over which the headline latency percentiles are computed.
LATENCY_WINDOW_S = 60

#: Below this many completed queries the verdict stays ``unknown``.  Any verdict
#: drawn from a handful of packets is noise dressed up as analysis.
MIN_VERDICT_SAMPLE = 200

#: A filter that blocks less than this share of known-bad traffic is described as
#: ``passthrough`` rather than as leaking: the policy is not being enforced, and
#: that is a different (and more actionable) finding than a partially complete
#: blocklist.  Not zero, because a filter that only intercepts one query type can
#: still block a token few names while letting the traffic through.
PASSTHROUGH_MAX_BLOCK_RATIO = 0.20

#: Coarse buckets for *per-domain* latency.  A per-domain histogram has to exist
#: for tens of thousands of domains at once, so it gets 8 buckets instead of 19.
#: Per-category and per-window percentiles use the fine list from ``spec``.
DOMAIN_LATENCY_BUCKETS_MS: tuple[float, ...] = (1.0, 5.0, 20.0, 50.0, 100.0, 250.0, 1000.0, math.inf)

#: Hard cap on how many distinct domains get their own latency histogram.  Past
#: this we keep counting the domain but stop tracking its latency, and say so, so
#: memory cannot run away on a multi-hour soak against a top-1M list.
MAX_TRACKED_DOMAINS = 100_000


def percentile_from_histogram(histogram: Sequence[int], buckets: Sequence[float], pct: float) -> float:
    """Estimate a percentile from a bucketed histogram.

    Returns the upper bound of the bucket containing the requested percentile,
    which is why the reported value is a slight over-estimate.  Returns 0.0 for an
    empty histogram -- callers distinguish "no data" from "instant" themselves.
    """
    total = sum(histogram)
    if total <= 0:
        return 0.0
    if pct <= 0:
        return 0.0
    target = total * (pct / 100.0)
    running = 0
    for index, count in enumerate(histogram):
        running += count
        if running >= target:
            value = float(buckets[index])
            if math.isinf(value):
                # An overflow bucket is a *floor* ("at least this slow"), and
                # reporting infinity would emit invalid JSON and blank the
                # dashboard.  Report the boundary below it instead.
                return float(buckets[index - 1]) if index else 0.0
            return value
    last = float(buckets[-1])
    return float(buckets[-2]) if math.isinf(last) and len(buckets) > 1 else last


def _bucket_index(value: float, buckets: Sequence[float]) -> int:
    for index, upper in enumerate(buckets):
        if value <= upper:
            return index
    return len(buckets) - 1


@dataclass
class SeriesWindow:
    """One second of traffic, as rendered on the rolling chart."""

    t: int
    sent: int = 0
    recv: int = 0
    timeout: int = 0
    error: int = 0
    fp: int = 0
    fn: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    latency_hist: list[int] = field(default_factory=lambda: [0] * len(LATENCY_BUCKETS_MS))
    latency_sum: float = 0.0
    latency_count: int = 0
    latency_min: float = math.inf
    latency_max: float = 0.0

    def as_dict(self) -> dict:
        p95 = percentile_from_histogram(self.latency_hist, LATENCY_BUCKETS_MS, 95.0)
        return {
            "t": self.t,
            "sent": self.sent,
            "recv": self.recv,
            "timeout": self.timeout,
            "fp": self.fp,
            "fn": self.fn,
            "p95": round(p95, 3),
        }


@dataclass
class _DomainStat:
    """Per-domain rollup for the top-domains table."""

    count: int = 0
    category: str = ""
    outcome: str = ""
    last_seen: float = 0.0
    hist: list[int] | None = None
    tracked: bool = True

    def observe(self, category: str, outcome: str, latency_ms: float, now: float, track: bool) -> None:
        self.count += 1
        self.category = category
        self.outcome = outcome
        self.last_seen = now
        if not self.tracked:
            return
        if not track:
            self.tracked = False
            self.hist = None
            return
        if self.hist is None:
            self.hist = [0] * len(DOMAIN_LATENCY_BUCKETS_MS)
        self.hist[_bucket_index(latency_ms, DOMAIN_LATENCY_BUCKETS_MS)] += 1

    def p95(self, fallback: float) -> float:
        if self.hist is None:
            return round(fallback, 3)
        return round(percentile_from_histogram(self.hist, DOMAIN_LATENCY_BUCKETS_MS, 95.0), 3)


@dataclass
class _CategoryStat:
    sent: int = 0
    blocked: int = 0
    allowed: int = 0
    fp: int = 0
    fn: int = 0
    timeout: int = 0
    error: int = 0
    nxdomain: int = 0
    latency_hist: list[int] = field(default_factory=lambda: [0] * len(LATENCY_BUCKETS_MS))

    def as_dict(self, category: str, expect: str | None = None) -> dict:
        completed = self.blocked + self.allowed + self.fp + self.fn + self.timeout + self.error + self.nxdomain
        failures = self.fp + self.fn + self.timeout + self.error
        pass_rate = 1.0 if completed <= 0 else max(0.0, 1.0 - failures / completed)
        return {
            "category": category,
            "label": CATEGORY_LABELS.get(category, category),
            "expect": expect or CATEGORY_EXPECTED.get(category, "unknown"),
            "sent": self.sent,
            "blocked": self.blocked,
            "allowed": self.allowed,
            "fp": self.fp,
            "fn": self.fn,
            "timeout": self.timeout,
            # Every outcome needs a column, or a category whose queries were all
            # NXDOMAIN renders as "sent: 627" with nothing beside it and reads like
            # the traffic vanished.  This is how borderline looks under a filter
            # that blocks it, and the operator should see that.
            "nxdomain": self.nxdomain,
            "p95": round(percentile_from_histogram(self.latency_hist, LATENCY_BUCKETS_MS, 95.0), 3),
            "pass_rate": round(pass_rate, 4),
        }


@dataclass
class _ClientStat:
    count: int = 0
    fp: int = 0
    fn: int = 0
    timeout: int = 0
    last_seen: float = 0.0


@dataclass
class _Finding:
    """A false positive or false negative, keyed for counting repeats."""

    qname: str
    client_ip: str
    category: str
    detail: str
    count: int = 1
    last_seen: float = 0.0


class StatsAggregator:
    """Thread-safe rollup of everything the engine observes.

    Locked rather than single-threaded because ``threads > 1`` shards the send
    loops, and because the web server reads snapshots from another thread.  The
    lock is held for a handful of dict updates per query, which at 10k qps is not
    where the time goes.
    """

    def __init__(
        self,
        *,
        series_seconds: int = SERIES_SECONDS,
        max_domains: int = MAX_TRACKED_DOMAINS,
        top_n: int = 25,
    ) -> None:
        self._lock = threading.Lock()
        self._series_seconds = series_seconds
        self._max_domains = max_domains
        self._top_n = top_n

        self._series: deque[SeriesWindow] = deque(maxlen=series_seconds)
        self._current: SeriesWindow | None = None

        self.sent = 0
        self.received = 0
        self.timeouts = 0
        self.errors = 0
        self.dropped = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.in_flight = 0

        self._outcomes: Counter[str] = Counter()
        self._rcodes: Counter[str] = Counter()
        self._categories: dict[str, _CategoryStat] = {c.value: _CategoryStat() for c in Category}
        self._domains: dict[str, _DomainStat] = {}
        self._clients: dict[str, _ClientStat] = {}
        self._domains_tracked = 0
        self._fp: dict[tuple[str, str], _Finding] = {}
        self._fn: dict[tuple[str, str], _Finding] = {}
        #: What each category is expected to do for the target under test.  Starts as
        #: the global default and is replaced per target via :meth:`set_expectations`.
        self._expect: dict[str, str] = dict(CATEGORY_EXPECTED)

        self._run: dict = {
            "state": "idle",
            "started_at": 0.0,
            "ended_at": 0.0,
            "server": "",
            "mode": "personas",
            "personas": 0,
            "source_ips": 0,
            "target_qps": 0.0,
            "seed": 0,
            "note": "",
        }
        #: Set when the engine stops, so ``elapsed_s`` freezes instead of growing.
        self._frozen_elapsed: float | None = None

    # -- run metadata -------------------------------------------------------

    def set_run(self, **fields) -> None:
        with self._lock:
            self._run.update(fields)

    def set_expectations(self, overrides: dict[str, str] | None) -> None:
        """Apply a target's per-category expectations on top of the defaults."""
        with self._lock:
            self._expect = {**CATEGORY_EXPECTED, **(overrides or {})}

    def set_state(self, state: str, note: str = "") -> None:
        with self._lock:
            previous = self._run.get("state")
            self._run["state"] = state
            if note:
                self._run["note"] = note
            if state == "running" and previous != "running":
                self._run["started_at"] = time.time()
                self._frozen_elapsed = None
            if state in ("stopped", "idle"):
                self._frozen_elapsed = self.elapsed_locked()

    def elapsed_locked(self) -> float:
        started = self._run.get("started_at") or 0.0
        if not started:
            return 0.0
        return (self._run.get("ended_at") or time.time()) - started

    def reset(self) -> None:
        """Clear all counters.  Used between runs so one run's findings cannot
        leak into the next run's verdict."""
        with self._lock:
            self._series.clear()
            self._current = None
            self.sent = self.received = self.timeouts = self.errors = 0
            self.dropped = 0
            self.bytes_sent = self.bytes_received = self.in_flight = 0
            self._outcomes.clear()
            self._rcodes.clear()
            self._categories = {c.value: _CategoryStat() for c in Category}
            self._domains.clear()
            self._clients.clear()
            self._domains_tracked = 0
            self._fp.clear()
            self._fn.clear()
            self._frozen_elapsed = None

    # -- ingest -------------------------------------------------------------

    def _roll(self, now: float) -> SeriesWindow:
        """Return the bucket for ``now``, pushing completed buckets onto the
        series deque.  Buckets are keyed on integer seconds so the chart's x axis
        is regular even if the send loop stutters."""
        current_second = int(now)
        if self._current is None:
            self._current = SeriesWindow(t=current_second)
            return self._current
        if current_second == self._current.t:
            return self._current
        # More than a second may have elapsed (a stalled loop, or a paused run).
        # Emitting empty buckets keeps the time axis honest instead of drawing a
        # gap as if the two neighbouring seconds were adjacent.
        self._series.append(self._current)
        gap = current_second - self._current.t
        for offset in range(1, gap):
            self._series.append(SeriesWindow(t=self._current.t + offset))
        self._current = SeriesWindow(t=current_second)
        return self._current

    def on_send(
        self,
        count: int = 1,
        bytes_sent: int = 0,
        now: float | None = None,
        *,
        inflight: bool = True,
    ) -> None:
        """Count queries as they leave the NIC.

        Tracked separately from results so the sent rate is real even while tens
        of thousands of responses are still outstanding -- which is exactly the
        window in which an appliance starts dropping.

        ``inflight=False`` is for the benchmark path, where packets are built but
        never sent: nothing will ever arrive to decrement the counter, so counting
        them as outstanding would leave a permanent fake backlog on the dashboard.
        """
        now = now if now is not None else time.time()
        with self._lock:
            bucket = self._roll(now)
            bucket.sent += count
            bucket.bytes_sent += bytes_sent
            self.sent += count
            self.bytes_sent += bytes_sent
            if inflight:
                self.in_flight += count

    def on_result(
        self,
        *,
        qname: str,
        client_ip: str,
        category: str,
        qtype: str,
        rcode: str,
        outcome: str,
        latency_ms: float,
        bytes_received: int = 0,
        answer_ip: str = "",
        now: float | None = None,
    ) -> None:
        """Fold one completed query into every rollup that needs it."""
        now = now if now is not None else time.time()
        with self._lock:
            bucket = self._roll(now)
            bucket.bytes_received += bytes_received
            self.bytes_received += bytes_received
            if self.in_flight > 0:
                self.in_flight -= 1

            is_timeout = outcome == Outcome.TIMEOUT.value
            is_error = outcome == Outcome.ERROR.value
            # ``received`` counts answers, full stop.  A timeout is a completed
            # query but it is NOT a received one, and letting it inflate the
            # received rate would hide exactly the failure the operator is
            # looking for.  Timeouts and errors get their own buckets.
            if is_timeout:
                bucket.timeout += 1
                self.timeouts += 1
            elif is_error:
                bucket.error += 1
                self.errors += 1
            else:
                bucket.recv += 1
                self.received += 1

            self._outcomes[outcome] += 1
            self._rcodes[rcode] += 1

            if not is_timeout:
                bucket.latency_hist[_bucket_index(latency_ms, LATENCY_BUCKETS_MS)] += 1
                bucket.latency_sum += latency_ms
                bucket.latency_count += 1
                if latency_ms < bucket.latency_min:
                    bucket.latency_min = latency_ms
                if latency_ms > bucket.latency_max:
                    bucket.latency_max = latency_ms

            stat = self._categories.get(category)
            if stat is None:
                stat = self._categories[category] = _CategoryStat()
            stat.sent += 1
            if not is_timeout:
                stat.latency_hist[_bucket_index(latency_ms, LATENCY_BUCKETS_MS)] += 1
            if outcome == Outcome.BLOCKED.value:
                stat.blocked += 1
            elif outcome == Outcome.ALLOWED.value:
                stat.allowed += 1
            elif outcome == Outcome.FALSE_POSITIVE.value:
                stat.fp += 1
                bucket.fp += 1
            elif outcome == Outcome.FALSE_NEGATIVE.value:
                stat.fn += 1
                bucket.fn += 1
            elif outcome == Outcome.TIMEOUT.value:
                stat.timeout += 1
            elif outcome == Outcome.ERROR.value:
                stat.error += 1
            elif outcome == Outcome.NXDOMAIN.value:
                stat.nxdomain += 1

            self._observe_domain(qname, category, outcome, latency_ms, now)
            self._observe_client(client_ip, outcome, now)
            if outcome == Outcome.FALSE_POSITIVE.value:
                self._remember(self._fp, qname, client_ip, category, rcode, now)
            elif outcome == Outcome.FALSE_NEGATIVE.value:
                self._remember(self._fn, qname, client_ip, category, answer_ip or "resolved", now)

    def _observe_domain(self, qname: str, category: str, outcome: str, latency_ms: float, now: float) -> None:
        stat = self._domains.get(qname)
        if stat is None:
            track = self._domains_tracked < self._max_domains
            if track:
                self._domains_tracked += 1
            stat = _DomainStat(tracked=track, hist=[0] * len(DOMAIN_LATENCY_BUCKETS_MS) if track else None)
            self._domains[qname] = stat
        stat.observe(category, outcome, latency_ms, now, True)

    def _observe_client(self, client_ip: str, outcome: str, now: float) -> None:
        stat = self._clients.get(client_ip)
        if stat is None:
            stat = self._clients[client_ip] = _ClientStat()
        stat.count += 1
        stat.last_seen = now
        if outcome == Outcome.FALSE_POSITIVE.value:
            stat.fp += 1
        elif outcome == Outcome.FALSE_NEGATIVE.value:
            stat.fn += 1
        elif outcome == Outcome.TIMEOUT.value:
            stat.timeout += 1

    @staticmethod
    def _remember(
        store: dict[tuple[str, str], _Finding],
        qname: str,
        client_ip: str,
        category: str,
        detail: str,
        now: float,
    ) -> None:
        key = (qname, client_ip)
        existing = store.get(key)
        if existing is None:
            store[key] = _Finding(qname=qname, client_ip=client_ip, category=category, detail=detail, last_seen=now)
        else:
            existing.count += 1
            existing.detail = detail
            existing.last_seen = now

    def on_drop(self, count: int = 1) -> None:
        """Queries the generator refused to send because the in-flight budget was full.

        Deliberately NOT counted as errors.  An error is a query that was sent and
        failed; a drop was never offered to the appliance, so folding the two together
        makes ``error_pct`` exceed 100% -- which is how the first benchmark run reported
        "128.5% loss" and made a perfectly healthy generator look broken.  Drops are a
        property of the *sender*, and they get their own counter and their own rate.
        """
        with self._lock:
            self.dropped += count
            if self.in_flight > 0:
                self.in_flight = max(0, self.in_flight - count)

    # -- reading ------------------------------------------------------------

    def snapshot(self) -> dict:
        """Build the dashboard payload.  See the schema comment in ``spec.py``."""
        with self._lock:
            return self._snapshot_locked()

    def _snapshot_locked(self) -> dict:
        series = list(self._series)
        if self._current is not None:
            series.append(self._current)

        totals_completed = self.received + self.timeouts + self.errors
        recent = series[-5:] if series else []
        window = series[-LATENCY_WINDOW_S:]

        hist = [0] * len(LATENCY_BUCKETS_MS)
        latency_sum = 0.0
        latency_count = 0
        latency_min = math.inf
        latency_max = 0.0
        for bucket in window:
            for index, count in enumerate(bucket.latency_hist):
                hist[index] += count
            latency_sum += bucket.latency_sum
            latency_count += bucket.latency_count
            if bucket.latency_min < latency_min:
                latency_min = bucket.latency_min
            if bucket.latency_max > latency_max:
                latency_max = bucket.latency_max

        p95_window = percentile_from_histogram(hist, LATENCY_BUCKETS_MS, 95.0)
        last = series[-1] if series else None
        recv_recent = sum(b.recv for b in recent)
        sent_recent = sum(b.sent for b in recent) or 1
        # Errors are a share of everything sent, not of what came back: a query
        # that timed out is exactly the failure this number exists to expose.
        error_recent = sum(b.timeout + b.error for b in recent)

        run = dict(self._run)
        elapsed = self._frozen_elapsed if self._frozen_elapsed is not None else self.elapsed_locked()
        run["elapsed_s"] = round(elapsed, 3)
        run["state"] = run.get("state", "idle")

        # Percentiles over the whole run as well as the window, because a run that
        # degraded halfway through looks fine in a 60s window but not in total.
        all_hist = [0] * len(LATENCY_BUCKETS_MS)
        all_sum = 0.0
        all_count = 0
        all_min = math.inf
        all_max = 0.0
        for bucket in series:
            for index, count in enumerate(bucket.latency_hist):
                all_hist[index] += count
            all_sum += bucket.latency_sum
            all_count += bucket.latency_count
            if bucket.latency_min < all_min:
                all_min = bucket.latency_min
            if bucket.latency_max > all_max:
                all_max = bucket.latency_max

        latency = {
            "p50": round(percentile_from_histogram(hist, LATENCY_BUCKETS_MS, 50.0), 3),
            "p95": round(p95_window, 3),
            "p99": round(percentile_from_histogram(hist, LATENCY_BUCKETS_MS, 99.0), 3),
            "min": round(all_min, 3) if all_count else 0.0,
            "max": round(all_max, 3) if all_count else 0.0,
            "avg": round(all_sum / all_count, 3) if all_count else 0.0,
            "run_p50": round(percentile_from_histogram(all_hist, LATENCY_BUCKETS_MS, 50.0), 3),
            "run_p95": round(percentile_from_histogram(all_hist, LATENCY_BUCKETS_MS, 95.0), 3),
            "run_p99": round(percentile_from_histogram(all_hist, LATENCY_BUCKETS_MS, 99.0), 3),
            "samples": all_count,
        }

        outcomes = {o.value: self._outcomes.get(o.value, 0) for o in Outcome}
        rcodes = {name: self._rcodes.get(name, 0) for name in RCODE_BUCKETS}
        for name, value in self._rcodes.items():
            if name not in rcodes:
                rcodes[name] = value

        top_domains = []
        for qname, stat in sorted(self._domains.items(), key=lambda kv: kv[1].count, reverse=True)[: self._top_n]:
            top_domains.append(
                {
                    "qname": qname,
                    "count": stat.count,
                    "category": stat.category,
                    "outcome": stat.outcome,
                    "p95": stat.p95(p95_window),
                }
            )

        top_clients = []
        for client_ip, stat in sorted(self._clients.items(), key=lambda kv: kv[1].count, reverse=True)[: self._top_n]:
            top_clients.append(
                {
                    "client_ip": client_ip,
                    "count": stat.count,
                    "fp": stat.fp,
                    "fn": stat.fn,
                    "timeout": stat.timeout,
                }
            )

        return {
            "run": run,
            "totals": {
                "sent": self.sent,
                "received": self.received,
                "timeouts": self.timeouts,
                "errors": self.errors,
                "dropped": self.dropped,
                "intended": self.sent + self.dropped,
                "completed": totals_completed,
                "bytes_sent": self.bytes_sent,
                "bytes_received": self.bytes_received,
                "unique_clients": len(self._clients),
                "unique_domains": len(self._domains),
                "domains_tracked": self._domains_tracked,
            },
            "rates": {
                "qps_sent": float(last.sent) if last else 0.0,
                "qps_recv": float(last.recv) if last else 0.0,
                "qps_sent_avg": round(sent_recent / len(recent), 2) if recent else 0.0,
                "qps_recv_avg": round(recv_recent / len(recent), 2) if recent else 0.0,
                "qps_completed_avg": round((recv_recent + error_recent) / len(recent), 2) if recent else 0.0,
                # Two rates, both bounded by construction.
                #
                # ``error_pct`` is the run's loss: failures over queries actually
                # sent.  It must divide by the *cumulative* send count, because a
                # timeout lands up to ``timeout_s`` after the send it belongs to, so a
                # short window can accumulate more errors than it accumulated sends
                # and report a loss above 100%.  That is exactly how the first
                # benchmark run reported "131.7% loss" while behaving normally.
                #
                # ``window_error_pct`` is the near-real-time indicator: the share of
                # recent *outcomes* that were failures.  Bounded, and it responds to a
                # problem immediately instead of being diluted by the run's history.
                "error_pct": round(100.0 * (self.timeouts + self.errors) / max(self.sent, 1), 3),
                "window_error_pct": round(
                    100.0 * error_recent / max(recv_recent + error_recent, 1), 3
                ),
                # Share of *intended* traffic the sender never managed to offer.  A
                # nonzero value means the generator, not the appliance, is the
                # bottleneck, and any conclusion about the appliance is suspect.
                "dropped_pct": round(
                    100.0 * self.dropped / max(self.sent + self.dropped, 1), 3
                ),
                "in_flight": self.in_flight,
            },
            "latency_ms": latency,
            "outcomes": outcomes,
            "rcodes": rcodes,
            "series": [b.as_dict() for b in series[-self._series_seconds:]],
            "by_category": [
                self._categories[c.value].as_dict(c.value, self._expect.get(c.value)) for c in Category
            ],
            "top_domains": top_domains,
            "top_clients": top_clients,
            "false_positives": self._findings(self._fp, "rcode"),
            "false_negatives": self._findings(self._fn, "answer"),
            "verdict": self._verdict_locked(rcodes, outcomes),
        }

    def _findings(self, store: dict[tuple[str, str], _Finding], detail_key: str) -> list[dict]:
        rows = []
        for finding in sorted(store.values(), key=lambda f: f.count, reverse=True)[: self._top_n]:
            row = {
                "qname": finding.qname,
                "client_ip": finding.client_ip,
                "category": finding.category,
                "count": finding.count,
                "last_seen": finding.last_seen,
            }
            row[detail_key] = finding.detail
            rows.append(row)
        return rows

    # -- verdict ------------------------------------------------------------

    def _verdict_locked(self, rcodes: dict[str, int], outcomes: dict[str, int]) -> dict:
        """Decide what the evidence supports.

        Ordering matters.  "Nothing answered" outranks everything -- there is no
        point reporting a false-positive rate against a resolver that never spoke.
        Then a resolver that answers but never blocks is ``passthrough``, which is
        the single most common real-world finding: the filter is deployed but the
        policy never took effect.
        """
        state = self._run.get("state", "idle")
        if state == "idle" and self.sent == 0:
            return {"status": "idle", "note": "No run in progress. Press Start, or launch with --qps."}

        completed = self.received + self.timeouts + self.errors
        if completed < MIN_VERDICT_SAMPLE:
            return {
                "status": "unknown",
                "note": f"Only {completed} queries completed; {MIN_VERDICT_SAMPLE} are needed before any conclusion is trustworthy.",
            }

        answered = rcodes.get("NOERROR", 0) + rcodes.get("NXDOMAIN", 0)
        # Both rates are shares of queries actually *sent*.  Drops are excluded
        # because they were never offered to the appliance; including them is how
        # "loss" climbed past 100% in the first benchmark run.
        loss_pct = 100.0 * (self.timeouts + self.errors) / max(self.sent, 1)
        servfail_pct = 100.0 * rcodes.get("SERVFAIL", 0) / max(completed, 1)
        drop_pct = 100.0 * self.dropped / max(self.sent + self.dropped, 1)
        caveat = ""
        if drop_pct >= 1.0:
            # The tool must not let its own backpressure be mistaken for the
            # appliance's.  Whatever the verdict, this invalidates a claim about
            # capacity, so it is appended to every note rather than buried.
            caveat = (
                f"  [Caution: the generator itself dropped {drop_pct:.0f}% of intended "
                f"queries ({self.dropped:,}) because the in-flight budget was full, so the "
                f"appliance was never offered the full requested rate. Reduce --qps or raise "
                f"--max-inflight before drawing a conclusion about capacity.]"
            )

        if answered == 0:
            return {
                "status": "degraded",
                "note": (
                    f"The resolver answered none of {completed} queries "
                    f"({loss_pct:.1f}% loss). Check the target address and that the "
                    f"appliance is listening before drawing any conclusion."
                    + caveat
                ),
            }

        fp = outcomes.get(Outcome.FALSE_POSITIVE.value, 0)
        fn = outcomes.get(Outcome.FALSE_NEGATIVE.value, 0)
        allowed = outcomes.get(Outcome.ALLOWED.value, 0)
        blocked = outcomes.get(Outcome.BLOCKED.value, 0)
        # ``fn`` and ``blocked`` are read again in the passthrough branch below, so
        # they must be defined before it.

        # Passthrough is decided on a *rate*, not on a zero.  Requiring that nothing
        # at all was blocked sounds strict but is brittle: an appliance that blocks
        # 12% of known-bad names (say, only the A-record path) is not filtering, and
        # should still read as passthrough rather than as a pile of individual leaks.
        # "Almost nothing is being blocked" is the finding that changes what the
        # operator does next.
        block_sent = sum(
            stat.sent for category, stat in self._categories.items()
            if self._expect.get(category) == "block"
        )
        block_blocked = sum(
            stat.blocked for category, stat in self._categories.items()
            if self._expect.get(category) == "block"
        )
        block_ratio = (block_blocked / block_sent) if block_sent else 1.0
        if block_sent >= MIN_VERDICT_SAMPLE and block_ratio < PASSTHROUGH_MAX_BLOCK_RATIO:
            return {
                "status": "passthrough",
                "note": (
                    f"Not filtering. {block_sent} queries went to domains that should be blocked and only "
                    f"{block_blocked} ({100.0 * block_ratio:.0f}%) were blocked; {fn} resolved to real "
                    f"addresses. The resolver is answering, so the traffic is reaching it -- the policy "
                    f"simply is not being applied."
                    + caveat
                ),
            }

        if loss_pct > 5.0 or servfail_pct > 5.0:
            return {
                "status": "degraded",
                "note": (
                    f"Answering but failing under load: {loss_pct:.1f}% never answered, "
                    f"{servfail_pct:.1f}% SERVFAIL, p95 {self._p95_locked():.0f}ms. "
                    f"This is a capacity or upstream problem, not a policy one."
                    + caveat
                ),
            }

        if fp:
            return {
                "status": "degraded",
                "note": (
                    f"Blocking legitimate traffic. {fp} queries for allow-listed domains were "
                    f"refused, NXDOMAINed or dropped, affecting {len(self._fp)} distinct "
                    f"name/client pairs. See the false-positive table -- this is what users report as outages."
                    + caveat
                ),
            }

        if fn:
            return {
                "status": "degraded",
                "note": (
                    f"Leaking known-bad traffic. {fn} queries to block-listed domains resolved to real "
                    f"addresses across {len(self._fn)} names. The filter is active but its lists are incomplete."
                    + caveat
                ),
            }

        if not any(expect == "block" for expect in self._expect.values()):
            # Nothing is expected to be blocked for this target (an unfiltered
            # baseline), so "filtering correctly" would be a claim the run never tested.
            return {
                "status": "baseline",
                "note": (
                    f"No categories are expected to be blocked for this target, so this run measures "
                    f"resolver behaviour only: {allowed} queries resolved, {loss_pct:.1f}% loss "
                    f"(p95 {self._p95_locked():.0f}ms)."
                    + caveat
                ),
            }

        return {
            "status": "filtering",
            "note": (
                f"Filtering correctly. {blocked} block-listed queries were refused and {allowed} legitimate "
                f"queries resolved, with no false positives and {loss_pct:.1f}% loss "
                f"(p95 {self._p95_locked():.0f}ms)."
                + caveat
            ),
        }

    def _p95_locked(self) -> float:
        hist = [0] * len(LATENCY_BUCKETS_MS)
        for bucket in list(self._series)[-LATENCY_WINDOW_S:]:
            for index, count in enumerate(bucket.latency_hist):
                hist[index] += count
        return percentile_from_histogram(hist, LATENCY_BUCKETS_MS, 95.0)


# ---------------------------------------------------------------------------
# Record log
# ---------------------------------------------------------------------------


#: CSV values arrive as text.  These maps restore the types the JSONL path would
#: have given, so both formats produce interchangeable dictionaries -- an operator
#: should not get numbers as strings from one export and numbers from another.
_CSV_TYPES: dict[str, type] = {
    "ts": float,
    "persona_id": int,
    "latency_ms": float,
    "bytes_sent": int,
    "bytes_received": int,
}
_CSV_DEFAULT: dict[str, object] = {
    "ts": 0.0,
    "persona_id": 0,
    "latency_ms": 0.0,
    "bytes_sent": 0,
    "bytes_received": 0,
}


class RecordLog:
    """Append-only per-query record log.

    Every run keeps the raw evidence on disk, because "what traffic did I actually
    send" is a question the dashboard's aggregates cannot answer and a capture
    file cannot answer either (it has no notion of which persona or category a
    packet belonged to).  Writes are buffered and flushed in batches: at 10k qps a
    synchronous write per record would dominate the event loop's time budget.

    Disk sizing, so it is not a surprise: a record is roughly 140-200 bytes, so a
    60-second run at 10,000 qps is about 100 MB.  Use ``sample`` to keep a
    representative fraction instead, and ``max_bytes`` as a hard stop.
    """

    def __init__(
        self,
        path: str | os.PathLike,
        *,
        fmt: str = "jsonl",
        sample: float = 1.0,
        max_bytes: int = 2 * 1024**3,
        flush_every: int = 4096,
        buffer_bytes: int = 1 * 1024**2,
    ) -> None:
        if fmt not in ("jsonl", "csv"):
            raise ValueError(f"unsupported record format {fmt!r}; use 'jsonl' or 'csv'")
        if not 0.0 <= sample <= 1.0:
            raise ValueError(f"sample must be between 0.0 and 1.0, got {sample}")
        self.path = str(path)
        self.fmt = fmt
        self.sample = float(sample)
        self.max_bytes = int(max_bytes)
        self._flush_every = int(flush_every)
        self._buffer_bytes = int(buffer_bytes)
        self._buffer: list[str] = []
        self._handle = None
        self.count = 0
        self.written = 0
        self.truncated = False
        self._bytes = 0

    def open(self) -> "RecordLog":
        directory = os.path.dirname(os.path.abspath(self.path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._handle = open(self.path, "w", encoding="utf-8", newline="")
        if self.fmt == "csv":
            self._handle.write(",".join(RECORD_FIELDS) + "\n")
            self._bytes = len(RECORD_FIELDS) + 1
        return self

    def write(self, record) -> None:
        """Record one query.  ``record`` is a ``spec.QueryRecord`` or the tuple
        form the engine uses in its hot path."""
        if self._handle is None or self.truncated:
            return
        self.count += 1
        if self.sample < 1.0 and (self.count % max(1, round(1.0 / self.sample))) != 0:
            return
        if self.fmt == "csv":
            from .spec import QueryRecord

            values = record if isinstance(record, tuple) else record.as_tuple()
            line = ",".join(_csv_cell(v) for v in values)
        else:
            line = json.dumps(record.as_dict() if hasattr(record, "as_dict") else _tuple_to_dict(record), separators=(",", ":"))
        self._buffer.append(line)
        self.written += 1
        self._bytes += len(line) + 1
        if len(self._buffer) >= self._flush_every or sum(len(x) for x in self._buffer[-16:]) >= self._buffer_bytes:
            self.flush()

    def flush(self) -> None:
        if self._handle is None or not self._buffer:
            return
        if self._bytes >= self.max_bytes:
            self.truncated = True
            self._buffer.clear()
            note = "record log stopped: max_bytes reached; aggregates remain complete"
            # Comment syntax per format, so the truncated file is still parseable.
            self._handle.write(f"# {note}\n" if self.fmt == "csv" else json.dumps({"_note": note}) + "\n")
            self._handle.flush()
            return
        self._handle.write("\n".join(self._buffer) + "\n")
        self._buffer.clear()
        self._handle.flush()

    def close(self) -> None:
        if self._handle is None:
            return
        self.flush()
        self._handle.close()
        self._handle = None

    def __enter__(self) -> "RecordLog":
        return self.open()

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def exists(self) -> bool:
        return os.path.exists(self.path)

    def size_bytes(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def read_records(self, limit: int | None = None) -> Iterable[dict]:
        """Yield records back as dicts, for the export endpoints.

        Handles both on-disk formats.  A CSV log has to be parsed as CSV -- reading
        it line-by-line as JSON silently skipped every row and made the JSON export
        of a CSV run come back empty, which looks like "no traffic was sent"
        rather than like a bug.
        """
        if not self.exists:
            return
        if self.fmt == "csv":
            import csv

            with open(self.path, "r", encoding="utf-8", newline="") as handle:
                for index, row in enumerate(csv.DictReader(handle)):
                    if limit is not None and index >= limit:
                        return
                    yield {key: _CSV_TYPES.get(key, str)(value) if value != "" else _CSV_DEFAULT.get(key, "")
                           for key, value in row.items() if key}
            return
        with open(self.path, "r", encoding="utf-8") as handle:
            for index, line in enumerate(handle):
                if limit is not None and index >= limit:
                    return
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("{\"_note\""):
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def _tuple_to_dict(values: tuple) -> dict:
    return dict(zip(RECORD_FIELDS, values))


def _csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if any(ch in text for ch in (",", '"', "\n", "\r")):
        return '"' + text.replace('"', '""') + '"'
    return text
