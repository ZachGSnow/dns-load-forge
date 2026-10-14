"""Reduce a finished run to a handful of comparable numbers.

Comparing filters is the point of running the same seeded traffic at each one, so a
run is boiled down to the figures that answer "which one is better, and at what
cost": how much of the bad traffic it stopped, how much good traffic it harmed,
and how fast and reliably it answered.

Rates are computed over *answered* queries so a timeout does not masquerade as
either a block or a leak.
"""

from __future__ import annotations

import time
from typing import Iterable

from .spec import RunConfig

__all__ = ["summarise_run", "format_comparison"]


def _ratio(numerator: float, denominator: float) -> float | None:
    return round(numerator / denominator, 4) if denominator > 0 else None


def summarise_run(snapshot: dict, config: RunConfig, *, index: int = 0) -> dict:
    """One comparable record from a finished run's final stats snapshot."""
    totals = snapshot.get("totals", {})
    rates = snapshot.get("rates", {})
    latency = snapshot.get("latency_ms", {})
    verdict = snapshot.get("verdict", {})
    run = snapshot.get("run", {})
    categories = snapshot.get("by_category", [])

    blocked = leaked = allowed = harmed = 0
    for row in categories:
        if row.get("expect") == "block":
            blocked += row.get("blocked", 0)
            leaked += row.get("fn", 0)
        elif row.get("expect") == "allow":
            allowed += row.get("allowed", 0)
            harmed += row.get("fp", 0)

    elapsed = float(run.get("elapsed_s", 0.0)) or 0.0
    return {
        "index": index,
        "target": config.target_name or config.target,
        "server": config.target,
        "finished_at": time.time(),
        "seed": config.seed,
        "personas": config.personas,
        "target_qps": config.target_qps,
        "elapsed_s": round(elapsed, 1),
        "verdict": verdict.get("status", "unknown"),
        "note": verdict.get("note", ""),
        "sent": totals.get("sent", 0),
        "received": totals.get("received", 0),
        "timeouts": totals.get("timeouts", 0),
        "achieved_qps": round(totals.get("sent", 0) / elapsed, 1) if elapsed > 0 else 0.0,
        "error_pct": rates.get("error_pct", 0.0),
        "latency_ms": {
            "p50": latency.get("run_p50", latency.get("p50", 0.0)),
            "p95": latency.get("run_p95", latency.get("p95", 0.0)),
            "p99": latency.get("run_p99", latency.get("p99", 0.0)),
        },
        # Share of expected-block queries that were blocked.  None when the target
        # is not expected to block anything.
        "block_rate": _ratio(blocked, blocked + leaked),
        # Share of expected-allow queries that were wrongly blocked.
        "false_block_rate": _ratio(harmed, harmed + allowed),
        "blocked": blocked,
        "leaked": leaked,
        "false_positives": harmed,
        "by_category": [
            {
                key: row.get(key)
                for key in ("category", "label", "expect", "sent", "blocked", "allowed", "fp", "fn", "nxdomain", "timeout", "pass_rate")
            }
            for row in categories
            if row.get("sent")
        ],
    }


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{100.0 * value:.1f}%"


def format_comparison(summaries: Iterable[dict]) -> str:
    """A plain-text side-by-side table for the console."""
    rows = list(summaries)
    if not rows:
        return "  (no completed runs to compare)"
    headers = ("target", "verdict", "blocked", "leaked", "false block", "p50", "p95", "timeouts", "sent")
    body = [
        (
            r["target"],
            r["verdict"].upper(),
            _pct(r["block_rate"]),
            f"{r['leaked']:,}",
            _pct(r["false_block_rate"]),
            f"{r['latency_ms']['p50']:.0f}ms",
            f"{r['latency_ms']['p95']:.0f}ms",
            f"{r['error_pct']:.1f}%",
            f"{r['sent']:,}",
        )
        for r in rows
    ]
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *body)]
    lines = ["  " + "  ".join(str(h).ljust(w) for h, w in zip(headers, widths))]
    lines.append("  " + "  ".join("-" * w for w in widths))
    lines += ["  " + "  ".join(str(c).ljust(w) for c, w in zip(row, widths)) for row in body]
    return "\n".join(lines)
