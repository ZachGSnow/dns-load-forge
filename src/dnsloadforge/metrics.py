"""Prometheus metrics for the run in progress, at ``GET /metrics``.

A load test that runs for hours belongs on the same graphs as the appliance it
is testing: its CPU, its queue, its own counters.  The dashboard shows the run;
these let Prometheus (or anything that reads its text format) record it beside
everything else.

The counters are the current run's, so they start again from zero when a new
run starts, which Prometheus treats as a counter reset.  Latency is the last 60
seconds' percentiles, in seconds, Prometheus' base unit.
"""

from __future__ import annotations

from . import __version__

__all__ = ["CONTENT_TYPE", "render_metrics"]

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

_VERDICTS = ("idle", "unknown", "filtering", "baseline", "passthrough", "degraded")


def _label(value: object) -> str:
    """A label value, escaped as the text format requires."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _number(value: object) -> str:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "0"
    if number != number:  # NaN
        return "NaN"
    return str(int(number)) if number.is_integer() else repr(number)


class _Families:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def add(self, name: str, kind: str, help_text: str, samples: list[tuple[dict, object]]) -> None:
        self.lines.append(f"# HELP {name} {help_text}")
        self.lines.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            if labels:
                rendered = ",".join(f'{key}="{_label(val)}"' for key, val in labels.items())
                self.lines.append(f"{name}{{{rendered}}} {_number(value)}")
            else:
                self.lines.append(f"{name} {_number(value)}")


def render_metrics(snapshot: dict, *, running: bool, config=None) -> str:
    """The text exposition of ``snapshot`` (``StatsAggregator.snapshot()``)."""
    run = snapshot.get("run", {})
    totals = snapshot.get("totals", {})
    rates = snapshot.get("rates", {})
    latency = snapshot.get("latency_ms", {})
    out = _Families()

    info = {
        "version": __version__,
        "target": run.get("target_name") or run.get("server", ""),
        "endpoint": run.get("server", ""),
        "transport": run.get("transport", "udp"),
        "mode": run.get("mode", ""),
    }
    out.add("dnsloadforge_info", "gauge", "The tool and the target of the current run.", [(info, 1)])
    out.add("dnsloadforge_running", "gauge", "1 while a run is in progress.", [({}, 1 if running else 0)])
    out.add(
        "dnsloadforge_target_qps",
        "gauge",
        "The queries per second the run asks for.",
        [({}, run.get("target_qps", config.target_qps if config is not None else 0))],
    )
    out.add("dnsloadforge_elapsed_seconds", "gauge", "Seconds since the run started.", [({}, run.get("elapsed_s", 0))])
    for name, key, text in (
        ("dnsloadforge_queries_sent_total", "sent", "Queries sent in the current run."),
        ("dnsloadforge_responses_received_total", "received", "Answers received in the current run."),
        ("dnsloadforge_queries_timed_out_total", "timeouts", "Queries never answered in the current run."),
        ("dnsloadforge_queries_failed_total", "errors", "Queries that failed in the current run (socket or HTTP errors)."),
        ("dnsloadforge_queries_dropped_total", "dropped", "Queries the generator never sent: its in-flight budget was full."),
    ):
        out.add(name, "counter", text, [({}, totals.get(key, 0))])
    out.add(
        "dnsloadforge_outcomes_total",
        "counter",
        "Completed queries by how they were scored.",
        [({"outcome": outcome}, count) for outcome, count in (snapshot.get("outcomes") or {}).items()],
    )
    out.add(
        "dnsloadforge_rcodes_total",
        "counter",
        "Completed queries by response code (TIMEOUT and ERROR for those never answered).",
        [({"rcode": rcode}, count) for rcode, count in (snapshot.get("rcodes") or {}).items()],
    )
    out.add(
        "dnsloadforge_block_signals_total",
        "counter",
        "Blocked answers by how the block was signalled.",
        [({"signal": signal}, count) for signal, count in (snapshot.get("block_signals") or {}).items()],
    )
    out.add(
        "dnsloadforge_extended_dns_errors_total",
        "counter",
        "Answers carrying an Extended DNS Error (RFC 8914), by code.",
        [({"code": row.get("code"), "name": row.get("name", "")}, row.get("count", 0)) for row in snapshot.get("ede") or []],
    )
    out.add(
        "dnsloadforge_rate_qps",
        "gauge",
        "Queries per second in the last finished second.",
        [({"direction": "sent"}, rates.get("qps_sent", 0)), ({"direction": "received"}, rates.get("qps_recv", 0))],
    )
    out.add("dnsloadforge_in_flight", "gauge", "Queries sent and not yet answered.", [({}, rates.get("in_flight", 0))])
    out.add(
        "dnsloadforge_latency_seconds",
        "gauge",
        "Response latency percentiles over the last 60 seconds (each the upper bound of its histogram bucket).",
        [
            ({"quantile": quantile}, float(latency.get(key, 0) or 0) / 1000.0)
            for quantile, key in (("0.5", "p50"), ("0.95", "p95"), ("0.99", "p99"))
        ],
    )
    pool = snapshot.get("connections")
    if pool:
        out.add("dnsloadforge_connections_open", "gauge", "TCP, DoT or DoH connections open now.", [({}, pool.get("open", 0))])
        for name, key, text in (
            ("dnsloadforge_connections_opened_total", "opened", "Connections opened, replacements included."),
            ("dnsloadforge_connections_lost_total", "lost", "Connections closed with queries unanswered, or with an error."),
            ("dnsloadforge_connections_failed_total", "failed", "Connection attempts that failed."),
        ):
            out.add(name, "counter", text, [({}, pool.get(key, 0))])
    status = (snapshot.get("verdict") or {}).get("status", "idle")
    out.add(
        "dnsloadforge_verdict",
        "gauge",
        "The current verdict: 1 for the status it has, 0 for the rest.",
        [({"status": name}, 1 if name == status else 0) for name in _VERDICTS],
    )
    return "\n".join(out.lines) + "\n"
