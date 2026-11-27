"""A report of the session, as one HTML page that prints to PDF.

The dashboard is for watching a run; the report is what goes to whoever asked
for the test.  It is one self-contained page -- no scripts, no fonts, no images,
nothing fetched -- so it opens anywhere, can be attached to an email, and prints
cleanly from any browser (Print, then Save as PDF).  It shows the latest run in
full, and alongside it whatever else the session produced: the comparison
table, the capacity search, the deployment checks.

Every value from the network or the user is escaped, and the page is plain
ASCII, like the dashboard.
"""

from __future__ import annotations

import html
import time
from datetime import datetime

from . import __version__
from .compare import summarise_run
from .spec import CATEGORY_LABELS, TRANSPORT_LABELS

__all__ = ["render_report"]

VERDICT_TITLE = {
    "filtering": "Filtering correctly",
    "baseline": "Baseline",
    "passthrough": "Not filtering",
    "degraded": "Degraded",
    "unknown": "Not judged",
    "idle": "No run",
}

SIGNAL_LABELS = {
    "nxdomain": "NXDOMAIN: the name does not exist",
    "refused": "REFUSED: the query is refused",
    "sinkhole": "A sinkhole or block-page address",
    "nodata": "No records",
    "address": "An unlisted address, recognised by its Extended DNS Error",
    "servfail": "SERVFAIL",
    "other": "Another response code",
}

CHECK_ORDER = ("fail", "warn", "error", "pass", "info", "skip")

_STYLE = """
:root { color-scheme: light; --ink: #16181d; --muted: #5b6270; --line: #dfe2e8; --soft: #f4f5f8;
  --ok: #157f3b; --bad: #b42318; --warn: #a15c07; --info: #1d5fbf; }
* { box-sizing: border-box; }
body { margin: 0; color: var(--ink); background: #fff; font: 14px/1.5 system-ui, -apple-system, "Segoe UI",
  Roboto, Helvetica, Arial, sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 32px 28px 48px; }
h1 { font-size: 26px; margin: 4px 0 2px; }
h2 { font-size: 17px; margin: 0 0 10px; }
h3 { font-size: 13px; margin: 14px 0 6px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
p { margin: 6px 0; }
section { margin-top: 26px; }
.eyebrow { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
.mono, td.num, .figure b { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; }
.muted { color: var(--muted); }
.hint { background: var(--soft); border: 1px solid var(--line); border-radius: 8px; padding: 8px 12px;
  font-size: 12px; color: var(--muted); }
.verdict { border: 1px solid var(--line); border-left: 6px solid var(--muted); border-radius: 10px;
  padding: 14px 18px; background: var(--soft); }
.verdict.filtering { border-left-color: var(--ok); }
.verdict.degraded, .verdict.passthrough { border-left-color: var(--bad); }
.verdict.baseline { border-left-color: var(--info); }
.verdict h2 { margin: 0 0 4px; font-size: 20px; }
.figures { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
.figure { border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; }
.figure span { display: block; font-size: 12px; color: var(--muted); }
.figure b { font-size: 20px; }
dl.settings { display: grid; grid-template-columns: max-content 1fr; gap: 4px 18px; margin: 0; }
dl.settings dt { color: var(--muted); }
dl.settings dd { margin: 0; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 11.5px; color: var(--muted); font-weight: 600; background: var(--soft); }
td.num, th.num { text-align: right; white-space: nowrap; }
.name { word-break: break-all; }
.pill { display: inline-block; min-width: 54px; text-align: center; border-radius: 999px; padding: 1px 8px;
  font-size: 11px; font-weight: 700; text-transform: uppercase; border: 1px solid currentColor; }
.pill.pass, .pill.filtering { color: var(--ok); }
.pill.fail, .pill.degraded, .pill.passthrough { color: var(--bad); }
.pill.warn, .pill.generator { color: var(--warn); }
.pill.error { color: var(--bad); }
.pill.info, .pill.baseline { color: var(--info); }
.pill.skip, .pill.unknown, .pill.small, .pill.stopped { color: var(--muted); }
.bad { color: var(--bad); }
footer { margin-top: 36px; padding-top: 12px; border-top: 1px solid var(--line); font-size: 12px; color: var(--muted); }
@media (max-width: 720px) { .figures { grid-template-columns: repeat(2, 1fr); } }
@media print {
  main { max-width: none; padding: 0; }
  .no-print { display: none; }
  section { break-inside: avoid; }
  table { break-inside: auto; }
  tr { break-inside: avoid; }
  @page { margin: 16mm; }
}
"""


def _e(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _int(value: object) -> str:
    try:
        return f"{int(round(float(value))):,}"
    except (TypeError, ValueError):
        return "-"


def _pct(value: object, digits: int = 1) -> str:
    try:
        return f"{float(value):.{digits}f}%"
    except (TypeError, ValueError):
        return "-"


def _ratio(value: object) -> str:
    if value is None:
        return "-"
    try:
        return f"{100.0 * float(value):.1f}%"
    except (TypeError, ValueError):
        return "-"


def _ms(value: object) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "-"
    return f"{number:g} ms"


def _when(epoch: object) -> str:
    try:
        return datetime.fromtimestamp(float(epoch)).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OverflowError, OSError):
        return "-"


def _duration(seconds: object) -> str:
    try:
        total = int(round(float(seconds)))
    except (TypeError, ValueError):
        return "-"
    minutes, secs = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m {secs:02d}s" if hours else f"{minutes}m {secs:02d}s"


def _table(headers: list[str], rows: list[list[str]], numeric: frozenset[int] | set[int] = frozenset()) -> str:
    """Rows of already-escaped cells."""
    head = "".join(f'<th class="num">{h}</th>' if i in numeric else f"<th>{h}</th>" for i, h in enumerate(headers))
    body = []
    for row in rows:
        cells = []
        for index, cell in enumerate(row):
            if index in numeric:
                cells.append(f'<td class="num">{cell}</td>')
            else:
                cells.append(f"<td>{cell}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def _pill(status: str) -> str:
    return f'<span class="pill {_e(status)}">{_e(status)}</span>'


def _section(title: str, body: str) -> str:
    return f"<section><h2>{_e(title)}</h2>{body}</section>"


def _figures(summary: dict, snapshot: dict) -> str:
    latency = summary.get("latency_ms", {})
    totals = snapshot.get("totals", {})
    cells = [
        ("Blocked as expected", _ratio(summary.get("block_rate"))),
        ("Wrongly blocked", _ratio(summary.get("false_block_rate"))),
        ("Leaked block-listed names", _int(summary.get("leaked"))),
        ("Loss", _pct(summary.get("error_pct"))),
        ("p50 latency", _ms(latency.get("p50"))),
        ("p95 latency", _ms(latency.get("p95"))),
        ("p99 latency", _ms(latency.get("p99"))),
        ("Queries sent", _int(totals.get("sent"))),
    ]
    return '<div class="figures">' + "".join(
        f'<div class="figure"><span>{_e(label)}</span><b>{value}</b></div>' for label, value in cells
    ) + "</div>"


def _settings(config, snapshot: dict, lists: dict | None, achieved_qps: float | None) -> str:
    run = snapshot.get("run", {})
    elapsed = float(run.get("elapsed_s") or 0.0)
    rows = [
        ("Target", f"{_e(config.target_name or config.target)}"),
        ("Endpoint", f'<span class="mono">{_e(config.target)}</span>'),
        ("Transport", _e(TRANSPORT_LABELS.get(config.transport, config.transport))),
        ("Started", _e(_when(run.get("started_at")))),
        ("Ran for", _e(_duration(elapsed))),
        (
            "Rate",
            f"{_int(config.target_qps)} qps asked"
            + (f", {_int(achieved_qps)} qps achieved" if achieved_qps else ""),
        ),
        (
            "Simulated office",
            f"{_int(config.personas)} workers, {_e(config.mode)} mode, "
            f"{_int(len(config.source_ips) or 1)} source address(es)",
        ),
        ("Seed", _e(config.seed)),
    ]
    if lists:
        rows.append(
            ("Domain lists", f"{_int(lists.get('total'))} names, fetched {_e(_when(lists.get('fetched_at')))}")
        )
    body = "".join(f"<dt>{label}</dt><dd>{value}</dd>" for label, value in rows)
    return f'<dl class="settings">{body}</dl>'


def _categories(snapshot: dict) -> str:
    rows = []
    for row in snapshot.get("by_category", []):
        if not row.get("sent"):
            continue
        pass_rate = row.get("pass_rate")
        rows.append(
            [
                _e(row.get("label") or CATEGORY_LABELS.get(row.get("category", ""), row.get("category", ""))),
                _e(row.get("expect", "")),
                _int(row.get("sent")),
                _int(row.get("blocked")),
                _int(row.get("allowed")),
                f'<span class="bad">{_int(row.get("fp"))}</span>' if row.get("fp") else "0",
                f'<span class="bad">{_int(row.get("fn"))}</span>' if row.get("fn") else "0",
                _int(row.get("timeout")),
                _ms(row.get("p95")),
                _ratio(pass_rate) if pass_rate is not None else "-",
            ]
        )
    if not rows:
        return "<p class='muted'>No query completed.</p>"
    return _table(
        ["Category", "Expect", "Sent", "Blocked", "Allowed", "Wrongly blocked", "Leaked", "Timeouts", "p95", "Pass rate"],
        rows,
        numeric={2, 3, 4, 5, 6, 7, 8, 9},
    )


def _findings(rows: list[dict], detail_key: str, detail_title: str) -> str:
    if not rows:
        return "<p class='muted'>None.</p>"
    table_rows = [
        [
            f'<span class="mono name">{_e(row.get("qname"))}</span>',
            _e(CATEGORY_LABELS.get(row.get("category", ""), row.get("category", ""))),
            _e(row.get("qtype", "")),
            f'<span class="mono">{_e(row.get(detail_key, "") or "-")}</span>',
            _e(row.get("ede") or "-"),
            _int(row.get("count")),
        ]
        for row in rows[:25]
    ]
    return _table(["Name", "Category", "Type", detail_title, "Extended DNS Error", "Count"], table_rows, numeric={5})


def _signals(snapshot: dict) -> str:
    signals = snapshot.get("block_signals") or {}
    total = sum(int(v) for v in signals.values()) or 0
    parts = []
    if total:
        rows = [
            [_e(SIGNAL_LABELS.get(key, key)), _int(count), _pct(100.0 * int(count) / total)]
            for key, count in sorted(signals.items(), key=lambda kv: -int(kv[1]))
        ]
        parts.append(_table(["Blocked answers came back as", "Count", "Share"], rows, numeric={1, 2}))
    else:
        parts.append("<p class='muted'>Nothing was blocked.</p>")
    ede = snapshot.get("ede") or []
    if ede:
        parts.append("<h3>Extended DNS Errors</h3>")
        parts.append(
            "<p>" + ", ".join(f'<span class="mono">{_e(row.get("code"))} {_e(row.get("name"))}</span> '
                             f"({_int(row.get('count'))})" for row in ede) + "</p>"
        )
    nsid = snapshot.get("nsid") or []
    if nsid:
        parts.append("<h3>Answering servers (NSID)</h3>")
        parts.append("<p>" + ", ".join(f'<span class="mono">{_e(row.get("id"))}</span> ({_int(row.get("count"))})'
                                       for row in nsid) + "</p>")
    return "".join(parts)


def _comparison(history: list[dict]) -> str:
    rows = []
    for run in sorted(history, key=lambda r: float(r.get("finished_at") or 0), reverse=True)[:20]:
        latency = run.get("latency_ms") or {}
        rows.append(
            [
                _e(run.get("target")),
                _e(TRANSPORT_LABELS.get(run.get("transport", "udp"), run.get("transport", ""))),
                _pill(run.get("verdict", "unknown")),
                _ratio(run.get("block_rate")),
                _int(run.get("leaked")),
                _ratio(run.get("false_block_rate")),
                _ms(latency.get("p50")),
                _ms(latency.get("p95")),
                _pct(run.get("error_pct")),
                _int(run.get("sent")),
                _e(_when(run.get("finished_at"))),
            ]
        )
    return _table(
        ["Target", "Via", "Verdict", "Blocked", "Leaked", "Wrongly blocked", "p50", "p95", "Loss", "Sent", "Finished"],
        rows,
        numeric={3, 4, 5, 6, 7, 8, 9},
    )


def _capacity(capacity: dict) -> str:
    result = capacity.get("result") or {}
    target = capacity.get("target") or {}
    slo = capacity.get("slo") or {}
    parts = [
        f"<p><b>{_e(target.get('name', ''))}</b> <span class='mono muted'>{_e(target.get('endpoint', ''))}</span></p>",
        f"<p>{_e(result.get('summary', ''))}</p>",
        f"<p class='muted'>Limits: loss up to {_e(slo.get('loss_pct'))}%, SERVFAIL up to {_e(slo.get('servfail_pct'))}% "
        f"of answers, p95 up to {_e(slo.get('p95_ms'))} ms; more than 0.5% of answers rate-limited (EDE 31 or 32) "
        "also breaks a step.</p>",
    ]
    rows = [
        [
            _int(step.get("index")),
            _e("narrowing" if step.get("phase") == "refine" else "ramp"),
            _int(step.get("target_qps")),
            _int(step.get("achieved_qps")),
            _pct(step.get("loss_pct")),
            _pct(step.get("servfail_pct")),
            _ms(step.get("p95_ms")) if step.get("received") else "-",
            _pill(step.get("status", "")),
            _e("; ".join(step.get("reasons") or [])),
        ]
        for step in capacity.get("steps", [])
    ]
    parts.append(
        _table(["Step", "Phase", "Rate", "Achieved", "Loss", "SERVFAIL", "p95", "Result", "Why"], rows, numeric={0, 2, 3, 4, 5, 6})
    )
    return "".join(parts)


def _checks(checks: dict) -> str:
    results = checks.get("results") or []
    target = checks.get("target") or {}
    parts = [
        f"<p><b>{_e(target.get('name', ''))}</b> <span class='mono muted'>{_e(target.get('endpoint', ''))}</span>"
        f" - checked {_e(_when(checks.get('finished_at')))}</p>"
    ]
    rows = []
    for status in CHECK_ORDER:
        for result in results:
            if result.get("status") != status:
                continue
            detail = f"<br><span class='muted'>{_e(result.get('detail'))}</span>" if result.get("detail") else ""
            rows.append(
                [
                    _pill(status),
                    _e(result.get("group", "")),
                    f"<b>{_e(result.get('title', ''))}</b>",
                    f"{_e(result.get('summary', ''))}{detail}",
                ]
            )
    parts.append(_table(["Result", "Group", "Check", "What was found"], rows))
    return "".join(parts)


def _method(config, snapshot: dict) -> str:
    notes = [
        "Every query was scored against what this target is expected to do with its category: allow-listed "
        "names must resolve, block-listed ones must be blocked. A name that was wrongly blocked is a false "
        "positive (an outage for whoever needed it); a block-listed name that resolved is a leak. Borderline "
        "names (trackers, CDNs) are reported and never judged.",
        "A block is recognised by NXDOMAIN, REFUSED, no records, a known block-page address, or an Extended DNS "
        "Error in which the filter says it applied a policy. The address hints in HTTPS records count as "
        "addresses, because a browser connects to them directly.",
        "Latency percentiles come from histograms and are each the upper bound of their bucket: a slight "
        "over-estimate rather than a flattering one.",
    ]
    if config.mode == "personas":
        notes.append(
            "All traffic came from one source address standing for many simulated workers, so per-client policy "
            "was not tested; that needs pool mode with real secondary addresses."
        )
    dropped = float(snapshot.get("rates", {}).get("dropped_pct", 0) or 0)
    if dropped >= 0.5:
        notes.append(
            f"{dropped:.1f}% of the intended queries were never sent because the generator's in-flight budget was "
            "full; the rate the target saw was lower than asked."
        )
    return "".join(f"<p>{_e(note)}</p>" for note in notes)


def render_report(
    snapshot: dict,
    config,
    *,
    history: list[dict] | None = None,
    checks: dict | None = None,
    capacity: dict | None = None,
    lists: dict | None = None,
    achieved_qps: float | None = None,
    generated_at: float | None = None,
) -> str:
    """The session as one self-contained, printable HTML page.  ``config`` is the
    latest run's :class:`~dnsloadforge.spec.RunConfig`; the other parts appear only
    when there is something to show.  ``achieved_qps`` is the engine's rate over
    the sending window; the snapshot's elapsed time also covers the drain."""
    generated = generated_at if generated_at is not None else time.time()
    verdict = snapshot.get("verdict") or {}
    status = verdict.get("status", "idle")
    summary = summarise_run(snapshot, config)
    title = config.target_name or config.target
    has_run = int(snapshot.get("totals", {}).get("sent", 0) or 0) > 0

    sections: list[str] = []
    others = bool((history and len(history) > 1) or (capacity and capacity.get("steps")) or (checks and checks.get("results")))
    if has_run or not others:
        sections.append(
            f'<section class="verdict {_e(status)}"><p class="eyebrow">Verdict</p>'
            f"<h2>{_e(VERDICT_TITLE.get(status, status))}</h2><p>{_e(verdict.get('note', ''))}</p></section>"
        )
    if has_run:
        sections.append(_section("Results", _figures(summary, snapshot)))
        sections.append(_section("The run", _settings(config, snapshot, lists, achieved_qps)))
        sections.append(_section("By category", _categories(snapshot)))
        sections.append(
            _section(
                "Wrongly blocked (false positives)",
                _findings(snapshot.get("false_positives") or [], "rcode", "Answer"),
            )
        )
        sections.append(
            _section(
                "Leaked (false negatives)",
                _findings(snapshot.get("false_negatives") or [], "answer", "Resolved to"),
            )
        )
        sections.append(_section("How blocks were signalled", _signals(snapshot)))
    if history and len(history) > 1:
        sections.append(_section("Comparison", _comparison(history)))
    if capacity and capacity.get("steps"):
        sections.append(_section("Capacity", _capacity(capacity)))
    if checks and checks.get("results"):
        sections.append(_section("Deployment checks", _checks(checks)))
    if has_run:
        sections.append(_section("How the run was scored", _method(config, snapshot)))

    page = (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>DNS filter report - {_e(title)}</title><style>{_STYLE}</style></head><body><main>"
        '<p class="hint no-print">To keep this report, print it and choose Save as PDF.</p>'
        f'<p class="eyebrow">DNS filter report, {_e(_when(generated))}</p>'
        f"<h1>{_e(title)}</h1>"
        f'<p class="mono muted">{_e(config.target)}</p>'
        + "".join(sections)
        + f"<footer>Generated by DNS Load Forge {_e(__version__)}. Results depend on the network, the "
        "target and the day's threat lists; the domain lists are a snapshot of public sources.</footer>"
        "</main></body></html>\n"
    )
    # Plain ASCII, like the dashboard: anything else becomes a character reference.
    return page.encode("ascii", "xmlcharrefreplace").decode("ascii")
