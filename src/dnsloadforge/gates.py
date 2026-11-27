"""Pass/fail limits on a run, for scripts and CI.

``--assert "p95<=50"`` turns a run into a test.  Each expression is checked
against the run's summary when it ends, the results are printed, and the process
exits 1 if any failed, so a nightly job can catch a filter update that started
blocking the sign-in page or slowed every answer down.  ``--junit PATH`` writes
the results as JUnit XML, which every CI system reads: one test suite per target,
one test case per assertion.

Assertions are parsed as the arguments are read, so a typo fails before a single
query is sent rather than after a ten-minute run.
"""

from __future__ import annotations

import operator
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Sequence

__all__ = [
    "DEFAULT_ASSERTIONS",
    "METRICS",
    "VERDICTS",
    "Assertion",
    "AssertionResult",
    "evaluate",
    "format_results",
    "junit_xml",
    "parse_assertion",
]

VERDICTS = ("filtering", "baseline", "degraded", "passthrough", "unknown", "idle")


def _percent(value: object) -> float | None:
    return None if value is None else round(100.0 * float(value), 3)


def _latency(key: str) -> Callable[[dict], object]:
    return lambda summary: (summary.get("latency_ms") or {}).get(key)


#: What can be asserted: name -> (what it is, unit, how to read it from a run summary).
METRICS: dict[str, tuple[str, str, Callable[[dict], object]]] = {
    "block_rate": ("share of block-listed queries blocked", "%", lambda s: _percent(s.get("block_rate"))),
    "false_block_rate": (
        "share of allow-listed queries wrongly blocked",
        "%",
        lambda s: _percent(s.get("false_block_rate")),
    ),
    "leaked": ("block-listed queries that resolved", "", lambda s: s.get("leaked")),
    "false_positives": ("allow-listed queries wrongly blocked", "", lambda s: s.get("false_positives")),
    "loss": ("timeouts and errors, share of queries sent", "%", lambda s: s.get("error_pct")),
    "servfail": ("SERVFAIL, share of answers", "%", lambda s: s.get("servfail_pct")),
    "dropped": ("intended queries the generator never sent", "%", lambda s: s.get("dropped_pct")),
    "timeouts": ("queries never answered", "", lambda s: s.get("timeouts")),
    "p50": ("median latency over the run", " ms", _latency("p50")),
    "p95": ("95th-percentile latency over the run", " ms", _latency("p95")),
    "p99": ("99th-percentile latency over the run", " ms", _latency("p99")),
    "achieved_qps": ("queries per second sent", " qps", lambda s: s.get("achieved_qps")),
    "verdict": ("the verdict: " + ", ".join(VERDICTS), "", lambda s: s.get("verdict")),
}

_OPS: dict[str, Callable[[object, object], bool]] = {
    "<=": operator.le,
    ">=": operator.ge,
    "<": operator.lt,
    ">": operator.gt,
    "==": operator.eq,
    "!=": operator.ne,
    "in": lambda actual, allowed: actual in allowed,  # type: ignore[operator]
}
_EXPRESSION = re.compile(r"^\s*([a-z_0-9]+)\s*(<=|>=|==|!=|<|>)\s*([A-Za-z0-9_.-]+)\s*$")


@dataclass(frozen=True)
class Assertion:
    metric: str
    op: str
    value: float | str | tuple[str, ...]
    #: As shown in reports: ``p95 <= 50``.
    text: str


def parse_assertion(text: str) -> Assertion:
    """``"p95<=50"`` as an :class:`Assertion`, or ValueError saying what is wrong."""
    match = _EXPRESSION.match(text or "")
    if not match:
        raise ValueError(f"{text!r} is not an assertion such as p95<=50 or verdict==filtering")
    metric, op, raw = match.groups()
    if metric not in METRICS:
        raise ValueError(f"{text!r}: unknown metric {metric!r}; choose from {', '.join(METRICS)}")
    if metric == "verdict":
        if op not in ("==", "!="):
            raise ValueError(f"{text!r}: a verdict can only be compared with == or !=")
        if raw not in VERDICTS:
            raise ValueError(f"{text!r}: the verdict is one of {', '.join(VERDICTS)}")
        return Assertion(metric, op, raw, f"verdict {op} {raw}")
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{text!r}: {metric} is compared with a number, not {raw!r}") from None
    return Assertion(metric, op, value, f"{metric} {op} {raw}")


#: With ``--junit`` and no ``--assert``: the verdict says the filter works, or the
#: target is a baseline that is not meant to filter.
DEFAULT_ASSERTIONS: tuple[Assertion, ...] = (
    Assertion("verdict", "in", ("filtering", "baseline"), "verdict is filtering or baseline"),
)


@dataclass
class AssertionResult:
    assertion: Assertion
    target: str
    actual: object
    passed: bool
    message: str


def _shown(value: object, unit: str) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{value:,.3f}".rstrip("0").rstrip(".") + unit
    return str(value)


def evaluate(assertions: Sequence[Assertion], summary: dict) -> list[AssertionResult]:
    """Check each assertion against one run's summary (``compare.summarise_run``)."""
    target = str(summary.get("target", ""))
    results = []
    for assertion in assertions:
        _what, unit, read = METRICS[assertion.metric]
        actual = read(summary)
        if actual is None:
            results.append(
                AssertionResult(assertion, target, None, False, f"{assertion.metric} was not measured in this run")
            )
            continue
        passed = bool(_OPS[assertion.op](actual, assertion.value))
        message = f"{assertion.metric} was {_shown(actual, unit)}"
        if not passed and assertion.op != "in":
            message += f", needs {assertion.op} {_shown(assertion.value, unit)}"
        results.append(AssertionResult(assertion, target, actual, passed, message))
    return results


def format_results(results: Sequence[AssertionResult]) -> str:
    """The console table: one line per assertion, then a count."""
    if not results:
        return ""
    width = max(len(r.assertion.text) for r in results)
    several = len({r.target for r in results}) > 1
    lines = ["ASSERTIONS"]
    for result in results:
        where = f"[{result.target}] " if several else ""
        mark = "PASS" if result.passed else "FAIL"
        lines.append(f"  {mark}  {where}{result.assertion.text:<{width}}  {result.message}")
    failed = sum(1 for r in results if not r.passed)
    lines.append(f"  {failed} of {len(results)} failed." if failed else f"  All {len(results)} passed.")
    return "\n".join(lines)


def junit_xml(runs: Sequence[tuple[dict, Sequence[AssertionResult]]]) -> str:
    """JUnit XML: a test suite per run (target), a test case per assertion."""
    total = sum(len(results) for _summary, results in runs)
    failures = sum(1 for _summary, results in runs for r in results if not r.passed)
    root = ET.Element("testsuites", name="dnsloadforge", tests=str(total), failures=str(failures))
    for summary, results in runs:
        target = str(summary.get("target", "target"))
        finished = float(summary.get("finished_at") or 0.0)
        suite = ET.SubElement(
            root,
            "testsuite",
            name=target,
            tests=str(len(results)),
            failures=str(sum(1 for r in results if not r.passed)),
            errors="0",
            skipped="0",
            time=f"{float(summary.get('elapsed_s') or 0.0):.1f}",
            timestamp=datetime.fromtimestamp(finished, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") if finished else "",
        )
        properties = ET.SubElement(suite, "properties")
        for key in ("server", "transport", "verdict", "sent", "target_qps", "seed"):
            ET.SubElement(properties, "property", name=key, value=str(summary.get(key, "")))
        classname = "dnsloadforge." + re.sub(r"[^A-Za-z0-9]+", "_", target).strip("_").lower()
        for result in results:
            case = ET.SubElement(suite, "testcase", classname=classname, name=result.assertion.text, time="0")
            if result.passed:
                ET.SubElement(case, "system-out").text = result.message
            else:
                failure = ET.SubElement(case, "failure", message=result.message, type="AssertionError")
                failure.text = result.message
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"
