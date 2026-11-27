"""Capacity search: the highest query rate a target sustains within its limits.

A run at one rate answers "does it cope with this".  The question before a
purchase or a go-live is "how much can it take", which load tools such as
resperf and DNS Shotgun answer by raising the rate until something gives.  This
does the same with the office's own traffic, so the answer is the rate at which
*this* mix of names is served, not a synthetic best case.

The search:

1. **Ramp.**  Run ``step_s`` seconds at ``start_qps``, then ``growth`` times
   that, and so on; every step is a fresh run on the same seed.  Stop at the
   first step that breaks a limit, or at ``max_qps``.
2. **Refine.**  Bisect between the last step that passed and the first that
   failed, ``refine`` times, so the answer is not off by a whole growth factor.
3. **Report.**  The highest rate that passed is what the target sustains; the
   first that failed, and why, is where it breaks.

A step is judged on loss (timeouts and errors), the SERVFAIL share of answers,
Extended DNS Errors that say the target rate-limited (31 Rate Limited, 32 Over
Quota), and p95 latency.  Before any of that the *generator* is checked: a step
this machine could not send at its rate says nothing about the target, so the
search stops there and says so, rather than reporting the generator's limit as
the target's.  A full in-flight budget is the exception: if the target is
already failing, the queries piling up unanswered are its doing, not ours.
"""

from __future__ import annotations

import math
import time
from dataclasses import asdict, dataclass, field
from typing import Callable

__all__ = [
    "CapacityPlan",
    "CapacityResult",
    "MIN_COMPLETED",
    "RATE_LIMIT_EDE",
    "STEP_PAUSE_S",
    "Slo",
    "Step",
    "judge",
    "measure",
    "nice_rate",
    "search",
]

#: Extended DNS Errors that mean the target rate-limited the query.
RATE_LIMIT_EDE: tuple[int, ...] = (31, 32)
#: Below this many completed queries a step is too small to judge.
MIN_COMPLETED = 200
#: A step whose offered rate fell this far short was limited by this machine.
GENERATOR_FLOOR = 0.9
#: Sender drops above this share, with the target healthy, mean the in-flight
#: budget, not the target, was the limit.
GENERATOR_DROPS_PCT = 1.0
#: Rate-limited answers above this share break the step.
RATE_LIMIT_PCT = 0.5
#: Pause between steps, so one step's stragglers are not the next step's load.
STEP_PAUSE_S = 2.0


def nice_rate(rate: float) -> int:
    """A rate rounded to two significant figures (1,519 -> 1,500), which is as
    precise as a stepped search can honestly claim."""
    if rate < 10:
        return max(1, round(rate))
    digits = int(math.floor(math.log10(rate))) - 1
    return int(round(rate / 10**digits) * 10**digits)


@dataclass
class Slo:
    """What a step must achieve to pass."""

    loss_pct: float = 1.0
    servfail_pct: float = 1.0
    p95_ms: float = 100.0

    def validate(self) -> None:
        for name in ("loss_pct", "servfail_pct", "p95_ms"):
            value = getattr(self, name)
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a number greater than zero")
        if self.loss_pct > 100 or self.servfail_pct > 100:
            raise ValueError("percentages must be at most 100")


@dataclass
class CapacityPlan:
    """The rates to try, and for how long."""

    start_qps: float = 200.0
    max_qps: float = 20_000.0
    growth: float = 1.5
    step_s: float = 20.0
    refine: int = 2

    def validate(self) -> None:
        for name in ("start_qps", "max_qps", "growth", "step_s"):
            if not math.isfinite(getattr(self, name)):
                raise ValueError(f"{name} must be a finite number")
        if self.start_qps <= 0:
            raise ValueError("the starting rate must be greater than zero")
        if self.max_qps < self.start_qps:
            raise ValueError("the highest rate must be at least the starting rate")
        if not 1.1 <= self.growth <= 10:
            raise ValueError("growth must be between 1.1 and 10")
        if self.step_s < 3:
            raise ValueError("each step must last at least 3 seconds")
        if not 0 <= int(self.refine) <= 6:
            raise ValueError("refine must be between 0 and 6 steps")
        if self.start_qps * self.step_s < MIN_COMPLETED:
            raise ValueError(
                f"a step at {self.start_qps:g} qps for {self.step_s:g}s sends too few queries to judge; "
                f"raise the starting rate or the step length (at least {MIN_COMPLETED} queries)"
            )

    def ramp(self) -> list[int]:
        """The rates the ramp tries if nothing fails, start to max."""
        rates: list[int] = []
        index = 0
        while True:
            rate = self.start_qps * self.growth**index
            if rate >= self.max_qps * 0.999:
                break
            rounded = nice_rate(rate)
            if not rates or rounded > rates[-1]:
                rates.append(rounded)
            index += 1
        top = int(round(self.max_qps))
        if not rates or top > rates[-1]:
            rates.append(top)
        return rates

    def estimate_s(self) -> float:
        """The longest the search can take: every ramp step and every refinement,
        with the drain after each step and the pause before the next."""
        steps = len(self.ramp()) + int(self.refine)
        return steps * (self.step_s + 2.5 + STEP_PAUSE_S)


@dataclass
class Step:
    """One rate tried, what came back, and the verdict on it."""

    index: int
    phase: str  # "ramp" or "refine"
    target_qps: float
    achieved_qps: float = 0.0
    offered_qps: float = 0.0
    sent: int = 0
    received: int = 0
    completed: int = 0
    loss_pct: float = 0.0
    servfail_pct: float = 0.0
    rate_limited_pct: float = 0.0
    dropped_pct: float = 0.0
    p50_ms: float = 0.0
    p95_ms: float = 0.0
    p99_ms: float = 0.0
    #: pass, fail, generator (this machine could not send the rate), small (too
    #: few queries completed to judge), or stopped (cut short by a stop)
    status: str = ""
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


def measure(step: Step, snapshot: dict, achieved_qps: float) -> Step:
    """Fill ``step`` in from a finished run's snapshot."""
    totals = snapshot.get("totals", {})
    rates = snapshot.get("rates", {})
    latency = snapshot.get("latency_ms", {})
    rcodes = snapshot.get("rcodes", {})
    sent = int(totals.get("sent", 0))
    received = int(totals.get("received", 0))
    failed = int(totals.get("timeouts", 0)) + int(totals.get("errors", 0))
    intended = int(totals.get("intended", sent)) or sent
    limited = sum(int(row.get("count", 0)) for row in snapshot.get("ede", []) if row.get("code") in RATE_LIMIT_EDE)
    step.sent = sent
    step.received = received
    step.completed = received + failed
    step.achieved_qps = round(achieved_qps, 1)
    # What the pacer offered, drops included: whether *this machine* kept up.
    step.offered_qps = round(achieved_qps * intended / sent, 1) if sent else 0.0
    step.loss_pct = round(100.0 * failed / sent, 3) if sent else 0.0
    step.servfail_pct = round(100.0 * int(rcodes.get("SERVFAIL", 0)) / received, 3) if received else 0.0
    step.rate_limited_pct = round(100.0 * limited / received, 3) if received else 0.0
    step.dropped_pct = float(rates.get("dropped_pct", 0.0))
    step.p50_ms = float(latency.get("run_p50", latency.get("p50", 0.0)))
    step.p95_ms = float(latency.get("run_p95", latency.get("p95", 0.0)))
    step.p99_ms = float(latency.get("run_p99", latency.get("p99", 0.0)))
    return step


def judge(step: Step, slo: Slo) -> Step:
    """Pass, fail with the reasons, or ``generator`` when this machine did not
    reach the rate, which makes the step no evidence about the target."""
    if step.offered_qps < GENERATOR_FLOOR * step.target_qps:
        step.status = "generator"
        step.reasons = [
            f"this machine offered {step.offered_qps:,.0f} qps of {step.target_qps:,.0f}: add --threads, "
            "or run from a faster machine"
        ]
        return step
    if step.completed < MIN_COMPLETED:
        step.status = "small"
        step.reasons = [f"only {step.completed} queries completed; a step needs {MIN_COMPLETED} to be judged"]
        return step
    reasons: list[str] = []
    if step.loss_pct > slo.loss_pct:
        reasons.append(f"loss {step.loss_pct:.1f}% (limit {slo.loss_pct:g}%)")
    if step.servfail_pct > slo.servfail_pct:
        reasons.append(f"SERVFAIL {step.servfail_pct:.1f}% of answers (limit {slo.servfail_pct:g}%)")
    if step.rate_limited_pct > RATE_LIMIT_PCT:
        reasons.append(f"rate-limited {step.rate_limited_pct:.1f}% of answers (EDE 31/32)")
    if step.p95_ms > slo.p95_ms:
        reasons.append(f"p95 {step.p95_ms:g} ms (limit {slo.p95_ms:g} ms)")
    if not reasons and step.dropped_pct > GENERATOR_DROPS_PCT:
        # The target kept up but the in-flight budget did not: our limit, not its.
        step.status = "generator"
        step.reasons = [
            f"{step.dropped_pct:.1f}% of queries were dropped because the in-flight budget was full: "
            "raise --max-inflight"
        ]
        return step
    if reasons and step.dropped_pct > GENERATOR_DROPS_PCT:
        reasons.append(f"{step.dropped_pct:.1f}% more were never sent while it fell behind")
    step.status = "fail" if reasons else "pass"
    step.reasons = reasons
    return step


@dataclass
class CapacityResult:
    """What the search found."""

    #: done, or stopped when asked to stop
    state: str
    #: The highest rate that passed, or None when none did.
    sustained_qps: float | None
    #: The lowest rate that failed, or None when none did.
    knee_qps: float | None
    #: What ended the search: target (a rate failed), max (the highest rate
    #: passed), start (the first rate failed), generator, or stopped.
    limit: str
    summary: str
    steps: list[Step] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "state": self.state,
            "sustained_qps": self.sustained_qps,
            "knee_qps": self.knee_qps,
            "limit": self.limit,
            "summary": self.summary,
            "steps": [step.as_dict() for step in self.steps],
        }


RunStep = Callable[[float], "tuple[dict, float]"]


def search(
    plan: CapacityPlan,
    slo: Slo,
    run_step: RunStep,
    *,
    should_stop: Callable[[], bool] = lambda: False,
    on_step: Callable[[Step], None] | None = None,
    on_start: Callable[[int, str, float], None] | None = None,
    pause: Callable[[float], None] = time.sleep,
) -> CapacityResult:
    """Ramp, refine and report.  ``run_step(rate)`` runs one step and returns
    ``(snapshot, achieved_qps)``; the server and the command line run real load,
    and the tests a model of a target."""
    plan.validate()
    slo.validate()
    steps: list[Step] = []
    best: Step | None = None
    worst: Step | None = None
    ended = ""

    def attempt(rate: float, phase: str) -> Step:
        index = len(steps) + 1
        if on_start is not None:
            on_start(index, phase, rate)
        snapshot, achieved = run_step(rate)
        step = measure(Step(index=index, phase=phase, target_qps=rate), snapshot, achieved)
        if should_stop():
            # Cut short: a part of a step proves nothing either way.
            step.status, step.reasons = "stopped", ["stopped before the step finished"]
        else:
            judge(step, slo)
        steps.append(step)
        if on_step is not None:
            on_step(step)
        return step

    for position, rate in enumerate(plan.ramp()):
        if should_stop():
            ended = "stopped"
            break
        if position:
            pause(STEP_PAUSE_S)
        step = attempt(rate, "ramp")
        if step.status == "pass":
            best = step
        elif step.status == "fail":
            worst = step
            break
        else:
            ended = "generator" if step.status == "generator" else "stopped"
            break

    if worst is not None and best is not None and not ended:
        for _ in range(int(plan.refine)):
            low, high = best.target_qps, worst.target_qps
            mid = nice_rate((low + high) / 2)
            if not low < mid < high or should_stop():
                break
            pause(STEP_PAUSE_S)
            step = attempt(mid, "refine")
            if step.status == "pass":
                best = step
            elif step.status == "fail":
                worst = step
            else:
                ended = "generator" if step.status == "generator" else "stopped"
                break

    return _conclude(steps, best, worst, ended, plan)


def _figures(step: Step) -> str:
    return f"p95 {step.p95_ms:g} ms, loss {step.loss_pct:.1f}%"


def _conclude(steps: list[Step], best: Step | None, worst: Step | None, ended: str, plan: CapacityPlan) -> CapacityResult:
    sustained = best.target_qps if best is not None else None
    knee = worst.target_qps if worst is not None else None
    state = "stopped" if ended == "stopped" else "done"
    if ended == "stopped":
        summary = f"Stopped after {len(steps)} step(s)."
        if best is not None:
            summary += f" It had sustained {best.target_qps:,.0f} qps ({_figures(best)})."
        return CapacityResult(state, sustained, knee, "stopped", summary, steps)
    if ended == "generator":
        limited = steps[-1]
        if best is None:
            summary = (
                f"This machine could not send {limited.target_qps:,.0f} qps, so the target was never tested "
                f"at its limit: {limited.reasons[0]}."
            )
        else:
            summary = (
                f"Sustains at least {best.target_qps:,.0f} qps ({_figures(best)}). This machine could not test "
                f"beyond that: {limited.reasons[0]}."
            )
        return CapacityResult(state, sustained, knee, "generator", summary, steps)
    if worst is None:
        if best is None:
            return CapacityResult(state, None, None, "stopped", "No step completed.", steps)
        summary = (
            f"Sustained the highest rate tried, {best.target_qps:,.0f} qps ({_figures(best)}). "
            "Raise the highest rate to look further."
        )
        return CapacityResult(state, sustained, None, "max", summary, steps)
    if best is None:
        summary = (
            f"Fails at the starting rate, {worst.target_qps:,.0f} qps: {'; '.join(worst.reasons)}. "
            "Start lower to find what it does sustain."
        )
        return CapacityResult(state, None, knee, "start", summary, steps)
    summary = (
        f"Sustains {best.target_qps:,.0f} qps ({_figures(best)}). At {worst.target_qps:,.0f} qps: "
        f"{'; '.join(worst.reasons)}."
    )
    return CapacityResult(state, sustained, knee, "target", summary, steps)
