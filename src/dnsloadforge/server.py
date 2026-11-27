"""Local HTTP dashboard and run control.

Standard library only.  A FastAPI/uvicorn stack would be pleasant, but the whole
point of this tool is that it runs from a USB stick on an isolated management
segment, and ``ThreadingHTTPServer`` handles one long-lived SSE stream per open
browser tab perfectly well.

Threading model, which is the only subtle part:

* the HTTP server runs in its own thread and only ever *reads* the aggregator
  (which is internally locked) or hands a request to the controller;
* a run executes in its own supervisor thread, driving asyncio in the
  ``run_threaded`` worker threads;
* so a browser refresh can never block the traffic generator, and a slow SSE
  client can never stall a run.

Server-Sent Events rather than WebSockets: SSE is one-way (which is all the
dashboard needs), needs no handshake library, survives a proxy, and reconnects
itself in the browser with no code.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import os
import re
import threading
import time
from dataclasses import replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from . import __version__
from .compare import summarise_run
from .domainlist import (
    DomainCatalogue,
    default_cache_dir,
    refresh_source,
    set_source_enabled,
    source_inventory,
)
from .engine import DnsLoadEngine, RunResult, run_threaded
from .spec import RunConfig
from .stats import RecordLog, StatsAggregator
from .targets import Target, adhoc_target, find_target, public_target_problem

__all__ = [
    "RunController",
    "DashboardServer",
    "serve",
    "DEFAULT_HOST",
    "DEFAULT_PORT",
]

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787

#: How often an SSE client is sent a snapshot.
STREAM_INTERVAL_S = 1.0

#: Pause between the runs of a comparison, so one target's queued responses and the
#: sender's own backlog cannot bleed into the next target's numbers.
COMPARE_COOLDOWN_S = 3.0

#: How many finished runs the dashboard remembers.
HISTORY_LIMIT = 50

#: Largest value the dashboard may set for a rate or duration.
MAX_OVERRIDE = 1_000_000.0

_LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})

_DASHBOARD_DIR = Path(__file__).resolve().parent / "dashboard"
_DASHBOARD_PATH = _DASHBOARD_DIR / "index.html"
_NOTICES_PATH = _DASHBOARD_DIR / "THIRD_PARTY_NOTICES.txt"

#: The page's inline scripts, as the browser reads them: up to the first ``</script``.
_INLINE_SCRIPT = re.compile(rb"<script\b[^>]*>(.*?)</script\s*>", re.S | re.I)


def dashboard_csp(html: bytes) -> str:
    """The Content-Security-Policy the dashboard is served with.

    The page is one self-contained file, so the policy can say exactly that: it may
    talk to this server and nothing else.  Scripts are allowed by the SHA-256 of each
    inline block rather than by ``'unsafe-inline'``, so even a markup injection could
    not run anything, and ``frame-ancestors`` stops another site framing the Start
    button (clickjacking needs no credentials either).  Styles stay inline-allowed
    because the chart components write their colours into a ``<style>`` element.

    The browser normalises line endings before hashing a script, and a Windows
    checkout may have turned the file's LF into CRLF, so the hash is taken after the
    same normalisation.
    """
    hashes = []
    for match in _INLINE_SCRIPT.finditer(html):
        body = match.group(1).replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        hashes.append(f"'sha256-{digest}'")
    script_src = " ".join(hashes) if hashes else "'none'"
    return "; ".join(
        (
            "default-src 'none'",
            f"script-src {script_src}",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self' data:",
            "connect-src 'self'",
            "base-uri 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
        )
    )


class _DashboardFile:
    """The page bytes and their policy, re-read only when the file changes on disk."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._stamp: tuple[int, int] | None = None
        self._body = b""
        self._csp = ""

    def load(self) -> tuple[bytes, str]:
        stat = self._path.stat()
        stamp = (stat.st_mtime_ns, stat.st_size)
        with self._lock:
            if stamp != self._stamp:
                body = self._path.read_bytes()
                self._body, self._csp, self._stamp = body, dashboard_csp(body), stamp
            return self._body, self._csp


_DASHBOARD = _DashboardFile(_DASHBOARD_PATH)


def _sanitise(value):
    """Replace non-finite floats with ``None``.

    ``Infinity`` and ``NaN`` are not valid JSON: Python will happily serialise
    them, and then every strict parser on the other end -- including the
    browser's ``JSON.parse`` -- rejects the whole payload.  A dashboard that
    silently stops updating is far worse than one blank cell, so the payload is
    walked and any non-finite number is nulled.
    """
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {k: _sanitise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitise(v) for v in value]
    return value


def dumps(payload) -> bytes:
    """Serialise a snapshot to JSON bytes, guaranteed parseable by a browser."""
    try:
        return json.dumps(payload, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError):
        return json.dumps(_sanitise(payload)).encode("utf-8")


def _number(payload: dict, key: str, default: float) -> float:
    """A finite number from a request body, or ``default`` when it is absent.  JSON
    from a browser can carry NaN, 1e308 or a string; none of them is a rate."""
    value = payload.get(key)
    if value is None:
        return float(default)
    if isinstance(value, bool):
        raise ValueError(f"{key} must be a number")
    number = float(value)
    if not math.isfinite(number) or abs(number) > MAX_OVERRIDE:
        raise ValueError(f"{key} must be a finite number no larger than {MAX_OVERRIDE:,.0f}")
    return number


class RunController:
    """Owns the lifecycle of runs so the HTTP layer never touches an engine.

    A run is started on a supervisor thread and returns immediately, which is what
    lets ``POST /api/control`` answer in milliseconds while the generator is
    already sending.  ``stop()`` reaches into every live engine shard and asks it
    to wind down; the run then drains in-flight queries before reporting.

    A start request may name several targets.  They run back to back on the same
    seed with a short cooldown between them, and each finished run is condensed into
    ``history`` so the dashboard can lay them side by side.
    """

    def __init__(
        self,
        config: RunConfig,
        catalogue: DomainCatalogue,
        *,
        targets: list[Target] | None = None,
        catalogue_loader: Callable[[], DomainCatalogue] | None = None,
        cache_dir: str | None = None,
        allow_public_target: bool = False,
        record_log_path: str = "",
        record_format: str = "jsonl",
        record_sample: float = 1.0,
        log: Callable[[str], None] = print,
    ) -> None:
        self.config = config
        self.catalogue = catalogue
        self.targets: list[Target] = list(targets or [])
        self._catalogue_loader = catalogue_loader
        self._cache_dir = cache_dir
        self._allow_public_target = allow_public_target
        self._record_log_path = record_log_path
        self._record_format = record_format
        self._record_sample = record_sample
        self._log = log

        self.stats = StatsAggregator()
        self.record_log: RecordLog | None = None
        self._engines: list[DnsLoadEngine] = []
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._results: list[RunResult] = []
        self._error: str = ""
        self._state = "idle"
        self._stop_requested = False
        self.run_count = 0
        self.history: list[dict] = []
        self._plan: list[RunConfig] = []
        self._job: dict = {"kind": "", "state": "idle"}
        self._job_thread: threading.Thread | None = None
        self._checks: dict = {"state": "idle", "results": []}
        self._capacity: dict = {"state": "idle", "steps": []}

        self.stats.set_expectations(config.expectations)
        self.stats.set_run(
            state="idle",
            server=config.target,
            transport=config.transport,
            target_name=config.target_name,
            mode=config.mode,
            personas=config.personas,
            source_ips=len(config.source_ips) or 1,
            target_qps=config.target_qps,
            seed=config.seed,
        )

    # -- state --------------------------------------------------------------

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def running(self) -> bool:
        return self.state == "running"

    @property
    def results(self) -> list[RunResult]:
        with self._lock:
            return list(self._results)

    @property
    def error(self) -> str:
        with self._lock:
            return self._error

    def snapshot(self) -> dict:
        snapshot = self.stats.snapshot()
        with self._lock:
            if self._error and self._state != "running":
                snapshot["run"]["note"] = self._error
        return snapshot

    def lists_payload(self) -> dict:
        cache = Path(self._cache_dir) if self._cache_dir else default_cache_dir()
        return {
            "categories": self.catalogue.summary(),
            "cache_dir": str(cache),
            "fetched_at": self.catalogue.fetched_at,
            "offline": self.catalogue.offline,
            "total": self.catalogue.total(),
        }

    def targets_payload(self) -> dict:
        return {
            "targets": [t.as_dict() for t in self.targets],
            "active": self.config.target_name,
            "server": self.config.target,
        }

    def history_payload(self) -> dict:
        with self._lock:
            return {"runs": list(self.history)}

    # -- control ------------------------------------------------------------

    def _validated_overrides(self, payload: dict) -> dict:
        """The knobs the dashboard may adjust between runs, checked but not applied.

        Deliberately a short allow-list.  Anything that changes the *shape* of the
        office (persona count, mode, source-IP pool) has to be set at launch,
        because changing it mid-session would make two runs incomparable while
        looking identical on the dashboard.

        Returned rather than applied so a request is all-or-nothing: one bad value,
        or a target that turns out not to exist, must not leave the others behind.
        """
        checked: dict = {}
        for key, caster in (
            ("target_qps", float),
            ("duration_s", float),
            ("timeout_s", float),
            ("qps_burst", float),
        ):
            if key in payload and payload[key] is not None:
                value = caster(payload[key])
                # JSON from a browser can carry NaN or 1e308; neither is a rate.
                if not math.isfinite(value) or value > MAX_OVERRIDE:
                    raise ValueError(f"{key} must be a finite number no larger than {MAX_OVERRIDE:,.0f}")
                # A duration of zero means "until stopped", which is how the CLI
                # already treats --duration 0.
                if value < 0 or (value == 0 and key != "duration_s"):
                    raise ValueError(f"{key} must be greater than zero")
                checked[key] = value
        return checked

    def _apply_overrides(self, payload: dict) -> None:
        for key, value in self._validated_overrides(payload).items():
            setattr(self.config, key, value)

    def _resolve_plan(self, payload: dict, base: RunConfig) -> list[RunConfig]:
        """The ordered list of run configurations a start request asks for, built on
        ``base`` (the current config with this request's overrides applied)."""
        names = payload.get("targets")
        if names is None and payload.get("target"):
            names = [payload["target"]]
        if not names:
            return [base]
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise ValueError("targets must be a list of target names")
        if len(names) > 12:
            raise ValueError("a comparison is limited to 12 targets")
        plan: list[RunConfig] = []
        for name in names:
            target = find_target(name, self.targets)
            problem = public_target_problem(target, base.target_qps, self._allow_public_target)
            if problem:
                raise ValueError(problem)
            plan.append(target.apply(base))
        if len(plan) > 1 and base.duration_s <= 0:
            raise ValueError(
                "a comparison needs a finite duration so each target gets the same traffic; "
                "set duration_s to the seconds each target should run"
            )
        return plan

    def start(self, payload: dict | None = None) -> dict:
        with self._lock:
            if self._state == "running":
                return {"ok": False, "state": self._state, "message": "a run is already in progress"}
            if self._job.get("state") == "running":
                return {
                    "ok": False,
                    "state": self._state,
                    "message": "domain lists are being updated; wait for that to finish before starting a run",
                }
            if self._checks.get("state") == "running":
                return {
                    "ok": False,
                    "state": self._state,
                    "message": "deployment checks are running; wait for them to finish before starting a run",
                }
            if self._capacity.get("state") == "running":
                return {"ok": False, "state": self._state, "message": "a capacity search is running"}
            payload = payload or {}
            try:
                overrides = self._validated_overrides(payload)
                base = replace(self.config, **overrides) if overrides else self.config
                plan = self._resolve_plan(payload, base)
            except (TypeError, ValueError) as exc:
                return {"ok": False, "state": self._state, "message": f"bad parameter: {exc}"}

            if self.config.mode == "pool" and not self.config.source_ips:
                return {
                    "ok": False,
                    "state": self._state,
                    "message": "pool mode needs --source-ips or --source-ips-file; run scripts/New-LabSourceIPs.ps1 to create them",
                }

            self._plan = plan
            self._stop_requested = False
            self._results = []
            self._error = ""
            self._state = "running"
            first = self._prepare_run_locked(plan[0], 0)

        self.stats.set_state("running")
        self._open_record_log(first)

        self._thread = threading.Thread(
            target=self._supervise,
            name="dnsloadforge-supervisor",
            daemon=True,
        )
        self._thread.start()
        label = f"{len(plan)} targets" if len(plan) > 1 else plan[0].target_name or plan[0].target
        self._log(
            f"run {first} started: {label} at {self.config.target_qps:,.0f} qps, "
            f"{self.config.personas:,} personas, {self.config.duration_s:g}s"
        )
        return {
            "ok": True,
            "state": "running",
            "message": (
                f"started a comparison of {len(plan)} targets at {self.config.target_qps:,.0f} qps"
                if len(plan) > 1
                else f"started run {first} against {plan[0].target_name or plan[0].target} at {self.config.target_qps:,.0f} qps"
            ),
        }

    def _prepare_run_locked(self, config: RunConfig, index: int) -> int:
        """Point the controller at the next run.  Caller holds the lock."""
        # A fresh aggregator per run: each run's findings must be its own, or a
        # false positive from yesterday's run would keep failing today's verdict.
        self.config = config
        self.stats = StatsAggregator()
        self.stats.set_expectations(config.expectations)
        self.stats.set_run(
            state="starting",
            server=config.target,
            transport=config.transport,
            target_name=config.target_name,
            mode=config.mode,
            personas=config.personas,
            source_ips=len(config.source_ips) or 1,
            target_qps=config.target_qps,
            seed=config.seed,
            started_at=time.time(),
            plan_index=index + 1,
            plan_total=len(self._plan),
            plan_targets=[p.target_name or p.target for p in self._plan],
        )
        self.run_count += 1
        self._engines = []
        return self.run_count

    def _open_record_log(self, run_index: int) -> None:
        self.record_log = None
        if not self._record_log_path:
            return
        path = self._expand_record_path(self._record_log_path, run_index)
        try:
            self.record_log = RecordLog(
                path,
                fmt=self._record_format,
                sample=self._record_sample,
            ).open()
            self.stats.set_run(record_log=path)
        except OSError as exc:
            self.record_log = None
            self._log(f"warning: could not open record log {path}: {exc}")

    @staticmethod
    def _expand_record_path(path: str, run_index: int) -> str:
        """``{run}`` is substituted so consecutive runs do not overwrite the
        evidence from the previous one."""
        if "{run}" in path:
            return path.replace("{run}", str(run_index))
        return path

    def _supervise(self) -> None:
        plan = list(self._plan)
        for position, config in enumerate(plan):
            if position > 0:
                if not self._cooldown():
                    break
                with self._lock:
                    run_index = self._prepare_run_locked(config, position)
                self.stats.set_state("running")
                self._open_record_log(run_index)
                self._log(f"run {run_index} started: {config.target_name or config.target}")
            else:
                run_index = self.run_count

            failed = self._run_one(config, run_index)
            if failed or self._stop_requested:
                break

        with self._lock:
            self._state = "stopped"
        if not self._error:
            self.stats.set_state("stopped")

    def _cooldown(self) -> bool:
        """Wait between comparison runs.  Returns False if a stop arrived."""
        deadline = time.time() + COMPARE_COOLDOWN_S
        while time.time() < deadline:
            if self._stop_requested:
                return False
            time.sleep(0.1)
        return not self._stop_requested

    def _run_one(self, config: RunConfig, run_index: int) -> bool:
        """Execute one run to completion.  Returns True if it failed."""
        failed = False
        try:
            results = run_threaded(
                config,
                self.catalogue,
                stats=self.stats,
                record_log=self.record_log,
                threads=max(1, config.threads),
                on_engine=self._register_engine,
            )
            with self._lock:
                self._results = results
        except BaseException as exc:  # noqa: BLE001 - surfaced through the dashboard
            failed = True
            with self._lock:
                self._error = f"{type(exc).__name__}: {exc}"
            self._log(f"run failed: {type(exc).__name__}: {exc}")
            self.stats.set_state("stopped", note=self._error)
        finally:
            if self.record_log is not None:
                self.record_log.close()
        if not failed:
            summary = summarise_run(self.stats.snapshot(), config, index=run_index)
            with self._lock:
                self.history.append(summary)
                del self.history[:-HISTORY_LIMIT]
        return failed

    def _register_engine(self, engine: DnsLoadEngine) -> None:
        with self._lock:
            self._engines.append(engine)

    def stop(self) -> dict:
        with self._lock:
            engines = list(self._engines)
            if self._state != "running":
                return {"ok": False, "state": self._state, "message": "no run is in progress"}
            self._stop_requested = True
        for engine in engines:
            engine.stop()
        if not engines:
            # Started but no shard exists yet: the supervisor will see the flag on
            # its first arrival.
            self.stats.set_state("stopping", note="stop requested")
        thread = self._thread
        if thread is not None:
            thread.join(timeout=min(self.config.timeout_s + 5.0, 30.0))
        with self._lock:
            state = self._state
        return {"ok": True, "state": state, "message": "stop requested; draining outstanding queries"}

    def wait(self, timeout: float | None = None) -> bool:
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout=timeout)
        return not thread.is_alive()

    def summary(self) -> dict:
        """End-of-run rollup for the console."""
        results = self.results
        snapshot = self.stats.snapshot()
        sent = sum(r.sent for r in results)
        return {
            "runs": len(results),
            "sent": sent,
            "received": sum(r.received for r in results),
            "timeouts": sum(r.timeouts for r in results),
            "errors": sum(r.errors for r in results),
            "dropped": sum(r.dropped for r in results),
            "malformed": sum(r.malformed for r in results),
            "achieved_qps": round(sum(r.achieved_qps for r in results), 1),
            "verdict": snapshot.get("verdict", {}),
            "snapshot": snapshot,
            "record_log": self.record_log.path if self.record_log else "",
            "error": self.error,
        }

    # -- domain list management --------------------------------------------

    def sources_payload(self) -> dict:
        with self._lock:
            job = {**self._job, "results": list(self._job.get("results", []))}
        try:
            rows = source_inventory(self._cache_dir)
        except OSError as exc:
            return {"ok": False, "error": f"cannot read the list cache: {exc}", "sources": [], "job": job}
        return {
            "ok": True,
            "sources": rows,
            "job": job,
            "available": self._catalogue_loader is not None,
            "categories": self.catalogue.summary(),
            "total": self.catalogue.total(),
        }

    def _begin_job(self, kind: str, total: int, work: Callable[[], None]) -> dict:
        """Run list maintenance on a background thread, one job at a time.

        Refused while a run is in progress: re-parsing a million-domain list shares
        the sender's interpreter, so doing it mid-run would distort the very
        latency numbers the run exists to measure.
        """
        if self._catalogue_loader is None:
            return {"ok": False, "message": "this dashboard was started without list management"}
        with self._lock:
            if self._state == "running":
                return {"ok": False, "message": "stop the current run before changing domain lists"}
            if self._job.get("state") == "running":
                return {"ok": False, "message": "a list update is already in progress"}
            self._job = {
                "kind": kind,
                "state": "running",
                "total": total,
                "done": 0,
                "current": "",
                "results": [],
                "error": "",
                "started_at": time.time(),
                "finished_at": 0.0,
            }

        def runner() -> None:
            try:
                work()
                with self._lock:
                    self._job.update(state="done", finished_at=time.time(), current="")
            except Exception as exc:  # noqa: BLE001 - reported through the dashboard
                with self._lock:
                    self._job.update(
                        state="error",
                        error=f"{type(exc).__name__}: {exc}",
                        finished_at=time.time(),
                        current="",
                    )
                self._log(f"list update failed: {type(exc).__name__}: {exc}")

        self._job_thread = threading.Thread(target=runner, name="dnsloadforge-lists", daemon=True)
        self._job_thread.start()
        return {"ok": True, "message": f"{kind} started"}

    def _rebuild_catalogue(self) -> None:
        with self._lock:
            self._job.update(current="rebuilding the domain catalogue")
        loader = self._catalogue_loader
        assert loader is not None
        self.catalogue = loader()

    def refresh_sources(self, slugs: list[str] | None = None) -> dict:
        known = [row["slug"] for row in source_inventory(self._cache_dir)]
        wanted = known if not slugs else slugs
        unknown = [s for s in wanted if s not in known]
        if unknown:
            return {"ok": False, "message": f"unknown source(s): {', '.join(unknown)}"}

        def work() -> None:
            for slug in wanted:
                with self._lock:
                    self._job.update(current=slug)
                result = refresh_source(slug, self._cache_dir)
                with self._lock:
                    self._job["results"].append(result)
                    self._job["done"] += 1
            self._rebuild_catalogue()

        return self._begin_job("refresh", len(wanted) + 1, work)

    def set_source_enabled(self, slug: str, enabled: bool) -> dict:
        if slug not in [row["slug"] for row in source_inventory(self._cache_dir)]:
            return {"ok": False, "message": f"unknown source: {slug}"}

        def work() -> None:
            set_source_enabled(slug, enabled, self._cache_dir)
            self._rebuild_catalogue()

        return self._begin_job("enable" if enabled else "disable", 1, work)


    # -- capacity search ---------------------------------------------------

    def capacity_payload(self) -> dict:
        with self._lock:
            return {**self._capacity, "steps": list(self._capacity.get("steps", []))}

    def start_capacity(self, payload: dict | None = None) -> dict:
        """Search for the highest rate the target sustains, on a background thread.

        Each step is a run like any other, so the live view shows it as it
        happens; the steps are kept here rather than in the comparison history,
        which they would otherwise fill with a dozen near-identical rows.
        """
        from dataclasses import asdict

        from .capacity import CapacityPlan, Slo

        payload = payload or {}
        try:
            plan = CapacityPlan(
                start_qps=_number(payload, "start_qps", 200.0),
                max_qps=_number(payload, "max_qps", 20_000.0),
                growth=_number(payload, "growth", 1.5),
                step_s=_number(payload, "step_s", 20.0),
                refine=int(_number(payload, "refine", 2)),
            )
            plan.validate()
            limits = payload.get("slo") or {}
            if not isinstance(limits, dict):
                raise ValueError("slo must be an object")
            slo = Slo(
                loss_pct=_number(limits, "loss_pct", 1.0),
                servfail_pct=_number(limits, "servfail_pct", 1.0),
                p95_ms=_number(limits, "p95_ms", 100.0),
            )
            slo.validate()
            name = payload.get("target") or self.config.target_name
            if name is not None and not isinstance(name, str):
                raise ValueError("target must be a target name")
            target = self._check_target(name or None)
            problem = public_target_problem(target, plan.max_qps, self._allow_public_target)
            if problem:
                raise ValueError(problem)
        except (TypeError, ValueError) as exc:
            return {"ok": False, "state": self.state, "message": f"bad parameter: {exc}"}

        with self._lock:
            if self._state == "running":
                return {"ok": False, "state": self._state, "message": "a run is already in progress"}
            if self._job.get("state") == "running" or self._checks.get("state") == "running":
                return {"ok": False, "state": self._state, "message": "wait for the list update or the checks to finish"}
            base = target.apply(self.config)
            self._state = "running"
            self._stop_requested = False
            self._error = ""
            self._results = []
            self._capacity = {
                "state": "running",
                "target": target.as_dict(),
                "plan": asdict(plan),
                "slo": asdict(slo),
                "estimate_s": round(plan.estimate_s()),
                "started_at": time.time(),
                "finished_at": 0.0,
                "current": None,
                "steps": [],
                "result": None,
                "error": "",
            }
        self._thread = threading.Thread(
            target=self._supervise_capacity, args=(base, plan, slo), name="dnsloadforge-capacity", daemon=True
        )
        self._thread.start()
        message = f"capacity search on {target.name}, {plan.start_qps:,.0f} to {plan.max_qps:,.0f} qps"
        self._log(message)
        return {"ok": True, "state": "running", "message": f"started a {message}"}

    def _supervise_capacity(self, base: RunConfig, plan, slo) -> None:
        from .capacity import search

        def run_step(rate: float) -> tuple[dict, float]:
            config = replace(base, target_qps=float(rate), duration_s=float(plan.step_s))
            with self._lock:
                self._plan = [config]
                self._prepare_run_locked(config, 0)
            self.stats.set_run(capacity_rate=float(rate))
            self.stats.set_state("running")
            results = run_threaded(
                config,
                self.catalogue,
                stats=self.stats,
                threads=max(1, config.threads),
                on_engine=self._register_engine,
            )
            with self._lock:
                self._results = results
            return self.stats.snapshot(), sum(r.achieved_qps for r in results)

        def on_start(index: int, phase: str, rate: float) -> None:
            with self._lock:
                self._capacity["current"] = {
                    "index": index,
                    "phase": phase,
                    "target_qps": rate,
                    "started_at": time.time(),
                }

        def on_step(step) -> None:
            with self._lock:
                self._capacity["steps"].append(step.as_dict())
                self._capacity["current"] = None
            self._log(f"capacity step {step.index}: {step.target_qps:,.0f} qps {step.status}")

        try:
            result = search(
                plan,
                slo,
                run_step,
                should_stop=lambda: self._stop_requested,
                on_step=on_step,
                on_start=on_start,
                pause=self._pause,
            )
            with self._lock:
                self._capacity.update(
                    state=result.state,
                    finished_at=time.time(),
                    current=None,
                    result={
                        "sustained_qps": result.sustained_qps,
                        "knee_qps": result.knee_qps,
                        "limit": result.limit,
                        "summary": result.summary,
                    },
                )
            self._log(f"capacity search finished: {result.summary}")
        except BaseException as exc:  # noqa: BLE001 - surfaced through the dashboard
            with self._lock:
                self._error = f"{type(exc).__name__}: {exc}"
                self._capacity.update(state="error", error=self._error, finished_at=time.time(), current=None)
            self._log(f"capacity search failed: {self._error}")
        finally:
            with self._lock:
                self._state = "stopped"
            if not self._error:
                self.stats.set_state("stopped")

    def _pause(self, seconds: float) -> None:
        deadline = time.time() + seconds
        while time.time() < deadline and not self._stop_requested:
            time.sleep(0.1)

    # -- deployment checks -------------------------------------------------

    def checks_payload(self) -> dict:
        with self._lock:
            return {**self._checks, "results": list(self._checks.get("results", []))}

    def _check_target(self, name: str | None) -> Target:
        if name:
            return find_target(name, self.targets)
        if self.config.target_name:
            try:
                return find_target(self.config.target_name, self.targets)
            except ValueError:
                pass
        cfg = self.config
        return adhoc_target(
            cfg.server, cfg.port, transport=cfg.transport, tls_name=cfg.tls_name, doh_path=cfg.doh_path
        )

    def start_checks(self, payload: dict | None = None) -> dict:
        """Run the deployment checks on a background thread.

        Refused during a run: the checks share this machine's network with the
        sender, and a few dozen extra queries in the middle of a latency
        measurement are exactly the noise the run exists to exclude.
        """
        from .checks import context_for_target, run_checks, summarise

        payload = payload or {}
        name = payload.get("target")
        if name is not None and not isinstance(name, str):
            return {"ok": False, "message": "target must be a target name"}
        network = payload.get("network", True)
        if not isinstance(network, bool):
            return {"ok": False, "message": "network must be true or false"}
        try:
            target = self._check_target(name)
        except ValueError as exc:
            return {"ok": False, "message": str(exc)}
        with self._lock:
            if self._state == "running":
                return {"ok": False, "message": "stop the current run before running checks"}
            if self._checks.get("state") == "running":
                return {"ok": False, "message": "the checks are already running"}
            self._checks = {
                "state": "running",
                "target": target.as_dict(),
                "network": network,
                "current": "",
                "started_at": time.time(),
                "finished_at": 0.0,
                "results": [],
                "summary": {},
                "error": "",
            }
        samples = []
        for category in ("block_malware", "block_phishing"):
            samples += self.catalogue.domains_for(category)[:3]
        context = context_for_target(
            target,
            network=network,
            samples=samples,
            verify=self.config.tls_verify,
            ca_file=self.config.ca_file,
        )

        def progress(check_id: str) -> None:
            with self._lock:
                self._checks["current"] = check_id

        def runner() -> None:
            try:
                results = run_checks(context, progress=progress)
                with self._lock:
                    self._checks.update(
                        state="done",
                        current="",
                        finished_at=time.time(),
                        results=[r.as_dict() for r in results],
                        summary=summarise(results),
                    )
            except Exception as exc:  # noqa: BLE001 - reported through the dashboard
                with self._lock:
                    self._checks.update(state="error", current="", finished_at=time.time(), error=f"{type(exc).__name__}: {exc}")

        threading.Thread(target=runner, name="dnsloadforge-checks", daemon=True).start()
        self._log(f"deployment checks started against {target.name}")
        return {"ok": True, "message": f"checking {target.name}"}


class _Handler(BaseHTTPRequestHandler):
    server_version = "DnsLoadForge"
    protocol_version = "HTTP/1.1"

    # -- plumbing -----------------------------------------------------------

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003 - stdlib signature
        """Silence per-request logging.

        The dashboard polls and streams continuously, so the default stderr access
        log would bury the run output.  Run lifecycle messages go through the
        controller's logger instead.
        """
        return

    @property
    def controller(self) -> RunController:
        return self.server.controller  # type: ignore[attr-defined]

    def _send(self, status: int, body: bytes, content_type: str = "application/json", extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, payload, status: int = HTTPStatus.OK) -> None:
        self._send(status, dumps(payload))

    def _error_json(self, status: int, message: str) -> None:
        self._send_json({"ok": False, "error": message}, status)

    # -- routing ------------------------------------------------------------

    # -- request screening --------------------------------------------------
    #
    # The dashboard can start load tests, so a web page the operator happens to have
    # open in another tab must not be able to drive it.  Two browser attacks matter:
    #
    # * cross-site requests (a page on evil.example posting to localhost:8787), which
    #   a browser always labels with an ``Origin`` header; and
    # * DNS rebinding (evil.example re-pointed at 127.0.0.1), which arrives with the
    #   attacker's name in ``Host``.
    #
    # Neither needs a password, only a check that the request is really addressed to
    # this server and really came from its own page.

    def _host_name(self) -> str:
        host = (self.headers.get("Host") or "").strip().lower()
        if host.startswith("["):
            return host.split("]")[0] + "]"
        return host.rsplit(":", 1)[0] if ":" in host else host

    def _refuse(self, status: int, message: str) -> bool:
        """Answer a screened-out request and drop the connection.

        The body is read and discarded first.  Leaving it unread has two bad effects: on
        a keep-alive connection those bytes would be parsed as the next request, and on
        Windows closing a socket with unread data sends a reset that can swallow the
        refusal before the client reads it.  The connection is then closed regardless.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if 0 < length <= 1_000_000:
            try:
                self.rfile.read(length)
            except OSError:
                pass
        self.close_connection = True
        self._error_json(status, message)
        return False

    def _screen(self, *, write: bool) -> bool:
        """Return True if the request may proceed; otherwise answer it and return False."""
        server = self.server
        if getattr(server, "loopback", True) and self._host_name() not in _LOOPBACK_NAMES:
            return self._refuse(HTTPStatus.MISDIRECTED_REQUEST, "this dashboard only answers to localhost")
        if not write:
            return True
        origin = self.headers.get("Origin")
        if origin:
            host = self.headers.get("Host", "")
            if origin.lower() not in {f"http://{host}", f"https://{host}"}:
                return self._refuse(HTTPStatus.FORBIDDEN, "cross-origin requests are not allowed")
        site = self.headers.get("Sec-Fetch-Site")
        if site and site not in ("same-origin", "none"):
            return self._refuse(HTTPStatus.FORBIDDEN, "cross-site requests are not allowed")
        if "application/json" not in (self.headers.get("Content-Type") or "").lower():
            return self._refuse(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "send the request body as application/json")
        return True

    def do_GET(self) -> None:  # noqa: N802 - stdlib signature
        route = urlparse(self.path).path.rstrip("/") or "/"
        if not self._screen(write=False):
            return
        try:
            if route in ("/", "/index.html", "/dashboard"):
                self._serve_dashboard()
            elif route == "/api/stats":
                self._send_json(self.controller.snapshot())
            elif route == "/api/stream":
                self._serve_stream()
            elif route == "/api/lists":
                self._send_json(self.controller.lists_payload())
            elif route == "/api/targets":
                self._send_json(self.controller.targets_payload())
            elif route == "/api/history":
                self._send_json(self.controller.history_payload())
            elif route == "/api/history/export.json":
                self._send(
                    HTTPStatus.OK,
                    dumps(self.controller.history_payload()),
                    "application/json",
                    {"Content-Disposition": 'attachment; filename="dnsloadforge-comparison.json"'},
                )
            elif route == "/api/sources":
                self._send_json(self.controller.sources_payload())
            elif route == "/api/config":
                self._send_json(self._config_payload())
            elif route == "/api/health":
                self._send_json({"ok": True, "state": self.controller.state, "time": time.time()})
            elif route == "/api/licenses":
                self._serve_notices()
            elif route == "/api/checks":
                self._send_json(self.controller.checks_payload())
            elif route == "/api/capacity":
                self._send_json(self.controller.capacity_payload())
            elif route == "/api/capacity/export.json":
                self._send(
                    HTTPStatus.OK,
                    dumps(self.controller.capacity_payload()),
                    "application/json",
                    {"Content-Disposition": 'attachment; filename="dnsloadforge-capacity.json"'},
                )
            elif route == "/api/run/export.jsonl":
                self._serve_records("jsonl")
            elif route == "/api/run/export.csv":
                self._serve_records("csv")
            elif route == "/api/run/export.json":
                self._serve_records("json")
            elif route == "/favicon.ico":
                self._send(HTTPStatus.NO_CONTENT, b"", "image/x-icon")
            else:
                self._error_json(HTTPStatus.NOT_FOUND, f"no such route: {route}")
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # The browser navigated away mid-response; not an error worth logging.
            return
        except Exception as exc:  # noqa: BLE001 - never let a handler kill the server
            try:
                self._error_json(HTTPStatus.INTERNAL_SERVER_ERROR, f"{type(exc).__name__}: {exc}")
            except Exception:
                pass

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib signature
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802 - stdlib signature
        route = urlparse(self.path).path.rstrip("/")
        if not self._screen(write=True):
            return
        try:
            payload = self._read_json()
            if route == "/api/control":
                action = str(payload.get("action", "")).lower()
                if action in ("start", "compare"):
                    if action == "compare" and not payload.get("targets"):
                        self._error_json(HTTPStatus.BAD_REQUEST, "compare needs a list of targets")
                        return
                    self._send_json(self.controller.start(payload))
                elif action == "capacity":
                    self._send_json(self.controller.start_capacity(payload))
                elif action == "stop":
                    self._send_json(self.controller.stop())
                else:
                    self._error_json(HTTPStatus.BAD_REQUEST, "action must be 'start', 'compare', 'capacity' or 'stop'")
            elif route == "/api/checks/run":
                self._send_json(self.controller.start_checks(payload))
            elif route == "/api/sources/refresh":
                slugs = payload.get("slugs")
                if slugs is not None and not (isinstance(slugs, list) and all(isinstance(s, str) for s in slugs)):
                    self._error_json(HTTPStatus.BAD_REQUEST, "slugs must be a list of source names")
                    return
                self._send_json(self.controller.refresh_sources(slugs or None))
            elif route == "/api/sources/enabled":
                slug, enabled = payload.get("slug"), payload.get("enabled")
                if not isinstance(slug, str) or not isinstance(enabled, bool):
                    self._error_json(HTTPStatus.BAD_REQUEST, "send {\"slug\": string, \"enabled\": true|false}")
                    return
                self._send_json(self.controller.set_source_enabled(slug, enabled))
            else:
                self._error_json(HTTPStatus.NOT_FOUND, f"no such route: {route}")
        except ValueError as exc:
            self._error_json(HTTPStatus.BAD_REQUEST, str(exc))
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return
        except Exception as exc:  # noqa: BLE001
            try:
                self._error_json(HTTPStatus.INTERNAL_SERVER_ERROR, f"{type(exc).__name__}: {exc}")
            except Exception:
                pass

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > 1_000_000:
            raise ValueError("request body too large")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"invalid JSON body: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError("body must be a JSON object")
        return payload

    # -- responses ----------------------------------------------------------

    def _config_payload(self) -> dict:
        cfg = self.controller.config
        return {
            "server": cfg.server,
            "port": cfg.port,
            "target": cfg.target,
            "transport": cfg.transport,
            "tls_verify": cfg.tls_verify,
            "connections": cfg.connections,
            "mode": cfg.mode,
            "personas": cfg.personas,
            "target_qps": cfg.target_qps,
            "duration_s": cfg.duration_s,
            "timeout_s": cfg.timeout_s,
            "seed": cfg.seed,
            "threads": cfg.threads,
            "max_inflight": cfg.max_inflight,
            "qps_burst": cfg.qps_burst,
            "source_ips": cfg.source_ips,
            "state": self.controller.state,
            "version": __version__,
        }

    def _serve_dashboard(self) -> None:
        try:
            body, csp = _DASHBOARD.load()
        except OSError:
            self._send(
                HTTPStatus.NOT_FOUND,
                b"dashboard/index.html is missing from the package; build it with `npm run build` in web/",
                "text/plain; charset=utf-8",
            )
            return
        self._send(
            HTTPStatus.OK,
            body,
            "text/html; charset=utf-8",
            {
                "Content-Security-Policy": csp,
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Cross-Origin-Opener-Policy": "same-origin",
            },
        )

    def _serve_notices(self) -> None:
        try:
            body = _NOTICES_PATH.read_bytes()
        except OSError:
            self._error_json(HTTPStatus.NOT_FOUND, "THIRD_PARTY_NOTICES.txt is missing from the package")
            return
        self._send(HTTPStatus.OK, body, "text/plain; charset=utf-8")

    def _serve_stream(self) -> None:
        """Push a snapshot roughly once a second until the client goes away.

        The connection has no Content-Length, so the response is sent with
        ``Connection: close`` and the loop ends when a write raises.  That is the
        normal way an SSE stream terminates, not an error.
        """
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        self.close_connection = True

        try:
            while True:
                payload = dumps(self.controller.snapshot())
                self.wfile.write(b"event: stats\ndata: " + payload + b"\n\n")
                self.wfile.flush()
                time.sleep(STREAM_INTERVAL_S)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
            return

    def _serve_records(self, fmt: str) -> None:
        log = self.controller.record_log
        if log is None or not log.exists:
            self._error_json(
                HTTPStatus.NOT_FOUND,
                "no record log for this run; launch with --record-log to keep the raw per-query evidence",
            )
            return

        if fmt == "jsonl":
            self._send_file(log.path, "application/x-ndjson")
            return

        if fmt == "json":
            records = list(log.read_records())
            self._send_json({"count": len(records), "records": records})
            return

        from .spec import RECORD_FIELDS

        rows = [",".join(RECORD_FIELDS)]
        for record in log.read_records():
            rows.append(",".join(_csv_cell(record.get(field, "")) for field in RECORD_FIELDS))
        body = ("\n".join(rows) + "\n").encode("utf-8")
        self._send(
            HTTPStatus.OK,
            body,
            "text/csv; charset=utf-8",
            {"Content-Disposition": 'attachment; filename="dnsloadforge-records.csv"'},
        )

    def _send_file(self, path: str, content_type: str) -> None:
        size = os.path.getsize(path)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(64 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)


def _csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if any(ch in text for ch in (",", '"', "\n", "\r")):
        return '"' + text.replace('"', '""') + '"'
    return text


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class DashboardServer(ThreadingHTTPServer):
    """Threading HTTP server that carries a reference to the run controller."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], controller: RunController) -> None:
        super().__init__(address, _Handler)
        self.controller = controller
        self.loopback = _is_loopback(address[0])

    @property
    def url(self) -> str:
        host, port = self.server_address[0], self.server_address[1]
        return f"http://{host}:{port}/"


def serve(
    config: RunConfig,
    catalogue: DomainCatalogue,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    record_log_path: str = "",
    record_format: str = "jsonl",
    record_sample: float = 1.0,
    autostart: bool = True,
    log: Callable[[str], None] = print,
    targets: list[Target] | None = None,
    catalogue_loader: Callable[[], DomainCatalogue] | None = None,
    cache_dir: str | None = None,
    allow_public_target: bool = False,
    start_payload: dict | None = None,
) -> tuple[DashboardServer, RunController]:
    """Start the dashboard and return the live server.

    Returns rather than blocks so the CLI can start a run, wait for it, and keep
    serving the final results for inspection -- an operator who has just spent 20
    minutes driving an appliance wants to read the report, not lose it.
    """
    controller = RunController(
        config,
        catalogue,
        targets=targets,
        catalogue_loader=catalogue_loader,
        cache_dir=cache_dir,
        allow_public_target=allow_public_target,
        record_log_path=record_log_path,
        record_format=record_format,
        record_sample=record_sample,
        log=log,
    )
    server = DashboardServer((host, port), controller)
    thread = threading.Thread(target=server.serve_forever, name="dnsloadforge-http", daemon=True)
    thread.start()
    if autostart:
        controller.start(start_payload)
    return server, controller
