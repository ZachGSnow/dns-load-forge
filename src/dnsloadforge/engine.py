"""The traffic engine: paced, bursty, multi-client DNS query generation.

How the load is produced matters as much as how much of it there is, so the three
mechanisms here are deliberate:

**Aggregate Poisson pacing.**  Each persona's lookups are an independent Poisson
process.  Rather than run 10,000 timers, the engine draws *one* inter-arrival time
for the whole office and then picks who acted in proportion to their rate --
mathematically identical, because a superposition of independent Poisson processes
is itself Poisson.  When the target rate exceeds what the machine can actually
deliver, the pacer simply stops sleeping and falls behind, which is reported
honestly as unanswered queries rather than papered over.

**Compound arrivals.**  A persona does not emit one query at a time; it opens a
page and a burst of lookups goes out at once.  That burstiness is what breaks a
resolver that handles the same average rate smoothly, so it is modelled
explicitly: inter-arrival times are for *page loads*, and each page fires a
geometric number of queries.

**A real in-flight budget.**  ``max_inflight`` caps outstanding queries.  When it
is hit the engine *drops* queries and counts them, instead of queueing without
bound and reporting a rate it never achieved.  A nonzero drop count is the signal
that the generator, not the appliance, is the bottleneck.

Timeouts are expired with a deque rather than 10,000 timer handles: pending
queries are appended in send order, so they are already sorted by deadline and the
sweeper just pops from the left until it finds one that has not expired yet.
"""

from __future__ import annotations

import asyncio
import bisect
import random
import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Container, Sequence

from .packets import DNSError, decode_message, encode_query
from .profiles import Persona, PersonaModel
from .spec import (
    CATEGORY_EXPECTED,
    RCODE_ERROR,
    RCODE_TIMEOUT,
    Outcome,
    RunConfig,
    SinkholeSet,
    is_internal_name,
    is_reverse_name,
)
from .stats import RecordLog, StatsAggregator

__all__ = [
    "DnsLoadEngine",
    "RunResult",
    "classify",
    "detect_local_ip",
    "MAX_BURST",
]

#: Bursts are geometric with the role's mean, truncated here.  A real page load
#: fires a handful of lookups, not hundreds; an unbounded geometric draw would
#: occasionally emit a thousand-query "burst" that is really just a tail artefact.
MAX_BURST = 24


def detect_local_ip(server: str) -> str:
    """Best-effort source address the kernel would use to reach ``server``.

    Uses a connected UDP socket, which makes the kernel choose a route and a
    source address without sending a single packet -- there is no traffic to a
    name server just to find out what our own address is.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((server, 9))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def classify(
    category: str,
    rcode: str,
    answer_ips: Sequence[str],
    sinkhole_ips: Container[str],
    expect: str | None = None,
    *,
    qname: str = "",
    ignore_internal: bool = False,
) -> tuple[str, str]:
    """Turn one response into an :class:`Outcome`.

    Returns ``(outcome, answer_repr)``.  The rule that matters most: a query is a
    **false positive** only when a category we expect to resolve came back
    blocked (REFUSED, NXDOMAIN, a sinkhole address, or a server error).  A
    filtered-DNS appliance's most expensive failure is blocking the intranet or the
    Microsoft sign-in endpoint, and that is exactly what this isolates.

    ``expect == "unknown"`` (the borderline tracker/CDN bucket) never produces a
    false positive or negative -- those categories are deliberately in the grey
    zone, so the tool reports what happened without judging it.
    """
    expect = expect or CATEGORY_EXPECTED.get(category, "unknown")

    # NXDOMAIN is the correct answer for some names that sit in an allow category:
    # reverse lookups of addresses with no PTR record, and (when the target is a
    # public resolver) internal-only names such as ``_ldap._tcp.corp.local``.  Scoring
    # those as false positives would make every public resolver look broken.
    if rcode == "NXDOMAIN" and expect == "allow" and qname:
        if is_reverse_name(qname) or (ignore_internal and is_internal_name(qname)):
            return Outcome.NXDOMAIN.value, ""

    sinkholed = bool(answer_ips) and all(ip in sinkhole_ips for ip in answer_ips)
    resolved = bool(answer_ips) and not sinkholed
    answer_repr = ",".join(answer_ips[:3])

    if rcode == "NOERROR":
        if sinkholed:
            if expect == "allow":
                return Outcome.FALSE_POSITIVE.value, answer_repr
            return Outcome.BLOCKED.value, answer_repr
        if resolved:
            if expect == "block":
                return Outcome.FALSE_NEGATIVE.value, answer_repr
            return Outcome.ALLOWED.value, answer_repr
        # NODATA: a legitimate answer carrying no records.  Normal for a name that
        # exists without an address of the requested type.
        if expect == "block":
            # For a block-listed name this counts as blocked, whatever the query
            # type.  A sinkholing appliance that answers A with 0.0.0.0 cannot put
            # an address in an HTTPS or MX record, so it returns NODATA for those --
            # calling that a leak would fill the findings table with noise from
            # every non-address lookup and bury the number that matters.
            #
            # Known limitation, stated rather than hidden: an appliance that blocks A
            # lookups but *answers* HTTPS records for a blocked name is still leaking
            # connectivity, because an HTTPS record carries the address.  This
            # classifier does not distinguish that case.  Filtering on HTTPS/SVCB
            # types with --qps against a known sinkhole target is the way to test it.
            return Outcome.BLOCKED.value, ""
        return Outcome.ALLOWED.value, ""

    if rcode == "NXDOMAIN":
        if expect == "block":
            return Outcome.BLOCKED.value, ""
        if expect == "nxdomain":
            return Outcome.NXDOMAIN.value, ""
        if expect == "allow":
            return Outcome.FALSE_POSITIVE.value, ""
        return Outcome.NXDOMAIN.value, ""

    if rcode == "REFUSED":
        if expect in ("block", "nxdomain"):
            return Outcome.BLOCKED.value, ""
        # REFUSED is never an acceptable answer for a name that should resolve, and
        # it is not a false positive for a category with no expectation.
        if expect == "allow":
            return Outcome.FALSE_POSITIVE.value, ""
        return Outcome.ERROR.value, ""

    # SERVFAIL / FORMERR / NOTIMP / NOTAUTH / NOTZONE and anything unexpected.
    if expect == "block":
        return Outcome.BLOCKED.value, ""
    if expect == "allow":
        return Outcome.FALSE_POSITIVE.value, ""
    return Outcome.ERROR.value, ""


@dataclass(slots=True)
class _Pending:
    """One outstanding query awaiting a response."""

    qid: int
    sock_index: int
    persona_id: int
    role: str
    client_ip: str
    qname: str
    qtype: str
    category: str
    sent_at: float
    bytes_sent: int
    done: bool = False


@dataclass(slots=True)
class RunResult:
    """What a finished run adds up to, for the CLI and for tests.

    ``send_started_at``/``send_ended_at`` bracket the *sending* window and are
    what ``achieved_qps`` divides by.  Using the whole run instead would include
    the drain at the end, where the pacer has stopped and only stragglers are
    being collected -- on a lossy target that is a second and a half of no traffic,
    which would understate throughput by a third and make a healthy generator look
    like the bottleneck.
    """

    started_at: float
    ended_at: float
    sent: int
    received: int
    timeouts: int
    errors: int
    dropped: int
    malformed: int
    unknown_responses: int
    verdict: dict
    send_started_at: float = 0.0
    send_ended_at: float = 0.0

    @property
    def duration_s(self) -> float:
        """Wall-clock seconds spent sending."""
        if self.send_ended_at and self.send_started_at:
            return self.send_ended_at - self.send_started_at
        return self.ended_at - self.started_at

    @property
    def wall_s(self) -> float:
        """Total time from start to final result, including the drain."""
        return self.ended_at - self.started_at

    @property
    def completed(self) -> int:
        return self.received + self.timeouts + self.errors

    @property
    def achieved_qps(self) -> float:
        duration = self.duration_s
        return self.sent / duration if duration > 0 else 0.0


class _QueryProtocol(asyncio.DatagramProtocol):
    """One connected UDP socket, and the queries outstanding on it.

    The endpoint is created with a remote address, so the socket is connected:
    the kernel discards datagrams from anyone but the appliance under test, which
    keeps a stray responder on the network from polluting the results.  It also
    means an ICMP port-unreachable arrives as ``error_received`` -- the fastest
    possible signal that the target address or port is simply wrong.
    """

    def __init__(self, engine: "DnsLoadEngine", index: int, source_ip: str) -> None:
        self.engine = engine
        self.index = index
        self.source_ip = source_ip
        self.transport: asyncio.DatagramTransport | None = None
        self.pending: dict[int, _Pending] = {}
        self.next_qid = 1

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        self.engine._handle_response(self, data)

    def error_received(self, exc: Exception) -> None:  # type: ignore[override]
        self.engine._handle_socket_error(self, exc)

    def connection_lost(self, exc: Exception | None) -> None:  # type: ignore[override]
        pass

    def alloc_qid(self) -> int:
        """Next unused transaction ID on this socket.  IDs are per-socket, so a
        collision only matters among this socket's outstanding queries."""
        for _ in range(0xFFFF):
            qid = self.next_qid
            self.next_qid = 1 if qid >= 0xFFFF else qid + 1
            if qid not in self.pending:
                return qid
        raise RuntimeError("transaction ID space exhausted: too many queries in flight on one socket")


class DnsLoadEngine:
    """Generates the office's DNS traffic against one target and measures it.

    ``shard_index``/``shard_count`` let several threads split the same logical run
    across cores.  Each shard owns a disjoint slice of the personas and a disjoint
    slice of the sockets, and divides the target rate, so the office as a whole is
    still exactly what was asked for.
    """

    def __init__(
        self,
        config: RunConfig,
        catalogue,
        *,
        stats: StatsAggregator | None = None,
        record_log: RecordLog | None = None,
        model: PersonaModel | None = None,
        shard_index: int = 0,
        shard_count: int = 1,
    ) -> None:
        self.config = config
        self.catalogue = catalogue
        self.stats = stats or StatsAggregator()
        # The verdict and the by-category table must judge by the same expectations
        # classify() used, or they would disagree about what "blocked" means.
        self.stats.set_expectations(config.expectations)
        self.record_log = record_log
        self.shard_index = int(shard_index)
        self.shard_count = max(1, int(shard_count))
        self.rng = random.Random(config.seed + self.shard_index * 7919)

        self.sinkhole_ips = SinkholeSet(config.sinkhole_ips, config.sinkhole_cidrs)

        # Resolve what the appliance will actually see as our source address.
        bind_ips: list[str] = list(config.source_ips) if config.source_ips else [""]
        self._bind_ips = bind_ips
        labels: list[str] = []
        for ip in bind_ips:
            labels.append(ip if ip else detect_local_ip(config.server))
        self._client_labels = labels

        self.model = model or PersonaModel(
            catalogue,
            personas=config.personas,
            source_ips=labels,
            seed=config.seed,
        )
        if model is not None and config.source_ips:
            # A caller-supplied model may have been built with placeholder labels.
            self.model.source_ips = labels

        self._prepare_shard()

        self._protocols: list[_QueryProtocol] = []
        self._order: deque[_Pending] = deque()
        self._inflight = 0
        self._stop = asyncio.Event()
        self._deadline: float | None = None
        self.started_at = 0.0
        self.ended_at = 0.0
        self.send_started_at = 0.0
        self.send_ended_at = 0.0
        # Per-shard counters.  These deliberately do NOT read back from the shared
        # aggregator: with several shards reporting into one aggregator, every
        # shard would otherwise claim credit for the whole office's traffic and a
        # 2-thread run would report double the load it actually generated.
        self._sent = 0
        self._received = 0
        self._timeouts = 0
        self._errors = 0
        self.dropped = 0
        self.malformed = 0
        self.unknown_responses = 0

    # -- sharding -----------------------------------------------------------

    def _prepare_shard(self) -> None:
        """Select this shard's personas and build its arrival distribution.

        ``page_weight`` is ``rate / burst_mean``: the *page* arrival rate, not the
        query rate, because the pacer times page loads.  Getting this wrong would
        make the reported qps drift from the requested qps by the mean burst size.
        """
        personas = [
            p for p in self.model.personas if p.pid % self.shard_count == self.shard_index
        ]
        self._shard_personas = personas
        self._page_cum: list[float] = []
        total = 0.0
        for persona in personas:
            weight = persona.rate_weight / max(persona.burst_mean, 0.01)
            total += weight
            self._page_cum.append(total)
        self._page_total = total

    @property
    def page_rate(self) -> float:
        """Page-loads per second for this shard, derived from the target *query* rate.

        The arithmetic, because getting it wrong silently scales the whole run:
        persona i carries ``qps_i = target * w_i / W`` queries, where ``W`` is the
        sum of every persona's rate weight.  Its page rate is ``qps_i / b_i``, so
        the office's page rate is ``target * sum(w_i / b_i) / W``.  Dividing by
        ``W`` -- not by the office page total -- is what keeps ``--qps`` meaning
        *queries* per second; using the page total instead multiplies the load by
        the mean burst size, which on a real office is roughly 5x.

        For one shard of many, ``sum(w_i / b_i)`` is this shard's share of page
        weights, so the same expression already yields the correct per-shard rate.
        """
        office_rate_weight = self.model.total_weight
        if office_rate_weight <= 0:
            return 0.0
        return self.config.target_qps * self._page_total / office_rate_weight

    def persona_for_arrival(self) -> Persona | None:
        if not self._shard_personas or self._page_total <= 0:
            return None
        target = self.rng.random() * self._page_total
        index = bisect.bisect_left(self._page_cum, target)
        if index >= len(self._shard_personas):
            index = len(self._shard_personas) - 1
        return self._shard_personas[index]

    def burst_size(self, persona: Persona) -> int:
        """Geometric burst size with mean ``persona.burst_mean``.

        ``P(size > k) = (1 - 1/mean) ** k`` gives exactly the role's mean while
        keeping the draw O(mean) in the common case.
        """
        mean = max(persona.burst_mean, 1.0)
        probability = 1.0 / mean
        size = 1
        while size < MAX_BURST and self.rng.random() > probability:
            size += 1
        return size

    # -- socket lifecycle ---------------------------------------------------

    async def _open_sockets(self) -> None:
        loop = asyncio.get_running_loop()
        targets = [(index, ip) for index, ip in enumerate(self._bind_ips)]
        if self.shard_count > 1:
            targets = [t for t in targets if t[0] % self.shard_count == self.shard_index]
            if not targets:
                targets = [(self.shard_index % len(self._bind_ips), self._bind_ips[self.shard_index % len(self._bind_ips)])]

        for index, ip in targets:
            protocol = _QueryProtocol(self, index, ip)
            try:
                await loop.create_datagram_endpoint(
                    lambda p=protocol: p,
                    local_addr=(ip, 0) if ip else None,
                    remote_addr=(self.config.server, self.config.port),
                )
            except OSError as exc:
                self._close_sockets()
                hint = ""
                if ip:
                    hint = (
                        f"\nThe address {ip} is not assigned to any interface on this machine. "
                        f"Pool mode needs the secondary addresses to exist first -- run "
                        f"scripts/New-LabSourceIPs.ps1, or start with the default persona mode "
                        f"(no --source-ips), which uses one address and needs no privileges."
                    )
                raise OSError(f"cannot bind source address {ip or '0.0.0.0'} ({exc.strerror or exc}){hint}") from exc
            self._protocols.append(protocol)

        if not self._protocols:
            raise RuntimeError("no sending sockets were created")

    def _close_sockets(self) -> None:
        for protocol in self._protocols:
            if protocol.transport is not None:
                protocol.transport.close()
                protocol.transport = None
        self._protocols.clear()

    def _protocol_for(self, persona: Persona) -> _QueryProtocol:
        if len(self._protocols) == 1:
            return self._protocols[0]
        index = self._client_labels.index(persona.source_ip) if persona.source_ip in self._client_labels else 0
        for protocol in self._protocols:
            if protocol.index == index:
                return protocol
        return self._protocols[0]

    # -- run control --------------------------------------------------------

    async def run(self) -> RunResult:
        """Run until the duration elapses or :meth:`stop` is called."""
        cfg = self.config
        loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        self.started_at = time.time()
        self.stats.set_state("running")

        if not self._shard_personas:
            raise ValueError(
                "no personas are assigned to this shard; the catalogue has no domains in "
                "any traffic category (fetch the lists with "
                "`python -m dnsloadforge.domainlist --refresh`)"
            )

        await self._open_sockets()
        # An accelerated clock would be wrong here: pacing uses the event loop's own
        # monotonic clock, and the wall-clock deadline is only for the duration.
        self._deadline = loop.time() + cfg.duration_s if cfg.duration_s > 0 else None
        self.send_started_at = time.time()

        pacer = asyncio.create_task(self._pacer(), name="dnsloadforge-pacer")
        sweeper = asyncio.create_task(self._sweeper(), name="dnsloadforge-sweeper")
        try:
            await pacer
            self.send_ended_at = time.time()
            # Drain: the last page's queries were only just sent, and cutting them
            # off would report timeouts that never had a chance to be answered.
            await self._drain(cfg.timeout_s + 0.5)
        finally:
            self._stop.set()
            await self._cancel(pacer)
            await asyncio.sleep(0)  # let the sweeper observe the stop flag
            await self._cancel(sweeper, timeout=2.0)
            self._close_sockets()

        self._expire_all(graceful=True)
        self.ended_at = time.time()
        self.stats.set_state("stopped")
        return self._result()

    async def _cancel(self, task: asyncio.Task, timeout: float = 5.0) -> None:
        if task.done():
            return
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=timeout)
        except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
            pass

    async def _drain(self, grace: float) -> None:
        """Wait for outstanding queries to come back, then expire what is left."""
        deadline = time.time() + max(grace, 0.0)
        while self._inflight > 0 and time.time() < deadline and not self._stop.is_set():
            await asyncio.sleep(0.02)
        self._expire_all()

    def _expire_all(self, graceful: bool = False) -> None:
        """Attribute every still-outstanding query.

        On a graceful shutdown a pending query is a genuine timeout: it was sent
        and never answered.  That is a finding, so it is recorded as one rather
        than discarded.
        """
        now = time.time()
        while self._order:
            pending = self._order.popleft()
            if pending.done:
                continue
            pending.done = True
            protocol = self._protocol_at(pending.sock_index)
            if protocol is not None:
                protocol.pending.pop(pending.qid, None)
            self._inflight = max(0, self._inflight - 1)
            self._finalize(pending, RCODE_TIMEOUT, Outcome.TIMEOUT.value, 0.0, "", 0, now)

    def _protocol_at(self, index: int) -> _QueryProtocol | None:
        for protocol in self._protocols:
            if protocol.index == index:
                return protocol
        return None

    def stop(self) -> None:
        """Ask the run to end.  Safe to call from the event loop or a signal
        handler; the pacer notices on its next arrival."""
        try:
            self._stop.set()
        except RuntimeError:
            pass

    @property
    def running(self) -> bool:
        return not self._stop.is_set() and self.started_at > 0 and self.ended_at == 0

    # -- the two loops ------------------------------------------------------

    async def _pacer(self) -> None:
        """Emit page arrivals at the target rate."""
        cfg = self.config
        loop = asyncio.get_running_loop()
        base_rate = self.page_rate
        if base_rate <= 0:
            return
        next_at = loop.time()
        burst_modulus = self._burst_window_seconds

        while not self._stop.is_set():
            now = loop.time()
            if self._deadline is not None and now >= self._deadline:
                break

            rate = base_rate
            if cfg.qps_burst > 1.0 and burst_modulus > 0:
                # A synchronised event -- everyone opens mail at the top of the
                # hour.  Appliance CPU and per-second policy counters fail here far
                # more often than they fail at the average rate.
                if now % cfg.qps_burst_period_s < cfg.qps_burst_len_s:
                    rate = base_rate * cfg.qps_burst

            next_at += self.rng.expovariate(rate) if rate > 0 else 1.0
            delay = next_at - loop.time()
            if delay > 0:
                await asyncio.sleep(delay)
            elif delay < -1.0:
                # More than a second behind: the target rate is not achievable.
                # Resync instead of replaying the backlog, which would produce a
                # meaningless burst and flatter or wreck the measurement.
                next_at = loop.time()

            if cfg.dry_run:
                self._dry_emit()
            else:
                self._emit_page()

    @property
    def _burst_window_seconds(self) -> float:
        return max(float(self.config.qps_burst_period_s), 0.0)

    def _dry_emit(self) -> None:
        """Benchmark path: build packets but never touch the network.

        This separates "can the box generate this rate" from "can the network and
        the appliance carry it", which are the two things an operator needs to
        tell apart before blaming anyone.

        Counts every query in the burst, not the burst itself -- ``--qps`` means
        queries per second, so counting pages here would report the rate divided
        by the mean burst size and understate the machine by roughly 5x.
        """
        persona = self.persona_for_arrival()
        if persona is None:
            return
        total = 0
        emitted = 0
        for _ in range(self.burst_size(persona)):
            qname, qtype, _category = self.model.next_query(persona, self.rng)
            try:
                packet, _qid = encode_query(qname, qtype)
            except DNSError:
                continue
            total += len(packet)
            emitted += 1
        if emitted:
            self._sent += emitted
            self.stats.on_send(emitted, total, inflight=False)

    def _emit_page(self) -> None:
        """Send one persona's burst of lookups."""
        persona = self.persona_for_arrival()
        if persona is None:
            return
        protocol = self._protocol_for(persona)
        transport = protocol.transport
        if transport is None:
            return

        size = self.burst_size(persona)
        now = time.time()
        sent_bytes = 0
        emitted = 0
        capacity = self.config.max_inflight - self._inflight

        for _ in range(size):
            if capacity <= 0:
                # Drops are a sender-side event and stay out of the error counters:
                # a query that was never sent is not a query the appliance failed.
                self.dropped += size - emitted
                self.stats.on_drop(size - emitted)
                break
            capacity -= 1

            qname, qtype, category = self.model.next_query(persona, self.rng)
            qid = protocol.alloc_qid()
            try:
                packet, qid = encode_query(qname, qtype, qid)
            except DNSError:
                continue

            pending = _Pending(
                qid=qid,
                sock_index=protocol.index,
                persona_id=persona.pid,
                role=persona.role,
                client_ip=persona.source_ip,
                qname=qname,
                qtype=qtype,
                category=category,
                sent_at=now,
                bytes_sent=len(packet),
            )
            protocol.pending[qid] = pending
            self._order.append(pending)
            self._inflight += 1
            try:
                transport.sendto(packet)
            except OSError:
                # The socket died mid-run (adapter reset). Attribute it rather than
                # crashing, so the report still tells the operator what happened.
                pending.done = True
                protocol.pending.pop(qid, None)
                self._inflight = max(0, self._inflight - 1)
                self._finalize(pending, RCODE_ERROR, Outcome.ERROR.value, 0.0, "", 0, now)
                continue
            sent_bytes += len(packet)
            emitted += 1

        if emitted:
            self._sent += emitted
            self.stats.on_send(emitted, sent_bytes, now)

    async def _sweeper(self) -> None:
        """Expire queries that were never answered.

        The pending deque is in send order, so it is already sorted by deadline and
        the sweep is O(1) amortised -- no timer wheel, no per-query handle.
        """
        timeout = max(self.config.timeout_s, 0.01)
        interval = min(0.1, max(timeout / 4.0, 0.005))
        while not self._stop.is_set():
            await asyncio.sleep(interval)
            if not self._order:
                continue
            now = time.time()
            while self._order:
                pending = self._order[0]
                if pending.done:
                    self._order.popleft()
                    continue
                if now - pending.sent_at < timeout:
                    break
                self._order.popleft()
                pending.done = True
                protocol = self._protocol_at(pending.sock_index)
                if protocol is not None:
                    protocol.pending.pop(pending.qid, None)
                self._inflight = max(0, self._inflight - 1)
                self._finalize(pending, RCODE_TIMEOUT, Outcome.TIMEOUT.value, 0.0, "", 0, now)

    # -- response handling --------------------------------------------------

    def _handle_response(self, protocol: _QueryProtocol, data: bytes) -> None:
        try:
            message = decode_message(data)
        except DNSError:
            # No transaction ID means no way to attribute it to a query, so it
            # cannot be scored.  Counted separately so a garbage-spewing appliance
            # is visible rather than silently ignored.
            self.malformed += 1
            return

        pending = protocol.pending.pop(message.qid, None)
        if pending is None or pending.done:
            self.unknown_responses += 1
            return

        pending.done = True
        self._inflight = max(0, self._inflight - 1)
        latency_ms = (time.time() - pending.sent_at) * 1000.0
        rcode = message.rcode_name
        outcome, answer_repr = classify(
            pending.category,
            rcode,
            message.answer_ips,
            self.sinkhole_ips,
            self.config.expect_for(pending.category),
            qname=pending.qname,
            ignore_internal=self.config.ignore_internal,
        )
        self._finalize(
            pending,
            rcode,
            outcome,
            latency_ms,
            answer_repr,
            message.raw_len,
            time.time(),
        )

    def _handle_socket_error(self, protocol: _QueryProtocol, exc: Exception) -> None:
        """A connected UDP socket told us the far end is unreachable.

        Windows reports ICMP port-unreachable this way, which is the fastest
        possible way to discover that the target address or port is wrong.  Every
        outstanding query on the socket is doomed, so they are all attributed at
        once instead of being left to time out over the next few seconds.
        """
        now = time.time()
        for qid in list(protocol.pending):
            pending = protocol.pending.pop(qid, None)
            if pending is None or pending.done:
                continue
            pending.done = True
            self._inflight = max(0, self._inflight - 1)
            self._finalize(pending, RCODE_ERROR, Outcome.ERROR.value, 0.0, "", 0, now)

    def _finalize(
        self,
        pending: _Pending,
        rcode: str,
        outcome: str,
        latency_ms: float,
        answer_repr: str,
        bytes_received: int,
        now: float,
    ) -> None:
        """The single place a completed query is recorded.  Keeping it in one
        method is what guarantees ``rates``, ``by_category`` and ``verdict`` can
        never disagree about how many queries happened."""
        if outcome == Outcome.TIMEOUT.value:
            self._timeouts += 1
        elif outcome == Outcome.ERROR.value:
            self._errors += 1
        else:
            self._received += 1
        self.stats.on_result(
            qname=pending.qname,
            client_ip=pending.client_ip,
            category=pending.category,
            qtype=pending.qtype,
            rcode=rcode,
            outcome=outcome,
            latency_ms=latency_ms,
            bytes_received=bytes_received,
            answer_ip=answer_repr,
            now=now,
        )
        if self.record_log is not None:
            # Written on completion, not on send, because a record log with no
            # result column cannot answer the only question it exists for: what
            # happened to each query.  Field order is spec.RECORD_FIELDS, which
            # RecordLog relies on when reading records back; tests pin the mapping.
            self.record_log.write(
                (
                    now,
                    pending.client_ip,
                    pending.persona_id,
                    pending.role,
                    pending.qname,
                    pending.qtype,
                    pending.category,
                    rcode,
                    outcome,
                    latency_ms,
                    answer_repr,
                    pending.bytes_sent,
                    bytes_received,
                )
            )

    def _result(self) -> RunResult:
        return RunResult(
            started_at=self.started_at,
            ended_at=self.ended_at or time.time(),
            sent=self._sent,
            received=self._received,
            timeouts=self._timeouts,
            errors=self._errors,
            dropped=self.dropped,
            malformed=self.malformed,
            unknown_responses=self.unknown_responses,
            verdict=self.stats.snapshot().get("verdict", {}),
            send_started_at=self.send_started_at,
            send_ended_at=self.send_ended_at,
        )

    def snapshot(self) -> dict:
        return self.stats.snapshot()


# ---------------------------------------------------------------------------
# Multi-threaded front end
# ---------------------------------------------------------------------------


def run_threaded(
    config: RunConfig,
    catalogue,
    *,
    stats: StatsAggregator,
    record_log: RecordLog | None = None,
    threads: int = 1,
    on_finish=None,
    on_engine=None,
) -> list[RunResult]:
    """Run the same logical simulation across several threads.

    Python's event loop uses one core, so a single process tops out well below what
    a 16-thread box can push.  Sharding splits personas, sockets and the target
    rate evenly, and every shard reports into the same locked aggregator, so the
    dashboard sees one coherent office rather than N independent runs.

    ``threads=1`` still goes through here, running on the calling thread, so there
    is only one code path to trust.
    """
    threads = max(1, int(threads))
    results: list[RunResult | None] = [None] * threads
    errors: list[BaseException | None] = [None] * threads

    def worker(index: int) -> None:
        engine = DnsLoadEngine(
            config,
            catalogue,
            stats=stats,
            record_log=record_log,
            shard_index=index,
            shard_count=threads,
        )
        # Handed back before the run starts so the caller can stop it later; a
        # controller that could not reach a running engine could not stop a run
        # at all, which for a load generator aimed at production is unacceptable.
        if on_engine is not None:
            on_engine(engine)
        try:
            results[index] = asyncio.run(engine.run())
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller's thread
            errors[index] = exc

    if threads == 1:
        worker(0)
    else:
        # Sockets are bound per thread, so use one thread per shard and let the
        # kernel schedule them; oversubscribing an event loop gains nothing.
        pool = [
            threading.Thread(target=worker, args=(index,), name=f"dnsloadforge-{index}", daemon=True)
            for index in range(threads)
        ]
        for thread in pool:
            thread.start()
        for thread in pool:
            thread.join()

    for exc in errors:
        if exc is not None:
            raise exc

    if on_finish is not None:
        on_finish([r for r in results if r is not None])
    return [r for r in results if r is not None]
