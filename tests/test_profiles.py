"""Office model tests.

These use a synthetic catalogue rather than the real cached lists.  Two reasons:
the real cache is 1.5 million domains and takes 16 seconds to load, which is not
something a unit test should do, and a fake catalogue with known contents lets the
assertions be exact instead of approximate.

The assertions that earn their keep are the *invariants*: the roster is exactly
10,000 people, every role's mix is a proper distribution, and a seeded model
produces an identical sequence of queries twice -- because two validation runs
against the same appliance have to be comparable or the whole exercise is
guesswork.
"""

from __future__ import annotations

import pathlib
import random
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from dnsloadforge.domainlist import DomainCatalogue, DomainPool  # noqa: E402
from dnsloadforge.profiles import (  # noqa: E402
    ROLES,
    ROLE_TOTAL_HEADCOUNT,
    TRAFFIC_CATEGORIES,
    PersonaModel,
    _normalise,
    diurnal_factor,
)
from dnsloadforge.spec import QTYPES, Category  # noqa: E402


def fake_catalogue() -> DomainCatalogue:
    """A small catalogue with every traffic category populated, so no role is
    filtered out for lack of domains."""
    pools: dict[str, DomainPool] = {}
    for category in Category:
        pools[category.value] = DomainPool(category=category.value, source="synthetic")
    for index, category in enumerate(TRAFFIC_CATEGORIES):
        domains = [f"{category}-{n:03d}.example.com" for n in range(40)]
        weights = [1.0 / (n + 1) for n in range(40)]
        pools[category] = DomainPool(
            category=category, domains=domains, weights=weights, source="synthetic", ranked=False
        )
    # 20 enterprise-style SRV/PTR names, mirroring the curated list.
    pools[Category.ENTERPRISE.value] = DomainPool(
        category=Category.ENTERPRISE.value,
        domains=[f"host{n:02d}.corp.local" for n in range(20)],
        weights=[1.0] * 20,
        source="synthetic",
    )
    return DomainCatalogue(pools=pools, fetched_at=1.0, offline=True)


class TestRoster(unittest.TestCase):
    def test_headcount_is_exactly_ten_thousand(self) -> None:
        self.assertEqual(sum(role.headcount_weight for role in ROLES.values()), 10_000)
        self.assertEqual(ROLE_TOTAL_HEADCOUNT, 10_000)

    def test_every_role_mix_is_a_proper_distribution(self) -> None:
        for name, role in ROLES.items():
            with self.subTest(role=name):
                categories = _normalise(role.category_mix)
                self.assertAlmostEqual(sum(categories.values()), 1.0, places=9)
                self.assertTrue(set(categories) <= set(TRAFFIC_CATEGORIES) or Category.ENTERPRISE.value in categories)

                qtypes = _normalise(role.qtype_mix)
                self.assertAlmostEqual(sum(qtypes.values()), 1.0, places=9)
                self.assertTrue(set(qtypes) <= set(QTYPES), f"unknown qtype in {name}: {set(qtypes) - set(QTYPES)}")

    def test_role_defaults_are_sane(self) -> None:
        for name, role in ROLES.items():
            with self.subTest(role=name):
                self.assertGreater(role.rate_weight, 0)
                self.assertGreaterEqual(role.burst_mean, 1.0)
                self.assertLessEqual(role.hot_set_min, role.hot_set_max)
                self.assertGreater(role.hot_set_min, 0)

    def test_roles_that_must_resolve_are_the_high_value_ones(self) -> None:
        """The enterprise and server roles lean hardest on names whose blocking
        causes an outage, which is what makes them worth simulating at scale."""
        for name in ("server_infra", "iot_device", "helpdesk_it"):
            share = ROLES[name].category_mix[Category.ENTERPRISE.value]
            self.assertGreater(share, 0.15, f"{name} should care a lot about enterprise names")

    def test_normalise_rejects_bad_input(self) -> None:
        self.assertEqual(_normalise({"a": 1, "b": 1}), {"a": 0.5, "b": 0.5})
        with self.assertRaises(ValueError):
            _normalise({"a": 0})
        with self.assertRaises(ValueError):
            _normalise({"a": -1})


class TestDiurnal(unittest.TestCase):
    def test_curve_shape(self) -> None:
        self.assertAlmostEqual(diurnal_factor(10), 1.0, places=6)
        self.assertLess(diurnal_factor(3), 0.1)
        self.assertLess(diurnal_factor(3), diurnal_factor(9))
        self.assertGreater(diurnal_factor(9), diurnal_factor(13), "lunch should dip")
        self.assertGreater(diurnal_factor(13), diurnal_factor(20))

    def test_stays_in_range_and_wraps(self) -> None:
        for hour in (0.0, 6.5, 12.25, 23.99, 24.0, 25.0, -1.0):
            value = diurnal_factor(hour)
            self.assertGreaterEqual(value, 0.03)
            self.assertLessEqual(value, 1.0)

    def test_interpolates_between_hours(self) -> None:
        low, high = diurnal_factor(7), diurnal_factor(8)
        mid = diurnal_factor(7.5)
        self.assertTrue(min(low, high) <= mid <= max(low, high))


class TestPersonaModel(unittest.TestCase):
    def setUp(self) -> None:
        self.catalogue = fake_catalogue()

    def model(self, **kwargs) -> PersonaModel:
        params = dict(personas=300, source_ips=["10.0.0.5"], seed=42)
        params.update(kwargs)
        return PersonaModel(self.catalogue, **params)

    def test_builds_the_requested_number_of_personas(self) -> None:
        model = self.model()
        self.assertEqual(model.persona_count, 300)
        self.assertEqual(sum(model.counts_by_role().values()), 300)

    def test_headcount_follows_the_roster_ratio(self) -> None:
        counts = self.model(personas=10_000).counts_by_role()
        self.assertEqual(sum(counts.values()), 10_000)
        # The single largest role in the roster is the knowledge worker.
        self.assertEqual(max(counts, key=counts.get), "knowledge_worker")
        self.assertAlmostEqual(counts["knowledge_worker"] / 10_000, 0.38, delta=0.01)

    def test_only_requested_roles_are_used(self) -> None:
        model = self.model(roles=["developer", "call_center"])
        self.assertEqual(set(model.counts_by_role()), {"developer", "call_center"})

    def test_unknown_role_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.model(roles=["astronaut"])

    def test_should_be_deterministic_for_a_given_seed(self) -> None:
        """Comparability between runs is the whole point of the seed."""
        first, second = self.model(), self.model()
        draws_a = [first.next_query(first.choose_persona()) for _ in range(400)]
        draws_b = [second.next_query(second.choose_persona()) for _ in range(400)]
        self.assertEqual(draws_a, draws_b)

    def test_different_seeds_diverge(self) -> None:
        first, second = self.model(), self.model(seed=43)
        draws_a = [first.next_query(first.choose_persona()) for _ in range(200)]
        draws_b = [second.next_query(second.choose_persona()) for _ in range(200)]
        self.assertNotEqual(draws_a, draws_b)

    def test_hot_sets_match_the_role_bounds(self) -> None:
        model = self.model()
        for persona in model.personas:
            role = ROLES[persona.role]
            with self.subTest(role=persona.role):
                self.assertGreaterEqual(len(persona.hot), min(role.hot_set_min, len(persona.hot)))
                self.assertLessEqual(len(persona.hot), role.hot_set_max)
                self.assertEqual(len(set(persona.hot)), len(persona.hot), "hot set must not repeat a domain")

    def test_queries_are_classifiable(self) -> None:
        model = self.model()
        categories = set()
        for _ in range(3000):
            qname, qtype, category = model.next_query(model.choose_persona())
            self.assertTrue(qname)
            self.assertNotIn(" ", qname)
            self.assertIn(qtype.split(".")[-1], QTYPES)
            self.assertIn(category, {c.value for c in Category})
            categories.add(category)
        # A realistic office touches allow, enterprise, borderline and block names.
        self.assertIn(Category.ALLOW_POPULAR.value, categories)
        self.assertIn(Category.ENTERPRISE.value, categories)
        self.assertTrue(categories & {Category.BLOCK_ADS.value, Category.BLOCK_MALWARE.value})
        self.assertIn(Category.NXDOMAIN_PROBE.value, categories)

    def test_repeat_traffic_dominates_over_new_names(self) -> None:
        """Caching is real: most lookups should be names the client already knows,
        or every simulated client looks like it has an empty cache."""
        model = self.model(hot_share=0.7, nxdomain_share=0.0)
        repeats = new = 0
        for _ in range(4000):
            persona = model.choose_persona()
            qname, _qtype, _category = model.next_query(persona)
            if qname in persona.hot:
                repeats += 1
            else:
                new += 1
        self.assertGreater(repeats, new)

    def test_junk_probes_look_like_junk(self) -> None:
        model = self.model()
        reserved = 0
        for _ in range(1000):
            name = model.dga_name()
            self.assertIn(".", name)
            label, tld = name.rsplit(".", 1)
            self.assertGreaterEqual(len(label), 8)
            self.assertTrue(label.isalnum())
            self.assertTrue(label.islower())
            if tld in ("invalid", "test", "example"):
                reserved += 1
        self.assertGreater(reserved, 50, "a deterministic share of probes should use reserved TLDs")

    def test_rate_shares_sum_to_the_target(self) -> None:
        model = self.model(personas=1000)
        total = sum(model.rate_of(persona, 10_000.0) for persona in model.personas)
        self.assertAlmostEqual(total, 10_000.0, places=6)

    def test_summary_reports_the_office(self) -> None:
        model = self.model(personas=1000)
        rows = model.summary(target_qps=10_000.0)
        self.assertEqual(sum(row["headcount"] for row in rows), 1000)
        self.assertAlmostEqual(sum(row["qps"] for row in rows), 10_000.0, places=3)
        self.assertAlmostEqual(sum(row["share"] for row in rows), 1.0, places=9)
        for row in rows:
            self.assertGreater(row["qph_per_client"], 0)

    def test_queries_per_client_hour_is_an_office_plausible_number(self) -> None:
        model = self.model(personas=10_000)
        self.assertAlmostEqual(model.queries_per_client_hour(10_000.0), 3600.0, places=6)

    def test_source_addresses_are_shared_out(self) -> None:
        model = self.model(personas=10, source_ips=["10.1.0.1", "10.1.0.2", "10.1.0.3"])
        used = {persona.source_ip for persona in model.personas}
        self.assertEqual(used, {"10.1.0.1", "10.1.0.2", "10.1.0.3"})

    def test_an_empty_catalogue_is_reported_not_silently_faked(self) -> None:
        """Better to refuse than to invent hostnames that are not in any list."""
        empty = DomainCatalogue(
            pools={c.value: DomainPool(category=c.value) for c in Category}, fetched_at=0.0
        )
        with self.assertRaises(ValueError):
            PersonaModel(empty, personas=10)

    def test_roles_with_no_available_traffic_are_dropped(self) -> None:
        """A first offline run only has curated lists, so roles that depend on
        missing categories must be skipped rather than fed placeholder names."""
        thin = DomainCatalogue(
            pools={
                **{c.value: DomainPool(category=c.value) for c in Category},
                Category.ALLOW_POPULAR.value: DomainPool(
                    category=Category.ALLOW_POPULAR.value, domains=["a.example.com"], weights=[1.0]
                ),
            },
            fetched_at=0.0,
        )
        model = PersonaModel(thin, personas=50, seed=1, nxdomain_share=0.0)
        self.assertEqual(model.persona_count, 50)
        for _ in range(50):
            qname, _qtype, category = model.next_query(model.choose_persona())
            self.assertEqual(category, Category.ALLOW_POPULAR.value)
            self.assertEqual(qname, "a.example.com")

    def test_every_hot_domain_carries_its_own_category(self) -> None:
        """Regression guard.  The category reported for a query must describe the
        name that was actually queried, or a block-listed lookup gets attributed to
        an allow-listed category and the report invents a false positive against a
        filter that behaved correctly."""
        model = self.model()
        for persona in model.personas:
            for domain in persona.hot:
                with self.subTest(domain=domain):
                    expected = self.catalogue.category_of(domain)
                    self.assertIsNotNone(expected, f"{domain} is in a hot set but in no pool")
                    self.assertEqual(persona.hot_cats.get(domain), expected)

    def test_a_hot_lookup_reports_the_category_of_the_name_it_returns(self) -> None:
        """The end-to-end form of the same guard: over many repeat-set draws, the
        returned category must always match the returned name."""
        model = self.model(hot_share=1.0, nxdomain_share=0.0)
        for _ in range(2000):
            persona = model.choose_persona()
            qname, _qtype, category = model.next_query(persona)
            self.assertEqual(category, self.catalogue.category_of(qname), f"{qname} misattributed as {category}")

    def test_hot_share_one_confines_lookups_to_the_repeat_set(self) -> None:
        """The mirror of the repeat-traffic test: with no fresh-draw allowance at
        all, every name must come from the persona's own repertoire."""
        model = self.model(hot_share=1.0, nxdomain_share=0.0)
        for _ in range(500):
            persona = model.choose_persona()
            qname, _qtype, _category = model.next_query(persona)
            self.assertIn(qname, persona.hot)

    def test_choose_persona_is_weighted_by_role(self) -> None:
        rng = random.Random(7)
        model = self.model(roles=["server_infra", "kiosk_shared"], personas=2000, seed=7)
        picks = [model.choose_persona(rng).role for _ in range(4000)]
        # server_infra has 3x the rate weight of kiosk_shared but a tenth the seats.
        counts = {name: picks.count(name) for name in set(picks)}
        self.assertEqual(set(counts), {"server_infra", "kiosk_shared"})
        ratio = counts["server_infra"] / counts["kiosk_shared"]
        seat_ratio = model.counts_by_role()["server_infra"] / model.counts_by_role()["kiosk_shared"]
        self.assertGreater(ratio, seat_ratio, "the higher-rate role must be picked more often than its seats imply")


if __name__ == "__main__":
    unittest.main()
