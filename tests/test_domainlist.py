"""Offline tests for ``dnsloadforge.domainlist``.

Every test here must pass with the network cable pulled: they use the committed
fixtures and hand-seeded cache directories, and one test asserts that the
``offline=True`` path never calls ``urllib`` at all.  Run with:

    cd DnsLoadForge/src && python -m unittest discover -s ../tests -t . -v
"""

from __future__ import annotations

import io
import json
import math
import pathlib
import random
import sys
import tempfile
import time
import unittest
import urllib.request
import zipfile
from unittest import mock

# Make the package importable no matter which directory the tests run from.
_SRC = pathlib.Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from dnsloadforge import curated  # noqa: E402
from dnsloadforge import domainlist as dl  # noqa: E402

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def seed_cache(cache_dir: pathlib.Path, slug: str, domains: list[str], category: str) -> None:
    """Write a cache file plus manifest entry, so ``offline=True`` finds it."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / f"{slug}.txt").write_text("\n".join(domains) + "\n", encoding="utf-8")
    manifest_path = cache_dir / "manifest.json"
    manifest: dict = {}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[slug] = {
        "url": f"http://example.invalid/{slug}",
        "category": category,
        "format": "auto",
        "fetched_at": time.time(),
        "count": len(domains),
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


class TempCacheTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cache = pathlib.Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def catalogue(self, **kwargs):
        kwargs.setdefault("offline", True)
        return dl.load_catalogue(self.cache, verbose=False, **kwargs)


# ---------------------------------------------------------------------------
# normalisation and validation
# ---------------------------------------------------------------------------


class TestNormalisation(unittest.TestCase):
    def test_collapses_spellings_to_one_form(self) -> None:
        for raw in (
            "Example.COM",
            "example.com.",
            "  example.com  ",
            "*.example.com",
            ".example.com",
            "example.com/path/to/thing",
        ):
            self.assertEqual(dl.normalise_domain(raw), "example.com", msg=raw)

    def test_strips_adblock_syntax(self) -> None:
        self.assertEqual(dl.normalise_domain("||ads.example.com^"), "ads.example.com")
        self.assertEqual(
            dl.normalise_domain("||ads.example.com^$third-party"), "ads.example.com"
        )

    def test_empty_input(self) -> None:
        self.assertEqual(dl.normalise_domain("   "), "")
        self.assertEqual(dl.normalise_domain("#"), "")

    def test_is_valid_domain_accepts_real_shapes(self) -> None:
        for name in (
            "example.com",
            "a.b.c.example.co.uk",
            "xn--bcher-kva.example",
            "_ldap._tcp.corp.local",
            "7.106.1.10.in-addr.arpa",
            "wsus01.corp.local",
            "cdn-1.edge.example.com",
        ):
            self.assertTrue(dl.is_valid_domain(name), msg=name)

    def test_is_valid_domain_rejects_debris(self) -> None:
        for name in (
            "",
            "singlelabel",
            "1.2.3.4",
            "94.45.46.46",
            "example.com:8080",
            "2001:db8::1",
            "-leading.example.com",
            "trailing-.example.com",
            "double..dot.example.com",
            "a" * 64 + ".example.com",
            "with space.example.com",
            "example.123",
        ):
            self.assertFalse(dl.is_valid_domain(name), msg=name)

    def test_is_ip_token(self) -> None:
        self.assertTrue(dl._is_ip_token("0.0.0.0"))
        self.assertTrue(dl._is_ip_token("127.0.0.1"))
        self.assertTrue(dl._is_ip_token("::1"))
        self.assertFalse(dl._is_ip_token("example.com"))
        self.assertFalse(dl._is_ip_token("999.1.1.1"))


# ---------------------------------------------------------------------------
# parsers
# ---------------------------------------------------------------------------


class TestParsers(unittest.TestCase):
    def test_hosts_format(self) -> None:
        self.assertEqual(
            dl.parse_payload(fixture("hosts_block.txt"), "hosts"),
            [
                "ads.example-blocked.com",
                "tracker.example-blocked.com",
                "two.example-blocked.com",
                "also.example-blocked.com",
                "v6.example-blocked.com",
                "upper.example-blocked.com",
                "has-path.example.com",
                "_ldap._tcp.corp.local",
                "7.106.1.10.in-addr.arpa",
            ],
        )

    def test_plain_format_including_abp_lines_and_debris(self) -> None:
        self.assertEqual(
            dl.parse_payload(fixture("plain_domains.txt"), "plain"),
            [
                "example-allowed.com",
                "cdn.example-allowed.com",
                "spaced.example-allowed.com",
                "trailing-dot.example-allowed.com",
                "adblock-style.example-blocked.com",
                "with-modifier.example-blocked.com",
                "upper-plain.example-allowed.com",
                "mixed.under_score.example.com",
                "www.valid-with-underscore.example.com",
                "plain.example-allowed.com",
            ],
        )

    def test_abp_format(self) -> None:
        self.assertEqual(
            dl.parse_payload("||a.example^$third-party\n||b.example^\nc.example", "abp"),
            ["a.example", "b.example", "c.example"],
        )

    def test_comments_and_blanks_produce_nothing(self) -> None:
        self.assertEqual(dl.parse_payload("# a comment\n\n  \n! adblock comment\n", "plain"), [])

    def test_rank_csv_without_header_uses_last_column(self) -> None:
        self.assertEqual(
            dl.parse_payload(fixture("rank_umbrella.csv"), "rank_csv"),
            [
                "google.com",
                "facebook.com",
                "youtube.com",
                "upper-case.example.com",
                "trailing.example.com",
            ],
        )

    def test_rank_csv_with_header_finds_the_domain_column(self) -> None:
        # Majestic puts Domain in column 3 behind a header row.
        self.assertEqual(
            dl.parse_payload(fixture("rank_majestic.csv"), "rank_csv"),
            ["google.com", "facebook.com", "youtube.com"],
        )

    def test_rank_csv_header_variants(self) -> None:
        for header in ("Domain Name", "hostname", "Host"):
            payload = f"rank,{header},extra\n1,example.com,x\n"
            self.assertEqual(dl.parse_payload(payload, "rank_csv"), ["example.com"], msg=header)

    def test_rank_csv_skips_hash_lines(self) -> None:
        self.assertEqual(dl.parse_payload("# generated\n1,a.example\n", "rank_csv"), ["a.example"])

    def test_order_is_preserved_and_domains_deduplicated(self) -> None:
        payload = "b.example\nA.example\na.example\nc.example\n"
        self.assertEqual(dl.parse_payload(payload, "plain"), ["b.example", "a.example", "c.example"])

    def test_multi_domain_hosts_line(self) -> None:
        self.assertEqual(
            dl.parse_payload("0.0.0.0 one.example two.example three.example\n", "hosts"),
            ["one.example", "two.example", "three.example"],
        )


class TestDecodeDownload(unittest.TestCase):
    def test_plain_payload(self) -> None:
        self.assertEqual(dl.decode_download(b"a.example\n", "http://x/y.txt"), "a.example\n")

    def test_utf8_bom_is_removed(self) -> None:
        self.assertEqual(dl.decode_download("\ufeffa.example\n".encode("utf-8"), "http://x/y.txt"), "a.example\n")

    def test_zip_payload_prefers_the_csv_over_a_readme(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("readme.txt", "this is not a domain list\n")
            archive.writestr("top-1m.csv", "1,google.com\n2,facebook.com\n")
        data = buffer.getvalue()

        text = dl.decode_download(data, "http://x/top-1m.csv.zip")
        self.assertIn("google.com", text)
        self.assertEqual(dl.parse_payload(text, "rank_csv"), ["google.com", "facebook.com"])

    def test_zip_detected_by_magic_bytes_even_without_an_extension(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("list.csv", "1,google.com\n")
        text = dl.decode_download(buffer.getvalue(), "http://x/download")
        self.assertEqual(dl.parse_payload(text, "rank_csv"), ["google.com"])

    def test_empty_zip_raises(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w"):
            pass
        with self.assertRaises(ValueError):
            dl.decode_download(buffer.getvalue(), "http://x/empty.zip")


# ---------------------------------------------------------------------------
# pools, weights and sampling
# ---------------------------------------------------------------------------


class TestPools(unittest.TestCase):
    def test_sample_is_deterministic_for_a_seed(self) -> None:
        pool = dl.DomainPool(
            category="block_ads",
            domains=[f"d{i}.example" for i in range(50)],
            weights=[1.0] * 50,
        )
        first = [pool.sample(random.Random(42)) for _ in range(25)]
        second = [pool.sample(random.Random(42)) for _ in range(25)]
        third = [pool.sample(random.Random(43)) for _ in range(25)]
        self.assertEqual(first, second)
        self.assertNotEqual(first, third)

    def test_single_domain_pool_always_returns_that_domain(self) -> None:
        pool = dl.DomainPool(category="enterprise", domains=["only.example"], weights=[1.0])
        self.assertEqual(pool.sample(random.Random(1)), "only.example")

    def test_empty_pool_sample_raises_with_guidance(self) -> None:
        pool = dl.DomainPool(category="allow_popular")
        self.assertEqual(len(pool), 0)
        with self.assertRaises(ValueError) as ctx:
            pool.sample(random.Random(1))
        self.assertIn("allow_popular", str(ctx.exception))

    def test_weighted_sampling_favours_the_head(self) -> None:
        """A Zipf-weighted pool must draw the #1 domain far more often than a
        uniform sample would -- this is what makes the traffic look real.

        Arithmetic: the total weight of 2001 Zipf ranks is sum(1/sqrt(k)) for
        k=1..2001, about 2*sqrt(2001) = 89.4, so the head has probability ~1.1%
        and 4000 draws should hit it roughly 45 times.  A uniform pool of 2001
        domains would hit it about twice.  The bar is set at 12: comfortably
        above uniform noise, comfortably below the true expectation, so the test
        fails on a broken sampler without being flaky.
        """
        pool = dl.DomainPool(
            category="allow_popular",
            domains=["top.example"] + [f"d{i}.example" for i in range(2000)],
            weights=[1.0 / math.sqrt(rank + 1) for rank in range(2001)],
        )
        rng = random.Random(7)
        draws = [pool.sample(rng) for _ in range(4000)]
        head_hits = draws.count("top.example")
        self.assertGreater(head_hits, 12, msg=f"head drawn {head_hits} times; uniform would be ~2")
        self.assertLess(head_hits, 120, msg=f"head drawn {head_hits} times; expected ~45")


class TestCatalogueAssembly(TempCacheTestCase):
    def test_all_nine_categories_always_exist(self) -> None:
        catalogue = self.catalogue()
        self.assertEqual(len(catalogue.pools), 9)
        self.assertEqual(len(catalogue.counts()), 9)
        self.assertEqual(len(catalogue.summary()), 9)

    def test_curated_pools_load_with_an_empty_cache(self) -> None:
        catalogue = self.catalogue()
        self.assertTrue(catalogue.has("enterprise"))
        self.assertTrue(catalogue.has("borderline"))
        self.assertGreater(catalogue.total(), 100)

        enterprise = {d.lower() for d in curated.ENTERPRISE_DOMAINS}
        borderline = {d.lower() for d in curated.BORDERLINE_DOMAINS}
        # Enterprise outranks borderline, so every enterprise name survives.
        self.assertEqual(catalogue.counts()["enterprise"], len(enterprise))
        self.assertEqual(catalogue.counts()["borderline"], len(borderline))

        for expected in (
            "login.microsoftonline.com",
            "_ldap._tcp.corp.local",
            "download.windowsupdate.com",
            "7.106.1.10.in-addr.arpa",
        ):
            self.assertIn(expected, catalogue.domains_for("enterprise"), msg=expected)
        self.assertIn("graph.facebook.com", catalogue.domains_for("borderline"))

    def test_every_curated_domain_is_syntactically_valid(self) -> None:
        for group in (curated.ENTERPRISE_DOMAINS, curated.BORDERLINE_DOMAINS):
            for raw in group:
                name = dl.normalise_domain(raw)
                self.assertTrue(dl.is_valid_domain(name), msg=f"bad curated entry: {raw!r}")

    def test_nxdomain_probe_pool_is_empty_by_design(self) -> None:
        catalogue = self.catalogue()
        self.assertFalse(catalogue.has("nxdomain_probe"))
        with self.assertRaises(ValueError):
            catalogue.sample("nxdomain_probe", random.Random(1))

    def test_blocked_and_expectation_helpers(self) -> None:
        catalogue = self.catalogue()
        self.assertTrue(catalogue.is_blocked_category("block_ads"))
        self.assertTrue(catalogue.is_blocked_category("block_phishing"))
        self.assertFalse(catalogue.is_blocked_category("allow_popular"))
        self.assertFalse(catalogue.is_blocked_category("enterprise"))
        self.assertFalse(catalogue.is_blocked_category("borderline"))

    def test_cached_source_is_read_and_ranked_weights_are_zipf(self) -> None:
        domains = [f"d{i:04d}.example.com" for i in range(1001)]
        seed_cache(self.cache, "umbrella-top1m", domains, "allow_popular")

        catalogue = self.catalogue()
        pool = catalogue.pool("allow_popular")
        self.assertTrue(pool.ranked)
        self.assertEqual(len(pool.domains), 1001)
        self.assertEqual(len(pool.weights), len(pool.domains))
        self.assertEqual(pool.domains[0], "d0000.example.com")
        # Rank order is preserved, so weights must decay monotonically.
        self.assertAlmostEqual(pool.weights[0], 1.0, places=9)
        self.assertAlmostEqual(pool.weights[999], 1.0 / math.sqrt(1000), places=9)
        self.assertGreater(pool.weights[0], pool.weights[1000])

    def test_unranked_block_pool_has_uniform_weights(self) -> None:
        seed_cache(self.cache, "stevenblack-unified", ["ads.a.example", "ads.b.example"], "block_ads")
        pool = self.catalogue().pool("block_ads")
        self.assertFalse(pool.ranked)
        self.assertEqual(pool.weights, [1.0, 1.0])

    def test_max_per_category_keeps_the_head_and_stays_aligned(self) -> None:
        domains = [f"d{i:04d}.example.com" for i in range(500)]
        seed_cache(self.cache, "umbrella-top1m", domains, "allow_popular")

        catalogue = self.catalogue(max_per_category=10)
        pool = catalogue.pool("allow_popular")
        self.assertEqual(len(pool.domains), 10)
        self.assertEqual(len(pool.weights), 10)
        self.assertEqual(pool.domains[0], "d0000.example.com")
        self.assertEqual(pool.domains[9], "d0009.example.com")
        # Enterprise is capped too, but must not be emptied.
        self.assertTrue(catalogue.has("enterprise"))
        self.assertLessEqual(catalogue.counts()["enterprise"], 10)

    def test_ranked_sources_are_interleaved_so_a_small_cap_covers_both(self) -> None:
        seed_cache(
            self.cache, "umbrella-top1m", [f"u{i}.example.com" for i in range(10)], "allow_popular"
        )
        seed_cache(
            self.cache, "tranco-top1m", [f"t{i}.example.com" for i in range(10)], "allow_popular"
        )
        pool = self.catalogue(max_per_category=4).pool("allow_popular")
        self.assertEqual(pool.domains, ["u0.example.com", "t0.example.com", "u1.example.com", "t1.example.com"])

    def test_overlapping_domain_belongs_to_exactly_one_category(self) -> None:
        seed_cache(
            self.cache,
            "stevenblack-unified",
            ["login.microsoftonline.com", "ads.example-blocked.com"],
            "block_ads",
        )
        catalogue = self.catalogue()

        # A curated enterprise name that also appears in a blocklist is owned by
        # 'enterprise', so the tool never asserts both "must resolve" and
        # "must be blocked" for one hostname.
        self.assertEqual(catalogue.category_of("login.microsoftonline.com"), "enterprise")
        self.assertNotIn("login.microsoftonline.com", catalogue.domains_for("block_ads"))
        self.assertGreaterEqual(catalogue.pool("block_ads").dropped_overlap, 1)

        self.assertIn("ads.example-blocked.com", catalogue.domains_for("block_ads"))
        self.assertEqual(catalogue.category_of("ads.example-blocked.com"), "block_ads")

    def test_category_of_falls_back_to_a_parent_domain(self) -> None:
        seed_cache(self.cache, "umbrella-top1m", ["example.com"], "allow_popular")
        catalogue = self.catalogue()
        self.assertEqual(catalogue.category_of("EXAMPLE.com."), "allow_popular")
        self.assertEqual(catalogue.category_of("deep.sub.example.com"), "allow_popular")
        self.assertIsNone(catalogue.category_of("unlisted.example.org"))
        self.assertIsNone(catalogue.category_of(""))

    def test_blocked_domains_helper(self) -> None:
        seed_cache(self.cache, "stevenblack-unified", ["ads.example-blocked.com"], "block_ads")
        blocked = self.catalogue().blocked_domains()
        self.assertIn("ads.example-blocked.com", blocked)
        self.assertNotIn("login.microsoftonline.com", blocked)

    def test_only_filters_fetched_sources_but_keeps_curated(self) -> None:
        seed_cache(self.cache, "stevenblack-unified", ["ads.example-blocked.com"], "block_ads")
        seed_cache(self.cache, "umbrella-top1m", ["google.com"], "allow_popular")

        catalogue = self.catalogue(only=["block_ads"])
        self.assertTrue(catalogue.has("block_ads"))
        self.assertFalse(catalogue.has("allow_popular"))
        self.assertTrue(catalogue.has("enterprise"), "curated lists are always included")

    def test_only_accepts_a_source_slug(self) -> None:
        seed_cache(self.cache, "umbrella-top1m", ["google.com"], "allow_popular")
        catalogue = self.catalogue(only=["umbrella-top1m"])
        self.assertTrue(catalogue.has("allow_popular"))

    def test_stale_cache_is_used_when_offline(self) -> None:
        seed_cache(self.cache, "stevenblack-unified", ["ads.example-blocked.com"], "block_ads")
        # Age the entry well past the TTL.
        manifest_path = self.cache / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["stevenblack-unified"]["fetched_at"] = time.time() - (dl.CACHE_TTL_S * 10)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        self.assertTrue(self.catalogue().has("block_ads"))

    def test_offline_never_touches_the_network(self) -> None:
        seed_cache(self.cache, "stevenblack-unified", ["ads.example-blocked.com"], "block_ads")

        def explode(*_args, **_kwargs):  # pragma: no cover - must not be called
            raise AssertionError("offline=True must not perform any network access")

        with mock.patch.object(urllib.request, "urlopen", explode), mock.patch.object(
            dl, "fetch_url", explode
        ):
            catalogue = dl.load_catalogue(self.cache, offline=True, verbose=False)
        self.assertTrue(catalogue.offline)
        self.assertTrue(catalogue.has("block_ads"))

    def test_empty_cache_directory_still_yields_a_usable_catalogue(self) -> None:
        empty = self.cache / "does-not-exist-yet"
        catalogue = dl.load_catalogue(empty, offline=True, verbose=False)
        self.assertEqual(len(catalogue.pools), 9)
        self.assertTrue(catalogue.has("enterprise"))
        self.assertFalse(catalogue.has("allow_popular"))
        self.assertIsInstance(catalogue.sample("enterprise", random.Random(5)), str)


class TestSubdomainConflicts(TempCacheTestCase):
    """A popularity list ranking an endpoint inside a blocked tree describes a query
    that is guaranteed to be blocked.  Scored as a finding it is noise -- the
    appliance did what its own list said -- so it is re-filed as borderline."""

    def catalogue(self, **kwargs):
        return dl.load_catalogue(self.cache, offline=True, **kwargs)

    def test_allowlisted_subdomain_of_a_blocklisted_parent_is_refiled(self) -> None:
        seed_cache(self.cache, "blocklistproject-ads", ["adsrvr.org"], "block_ads")
        seed_cache(
            self.cache,
            "umbrella-top1m",
            ["enduser.adsrvr.org", "independent.example.com"],
            "allow_popular",
        )
        catalogue = self.catalogue()

        self.assertNotIn("enduser.adsrvr.org", catalogue.domains_for("allow_popular"))
        self.assertIn("enduser.adsrvr.org", catalogue.domains_for("borderline"))
        # The unrelated name is untouched.
        self.assertIn("independent.example.com", catalogue.domains_for("allow_popular"))
        row = next(r for r in catalogue.summary() if r["category"] == "allow_popular")
        self.assertEqual(row["subdomain_conflicts"], 1)

    def test_the_parent_itself_is_still_blocked(self) -> None:
        seed_cache(self.cache, "blocklistproject-ads", ["adsrvr.org"], "block_ads")
        seed_cache(self.cache, "umbrella-top1m", ["enduser.adsrvr.org"], "allow_popular")
        catalogue = self.catalogue()
        self.assertIn("adsrvr.org", catalogue.domains_for("block_ads"))

    def test_enterprise_names_survive_a_conflict_because_it_is_the_finding(self) -> None:
        """An appliance blocking the tree above a must-resolve name is exactly what
        the operator needs to be told about, so it must not be quietly excused."""
        seed_cache(self.cache, "blocklistproject-ads", ["microsoftonline.com"], "block_ads")
        catalogue = self.catalogue()
        self.assertIn("login.microsoftonline.com", catalogue.domains_for("enterprise"))

    def test_a_sibling_name_with_a_shared_tld_is_not_a_conflict(self) -> None:
        """Only a strict ancestor counts: ``notadsrvr.org`` is not inside
        ``adsrvr.org`` just because the strings overlap."""
        seed_cache(self.cache, "blocklistproject-ads", ["adsrvr.org"], "block_ads")
        seed_cache(
            self.cache,
            "umbrella-top1m",
            ["notadsrvr.org", "adsrvr.org.evil.example.com", "evil.example.com"],
            "allow_popular",
        )
        catalogue = self.catalogue()
        popular = catalogue.domains_for("allow_popular")
        self.assertIn("notadsrvr.org", popular)
        self.assertIn("adsrvr.org.evil.example.com", popular)
        self.assertIn("evil.example.com", popular)
        row = next(r for r in catalogue.summary() if r["category"] == "allow_popular")
        self.assertEqual(row["subdomain_conflicts"], 0)

    def test_no_blocking_categories_means_no_conflict_work(self) -> None:
        seed_cache(self.cache, "umbrella-top1m", ["a.example.com", "b.example.com"], "allow_popular")
        catalogue = self.catalogue()
        self.assertEqual(len(catalogue.domains_for("allow_popular")), 2)


class TestSourceTable(TempCacheTestCase):
    def test_bundled_sources_table_is_valid(self) -> None:
        sources = dl.load_sources(verbose=False)
        self.assertTrue(sources, "sources.json should define at least one source")
        slugs = set()
        for source in sources:
            self.assertTrue(source["slug"])
            self.assertTrue(source["url"].startswith("http"))
            self.assertIn(source["format"], {"hosts", "plain", "rank_csv", "abp", "auto"})
            self.assertIn(source["category"], dl.CATEGORY_EXPECTED)
            self.assertNotIn(source["slug"], slugs)
            slugs.add(source["slug"])

    def test_missing_or_corrupt_source_table_is_tolerated(self) -> None:
        self.assertEqual(dl.load_sources("/definitely/not/here.json", verbose=False), [])
        broken = self.cache / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        self.assertEqual(dl.load_sources(broken, verbose=False), [])

    def test_unknown_category_in_source_table_is_skipped(self) -> None:
        table = self.cache / "sources.json"
        table.write_text(
            json.dumps(
                {
                    "sources": [
                        {"slug": "ok", "category": "block_ads", "url": "http://x/a", "format": "plain"},
                        {"slug": "bad", "category": "nonsense", "url": "http://x/b", "format": "plain"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        sources = dl.load_sources(table, verbose=False)
        self.assertEqual([s["slug"] for s in sources], ["ok"])

    def test_default_cache_dir_is_inside_the_project(self) -> None:
        path = dl.default_cache_dir()
        self.assertEqual(path.name, "cache")
        self.assertEqual(path.parent.name, "lists")
        # The checkout folder can be named anything, so compare with the project root, not a name.
        project_root = pathlib.Path(__file__).resolve().parents[1]
        self.assertEqual(path.resolve(), project_root / "lists" / "cache")


if __name__ == "__main__":
    unittest.main()
