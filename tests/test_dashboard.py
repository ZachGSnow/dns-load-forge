"""The packaged dashboard page and the way it is served.

The page is built from ``web/`` into one self-contained file, so these tests pin the
properties the operator relies on rather than its markup: it makes no request beyond
this server (so it works on an isolated segment), it is plain ASCII like every file in
the repository, and the server's Content-Security-Policy really admits its scripts --
a wrong hash does not fail loudly, it serves a blank page.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import pathlib
import re
import sys
import unittest
from html.parser import HTMLParser

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from dnsloadforge import __version__  # noqa: E402
from dnsloadforge import server as server_module  # noqa: E402
from dnsloadforge.server import dashboard_csp, serve  # noqa: E402
from dnsloadforge.spec import RunConfig  # noqa: E402

from test_targets import synthetic_catalogue  # noqa: E402

PAGE = pathlib.Path(server_module.__file__).resolve().parent / "dashboard" / "index.html"
NOTICES = PAGE.with_name("THIRD_PARTY_NOTICES.txt")


class _Scripts(HTMLParser):
    """Collects inline script bodies the way a browser tokenises them, as an
    independent check on the regex the server uses."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.scripts: list[str] = []
        self._inside = False

    def handle_starttag(self, tag, attrs) -> None:
        if tag == "script":
            self._inside = True
            self.scripts.append("")

    def handle_endtag(self, tag) -> None:
        if tag == "script":
            self._inside = False

    def handle_data(self, data) -> None:
        if self._inside:
            self.scripts[-1] += data


def script_hashes(html: str) -> set[str]:
    parser = _Scripts()
    parser.feed(html)
    return {
        "'sha256-" + base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii") + "'"
        for body in parser.scripts
    }


class TestPackagedPage(unittest.TestCase):
    def setUp(self) -> None:
        self.html = PAGE.read_text(encoding="utf-8")

    def test_the_page_is_plain_ascii(self) -> None:
        self.assertIsNone(re.search(r"[^\x09\x0a\x0d\x20-\x7e]", self.html))

    def test_the_page_fetches_nothing_from_anywhere_else(self) -> None:
        external = re.compile(
            r"<(?:script|link|img|iframe|source|video|audio)\b[^>]*\b(?:src|href)\s*=\s*[\"']?(?:https?:)?//", re.I
        )
        self.assertIsNone(external.search(self.html), "a script, stylesheet or image is loaded from elsewhere")
        self.assertIsNone(re.search(r"url\(\s*[\"']?(?:https?:)?//", self.html, re.I), "CSS fetches a remote url()")
        self.assertNotIn("@import", self.html)

    def test_the_page_mounts_an_app_and_stays_inside_the_text_scan_budget(self) -> None:
        self.assertIn('<div id="root">', self.html)
        self.assertLess(PAGE.stat().st_size, 2 * 1024 * 1024)

    def test_license_notices_ship_with_the_page(self) -> None:
        text = NOTICES.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"[^\x09\x0a\x0d\x20-\x7e]", text))
        for package in ("react ", "recharts ", "@fontsource-variable/geist "):
            self.assertIn(package, text)


class TestContentSecurityPolicy(unittest.TestCase):
    def test_every_inline_script_is_admitted_by_hash(self) -> None:
        html = PAGE.read_text(encoding="utf-8")
        policy = dashboard_csp(html.encode("utf-8"))
        script_src = re.search(r"script-src ([^;]+)", policy).group(1).split()
        expected = script_hashes(html)
        self.assertTrue(expected, "the page has no inline scripts to admit")
        self.assertEqual(set(script_src), expected)
        self.assertNotIn("'unsafe-inline'", script_src)

    def test_a_windows_checkout_with_crlf_gets_the_same_hashes(self) -> None:
        """A browser normalises line endings before hashing, so a CRLF copy of the
        page must produce the same policy, or the dashboard would load blank."""
        lf = b'<html><script>\nvar a = 1;\nvar b = 2;\n</script></html>'
        crlf = lf.replace(b"\n", b"\r\n")
        self.assertEqual(dashboard_csp(lf), dashboard_csp(crlf))

    def test_the_policy_allows_this_server_and_nothing_else(self) -> None:
        policy = dashboard_csp(PAGE.read_bytes())
        for directive in (
            "default-src 'none'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'none'",
        ):
            self.assertIn(directive, policy)
        self.assertNotIn("http", policy)


class TestServedPage(unittest.TestCase):
    def setUp(self) -> None:
        self.http, self.controller = serve(
            RunConfig(server="127.0.0.1", port=9), synthetic_catalogue(), port=0, autostart=False,
            log=lambda message: None,
        )
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)
        self.port = self.http.server_address[1]

    def get(self, path: str):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_the_page_is_served_with_its_policy_and_cannot_be_framed(self) -> None:
        status, headers, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        policy = headers["Content-Security-Policy"]
        for digest in script_hashes(body.decode("utf-8")):
            self.assertIn(digest, policy)

    def test_api_responses_are_not_sniffed(self) -> None:
        _status, headers, _body = self.get("/api/stats")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_the_license_notices_are_served(self) -> None:
        status, headers, body = self.get("/api/licenses")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/plain"))
        self.assertIn(b"third-party notices", body)

    def test_the_config_reports_the_version(self) -> None:
        status, _headers, body = self.get("/api/config")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["version"], __version__)


if __name__ == "__main__":
    unittest.main()
