"""The Windows executable: its icon, its zip, and what a double-click does.

PyInstaller itself runs in the release workflow, which builds the executable on
Windows and runs it; these tests cover the parts that are this project's own
code, so they run everywhere in seconds.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import pathlib
import struct
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dnsloadforge import cli  # noqa: E402


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "packaging" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TestIcon(unittest.TestCase):
    def test_the_committed_icon_is_what_the_script_draws(self) -> None:
        """Compared pixel by pixel: compressed bytes differ between zlib builds."""
        import zlib

        make_icon = load("make_icon")
        data = (ROOT / "packaging" / "dnsloadforge.ico").read_bytes()
        for index, size in enumerate(make_icon.SIZES):
            _w, _h, _c, _r, _planes, _bpp, length, offset = struct.unpack(
                "<BBBBHHII", data[6 + 16 * index : 22 + 16 * index]
            )
            image = data[offset : offset + length]
            # A PNG is the signature, then chunks: length, kind, data, CRC.
            position, pixels = 8, b""
            while position < len(image):
                (chunk_length,) = struct.unpack(">I", image[position : position + 4])
                kind = image[position + 4 : position + 8]
                if kind == b"IDAT":
                    pixels += image[position + 8 : position + 8 + chunk_length]
                position += 12 + chunk_length
            with self.subTest(size=size):
                self.assertEqual(
                    zlib.decompress(pixels), make_icon.render(size), "run python packaging/make_icon.py and commit it"
                )

    def test_it_is_an_icon_with_every_size(self) -> None:
        data = (ROOT / "packaging" / "dnsloadforge.ico").read_bytes()
        reserved, kind, count = struct.unpack("<HHH", data[:6])
        self.assertEqual((reserved, kind, count), (0, 1, 6))
        widths = []
        for index in range(count):
            width, _h, _c, _r, _planes, bpp, size, offset = struct.unpack("<BBBBHHII", data[6 + 16 * index : 22 + 16 * index])
            widths.append(width or 256)
            self.assertEqual(bpp, 32)
            self.assertEqual(data[offset : offset + 8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(widths, [16, 24, 32, 48, 64, 256])


class TestPackage(unittest.TestCase):
    def setUp(self) -> None:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.dist = pathlib.Path(folder.name)
        build = self.dist / "dnsloadforge"
        (build / "_internal" / "dnsloadforge").mkdir(parents=True)
        (build / "dnsloadforge.exe").write_bytes(b"MZ not really")
        (build / "_internal" / "dnsloadforge" / "index.html").write_text("<!doctype html>", encoding="ascii")
        self.package = load("package")

    def test_the_zip_holds_one_folder_ready_to_run(self) -> None:
        archive = self.package.package(self.dist, "1.2.3")
        self.assertEqual(archive.name, "DNS-Load-Forge-1.2.3-windows-x64.zip")
        names = zipfile.ZipFile(archive).namelist()
        prefix = "DNS-Load-Forge-1.2.3-windows-x64/"
        self.assertTrue(all(name.startswith(prefix) for name in names), names)
        for expected in ("dnsloadforge.exe", "README.txt", "LICENSE.txt", "targets.example.json", "lists/README.txt",
                         "_internal/dnsloadforge/index.html"):
            self.assertIn(prefix + expected, names)
        readme = zipfile.ZipFile(archive).read(prefix + "README.txt").decode("utf-8")
        self.assertIn("DNS Load Forge 1.2.3 for Windows", readme)
        self.assertNotIn("{version}", readme)
        self.assertIn("\r\n", readme, "Notepad-friendly line endings")
        readme.encode("ascii")

    def test_the_checksum_matches(self) -> None:
        archive = self.package.package(self.dist, "1.2.3")
        line = (self.dist / "SHA256SUMS").read_text(encoding="ascii")
        self.assertEqual(line, f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")

    def test_a_tag_must_match_the_code(self) -> None:
        version = self.package.version()
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(self.package.main(["--dist", str(self.dist), "--tag", "v0.0.0"]), 1)
        self.assertIn("does not match", err.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.package.main(["--dist", str(self.dist), "--tag", f"v{version}"]), 0)

    def test_the_spec_bundles_files_that_exist(self) -> None:
        spec = (ROOT / "packaging" / "dnsloadforge.spec").read_text(encoding="utf-8")
        for relative in ("dashboard/index.html", "dashboard/THIRD_PARTY_NOTICES.txt", "sources.json"):
            self.assertIn(relative.split("/")[-1], spec)
            self.assertTrue((ROOT / "src" / "dnsloadforge" / relative).exists(), relative)
        self.assertTrue((ROOT / "packaging" / "launch.py").exists())


class TestDoubleClick(unittest.TestCase):
    def test_only_the_frozen_executable_launches_the_dashboard(self) -> None:
        self.assertFalse(cli._launched_by_double_click(), "python itself never does")

    @unittest.skipUnless(sys.platform == "win32", "the console check is Windows-only")
    def test_a_console_of_its_own_means_explorer_started_it(self) -> None:
        with mock.patch.object(sys, "frozen", True, create=True), mock.patch("ctypes.windll") as windll:
            windll.kernel32.GetConsoleProcessList.return_value = 1
            self.assertTrue(cli._launched_by_double_click())
            windll.kernel32.GetConsoleProcessList.return_value = 2  # a terminal shares it
            self.assertFalse(cli._launched_by_double_click())

    def test_a_second_double_click_opens_the_running_dashboard(self) -> None:
        with mock.patch.object(cli, "_dashboard_running", return_value=True), mock.patch.object(
            cli.webbrowser, "open"
        ) as opened, mock.patch.object(cli.time, "sleep"), mock.patch.object(cli, "main") as main, contextlib.redirect_stdout(
            io.StringIO()
        ):
            self.assertEqual(cli._launch_dashboard(), 0)
        opened.assert_called_once_with("http://127.0.0.1:8787/")
        main.assert_not_called()

    def test_it_serves_the_mock_and_waits_after_an_error(self) -> None:
        with mock.patch.object(cli, "_dashboard_running", return_value=False), mock.patch.object(
            cli, "main", return_value=2
        ) as main, mock.patch("builtins.input") as waited, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli._launch_dashboard(), 2)
        main.assert_called_once_with(["serve", "--mock", "--open-dashboard"])
        waited.assert_called_once()
        self.assertIn("simulated filtering appliance", out.getvalue())
        with mock.patch.object(cli, "_dashboard_running", return_value=False), mock.patch.object(
            cli, "main", return_value=0
        ), mock.patch("builtins.input") as waited, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli._launch_dashboard(), 0)
        waited.assert_not_called()


if __name__ == "__main__":
    unittest.main()
