"""Zip the PyInstaller build for a release, and write its checksum.

    python -m PyInstaller --noconfirm --clean packaging/dnsloadforge.spec
    python packaging/package.py [--tag v1.1.0]

Turns ``dist/dnsloadforge`` into ``dist/DNS-Load-Forge-<version>-windows-x64.zip``
with a README, the licences, the example targets file and an empty ``lists``
folder -- which makes the tool keep its lists and history beside the executable,
so the folder works from a USB stick -- and writes ``dist/SHA256SUMS``.  With
``--tag`` it first checks the tag names the version in the code, so a release
can never ship a build that reports another version.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

__all__ = ["main", "package", "stage", "version"]


def version(root: Path = ROOT) -> str:
    text = (root / "src" / "dnsloadforge" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"', text, re.MULTILINE)
    if not match:
        raise SystemExit("cannot find __version__ in src/dnsloadforge/__init__.py")
    return match.group(1)


def stage(build: Path, folder: Path, release: str, root: Path = ROOT) -> None:
    """Lay out the release folder from the PyInstaller build."""
    if folder.exists():
        shutil.rmtree(folder)
    shutil.copytree(build, folder)
    readme = (root / "packaging" / "README-windows.txt").read_text(encoding="utf-8")
    (folder / "README.txt").write_text(readme.replace("{version}", release), encoding="utf-8", newline="\r\n")
    shutil.copyfile(root / "LICENSE", folder / "LICENSE.txt")
    shutil.copyfile(root / "targets.example.json", folder / "targets.example.json")
    python_licence = Path(sys.base_prefix) / "LICENSE.txt"
    if python_licence.exists():
        shutil.copyfile(python_licence, folder / "PYTHON-LICENSE.txt")
    lists = folder / "lists"
    lists.mkdir(exist_ok=True)
    (lists / "README.txt").write_text(
        "The domain lists are cached here after the first start. Delete the cache\r\n"
        "folder to download them afresh, or refresh them from the dashboard.\r\n",
        encoding="utf-8",
    )


def _zip(folder: Path, archive: Path) -> None:
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                bundle.write(path, path.relative_to(folder.parent).as_posix())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def package(dist: Path, release: str, root: Path = ROOT) -> Path:
    """Stage, zip and checksum; returns the archive."""
    build = dist / "dnsloadforge"
    if not (build / "dnsloadforge.exe").exists():
        raise SystemExit(f"{build / 'dnsloadforge.exe'} is missing: run PyInstaller first")
    name = f"DNS-Load-Forge-{release}-windows-x64"
    folder = dist / name
    stage(build, folder, release, root)
    archive = dist / f"{name}.zip"
    archive.unlink(missing_ok=True)
    _zip(folder, archive)
    (dist / "SHA256SUMS").write_text(f"{_sha256(archive)}  {archive.name}\n", encoding="ascii", newline="\n")
    return archive


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dist", default=str(ROOT / "dist"), help="PyInstaller's output folder (default: dist)")
    parser.add_argument("--tag", default="", help="the release tag; must be v followed by the code's version")
    args = parser.parse_args(argv)
    release = version()
    if args.tag and args.tag != f"v{release}":
        print(f"error: the tag {args.tag} does not match the version in the code, {release}", file=sys.stderr)
        return 1
    archive = package(Path(args.dist), release)
    print(f"{archive} ({archive.stat().st_size / 1e6:.1f} MB)")
    print((Path(args.dist) / "SHA256SUMS").read_text(encoding="ascii").strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
