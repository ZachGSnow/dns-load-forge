# PyInstaller recipe for the Windows executable:
#
#     python -m PyInstaller --noconfirm --clean packaging/dnsloadforge.spec
#     python packaging/package.py
#
# One folder (--onedir), not one file.  A one-file build unpacks itself into %TEMP%
# on every start, which is slower and is exactly what droppers do, so antivirus
# engines flag it far more often.  UPX is off for the same reason, and the release
# workflow compiles PyInstaller's bootloader itself rather than shipping the
# prebuilt one that every PyInstaller program, malware included, carries.

import re
from pathlib import Path

from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo,
    StringFileInfo,
    StringStruct,
    StringTable,
    VarFileInfo,
    VarStruct,
    VSVersionInfo,
)

ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 - defined by PyInstaller
PACKAGE = ROOT / "src" / "dnsloadforge"
VERSION = re.search(
    r'^__version__ = "([^"]+)"', (PACKAGE / "__init__.py").read_text(encoding="utf-8"), re.MULTILINE
).group(1)
NUMBERS = tuple(int(part) for part in (re.findall(r"\d+", VERSION) + ["0"] * 4)[:4])

version_info = VSVersionInfo(
    ffi=FixedFileInfo(
        filevers=NUMBERS,
        prodvers=NUMBERS,
        mask=0x3F,
        flags=0x0,
        OS=0x40004,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0),
    ),
    kids=[
        StringFileInfo(
            [
                StringTable(
                    "040904B0",
                    [
                        StringStruct("FileDescription", "DNS Load Forge"),
                        StringStruct("FileVersion", VERSION),
                        StringStruct("InternalName", "dnsloadforge"),
                        StringStruct("LegalCopyright", "Copyright (c) 2026 Zach Snow. MIT License."),
                        StringStruct("OriginalFilename", "dnsloadforge.exe"),
                        StringStruct("ProductName", "DNS Load Forge"),
                        StringStruct("ProductVersion", VERSION),
                    ],
                )
            ]
        ),
        VarFileInfo([VarStruct("Translation", [1033, 1200])]),
    ],
)

a = Analysis(  # noqa: F821 - PyInstaller spec globals
    [str(ROOT / "packaging" / "launch.py")],
    pathex=[str(ROOT / "src")],
    datas=[
        (str(PACKAGE / "dashboard" / "index.html"), "dnsloadforge/dashboard"),
        (str(PACKAGE / "dashboard" / "THIRD_PARTY_NOTICES.txt"), "dnsloadforge/dashboard"),
        (str(PACKAGE / "sources.json"), "dnsloadforge"),
    ],
    # Parts of the standard library the tool never uses.
    excludes=["tkinter", "test", "unittest", "pydoc_data", "lib2to3", "idlelib", "ensurepip", "venv"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="dnsloadforge",
    console=True,
    upx=False,
    icon=str(ROOT / "packaging" / "dnsloadforge.ico"),
    version=version_info,
)
coll = COLLECT(exe, a.binaries, a.datas, upx=False, name="dnsloadforge")  # noqa: F821
