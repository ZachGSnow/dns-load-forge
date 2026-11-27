"""Draw the executable's icon: the dashboard's favicon, as a Windows .ico.

The favicon is an SVG (web/index.html): a dark rounded square, a blue "D" and a
green dot.  Windows wants raster images, so this draws the same shapes at the
sizes Explorer uses, with 4x4 supersampling for smooth edges, and packs them as
PNG images in one .ico.  Standard library only, so the icon is reproducible from
the source without an image editor:

    python packaging/make_icon.py
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

SIZES = (16, 24, 32, 48, 64, 256)
OUT = Path(__file__).resolve().parent / "dnsloadforge.ico"

BACKGROUND = (0x17, 0x17, 0x17)
BLUE = (0x60, 0xA5, 0xFA)
GREEN = (0x34, 0xD3, 0x99)


def _in_rounded_square(x: float, y: float) -> bool:
    """The 32x32 square with corners of radius 8."""
    if not (0 <= x <= 32 and 0 <= y <= 32):
        return False
    cx = min(max(x, 8.0), 24.0)
    cy = min(max(y, 8.0), 24.0)
    return (x - cx) ** 2 + (y - cy) ** 2 <= 64.0


def _segment_distance(px: float, py: float, ax: float, ay: float, bx: float, by: float) -> float:
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def _on_d(x: float, y: float) -> bool:
    """The "D": M9 23 V9 h5 a7 7 0 0 1 0 14 z, stroked 2.6 wide."""
    half = 1.3
    distance = min(
        _segment_distance(x, y, 9, 23, 9, 9),
        _segment_distance(x, y, 9, 9, 14, 9),
        _segment_distance(x, y, 14, 23, 9, 23),
    )
    if x >= 14:
        distance = min(distance, abs(math.hypot(x - 14, y - 16) - 7))
    return distance <= half


def _on_dot(x: float, y: float) -> bool:
    return math.hypot(x - 24, y - 16) <= 2.6


def render(size: int) -> bytes:
    """RGBA rows for one size."""
    samples = 4
    scale = 32.0 / size
    rows = bytearray()
    for row in range(size):
        rows.append(0)  # PNG filter: none
        for column in range(size):
            red = green = blue = alpha = 0.0
            for sy in range(samples):
                for sx in range(samples):
                    x = (column + (sx + 0.5) / samples) * scale
                    y = (row + (sy + 0.5) / samples) * scale
                    if not _in_rounded_square(x, y):
                        continue
                    colour = GREEN if _on_dot(x, y) else BLUE if _on_d(x, y) else BACKGROUND
                    red += colour[0]
                    green += colour[1]
                    blue += colour[2]
                    alpha += 1
            if alpha:
                rows += bytes((round(red / alpha), round(green / alpha), round(blue / alpha)))
                rows.append(round(255 * alpha / samples**2))
            else:
                rows += b"\x00\x00\x00\x00"
    return bytes(rows)


def png(size: int) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(render(size), 9))
        + chunk(b"IEND", b"")
    )


def ico(sizes: tuple[int, ...] = SIZES) -> bytes:
    images = [png(size) for size in sizes]
    offset = 6 + 16 * len(images)
    directory = b""
    for size, image in zip(sizes, images):
        edge = 0 if size >= 256 else size  # 0 means 256 in an icon directory
        directory += struct.pack("<BBBBHHII", edge, edge, 0, 0, 1, 32, len(image), offset)
        offset += len(image)
    return struct.pack("<HHH", 0, 1, len(images)) + directory + b"".join(images)


if __name__ == "__main__":
    OUT.write_bytes(ico())
    print(f"wrote {OUT} ({OUT.stat().st_size:,} bytes)")
