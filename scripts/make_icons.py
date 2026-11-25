#!/usr/bin/env python3
"""Write the placeholder app icons (a white H on green) into TA-herd-security/static.

Splunkbase wants appIcon.png (36x36) and appIcon_2x.png (72x72), plus the
Alt variants shown on dark backgrounds. Replace these with the real Herd mark
before submitting; this script exists so the package builds without an image
library.
"""

import struct
import zlib
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "TA-herd-security" / "static"
GREEN = (31, 122, 77, 255)
WHITE = (255, 255, 255, 255)
CLEAR = (0, 0, 0, 0)


def png(width: int, height: int, pixel) -> bytes:
    rows = b""
    for y in range(height):
        row = b"\x00"
        for x in range(width):
            row += bytes(pixel(x, y))
        rows += row

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b"")


def h_mark(size: int, background, ink):
    unit = size / 36
    left = (9 * unit, 13 * unit)
    right = (23 * unit, 27 * unit)
    top, bottom = 8 * unit, 28 * unit
    bar = (16 * unit, 20 * unit)

    def pixel(x: int, y: int):
        in_left = left[0] <= x < left[1] and top <= y < bottom
        in_right = right[0] <= x < right[1] and top <= y < bottom
        in_bar = left[1] <= x < right[0] and bar[0] <= y < bar[1]
        return ink if (in_left or in_right or in_bar) else background

    return pixel


for name, size, background, ink in [
    ("appIcon.png", 36, GREEN, WHITE),
    ("appIcon_2x.png", 72, GREEN, WHITE),
    ("appIconAlt.png", 36, CLEAR, WHITE),
    ("appIconAlt_2x.png", 72, CLEAR, WHITE),
]:
    (STATIC / name).write_bytes(png(size, size, h_mark(size, background, ink)))
    print("wrote", STATIC / name)
