#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Atomic Heart Menu - internal mod menu for single-player Atomic Heart.
# Copyright (C) 2026 Skorchekd
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version. Distributed WITHOUT ANY WARRANTY. See the LICENSE file for details.
#
# Additional terms (GPLv3 Section 7): you must preserve attribution to the author
# (Skorchekd) and to Dumper-7 (Encryqed), MinHook (Tsuda Kageyu), and Dear ImGui
# (ocornut). See LICENSE and NOTICE. Forks must stay GPL-3.0-or-later and open.
"""Recover GObjects / GNames / GWorld from the shipping exe after a game patch.

Static analysis only: reads the .exe from disk, no game running and no Dumper-7.
Prints ready-to-paste constants for src/sdk/offsets.h.

    python tools/find_globals.py
    python tools/find_globals.py --exe "D:\\...\\AtomicHeart-Win64-Shipping.exe"

Dumper-7 is still the tool for CLASS and FUNCTION offsets (the member offsets
further down offsets.h). This only recovers the three engine globals -- which is
what actually breaks on a routine patch, and what gates everything else.
"""

import argparse
import os
import re
import struct
import sys
from collections import Counter

# Mirrors the SIG_* constants in src/sdk/offsets.h. Each entry is
# (pattern, offset_to_rel32, instruction_length) -- the same triple that
# Scanner::FindRipRel() is called with in ue4.cpp.
PATTERNS = {
    "GObjects": ("48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1 EB", 3, 7),
    "GNames":   ("48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05", 3, 7),
    "GWorld":   ("48 89 15 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? C3", 3, 7),
}

DEFAULT_EXE_SUFFIX = os.path.join(
    "steamapps", "common", "Atomic Heart", "AtomicHeart", "Binaries", "Win64",
    "AtomicHeart-Win64-Shipping.exe")

SEARCH_ROOTS = [
    r"C:\Program Files (x86)\Steam", r"C:\Program Files\Steam",
    r"C:\SteamLibrary", r"D:\SteamLibrary", r"E:\SteamLibrary", r"F:\SteamLibrary",
]


class Image:
    """A PE mapped to its virtual layout, so every offset here is an RVA."""

    def __init__(self, path):
        data = open(path, "rb").read()
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("not a PE file")
        fh = e_lfanew + 4
        num_sec = struct.unpack_from("<H", data, fh + 2)[0]
        opt_size = struct.unpack_from("<H", data, fh + 16)[0]
        opt = fh + 20
        if struct.unpack_from("<H", data, opt)[0] != 0x20B:
            raise ValueError("not a 64-bit PE")
        self.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]

        self.sections = []
        for i in range(num_sec):
            o = opt + opt_size + i * 40
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
            chars = struct.unpack_from("<I", data, o + 36)[0]
            self.sections.append({
                "name": data[o:o + 8].rstrip(b"\x00").decode("latin1"),
                "vaddr": vaddr, "vsize": vsize or rawsize,
                "exec": bool(chars & 0x20000000), "write": bool(chars & 0x80000000),
            })

        buf = bytearray(self.size_of_image)
        for i in range(num_sec):
            o = opt + opt_size + i * 40
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
            n = min(rawsize, vsize) if vsize else rawsize
            buf[vaddr:vaddr + n] = data[rawptr:rawptr + n]
        self.buf = bytes(buf)

    def exec_ranges(self):
        # Same scope Scanner::Find uses: executable sections, in section order.
        return [(s["vaddr"], s["vaddr"] + s["vsize"]) for s in self.sections if s["exec"]]

    def section_of(self, rva):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + s["vsize"]:
                return s
        return None


def parse_pattern(pattern):
    return [None if tok.startswith("?") else int(tok, 16) for tok in pattern.split()]


def scan(image, pattern, off, ilen):
    """Every match, as (first_match_rva, Counter of resolved targets)."""
    toks = parse_pattern(pattern)
    n = len(toks)
    if toks[0] is None:
        raise ValueError("pattern must start with a concrete byte, not a wildcard")
    lead = bytes([toks[0]])
    first = None
    targets = Counter()
    for lo, hi in image.exec_ranges():
        start = lo
        while True:
            i = image.buf.find(lead, start, hi - n)
            if i < 0:
                break
            if all(t is None or image.buf[i + j] == t for j, t in enumerate(toks) if t is not None):
                rel = struct.unpack_from("<i", image.buf, i + off)[0]
                target = i + ilen + rel
                targets[target] += 1
                if first is None:
                    first = i
            start = i + 1
    return first, targets


def resolve(image, label):
    pattern, off, ilen = PATTERNS[label]
    first, targets = scan(image, pattern, off, ilen)
    if not targets:
        return None, [f"pattern matched nothing -- signature is stale for this build"]

    rva, hits = targets.most_common(1)[0]
    total = sum(targets.values())
    notes = [f"{total} match(es), {len(targets)} distinct target(s), "
             f"{hits} agreeing ({100.0 * hits / total:.1f}%)"]

    warnings = []
    sec = image.section_of(rva)
    if sec is None:
        warnings.append("target is outside the image")
    else:
        notes.append(f"lands in {sec['name']}{' (writable)' if sec['write'] else ''}")
        if not sec["write"]:
            warnings.append(f"target is in {sec['name']}, expected a writable data section")

    # Engine globals are populated at runtime, so they are zero on disk. A
    # non-zero value here means the pattern resolved to a constant, not a global.
    if sec is not None and any(image.buf[rva:rva + 16]):
        warnings.append("non-zero on disk -- expected a zero-initialised runtime global")

    if hits < total * 0.5:
        warnings.append("under half the matches agree -- signature is ambiguous")

    return rva, notes + [f"WARNING: {w}" for w in warnings]


def read_current_offsets(repo_root):
    header = os.path.join(repo_root, "src", "sdk", "offsets.h")
    try:
        text = open(header, "r", encoding="utf-8", errors="replace").read()
    except OSError:
        return {}
    found = {}
    for label in PATTERNS:
        m = re.search(rf"{label}_RVA\s*=\s*(0x[0-9A-Fa-f]+)", text)
        if m:
            found[label] = int(m.group(1), 16)
    # 0 is the documented "disabled" value, so decimal has to parse too.
    m = re.search(r"ExpectedImageSize\s*=\s*(0x[0-9A-Fa-f]+|[0-9]+)", text)
    if m:
        raw = m.group(1)
        found["ExpectedImageSize"] = int(raw, 16 if raw.lower().startswith("0x") else 10)
    return found


def autodetect_exe():
    for root in SEARCH_ROOTS:
        candidate = os.path.join(root, DEFAULT_EXE_SUFFIX)
        if os.path.isfile(candidate):
            return candidate
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exe", help="path to AtomicHeart-Win64-Shipping.exe")
    args = ap.parse_args()

    exe = args.exe or autodetect_exe()
    if not exe:
        print("Could not find the game exe. Pass --exe with the full path to\n"
              "AtomicHeart-Win64-Shipping.exe (under AtomicHeart\\Binaries\\Win64).",
              file=sys.stderr)
        return 2
    if not os.path.isfile(exe):
        print(f"No such file: {exe}", file=sys.stderr)
        return 2

    print(f"exe          {exe}")
    image = Image(exe)

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    current = read_current_offsets(repo_root)

    # Not counted as a problem: after a patch the image size always differs, and
    # that is the case the tool exists for.
    was_size = current.get("ExpectedImageSize")
    if was_size is None:
        size_state = "  (offsets.h has no ExpectedImageSize)"
    elif was_size == 0:
        size_state = "  (offsets.h has 0 -- check disabled)"
    elif was_size == image.size_of_image:
        size_state = "  (offsets.h already up to date)"
    else:
        size_state = f"  (offsets.h has 0x{was_size:X} -- different build)"
    print(f"SizeOfImage  0x{image.size_of_image:X}{size_state}\n")

    results = {}
    problems = 0
    for label in ("GObjects", "GNames", "GWorld"):
        rva, notes = resolve(image, label)
        results[label] = rva
        if rva is None:
            problems += 1
            print(f"{label:<9} NOT FOUND")
        else:
            was = current.get(label)
            state = ""
            if was == rva:
                state = "  (offsets.h already up to date)"
            elif was is not None:
                state = f"  (offsets.h currently has 0x{was:08X} -- STALE)"
            print(f"{label:<9} 0x{rva:08X}{state}")
        for note in notes:
            if note.startswith("WARNING"):
                problems += 1
            print(f"          {note}")
        print()

    if problems:
        print("One or more checks failed. Do not paste these blindly -- a stale\n"
              "signature needs fixing in offsets.h (and here) first.\n")

    if all(results.values()):
        print("Paste into src/sdk/offsets.h:\n")
        print(f"    constexpr uintptr_t GObjects_RVA   = 0x{results['GObjects']:08X}; "
              "// TUObjectArray (not the outer FUObjectArray)")
        print(f"    constexpr uintptr_t GNames_RVA     = 0x{results['GNames']:08X}; // FNamePool")
        print(f"    constexpr uintptr_t GWorld_RVA     = 0x{results['GWorld']:08X}; // UWorld**")
        print(f"    constexpr size_t ExpectedImageSize = 0x{image.size_of_image:X};")
        print("\nThen rebuild, inject, and confirm the log says "
              "\"ResolveGlobals: VALID\".")

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
