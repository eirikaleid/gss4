#!/usr/bin/env python3
"""
07_verify_diff/verify_diff.py - Offset Sanity Verification & Diff Gate
Validates generated offsets against executable binaries, checks that all symbols
used in src/ exist, generates diff reports against previous versions, and handles backups.

Usage:
    python verify_diff.py --new ./build/offsets.h [--old ./src/core/offsets.h] \
                          [--so ./bin/libil2cpp.so] [--src ./src] [--profile ../profiles/royale.json] \
                          [--apply-to ./src/core/offsets.h] [--backup-dir ./backups]
"""

import argparse
import os
import re
import shutil
import struct
import sys
from datetime import datetime

CONST_RE = re.compile(r"constexpr\s+(?:uintptr_t|int|unsigned|uint32_t|uint64_t|int32_t)\s+(\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*;")
NS_OPEN_RE = re.compile(r"^\s*namespace\s+(\w+)\s*\{")
USE_RE = re.compile(r"Offsets::([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)")


def parse_header(path):
    if not os.path.exists(path):
        return {}
    vals = {}
    stack = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.split("//", 1)[0]
            m = NS_OPEN_RE.match(line)
            if m:
                stack.append(m.group(1))
                continue
            c = CONST_RE.search(line)
            if c:
                ns = [s for s in stack if s != "Offsets"]
                vals["::".join(ns + [c.group(1)])] = int(c.group(2), 0)
            for _ in range(line.count("}")):
                if stack:
                    stack.pop()
    return vals


def scan_source_symbols(src_dir):
    if not os.path.isdir(src_dir):
        return set()
    used = set()
    for root, _, files in os.walk(src_dir):
        for fn in files:
            if not fn.endswith((".cpp", ".h", ".hpp", ".cc")):
                continue
            p = os.path.join(root, fn)
            try:
                content = open(p, "r", encoding="utf-8", errors="replace").read()
                for m in USE_RE.finditer(content):
                    used.add(m.group(1))
            except Exception:
                pass
    return used


def diff_headers(old_map, new_map):
    all_keys = sorted(set(old_map.keys()) | set(new_map.keys()))
    changes = []
    added = []
    removed = []

    for k in all_keys:
        if k in old_map and k in new_map:
            if old_map[k] != new_map[k]:
                changes.append((k, old_map[k], new_map[k]))
        elif k in new_map:
            added.append((k, new_map[k]))
        else:
            removed.append((k, old_map[k]))

    return changes, added, removed


def main():
    parser = argparse.ArgumentParser(description="Verify generated offsets and diff against existing.")
    parser.add_argument("--new", required=True, help="Path to newly generated offsets.h")
    parser.add_argument("--old", help="Path to existing offsets.h for diff comparison")
    parser.add_argument("--so", help="Path to libil2cpp.so to verify file boundaries")
    parser.add_argument("--src", help="Path to source code directory to ensure 0 undefined symbols")
    parser.add_argument("--profile", help="Path to profile JSON for known check validations")
    parser.add_argument("--known", help="Specific known version tag to assert (e.g. 4.9)")
    parser.add_argument("--apply-to", help="If verified, copy new header to this destination path")
    parser.add_argument("--backup-dir", default="./backups", help="Directory for previous header backups")
    parser.add_argument("--report", help="Path to write text diff report")

    args = parser.parse_args()

    if not os.path.exists(args.new):
        print(f"[FAIL] New header not found: {args.new}", file=sys.stderr)
        sys.exit(1)

    new_map = parse_header(args.new)
    print(f"[*] Parsed {len(new_map)} constants from {args.new}")

    fails = []

    # 1. Sanity Checks
    so_size = os.path.getsize(args.so) if args.so and os.path.exists(args.so) else None
    for name, val in new_map.items():
        if "::" not in name:
            # Top-level Method RVA
            if val % 4 != 0:
                fails.append(f"Method not 4-aligned: {name}=0x{val:X}")
            if so_size and val >= so_size:
                fails.append(f"Method RVA outside binary size: {name}=0x{val:X}")
        elif name.startswith("TypeInfo::"):
            # TypeInfo pointer
            if val % 8 != 0:
                fails.append(f"TypeInfo not 8-aligned: {name}=0x{val:X}")
            if so_size and val >= so_size:
                fails.append(f"TypeInfo offset outside binary size: {name}=0x{val:X}")
        elif not name.startswith("Native::"):
            # Field offset
            if val >= 0x10000 or val <= 0:
                fails.append(f"Field offset out of sanity range (0..0x10000): {name}=0x{val:X}")

    # 2. Source Code Undefined Symbol Check
    if args.src and os.path.isdir(args.src):
        used_syms = scan_source_symbols(args.src)
        missing_in_header = []
        for sym in sorted(used_syms):
            if sym not in new_map:
                missing_in_header.append(sym)
        if missing_in_header:
            fails.append(f"Source code uses {len(missing_in_header)} undefined symbols: {missing_in_header[:5]}")
        else:
            print(f"[OK] All {len(used_syms)} symbols referenced in src/ are defined in the new header.")

    # 3. Known profile assertions
    if args.profile and args.known and os.path.exists(args.profile):
        import json
        with open(args.profile, "r", encoding="utf-8") as pf:
            pdata = json.load(pf)
        known_dict = pdata.get("known_checks", {}).get(args.known, {})
        for k, v_str in known_dict.items():
            expected = int(v_str, 0)
            actual = new_map.get(k)
            if actual is None:
                fails.append(f"Known check [{args.known}] missing symbol: {k}")
            elif actual != expected:
                fails.append(f"Known check [{args.known}] mismatch for {k}: expected 0x{expected:X}, got 0x{actual:X}")

    # 4. Diff Report
    diff_output = []
    if args.old and os.path.exists(args.old):
        old_map = parse_header(args.old)
        changes, added, removed = diff_headers(old_map, new_map)
        diff_output.append("\n=======================================================")
        diff_output.append(f" DIFF REPORT: {len(changes)} changed, {len(added)} added, {len(removed)} removed")
        diff_output.append("=======================================================")
        for k, old_v, new_v in changes[:30]:
            diff_output.append(f" ~ {k:<45} 0x{old_v:X} -> 0x{new_v:X}")
        if len(changes) > 30:
            diff_output.append(f"   ... and {len(changes) - 30} more changes")
        for k, new_v in added[:15]:
            diff_output.append(f" + {k:<45} 0x{new_v:X}")
        for k, old_v in removed[:15]:
            diff_output.append(f" - {k:<45} 0x{old_v:X}")
        print("\n".join(diff_output))

    if args.report:
        with open(args.report, "w", encoding="utf-8") as rf:
            rf.write("\n".join(diff_output))

    if fails:
        print("\n[FAIL] Offset verification encountered errors:", file=sys.stderr)
        for f in fails:
            print(f"  * {f}", file=sys.stderr)
        sys.exit(1)

    print("\n[OK] All verification checks passed cleanly!")

    # 5. Apply with backup
    if args.apply_to:
        dst = os.path.abspath(args.apply_to)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        os.makedirs(args.backup_dir, exist_ok=True)

        if os.path.exists(dst):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(args.backup_dir, f"offsets.h.{timestamp}")
            shutil.copy2(dst, backup_file)
            print(f"[OK] Backed up previous header to: {backup_file}")

        shutil.copy2(args.new, dst)
        print(f"[OK] Applied new header to: {dst}")


if __name__ == "__main__":
    main()
