#!/usr/bin/env python3
"""
07_verify_diff/verify_diff.py - Stage 7: Offset Sanity Verification & Diff Gate
Validates generated offsets against executable binaries, checks that all symbols
used in src/ exist, generates diff reports against previous versions, and handles backups.
Can be executed as a CLI script, imported as Stage7Verify(BaseStage), or called via MCP.
"""

import argparse
import os
import re
import shutil
import struct
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core.stage_base import BaseStage, StageResult
except ImportError:
    BaseStage = object

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


def verify_and_diff(new_path, old_path=None, so_path=None, src_dir=None,
                    profile_data=None, known_tag=None, apply_to=None, backup_dir=None):
    if not os.path.exists(new_path):
        raise FileNotFoundError(f"New header not found: {new_path}")

    new_map = parse_header(new_path)
    fails = []

    # 1. Sanity Checks
    so_size = os.path.getsize(so_path) if so_path and os.path.exists(so_path) else None
    for name, val in new_map.items():
        if "::" not in name:
            if val % 4 != 0:
                fails.append(f"Method not 4-aligned: {name}=0x{val:X}")
            if so_size and val >= so_size:
                fails.append(f"Method RVA outside binary size: {name}=0x{val:X}")
        elif name.startswith("TypeInfo::"):
            if val % 8 != 0:
                fails.append(f"TypeInfo not 8-aligned: {name}=0x{val:X}")
            if so_size and val >= so_size:
                fails.append(f"TypeInfo offset outside binary size: {name}=0x{val:X}")
        elif not name.startswith("Native::"):
            if val >= 0x10000 or val <= 0:
                fails.append(f"Field offset out of sanity range (0..0x10000): {name}=0x{val:X}")

    # 2. Source Code Undefined Symbol Check
    if src_dir and os.path.isdir(src_dir):
        used_syms = scan_source_symbols(src_dir)
        missing_in_header = [s for s in sorted(used_syms) if s not in new_map]
        if missing_in_header:
            fails.append(f"Source code uses {len(missing_in_header)} undefined symbols: {missing_in_header[:5]}")

    # 3. Known profile assertions
    if profile_data and known_tag:
        known_dict = profile_data.get("known_checks", {}).get(known_tag, {})
        for k, v_str in known_dict.items():
            expected = int(v_str, 0)
            actual = new_map.get(k)
            if actual is None:
                fails.append(f"Known check [{known_tag}] missing symbol: {k}")
            elif actual != expected:
                fails.append(f"Known check [{known_tag}] mismatch for {k}: expected 0x{expected:X}, got 0x{actual:X}")

    # 4. Diff Report
    changes, added, removed = [], [], []
    if old_path and os.path.exists(old_path):
        old_map = parse_header(old_path)
        changes, added, removed = diff_headers(old_map, new_map)

    if fails:
        raise ValueError(f"Verification errors:\n" + "\n".join(f"  * {f}" for f in fails))

    # 5. Apply
    applied_file = None
    if apply_to:
        dst = os.path.abspath(apply_to)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if backup_dir:
            os.makedirs(backup_dir, exist_ok=True)
        if os.path.exists(dst) and backup_dir:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(backup_dir, f"offsets.h.{timestamp}")
            shutil.copy2(dst, backup_file)
        shutil.copy2(new_path, dst)
        applied_file = dst

    return {
        "constants_count": len(new_map),
        "changes_count": len(changes),
        "added_count": len(added),
        "removed_count": len(removed),
        "applied_file": applied_file
    }


class Stage7Verify(BaseStage):
    stage_id = 7
    name = "07_verify_diff"
    description = "Sanity verification, symbol integrity check against src/, and diff report."

    def validate_inputs(self, workspace: str, config: dict):
        new_header = config.get("new_header") or os.path.join(workspace, "offsets.h")
        if not os.path.exists(new_header):
            return False, f"Missing header to verify at {new_header}"
        return True, ""

    def execute(self, workspace: str, config: dict):
        new_header = config.get("new_header") or os.path.join(workspace, "offsets.h")
        old_header = config.get("old_header")
        so_path = config.get("so_path") or os.path.join(workspace, "bin", "libil2cpp.so")
        src_dir = config.get("src_dir")
        profile_data = config.get("profile")
        known_tag = config.get("known")
        apply_to = config.get("apply_to")
        backup_dir = config.get("backup_dir") or os.path.join(workspace, "backups")

        res = verify_and_diff(
            new_path=new_header,
            old_path=old_header,
            so_path=so_path,
            src_dir=src_dir,
            profile_data=profile_data,
            known_tag=known_tag,
            apply_to=apply_to,
            backup_dir=backup_dir
        )
        return res

    def validate_outputs(self, workspace: str, config: dict):
        return True, ""


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

    profile_data = None
    if args.profile and os.path.exists(args.profile):
        import json
        with open(args.profile, "r", encoding="utf-8") as pf:
            profile_data = json.load(pf)

    try:
        res = verify_and_diff(
            new_path=args.new,
            old_path=args.old,
            so_path=args.so,
            src_dir=args.src,
            profile_data=profile_data,
            known_tag=args.known,
            apply_to=args.apply_to,
            backup_dir=args.backup_dir
        )
        print(f"[OK] All {res['constants_count']} constants verified cleanly.")
        if res.get("applied_file"):
            print(f"[OK] Applied to: {res['applied_file']}")
    except Exception as e:
        print(f"[FAIL] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
