#!/usr/bin/env python3
"""
02_extract/extract.py - Modular Binary & Metadata Extractor
Extracts libil2cpp.so, libunity.so (if available), and global-metadata.dat
from single or split APK files using pure Python zipfile (no Java / apktool required).

Usage:
    python extract.py --apks base.apk split.apk --out ./workspace/bin --arch arm64-v8a
    python extract.py --manifest ./workspace/apk/apk_manifest.json --out ./workspace/bin
"""

import argparse
import json
import os
import sys
import zipfile


def extract_binaries(apks, out_dir, arch="arm64-v8a", extra_libs=None):
    os.makedirs(out_dir, exist_ok=True)
    extra_libs = extra_libs or []

    # Mapping of zip internal paths to destination filenames
    wanted = {
        f"lib/{arch}/libil2cpp.so": os.path.join(out_dir, "libil2cpp.so"),
        "assets/bin/Data/Managed/Metadata/global-metadata.dat": os.path.join(out_dir, "global-metadata.dat"),
    }

    # Optional Unity engine library (if present)
    wanted[f"lib/{arch}/libunity.so"] = os.path.join(out_dir, "libunity.so")

    for lib in extra_libs:
        wanted[f"lib/{arch}/{lib}"] = os.path.join(out_dir, lib)

    # Clean existing destination files
    for dst in wanted.values():
        if os.path.exists(dst):
            try:
                os.remove(dst)
            except OSError:
                pass

    print(f"[*] Searching for binaries in {len(apks)} APK file(s) for architecture '{arch}'...")
    found = set()

    for apk_path in apks:
        if not os.path.isfile(apk_path):
            print(f"[WARN] File not found: {apk_path}", file=sys.stderr)
            continue

        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                names = set(z.namelist())
                for target_entry, dst_path in wanted.items():
                    if target_entry in names and target_entry not in found:
                        print(f"  [+] Extracting: {target_entry} -> {dst_path}")
                        with z.open(target_entry) as src, open(dst_path, "wb") as dst:
                            dst.write(src.read())
                        found.add(target_entry)
        except Exception as e:
            print(f"[FAIL] Error reading {apk_path}: {e}", file=sys.stderr)
            return None

    # Verify critical files
    crit_il2cpp = f"lib/{arch}/libil2cpp.so"
    crit_meta = "assets/bin/Data/Managed/Metadata/global-metadata.dat"

    if crit_il2cpp not in found:
        print(f"[FAIL] Missing critical binary in APKs: {crit_il2cpp}", file=sys.stderr)
        return None
    if crit_meta not in found:
        print(f"[FAIL] Missing critical metadata in APKs: {crit_meta}", file=sys.stderr)
        return None

    manifest = {
        "arch": arch,
        "il2cpp": wanted[crit_il2cpp],
        "metadata": wanted[crit_meta],
        "unity": wanted[f"lib/{arch}/libunity.so"] if f"lib/{arch}/libunity.so" in found else None,
        "all_extracted": [wanted[k] for k in found]
    }
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Extract IL2CPP binaries and metadata from APKs.")
    parser.add_argument("--apks", nargs="+", help="Paths to APK files")
    parser.add_argument("--manifest", help="Path to JSON manifest containing 'apks' array")
    parser.add_argument("--out", required=True, help="Destination directory for extracted binaries")
    parser.add_argument("--arch", default="arm64-v8a", help="Target ABI (arm64-v8a, armeabi-v7a, x86_64, x86)")
    parser.add_argument("--extra-libs", nargs="+", default=[], help="Additional shared libraries to extract")
    parser.add_argument("--output-manifest", help="Path to save output manifest JSON")

    args = parser.parse_args()

    apks = []
    if args.manifest and os.path.exists(args.manifest):
        with open(args.manifest, "r", encoding="utf-8") as f:
            data = json.load(f)
            apks = data.get("apks", [])
    elif args.apks:
        apks = args.apks
    else:
        print("[FAIL] Either --apks or --manifest must be supplied.", file=sys.stderr)
        sys.exit(1)

    result = extract_binaries(apks, args.out, arch=args.arch, extra_libs=args.extra_libs)
    if not result:
        sys.exit(1)

    out_man_path = args.output_manifest or os.path.join(args.out, "bin_manifest.json")
    with open(out_man_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print(f"[OK] Extracted critical files successfully. Manifest: {out_man_path}")


if __name__ == "__main__":
    main()
