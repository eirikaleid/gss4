#!/usr/bin/env python3
"""
01_apk_pull/pull.py - Modular APK Puller
Fetches APKs (base + splits) from an Android device via ADB or accepts local APK paths.

Usage:
    python pull.py --package com.example.game --out ./output_apk [--device 127.0.0.1:7555] [--arch arm64]
    python pull.py --apk-path C:/path/base.apk C:/path/split.apk --out ./output_apk
"""

import argparse
import json
import os
import shutil
import subprocess
import sys


def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def pull_from_device(package, out_dir, device=None, arch="arm64"):
    os.makedirs(out_dir, exist_ok=True)
    adb_cmd = ["adb"]
    if device:
        adb_cmd.extend(["-s", device])

    # Check ADB presence
    rc, stdout, stderr = run_cmd(adb_cmd + ["devices"])
    if rc != 0:
        print(f"[FAIL] ADB execution failed: {stderr}", file=sys.stderr)
        return []

    print(f"[*] Querying package paths for '{package}' on device '{device or 'default'}'...")
    rc, stdout, stderr = run_cmd(adb_cmd + ["shell", "pm", "path", package])
    if rc != 0 or not stdout:
        print(f"[FAIL] 'pm path {package}' failed. Is the package installed? Error: {stderr}", file=sys.stderr)
        return []

    lines = [line.strip() for line in stdout.splitlines() if line.strip().startswith("package:")]
    pulled_apks = []

    for line in lines:
        remote_path = line.replace("package:", "").strip()
        leaf = os.path.basename(remote_path)

        # Filter: keep base.apk and splits matching the target architecture.
        # Skip language/density splits to save time and bandwidth.
        if leaf != "base.apk" and arch not in leaf:
            print(f"  [i] Skipping irrelevant split: {leaf}")
            continue

        local_path = os.path.join(out_dir, leaf)
        print(f"  [+] Pulling: {remote_path} -> {local_path} ...")
        rc, _, err = run_cmd(adb_cmd + ["pull", remote_path, local_path])
        if rc != 0 or not os.path.exists(local_path):
            print(f"[FAIL] adb pull failed for {remote_path}: {err}", file=sys.stderr)
            return []

        pulled_apks.append(os.path.abspath(local_path))

    return pulled_apks


def copy_local_apks(apk_paths, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    pulled_apks = []
    for p in apk_paths:
        if not os.path.exists(p):
            print(f"[FAIL] APK not found: {p}", file=sys.stderr)
            return []
        dst = os.path.join(out_dir, os.path.basename(p))
        if os.path.abspath(p) != os.path.abspath(dst):
            shutil.copy2(p, dst)
        pulled_apks.append(os.path.abspath(dst))
    return pulled_apks


def main():
    parser = argparse.ArgumentParser(description="Pull APKs from device or copy local APKs.")
    parser.add_argument("--package", help="Target Android package name")
    parser.add_argument("--device", default="127.0.0.1:7555", help="ADB device identifier")
    parser.add_argument("--arch", default="arm64", help="Target architecture (e.g. arm64, armeabi-v7a)")
    parser.add_argument("--apk-path", nargs="+", help="One or more local APK paths")
    parser.add_argument("--out", required=True, help="Output directory for APKs")
    parser.add_argument("--manifest", help="Optional output JSON path for APK manifest")

    args = parser.parse_args()

    if args.apk_path:
        apks = copy_local_apks(args.apk_path, args.out)
    elif args.package:
        apks = pull_from_device(args.package, args.out, device=args.device, arch=args.arch)
    else:
        print("[FAIL] Either --package or --apk-path must be specified.", file=sys.stderr)
        sys.exit(1)

    if not apks:
        print("[FAIL] No APKs acquired.", file=sys.stderr)
        sys.exit(1)

    print(f"[OK] Successfully acquired {len(apks)} APK file(s).")
    manifest_data = {"apks": apks}
    manifest_path = args.manifest or os.path.join(args.out, "apk_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)
    print(f"[OK] Manifest written to: {manifest_path}")


if __name__ == "__main__":
    main()
