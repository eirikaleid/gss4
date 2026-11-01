#!/usr/bin/env python3
"""
04_il2cpp_dump/dump.py - Modular Il2CppDumper Runner
Executes Il2CppDumper on target libil2cpp.so and decrypted global-metadata.dat,
validating fresh generation of dump.cs and script.json.

Usage:
    python dump.py --so ./bin/libil2cpp.so --metadata ./bin/global-metadata.dec.dat --out ./dump
                   [--dumper ../tools/Il2CppDumper/Il2CppDumper.exe]
"""

import argparse
import datetime
import json
import os
import subprocess
import sys
import time


def run_dumper(so_path, meta_path, out_dir, dumper_exe, log_path=None):
    os.makedirs(out_dir, exist_ok=True)

    if not os.path.exists(so_path):
        print(f"[FAIL] libil2cpp.so not found: {so_path}", file=sys.stderr)
        return False
    if not os.path.exists(meta_path):
        print(f"[FAIL] Metadata file not found: {meta_path}", file=sys.stderr)
        return False
    if not os.path.exists(dumper_exe):
        print(f"[FAIL] Il2CppDumper executable not found: {dumper_exe}", file=sys.stderr)
        return False

    # Clean old dump files to guarantee freshness
    for f in ["dump.cs", "script.json", "il2cpp.h", "stringliteral.json"]:
        p = os.path.join(out_dir, f)
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass

    t0 = time.time()
    log_file = log_path or os.path.join(out_dir, "il2cppdumper.log")
    print(f"[*] Running Il2CppDumper...\n    SO: {so_path}\n    Metadata: {meta_path}\n    Output: {out_dir}")

    cmd = [os.path.abspath(dumper_exe), os.path.abspath(so_path), os.path.abspath(meta_path), os.path.abspath(out_dir)]

    # Run Il2CppDumper from its own directory so it loads its local config.json
    dumper_cwd = os.path.dirname(os.path.abspath(dumper_exe))

    try:
        with open(log_file, "w", encoding="utf-8", errors="replace") as lf:
            proc = subprocess.run(cmd, cwd=dumper_cwd, stdout=lf, stderr=subprocess.STDOUT, text=True, check=False)
    except Exception as e:
        print(f"[FAIL] Could not start Il2CppDumper process: {e}", file=sys.stderr)
        return False

    elapsed = time.time() - t0
    dump_cs = os.path.join(out_dir, "dump.cs")
    script_json = os.path.join(out_dir, "script.json")

    # Read log
    log_content = ""
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8", errors="replace") as lf:
            log_content = lf.read()

    # Success criteria: dump.cs and script.json exist and are freshly written
    if not os.path.exists(dump_cs) or not os.path.exists(script_json):
        print(f"[FAIL] Il2CppDumper did not produce expected output files. Return code: {proc.returncode}", file=sys.stderr)
        print("Last log lines:\n" + "\n".join(log_content.splitlines()[-15:]), file=sys.stderr)
        return False

    cs_size = os.path.getsize(dump_cs)
    sj_size = os.path.getsize(script_json)

    if cs_size == 0 or sj_size == 0:
        print("[FAIL] Generated dump files are empty.", file=sys.stderr)
        return False

    print(f"[OK] Il2CppDumper finished in {elapsed:.1f}s. dump.cs: {cs_size / (1024*1024):.1f} MB, script.json: {sj_size / (1024*1024):.1f} MB")

    manifest = {
        "timestamp": datetime.datetime.now().isoformat(),
        "elapsed_sec": round(elapsed, 2),
        "dump_cs": dump_cs,
        "dump_cs_size": cs_size,
        "script_json": script_json,
        "script_json_size": sj_size,
        "log_file": log_file
    }
    with open(os.path.join(out_dir, "dump_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return True


def main():
    parser = argparse.ArgumentParser(description="Run Il2CppDumper on binary and decrypted metadata.")
    parser.add_argument("--so", required=True, help="Path to libil2cpp.so")
    parser.add_argument("--metadata", required=True, help="Path to global-metadata.dec.dat")
    parser.add_argument("--out", required=True, help="Output directory for dump")
    parser.add_argument("--dumper", default="../tools/Il2CppDumper/Il2CppDumper.exe",
                        help="Path to Il2CppDumper.exe")
    parser.add_argument("--log", help="Path to log file")

    args = parser.parse_args()
    success = run_dumper(args.so, args.metadata, args.out, args.dumper, args.log)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
