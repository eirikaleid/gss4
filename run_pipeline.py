#!/usr/bin/env python3
"""
run_pipeline.py - Master Pipeline Orchestrator for GSS4
Coordinates stages 01 through 07 using configurable application profiles.

Usage:
    python run_pipeline.py --profile royale
    python run_pipeline.py --profile royale --apply
    python run_pipeline.py --profile my_unity_game --package com.example.game --device 127.0.0.1:7555
    python run_pipeline.py --profile royale --stage 6  (Run only stage 6)
"""

import argparse
import json
import os
import subprocess
import sys
import time

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILES_DIR = os.path.join(ROOT_DIR, "profiles")
TOOLS_DIR = os.path.join(ROOT_DIR, "tools")
DEFAULT_DUMPER = os.path.join(TOOLS_DIR, "Il2CppDumper", "Il2CppDumper.exe")


def log_stage(num, title):
    print(f"\n\033[1;36m=== [Stage {num}/7: {title}] ===\033[0m", flush=True)


def log_ok(msg):
    print(f"\033[1;32m[OK]\033[0m {msg}", flush=True)


def log_fail(msg):
    print(f"\033[1;31m[FAIL]\033[0m {msg}", file=sys.stderr, flush=True)


def run_py(script_path, args):
    cmd = [sys.executable, script_path] + [str(a) for a in args]
    res = subprocess.run(cmd, check=False)
    if res.returncode != 0:
        log_fail(f"Step failed with exit code {res.returncode}: {os.path.basename(script_path)}")
        sys.exit(res.returncode)


def load_profile(profile_arg):
    if os.path.exists(profile_arg):
        path = profile_arg
    else:
        candidate = os.path.join(PROFILES_DIR, f"{profile_arg}.json")
        if os.path.exists(candidate):
            path = candidate
        else:
            candidate = os.path.join(PROFILES_DIR, profile_arg)
            if os.path.exists(candidate):
                path = candidate
            else:
                log_fail(f"Profile not found: '{profile_arg}' (checked {PROFILES_DIR})")
                sys.exit(1)

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    data["_profile_path"] = os.path.abspath(path)
    return data


def execute_pipeline(profile="royale", package=None, device=None, arch=None, apk=None,
                     stage=None, from_stage=1, apply=False, out_header=None, workspace=None,
                     known=None, src=None, knowledge_dir=None):
    if knowledge_dir:
        os.environ["GSS4_KNOWLEDGE_DIR"] = os.path.abspath(knowledge_dir)

    if isinstance(profile, str):
        profile_data = load_profile(profile)
    else:
        profile_data = profile

    app_package = package or profile_data.get("package")
    app_device = device or profile_data.get("device", "127.0.0.1:7555")
    app_arch = arch or profile_data.get("arch", "arm64-v8a")
    app_name = profile_data.get("name", "app")

    ws = os.path.abspath(workspace or os.path.join(ROOT_DIR, "build", app_name))
    dest_header = os.path.abspath(out_header or profile_data.get("output_header", os.path.join(ROOT_DIR, "src", "core", "offsets.h")))
    src_dir = os.path.abspath(src or os.path.join(ROOT_DIR, "src"))

    apk_dir = os.path.join(ws, "apk")
    bin_dir = os.path.join(ws, "bin")
    dump_dir = os.path.join(ws, "dump")
    new_header = os.path.join(ws, "offsets.h")
    new_json = os.path.join(ws, "offsets.json")
    native_json = os.path.join(ws, "native.json")
    verify_log = os.path.join(ws, "verify_report.txt")

    os.makedirs(ws, exist_ok=True)
    os.makedirs(apk_dir, exist_ok=True)
    os.makedirs(bin_dir, exist_ok=True)
    os.makedirs(dump_dir, exist_ok=True)

    print(f"\033[1;35m>>> Starting GSS4 Pipeline for profile '{app_name}' (package: {app_package}) <<<\033[0m")
    t_start = time.time()

    def should_run(st):
        if stage:
            return stage == st
        return st >= (from_stage or 1)

    # Stage 1: APK Pull
    if should_run(1):
        log_stage(1, "APK Acquisition")
        p_args = ["--out", apk_dir]
        if apk:
            p_args.extend(["--apk-path"] + (apk if isinstance(apk, list) else [apk]))
        else:
            p_args.extend(["--package", app_package, "--device", app_device, "--arch", app_arch.split("-")[0]])
        run_py(os.path.join(ROOT_DIR, "01_apk_pull", "pull.py"), p_args)

    # Stage 2: Extract
    if should_run(2):
        log_stage(2, "Binary & Metadata Extraction")
        run_py(os.path.join(ROOT_DIR, "02_extract", "extract.py"), [
            "--manifest", os.path.join(apk_dir, "apk_manifest.json"),
            "--out", bin_dir,
            "--arch", app_arch
        ])

    il2cpp_so = os.path.join(bin_dir, "libil2cpp.so")
    unity_so = os.path.join(bin_dir, "libunity.so")
    enc_meta = os.path.join(bin_dir, "global-metadata.dat")
    dec_meta = os.path.join(bin_dir, "global-metadata.dec.dat")

    # Stage 3: Decrypt Metadata
    if should_run(3):
        log_stage(3, "Metadata Decryption")
        strategy = profile_data.get("decrypt_strategy", "auto")
        run_py(os.path.join(ROOT_DIR, "03_decrypt_metadata", "decrypt.py"), [
            "--in", enc_meta,
            "--out", dec_meta,
            "--strategy", strategy,
            "--report", os.path.join(ws, "decrypt_report.json")
        ])

    # Stage 4: IL2CPP Dump
    if should_run(4):
        log_stage(4, "Il2CppDumper")
        run_py(os.path.join(ROOT_DIR, "04_il2cpp_dump", "dump.py"), [
            "--so", il2cpp_so,
            "--metadata", dec_meta,
            "--out", dump_dir,
            "--dumper", DEFAULT_DUMPER
        ])

    # Stage 5: Native Analysis
    if should_run(5):
        log_stage(5, "Native ELF Analysis")
        native_rules = json.dumps(profile_data.get("native_rules", {}))
        run_py(os.path.join(ROOT_DIR, "05_native_analysis", "analyze_native.py"), [
            "--lib", unity_so,
            "--json", native_json,
            "--rules", native_rules
        ])

    # Stage 6: Parse Offsets
    if should_run(6):
        log_stage(6, "Offset Parsing & Header Generation")
        pargs = [
            "--dump", os.path.join(dump_dir, "dump.cs"),
            "--script", os.path.join(dump_dir, "script.json"),
            "--so", il2cpp_so,
            "--profile", profile_data["_profile_path"],
            "--out", new_header,
            "--out-json", new_json,
            "--report", os.path.join(ws, "parse_report.json")
        ]
        if os.path.exists(native_json):
            pargs.extend(["--native-json", native_json])
        run_py(os.path.join(ROOT_DIR, "06_parse_offsets", "parse_offsets.py"), pargs)

    # Stage 7: Verify & Diff
    if should_run(7):
        log_stage(7, "Verification & Diff Gate")
        vargs = [
            "--new", new_header,
            "--so", il2cpp_so,
            "--profile", profile_data["_profile_path"],
            "--report", verify_log,
            "--backup-dir", os.path.join(ROOT_DIR, "backups")
        ]
        if os.path.exists(dest_header):
            vargs.extend(["--old", dest_header])
        if os.path.isdir(src_dir):
            vargs.extend(["--src", src_dir])
        if known or profile_data.get("known_version"):
            vargs.extend(["--known", known or profile_data.get("known_version")])
        if apply:
            vargs.extend(["--apply-to", dest_header])

        run_py(os.path.join(ROOT_DIR, "07_verify_diff", "verify_diff.py"), vargs)

    total_time = time.time() - t_start
    print(f"\n\033[1;32m=======================================================\033[0m")
    print(f"\033[1;32m[SUCCESS] Pipeline completed in {total_time:.1f} seconds!\033[0m")
    print(f"Generated Header : {new_header}")
    print(f"Generated JSON   : {new_json}")
    if apply:
        print(f"Applied To       : {dest_header}")
    else:
        print(f"\033[1;33mNote: Run with '--apply' to update {dest_header}\033[0m")
    print(f"\033[1;32m=======================================================\033[0m\n")

    # Record holistic pipeline run in Learning Engine
    try:
        from core.learning import get_learning_engine
        le = get_learning_engine()
        le.learn_from_run(
            run_context={
                "profile": app_name,
                "package": app_package,
                "device": app_device,
                "arch": app_arch,
                "workspace": ws
            },
            results={
                "status": "success",
                "elapsed_sec": round(total_time, 2),
                "header_path": new_header,
                "json_path": new_json
            }
        )
    except Exception:
        pass

    return {
        "status": "success",
        "app_name": app_name,
        "elapsed_sec": round(total_time, 2),
        "header_path": new_header,
        "json_path": new_json,
        "applied_path": dest_header if apply else None
    }


def main():
    parser = argparse.ArgumentParser(description="Universal IL2CPP Offset Pipeline Runner.")
    parser.add_argument("--profile", default="royale", help="Profile name or JSON file path (default: royale)")
    parser.add_argument("--package", help="Override Android package name")
    parser.add_argument("--device", help="Override ADB device identifier")
    parser.add_argument("--arch", help="Override target ABI (arm64-v8a, etc.)")
    parser.add_argument("--apk", nargs="+", help="Explicit local APK path(s) to bypass pulling from device")
    parser.add_argument("--stage", type=int, choices=range(1, 8), help="Run only a single specific stage (1..7)")
    parser.add_argument("--from-stage", type=int, choices=range(1, 8), default=1, help="Start pipeline from stage N")
    parser.add_argument("--apply", action="store_true", help="Apply generated header to destination path upon successful verification")
    parser.add_argument("--out-header", help="Override output header destination")
    parser.add_argument("--workspace", help="Override workspace/build directory")
    parser.add_argument("--known", help="Assert specific known version checks (e.g. 4.9)")
    parser.add_argument("--src", help="Path to project source folder to check undefined symbols")
    parser.add_argument("--knowledge-dir", help="Override persistent knowledge base storage directory (default: ./knowledge)")

    args = parser.parse_args()
    execute_pipeline(
        profile=args.profile,
        package=args.package,
        device=args.device,
        arch=args.arch,
        apk=args.apk,
        stage=args.stage,
        from_stage=args.from_stage,
        apply=args.apply,
        out_header=args.out_header,
        workspace=args.workspace,
        known=args.known,
        src=args.src,
        knowledge_dir=args.knowledge_dir
    )


if __name__ == "__main__":
    main()
