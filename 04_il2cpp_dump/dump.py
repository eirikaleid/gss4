#!/usr/bin/env python3
"""
04_il2cpp_dump/dump.py - Stage 4: Il2CppDumper Runner
Runs Il2CppDumper on binary and decrypted metadata.
Can be executed as a CLI script, imported as Stage4Dump(BaseStage), or called via MCP.
"""

import argparse
import datetime
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core.stage_base import BaseStage, StageResult
except ImportError:
    BaseStage = object

DEFAULT_DUMPER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "tools", "Il2CppDumper", "Il2CppDumper.exe")


def run_dumper(so_path, meta_path, out_dir, dumper_exe=None, log_path=None):
    os.makedirs(out_dir, exist_ok=True)
    dumper_exe = dumper_exe or DEFAULT_DUMPER

    if not os.path.exists(so_path):
        raise FileNotFoundError(f"libil2cpp.so not found: {so_path}")
    if not os.path.exists(meta_path):
        raise FileNotFoundError(f"Metadata file not found: {meta_path}")
    if not os.path.exists(dumper_exe):
        raise FileNotFoundError(f"Il2CppDumper executable not found: {dumper_exe}")

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
    dumper_cwd = os.path.dirname(os.path.abspath(dumper_exe))

    with open(log_file, "w", encoding="utf-8", errors="replace") as lf:
        proc = subprocess.run(cmd, cwd=dumper_cwd, stdout=lf, stderr=subprocess.STDOUT, text=True, check=False)

    elapsed = time.time() - t0
    dump_cs = os.path.join(out_dir, "dump.cs")
    script_json = os.path.join(out_dir, "script.json")

    log_content = ""
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8", errors="replace") as lf:
            log_content = lf.read()

    if not os.path.exists(dump_cs) or not os.path.exists(script_json):
        print(f"[FAIL] Il2CppDumper failed. Exit code: {proc.returncode}\n{log_content[-500:]}", file=sys.stderr)
        return False

    cs_size = os.path.getsize(dump_cs)
    sj_size = os.path.getsize(script_json)

    if cs_size == 0 or sj_size == 0:
        print("[FAIL] Generated dump files are empty.", file=sys.stderr)
        return False

    manifest = {
        "timestamp": datetime.datetime.now().isoformat(),
        "elapsed_sec": round(elapsed, 2),
        "dump_cs": dump_cs,
        "dump_cs_size": cs_size,
        "script_json": script_json,
        "script_json_size": sj_size,
        "log_file": log_file
    }
    manifest_path = os.path.join(out_dir, "dump_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest


class Stage4Dump(BaseStage):
    stage_id = 4
    name = "04_il2cpp_dump"
    description = "Executes Il2CppDumper and verifies generation of dump.cs and script.json."

    def validate_inputs(self, workspace: str, config: dict):
        bin_dir = os.path.join(workspace, "bin")
        so_path = config.get("so_path") or os.path.join(bin_dir, "libil2cpp.so")
        meta_path = config.get("meta_path") or os.path.join(bin_dir, "global-metadata.dec.dat")
        if not os.path.exists(so_path):
            return False, f"Missing binary at {so_path}"
        if not os.path.exists(meta_path):
            return False, f"Missing metadata at {meta_path}"
        return True, ""

    def execute(self, workspace: str, config: dict):
        bin_dir = os.path.join(workspace, "bin")
        dump_dir = os.path.join(workspace, "dump")
        so_path = config.get("so_path") or os.path.join(bin_dir, "libil2cpp.so")
        meta_path = config.get("meta_path") or os.path.join(bin_dir, "global-metadata.dec.dat")
        dumper_exe = config.get("dumper_exe") or DEFAULT_DUMPER

        manifest = run_dumper(so_path, meta_path, dump_dir, dumper_exe=dumper_exe)
        if not manifest:
            raise RuntimeError("Il2CppDumper execution failed.")

        manifest["output_files"] = [manifest["dump_cs"], manifest["script_json"], os.path.join(dump_dir, "dump_manifest.json")]
        return manifest

    def validate_outputs(self, workspace: str, config: dict):
        dump_dir = os.path.join(workspace, "dump")
        dump_cs = os.path.join(dump_dir, "dump.cs")
        script_json = os.path.join(dump_dir, "script.json")
        if not os.path.exists(dump_cs) or os.path.getsize(dump_cs) == 0:
            return False, f"Missing or empty {dump_cs}"
        if not os.path.exists(script_json) or os.path.getsize(script_json) == 0:
            return False, f"Missing or empty {script_json}"
        return True, ""


def main():
    parser = argparse.ArgumentParser(description="Run Il2CppDumper on binary and decrypted metadata.")
    parser.add_argument("--so", required=True, help="Path to libil2cpp.so")
    parser.add_argument("--metadata", required=True, help="Path to global-metadata.dec.dat")
    parser.add_argument("--out", required=True, help="Output directory for dump")
    parser.add_argument("--dumper", default=DEFAULT_DUMPER, help="Path to Il2CppDumper.exe")
    parser.add_argument("--log", help="Path to log file")

    args = parser.parse_args()
    manifest = run_dumper(args.so, args.metadata, args.out, args.dumper, args.log)
    if not manifest:
        sys.exit(1)


if __name__ == "__main__":
    main()
