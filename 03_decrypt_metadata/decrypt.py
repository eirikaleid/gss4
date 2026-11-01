#!/usr/bin/env python3
"""
03_decrypt_metadata/decrypt.py - Stage 3: Universal Metadata Decryptor Dispatcher
Dynamically discovers and runs decryption strategies from the strategies/ directory.
Can be executed as a CLI script, imported as Stage3Decrypt(BaseStage), or called via MCP.
"""

import argparse
import importlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core.stage_base import BaseStage, StageResult
except ImportError:
    BaseStage = object

STRATEGIES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "strategies")


def discover_strategies():
    """Dynamically discover all strategy modules inside strategies/ directory."""
    strategies = {}
    if not os.path.exists(STRATEGIES_DIR):
        return strategies

    for fn in os.listdir(STRATEGIES_DIR):
        if fn.endswith(".py") and not fn.startswith("__"):
            mod_name = fn[:-3]
            try:
                mod = importlib.import_module(f"strategies.{mod_name}")
                if hasattr(mod, "run"):
                    strategies[mod_name] = mod
            except Exception as e:
                print(f"[WARN] Failed to load strategy '{mod_name}': {e}", file=sys.stderr)

    return strategies


def run_decryption(in_path, out_path, strategy="auto", report_path=None, custom_words=None):
    strategies = discover_strategies()
    if not os.path.exists(in_path):
        raise FileNotFoundError(f"Input metadata not found: {in_path}")

    selected_strategy = strategy
    with open(in_path, "rb") as f:
        head = f.read(16)

    # Auto detection: plaintext vs encrypted
    if selected_strategy == "auto":
        passthrough_mod = strategies.get("passthrough")
        if passthrough_mod and hasattr(passthrough_mod, "is_plaintext") and passthrough_mod.is_plaintext(head):
            print("[*] Metadata is standard plaintext IL2CPP -> using 'passthrough' strategy.")
            selected_strategy = "passthrough"
        else:
            print("[*] Metadata header is encrypted -> using 'gups' strategy.")
            selected_strategy = "gups"

    strat_mod = strategies.get(selected_strategy)
    if not strat_mod:
        raise ValueError(f"Unknown or unavailable strategy: '{selected_strategy}'. Available: {list(strategies.keys())}")

    print(f"[*] Executing strategy: {selected_strategy} ...")
    if selected_strategy == "gups":
        report = strat_mod.run(in_path, out_path, custom_words=custom_words)
    else:
        report = strat_mod.run(in_path, out_path)

    if report_path:
        os.makedirs(os.path.dirname(os.path.abspath(report_path)), exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as rf:
            json.dump(report, rf, indent=2)

    return report


class Stage3Decrypt(BaseStage):
    stage_id = 3
    name = "03_decrypt_metadata"
    description = "Decodes protected/encrypted global-metadata.dat into valid IL2CPP format."

    def validate_inputs(self, workspace: str, config: dict):
        meta_path = config.get("metadata_in") or os.path.join(workspace, "bin", "global-metadata.dat")
        if not os.path.exists(meta_path):
            return False, f"Missing input metadata at {meta_path}"
        return True, ""

    def execute(self, workspace: str, config: dict):
        bin_dir = os.path.join(workspace, "bin")
        in_path = config.get("metadata_in") or os.path.join(bin_dir, "global-metadata.dat")
        out_path = config.get("metadata_out") or os.path.join(bin_dir, "global-metadata.dec.dat")
        strategy = config.get("decrypt_strategy", "auto")
        report_path = os.path.join(workspace, "decrypt_report.json")
        words = config.get("validation_words", ["CharacterManager", "GamePlayer"])

        report = run_decryption(in_path, out_path, strategy=strategy, report_path=report_path, custom_words=words)
        return {
            "decrypted_metadata": out_path,
            "strategy": strategy,
            "report": report,
            "output_files": [out_path, report_path]
        }

    def validate_outputs(self, workspace: str, config: dict):
        out_path = config.get("metadata_out") or os.path.join(workspace, "bin", "global-metadata.dec.dat")
        if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
            return False, f"Missing or empty decrypted metadata at {out_path}"
        return True, ""


def main():
    parser = argparse.ArgumentParser(description="Universal IL2CPP global-metadata decryptor.")
    parser.add_argument("--in", dest="inp", required=True, help="Input global-metadata.dat path")
    parser.add_argument("--out", dest="out", required=True, help="Output decrypted .dat path")
    parser.add_argument("--strategy", default="auto", help="Decryption strategy name (default: auto)")
    parser.add_argument("--report", help="Path to write decryption report JSON")
    parser.add_argument("--words", nargs="*", default=["CharacterManager", "GamePlayer"],
                        help="Identifiers required for validation")

    args = parser.parse_args()
    try:
        res = run_decryption(args.inp, args.out, strategy=args.strategy, report_path=args.report, custom_words=args.words)
        print(f"[OK] Decrypted metadata ready: {args.out} ({res.get('size', 0):,} bytes)")
    except Exception as e:
        print(f"[FAIL] Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
