#!/usr/bin/env python3
"""
03_decrypt_metadata/decrypt.py - Universal Metadata Decryptor Dispatcher
Detects encryption protection (or lack thereof) and applies the matching decryption strategy.

Usage:
    python decrypt.py --in global-metadata.dat --out global-metadata.dec.dat [--strategy auto|gups|passthrough]
                      [--report decrypt_report.json] [--words CharacterManager GamePlayer]
"""

import argparse
import json
import os
import sys

from strategies import gups, passthrough


def main():
    parser = argparse.ArgumentParser(description="Universal IL2CPP global-metadata decryptor.")
    parser.add_argument("--in", dest="inp", required=True, help="Input global-metadata.dat path")
    parser.add_argument("--out", dest="out", required=True, help="Output decrypted .dat path")
    parser.add_argument("--strategy", default="auto", choices=["auto", "gups", "passthrough"],
                        help="Decryption strategy (default: auto)")
    parser.add_argument("--report", help="Path to write decryption report JSON")
    parser.add_argument("--words", nargs="*", default=["CharacterManager", "GamePlayer"],
                        help="Identifiers required for validation")

    args = parser.parse_args()

    if not os.path.exists(args.inp):
        print(f"[FAIL] Input file not found: {args.inp}", file=sys.stderr)
        sys.exit(1)

    with open(args.inp, "rb") as f:
        head = f.read(16)

    selected_strategy = args.strategy

    # In auto mode, check if already plaintext IL2CPP
    if selected_strategy == "auto":
        if passthrough.is_plaintext(head):
            print("[*] Metadata is standard plaintext IL2CPP -> using 'passthrough' strategy.")
            selected_strategy = "passthrough"
        else:
            print("[*] Metadata header is encrypted -> attempting 'gups' decryption strategy.")
            selected_strategy = "gups"

    try:
        if selected_strategy == "passthrough":
            report = passthrough.run(args.inp, args.out)
        elif selected_strategy == "gups":
            report = gups.run(args.inp, args.out, custom_words=args.words)
        else:
            print(f"[FAIL] Unknown strategy: {selected_strategy}", file=sys.stderr)
            sys.exit(1)

        print(f"[OK] Metadata ready: {args.out} ({report.get('size', 0):,} bytes)")
        if args.report:
            with open(args.report, "w", encoding="utf-8") as rf:
                json.dump(report, rf, indent=2)
            print(f"[OK] Report saved to: {args.report}")

    except Exception as e:
        print(f"[FAIL] Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
