#!/usr/bin/env python3
"""
test_all_stages.py - Master Test Runner for GSS4
Runs isolated unit test suites for all stages (01 to 07).

Usage:
    python test_all_stages.py
"""

import os
import subprocess
import sys
import time

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

STAGES = [
    ("Stage 1: APK Pull", os.path.join(ROOT_DIR, "01_apk_pull", "test_stage.py")),
    ("Stage 2: Extraction", os.path.join(ROOT_DIR, "02_extract", "test_stage.py")),
    ("Stage 3: Decrypt Metadata", os.path.join(ROOT_DIR, "03_decrypt_metadata", "test_stage.py")),
    ("Stage 4: Il2CppDump", os.path.join(ROOT_DIR, "04_il2cpp_dump", "test_stage.py")),
    ("Stage 5: Native Analysis", os.path.join(ROOT_DIR, "05_native_analysis", "test_stage.py")),
    ("Stage 6: Parse Offsets", os.path.join(ROOT_DIR, "06_parse_offsets", "test_stage.py")),
    ("Stage 7: Verify & Diff", os.path.join(ROOT_DIR, "07_verify_diff", "test_stage.py")),
    ("Multi-Engine & Common IR", os.path.join(ROOT_DIR, "tests", "test_multi_engine.py")),
    ("Ghidra & REA Static Integration", os.path.join(ROOT_DIR, "tests", "test_ghidra_rea_integration.py")),
    ("Frida Dynamic Analysis & Live Memory", os.path.join(ROOT_DIR, "tests", "test_frida_integration.py")),
    ("Self-Learning & Knowledge Engine", os.path.join(ROOT_DIR, "tests", "test_learning_engine.py")),
]


def main():
    print("\033[1;35m>>> Running GSS4 Modular Stage Test Suites <<<\033[0m\n")
    t0 = time.time()
    passed = 0

    import shutil
    import tempfile
    temp_knowledge_dir = tempfile.mkdtemp(prefix="gss4_test_knowledge_")
    env = os.environ.copy()
    env["GSS4_KNOWLEDGE_DIR"] = temp_knowledge_dir

    try:
        for title, test_script in STAGES:
            if not os.path.exists(test_script):
                print(f"[SKIP] {title}: test script not found ({test_script})")
                continue

            res = subprocess.run([sys.executable, test_script], cwd=os.path.dirname(test_script),
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False,
                                 env=env)
            if res.returncode == 0:
                print(f"\033[1;32m[PASS]\033[0m {title}")
                passed += 1
            else:
                print(f"\033[1;31m[FAIL]\033[0m {title}\n{res.stdout}")
    finally:
        shutil.rmtree(temp_knowledge_dir, ignore_errors=True)

    elapsed = time.time() - t0
    print(f"\n=======================================================")
    if passed == len(STAGES):
        print(f"\033[1;32m[ALL PASSED]\033[0m {passed}/{len(STAGES)} stage test suites passed in {elapsed:.2f}s!")
    else:
        print(f"\033[1;31m[SOME FAILED]\033[0m {passed}/{len(STAGES)} passed.")
    print("=======================================================\n")


if __name__ == "__main__":
    main()
