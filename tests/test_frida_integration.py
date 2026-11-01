#!/usr/bin/env python3
"""
tests/test_frida_integration.py - Master Unit Test Suite for GSS4 Frida Integration
===================================================================================
Tests all Frida-based dynamic analysis and live memory capabilities in GSS4:
  1. Stage 3: Frida Live Metadata Dumper (03_decrypt_metadata/strategies/frida_live.py)
  2. Stage 4: Frida Runtime Dumper Adapter (04_il2cpp_dump/adapters/frida_runtime_dumper.py)
  3. Stage 7: Frida Live Memory Assertion Gate (07_verify_diff/validators/frida_live_assert.py)
  4. End-to-End Pipeline Chain (Stage 3 -> Stage 4 -> Stage 6 -> Stage 7)
All tests run 100% device-free using synthetic mock memory simulation.
"""

import importlib
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from core.common_ir import CommonIR, ClassIR, FieldIR, MethodIR
from core.errors import VerificationGateError

# Import Stage 3 modules
Stage3Decrypt = getattr(importlib.import_module("03_decrypt_metadata.decrypt"), "Stage3Decrypt")
discover_strategies = getattr(importlib.import_module("03_decrypt_metadata.decrypt"), "discover_strategies")
run_decryption = getattr(importlib.import_module("03_decrypt_metadata.decrypt"), "run_decryption")
frida_live = importlib.import_module("03_decrypt_metadata.strategies.frida_live")

# Import Stage 4 modules
Stage4Dump = getattr(importlib.import_module("04_il2cpp_dump.dump"), "Stage4Dump")
frida_runtime_dumper = importlib.import_module("04_il2cpp_dump.adapters.frida_runtime_dumper")

# Import Stage 6 & 7 modules
Stage6Parse = getattr(importlib.import_module("06_parse_offsets.parse_offsets"), "Stage6Parse")
Stage7Verify = getattr(importlib.import_module("07_verify_diff.verify_diff"), "Stage7Verify")
verify_and_diff = getattr(importlib.import_module("07_verify_diff.verify_diff"), "verify_and_diff")
frida_live_assert = importlib.import_module("07_verify_diff.validators.frida_live_assert")
MockProcessMemory = frida_live_assert.MockProcessMemory
is_valid_arm64_prologue = frida_live_assert.is_valid_arm64_prologue


class TestStage3FridaLive(unittest.TestCase):
    """Tests Stage 3 Frida Live Metadata Dumper strategy."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gss4_frida_s3_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_strategy_discovery(self):
        strategies = discover_strategies()
        self.assertIn("frida_live", strategies)

    def test_mock_metadata_generation(self):
        out_path = os.path.join(self.test_dir, "global-metadata.dec.dat")
        rep = frida_live.run("dummy.dat", out_path, mock=True)
        self.assertEqual(rep["status"], "success")
        self.assertEqual(rep["strategy"], "frida_live")
        self.assertEqual(rep["mode"], "mock")
        self.assertTrue(os.path.exists(out_path))

        with open(out_path, "rb") as f:
            magic, version = struct.unpack_from("<II", f.read(8), 0)
        self.assertEqual(magic, 0xFAB11BAF)
        self.assertEqual(version, 29)

    def test_stage3_lifecycle_with_frida_strategy(self):
        stage = Stage3Decrypt()
        ws = os.path.join(self.test_dir, "ws")
        bin_dir = os.path.join(ws, "bin")
        os.makedirs(bin_dir, exist_ok=True)

        res = stage.run_stage(ws, config={
            "decrypt_strategy": "frida_live",
            "mock": True
        })
        self.assertEqual(res.status, "success")
        out_dec = os.path.join(bin_dir, "global-metadata.dec.dat")
        self.assertTrue(os.path.exists(out_dec))


class TestStage4FridaRuntimeDumper(unittest.TestCase):
    """Tests Stage 4 Frida Runtime Dumper adapter and CommonIR emission."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gss4_frida_s4_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_frida_runtime_dump_mock(self):
        dump_dir = os.path.join(self.test_dir, "dump")
        res = frida_runtime_dumper.run_dump(out_dir=dump_dir, mock=True)

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["adapter"], "frida_runtime_dumper")
        self.assertEqual(res["mode"], "mock")

        ir_path = os.path.join(dump_dir, "symbols_ir.json")
        cs_path = os.path.join(dump_dir, "dump.cs")
        sj_path = os.path.join(dump_dir, "script.json")

        self.assertTrue(os.path.exists(ir_path))
        self.assertTrue(os.path.exists(cs_path))
        self.assertTrue(os.path.exists(sj_path))

        # Check CommonIR structure
        cir = CommonIR.load(ir_path)
        self.assertEqual(cir.engine, "unity_il2cpp")
        self.assertIn("PlayerController", cir.classes)
        self.assertIn("m_health", cir.classes["PlayerController"].fields)
        self.assertIn("Update", cir.classes["PlayerController"].methods)
        self.assertEqual(cir.classes["PlayerController"].methods["Update"].rva, 0x1000)

    def test_stage4_lifecycle_with_frida_adapter(self):
        stage = Stage4Dump()
        dump_dir = os.path.join(self.test_dir, "dump")
        res = stage.run_stage(self.test_dir, config={
            "adapter": "frida",
            "mock": True,
            "dump_dir": dump_dir
        })
        self.assertEqual(res.status, "success")
        self.assertTrue(os.path.exists(os.path.join(dump_dir, "symbols_ir.json")))
        self.assertTrue(os.path.exists(os.path.join(dump_dir, "dump.cs")))
        self.assertTrue(os.path.exists(os.path.join(dump_dir, "script.json")))


class TestStage7FridaLiveAssert(unittest.TestCase):
    """Tests Stage 7 Frida live memory assertions and MockProcessMemory simulation."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gss4_frida_s7_")
        self.header_path = os.path.join(self.test_dir, "offsets.h")

        header_content = """#pragma once
#include <cstdint>
namespace Offsets {
    constexpr uintptr_t PlayerController_Update = 0x1000;
    constexpr uintptr_t PlayerController_TakeDamage = 0x1020;
    namespace Actor {
        constexpr uintptr_t HEALTH = 0x20;
    }
    namespace TypeInfo {
        constexpr uintptr_t PlayerController = 0x2000;
        constexpr uintptr_t Actor = 0x2040;
    }
}
"""
        with open(self.header_path, "w", encoding="utf-8") as f:
            f.write(header_content)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_arm64_prologue_detector(self):
        # Valid ARM64 prologues
        self.assertTrue(is_valid_arm64_prologue(0xA9BF7BFD))  # STP X29, X30, [SP, #-96]!
        self.assertTrue(is_valid_arm64_prologue(0xD10043FF))  # SUB SP, SP, #16
        self.assertTrue(is_valid_arm64_prologue(0xD503233F))  # PACIASP
        self.assertTrue(is_valid_arm64_prologue(0x910003FD))  # MOV X29, SP

        # Invalid opcodes
        self.assertFalse(is_valid_arm64_prologue(0x00000000))  # Zeroes
        self.assertFalse(is_valid_arm64_prologue(0xFFFFFFFF))  # Dead memory
        self.assertFalse(is_valid_arm64_prologue(0xD4200000))  # brk #0

    def test_mock_memory_clean_assertion(self):
        summary = frida_live_assert.verify_live(
            header_path=self.header_path,
            mock=True
        )
        self.assertEqual(summary["status"], "success")
        self.assertGreater(summary["passed_methods"], 0)
        self.assertGreater(summary["passed_typeinfos"], 0)
        self.assertEqual(len(summary["failures"]), 0)

    def test_catches_non_executable_page_violation(self):
        mem = MockProcessMemory.create_mock_il2cpp(base=0x7000000000)
        # Setup valid methods & typeinfos
        methods = {"PlayerController_Update": 0x1000}
        typeinfos = {"TypeInfo::PlayerController": (0x2000, "PlayerController")}
        frida_live_assert.populate_mock_il2cpp_environment(mem, methods, typeinfos, base=0x7000000000)

        # Corrupt the code page to non-executable 'rw-'
        for r in mem.ranges:
            if "text" in r["name"]:
                r["protection"] = "rw-"

        with self.assertRaises(VerificationGateError) as ctx:
            frida_live_assert.verify_live(
                header_path=self.header_path,
                mock_memory=mem
            )
        self.assertIn("NOT executable", str(ctx.exception))

    def test_catches_invalid_prologue_violation(self):
        mem = MockProcessMemory.create_mock_il2cpp(base=0x7000000000)
        methods = {"PlayerController_Update": 0x1000}
        typeinfos = {"TypeInfo::PlayerController": (0x2000, "PlayerController")}
        frida_live_assert.populate_mock_il2cpp_environment(mem, methods, typeinfos, base=0x7000000000)

        # Corrupt prologue with zeroes
        mem.write(0x7000000000 + 0x1000, b"\x00\x00\x00\x00")

        with self.assertRaises(VerificationGateError) as ctx:
            frida_live_assert.verify_live(
                header_path=self.header_path,
                mock_memory=mem
            )
        self.assertIn("invalid instruction prologue", str(ctx.exception))

    def test_catches_corrupted_typeinfo_class_mismatch(self):
        mem = MockProcessMemory.create_mock_il2cpp(base=0x7000000000)
        methods = {"PlayerController_Update": 0x1000}
        # Intentionally mismatch expected class name
        typeinfos = {"TypeInfo::PlayerController": (0x2000, "CompletelyWrongClass")}
        frida_live_assert.populate_mock_il2cpp_environment(mem, methods, typeinfos, base=0x7000000000)

        with self.assertRaises(VerificationGateError) as ctx:
            frida_live_assert.verify_live(
                header_path=self.header_path,
                mock_memory=mem
            )
        self.assertIn("mismatch", str(ctx.exception))

    def test_stage7_lifecycle_with_live_assert(self):
        stage = Stage7Verify()
        ws = os.path.join(self.test_dir, "ws")
        os.makedirs(ws, exist_ok=True)
        target_h = os.path.join(ws, "offsets.h")
        shutil.copy2(self.header_path, target_h)

        res = stage.run_stage(ws, config={
            "new_header": target_h,
            "live_assert": True,
            "mock": True
        })
        self.assertEqual(res.status, "success")


class TestFridaEndToEndPipeline(unittest.TestCase):
    """Verifies that all Frida modules interlock seamlessly in a multi-stage pipeline flow."""

    def setUp(self):
        self.ws = tempfile.mkdtemp(prefix="gss4_frida_e2e_")
        self.bin_dir = os.path.join(self.ws, "bin")
        self.dump_dir = os.path.join(self.ws, "dump")
        os.makedirs(self.bin_dir, exist_ok=True)
        os.makedirs(self.dump_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_end_to_end_frida_flow(self):
        # 1. Stage 3 with Frida live mock dumper
        s3 = Stage3Decrypt()
        res3 = s3.run_stage(self.ws, config={
            "decrypt_strategy": "frida_live",
            "mock": True
        })
        self.assertEqual(res3.status, "success")
        dec_meta = os.path.join(self.bin_dir, "global-metadata.dec.dat")
        self.assertTrue(os.path.exists(dec_meta))

        # 2. Stage 4 with Frida runtime dumper adapter
        s4 = Stage4Dump()
        res4 = s4.run_stage(self.ws, config={
            "adapter": "frida",
            "mock": True,
            "dump_dir": self.dump_dir
        })
        self.assertEqual(res4.status, "success")
        ir_file = os.path.join(self.dump_dir, "symbols_ir.json")
        self.assertTrue(os.path.exists(ir_file))

        # 3. Stage 6: Parse Common IR into offsets.h
        s6 = Stage6Parse()
        new_header = os.path.join(self.ws, "offsets.h")
        profile = {
            "name": "frida_e2e_game",
            "classes": ["PlayerController", "Actor"]
        }
        res6 = s6.run_stage(self.ws, config={
            "ir_path": ir_file,
            "profile": profile,
            "out_header": new_header,
            "dump_dir": self.dump_dir
        })
        self.assertEqual(res6.status, "success")
        self.assertTrue(os.path.exists(new_header))

        # 4. Stage 7: Safety gate verification with Frida live assert
        s7 = Stage7Verify()
        res7 = s7.run_stage(self.ws, config={
            "new_header": new_header,
            "live_assert": True,
            "mock": True
        })
        self.assertEqual(res7.status, "success")
        self.assertGreater(res7.data["constants_count"], 0)


if __name__ == "__main__":
    unittest.main()
