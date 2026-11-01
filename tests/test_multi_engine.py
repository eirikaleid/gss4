#!/usr/bin/env python3
"""
tests/test_multi_engine.py - Multi-Engine Simulation & Common IR Test Suite
Tests Common IR round-trips, EngineProvider registry, and cross-engine pipeline
execution (Unity IL2CPP, Unity Mono, Unreal Engine, and Generic Native).
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

import importlib

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from core.common_ir import CommonIR, ClassIR, FieldIR, MethodIR, NativeSymbolIR
from core.engine_provider import get_engine_provider, list_supported_engines, EngineVerificationPolicy

Stage6Parse = getattr(importlib.import_module("06_parse_offsets.parse_offsets"), "Stage6Parse")
Stage7Verify = getattr(importlib.import_module("07_verify_diff.verify_diff"), "Stage7Verify")
parse_header = getattr(importlib.import_module("07_verify_diff.verify_diff"), "parse_header")


class TestCommonIR(unittest.TestCase):
    """Test Common IR dataclasses, serialization, and round-trips."""

    def test_roundtrip_serialization(self):
        tmp_dir = tempfile.mkdtemp(prefix="gss4_ir_test_")
        ir_file = os.path.join(tmp_dir, "symbols_ir.json")

        try:
            cir = CommonIR(
                engine="unity_il2cpp",
                arch="arm64-v8a",
                package="com.example.game",
                classes={
                    "PlayerController": ClassIR(
                        name="PlayerController",
                        namespace="GameLogic",
                        type_token="0x20000100",
                        type_info_va=0xAE9E000,
                        type_info_file_offset=0x1E9E000,
                        fields={
                            "m_health": FieldIR(name="m_health", offset=0x28, type_name="int32_t"),
                            "m_speed": FieldIR(name="m_speed", offset=0x2C, type_name="float")
                        },
                        methods={
                            "Update": MethodIR(name="Update", rva=0x100004, params_count=0),
                            "TakeDamage": MethodIR(name="TakeDamage", rva=0x100020, params_count=1)
                        }
                    )
                },
                native_symbols={
                    "EGL_SWAP_GOT": NativeSymbolIR(
                        name="EGL_SWAP_GOT",
                        library="libunity.so",
                        file_offset=0x169B2E8,
                        va=0x169B2E8
                    )
                }
            )

            # Save to disk
            cir.save(ir_file)
            self.assertTrue(os.path.exists(ir_file))

            # Load from disk
            loaded = CommonIR.load(ir_file)
            self.assertEqual(loaded.engine, "unity_il2cpp")
            self.assertIn("PlayerController", loaded.classes)
            self.assertEqual(loaded.classes["PlayerController"].fields["m_health"].offset, 0x28)
            self.assertEqual(loaded.classes["PlayerController"].methods["Update"].rva, 0x100004)
            self.assertEqual(loaded.native_symbols["EGL_SWAP_GOT"].file_offset, 0x169B2E8)

            # Test legacy dictionary projection for generators
            legacy = loaded.to_legacy_data_dict()
            self.assertEqual(len(legacy["methods"]), 2)
            self.assertEqual(legacy["fields"]["PlayerController"]["m_health"], 0x28)
            self.assertIn("PlayerController", legacy["typeinfos"])

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


class TestEngineProviders(unittest.TestCase):
    """Test registry and verification policies."""

    def test_supported_engines_list(self):
        engines = list_supported_engines()
        engine_keys = [e["engine"] for e in engines]
        self.assertIn("unity_il2cpp", engine_keys)
        self.assertIn("unity_mono", engine_keys)
        self.assertIn("unreal", engine_keys)
        self.assertIn("native", engine_keys)

    def test_policies(self):
        il2cpp_p = get_engine_provider("unity_il2cpp").get_verification_policy()
        self.assertTrue(il2cpp_p.check_rva_alignment)
        self.assertEqual(il2cpp_p.rva_alignment_bytes, 4)

        mono_p = get_engine_provider("unity_mono").get_verification_policy()
        self.assertFalse(mono_p.check_rva_alignment)
        self.assertTrue(mono_p.allow_zero_rva)

        ue_p = get_engine_provider("unreal").get_verification_policy()
        self.assertTrue(ue_p.check_rva_alignment)
        self.assertFalse(ue_p.check_typeinfo_alignment)


class TestCrossEnginePipelineExecution(unittest.TestCase):
    """Simulate Stage 6 (Code Generation) and Stage 7 (Verification Gate) for various engines."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gss4_multi_engine_sim_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_unity_mono_pipeline(self):
        """Test Unity Mono (.NET) flow where methods use CIL tokens rather than machine code RVAs."""
        dump_dir = os.path.join(self.test_dir, "dump")
        os.makedirs(dump_dir, exist_ok=True)
        ir_path = os.path.join(dump_dir, "symbols_ir.json")

        # Unity Mono Common IR: Methods have CIL token values (not necessarily 4-aligned machine code)
        mono_ir = CommonIR(
            engine="unity_mono",
            arch="arm64-v8a",
            classes={
                "GameManager": ClassIR(
                    name="GameManager",
                    namespace="Main",
                    fields={
                        "score": FieldIR(name="score", offset=0x18, token="0x04000001"),
                        "level": FieldIR(name="level", offset=0x1C, token="0x04000002")
                    },
                    methods={
                        # CIL tokens (e.g. 0x06000045, odd number - would fail standard IL2CPP 4-alignment!)
                        "StartGame": MethodIR(name="StartGame", rva=0x06000045, token="0x06000045"),
                        "EndGame": MethodIR(name="EndGame", rva=0x06000046, token="0x06000046")
                    }
                )
            }
        )
        mono_ir.save(ir_path)

        # Stage 6 execution: Ingests Common IR and generates C++ header
        stage6 = Stage6Parse()
        res6 = stage6.run_stage(self.test_dir, config={"ir_path": ir_path})
        self.assertEqual(res6.status, "success")
        header_path = os.path.join(self.test_dir, "offsets.h")
        self.assertTrue(os.path.exists(header_path))

        # Stage 7 execution: Verifies using unity_mono policy (skips machine alignment)
        stage7 = Stage7Verify()
        res7 = stage7.run_stage(self.test_dir, config={
            "new_header": header_path,
            "profile": {"engine": "unity_mono", "name": "mono_mock"}
        })
        self.assertEqual(res7.status, "success", f"Mono verification failed: {res7.error_message}")

    def test_unreal_engine_pipeline(self):
        """Test Unreal Engine flow with VTable indices and property offsets."""
        dump_dir = os.path.join(self.test_dir, "dump")
        os.makedirs(dump_dir, exist_ok=True)
        ir_path = os.path.join(dump_dir, "symbols_ir.json")

        ue_ir = CommonIR(
            engine="unreal",
            arch="arm64-v8a",
            classes={
                "ACharacter": ClassIR(
                    name="ACharacter",
                    fields={
                        "RootComponent": FieldIR(name="RootComponent", offset=0x130),
                        "CharacterMovement": FieldIR(name="CharacterMovement", offset=0x288)
                    },
                    methods={
                        "Jump": MethodIR(name="Jump", rva=0x24A8100, vtable_index=42),
                        "StopJumping": MethodIR(name="StopJumping", rva=0x24A8180, vtable_index=43)
                    }
                )
            }
        )
        ue_ir.save(ir_path)

        # Stage 6 execution
        stage6 = Stage6Parse()
        res6 = stage6.run_stage(self.test_dir, config={"ir_path": ir_path})
        self.assertEqual(res6.status, "success")
        header_path = os.path.join(self.test_dir, "offsets.h")

        # Stage 7 execution with unreal policy
        stage7 = Stage7Verify()
        res7 = stage7.run_stage(self.test_dir, config={
            "new_header": header_path,
            "profile": {"engine": "unreal", "name": "ue_mock"}
        })
        self.assertEqual(res7.status, "success", f"Unreal verification failed: {res7.error_message}")


if __name__ == "__main__":
    unittest.main()
