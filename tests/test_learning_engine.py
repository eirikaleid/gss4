#!/usr/bin/env python3
"""
tests/test_learning_engine.py - Unit Test Suite for GSS4 Self-Learning & Knowledge Engine
Tests fingerprinting, strategy learning feedback loops, obfuscation alias matching,
version drift analysis, adaptive error recovery, and BaseStage lifecycle integration.
"""

import json
import os
import shutil
import struct
import sys
import tempfile
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from core.learning import (
    LearningEngine,
    extract_fingerprint,
    calculate_shannon_entropy,
    BinaryFingerprint,
    AliasRecord,
    DriftRecord,
    LearnedLesson
)
from core.stage_base import BaseStage, StageResult
from core.errors import DecryptionError, VerificationGateError


class DummyFailingStage(BaseStage):
    stage_id = 3
    name = "dummy_failing_stage"

    def execute(self, workspace, config):
        raise DecryptionError(
            message="XOR ramp deobfuscation mismatch on header block",
            error_code="ERR_DECRYPTION_FAILED"
        )


class TestLearningEngine(unittest.TestCase):
    """Test suite covering the complete autonomous learning lifecycle."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gss4_learning_test_")
        self.knowledge_dir = os.path.join(self.test_dir, "knowledge")
        self.engine = LearningEngine(knowledge_dir=self.knowledge_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # --------------------------------------------------------------------------
    # 1. Entropy & Fingerprinting
    # --------------------------------------------------------------------------

    def test_shannon_entropy_calculation(self):
        # 1. Uniform bytes -> zero entropy
        zero_entropy = calculate_shannon_entropy(b"\x00" * 1024)
        self.assertEqual(zero_entropy, 0.0)

        # 2. Random bytes -> high entropy (~8.0)
        import random
        random.seed(42)
        rand_bytes = bytes([random.randint(0, 255) for _ in range(4096)])
        high_entropy = calculate_shannon_entropy(rand_bytes)
        self.assertGreater(high_entropy, 7.5)

    def test_fingerprint_extraction_plaintext_metadata(self):
        # Plaintext IL2CPP metadata: magic 0xFAB11BAF + version 29
        data = struct.pack("<II", 0xFAB11BAF, 29) + b"PlayerController\x00GameManager\x00" + b"\x00" * 512
        fp = self.engine.extract_fingerprint(data, package="net.f8games.royale", file_name="global-metadata.dat")

        self.assertIsInstance(fp, BinaryFingerprint)
        self.assertEqual(fp.file_name, "global-metadata.dat")
        self.assertEqual(fp.magic_hex, "af1bb1fa")
        self.assertEqual(fp.metadata_version, 29)
        self.assertFalse(fp.is_encrypted_heuristic)
        self.assertTrue(fp.key.startswith("fp_"))

    def test_fingerprint_extraction_encrypted_file(self):
        # Encrypted metadata with masked magic
        masked_data = b"\xde\xad\xbe\xef" + os.urandom(2048)
        meta_path = os.path.join(self.test_dir, "encrypted.dat")
        with open(meta_path, "wb") as f:
            f.write(masked_data)

        fp = self.engine.extract_fingerprint(meta_path, package="net.f8games.royale")
        self.assertEqual(fp.magic_hex, "deadbeef")
        self.assertTrue(fp.is_encrypted_heuristic)

    # --------------------------------------------------------------------------
    # 2. Strategy Learning & Priority Feedback Loop
    # --------------------------------------------------------------------------

    def test_strategy_learning_and_priority(self):
        fp = self.engine.extract_fingerprint(
            b"encrypted_content_sample_123" + os.urandom(256),
            file_name="global-metadata.dat",
            package="com.custom.game"
        )

        # 1. Initially no exact learned strategy - falls back to heuristic (gups for encrypted metadata)
        suggested = self.engine.suggest_strategy(fp, available_strategies=["passthrough", "gups", "frida_live"])
        self.assertEqual(suggested, "gups")

        # 2. Record successful custom delta strategy
        self.engine.record_strategy_success(fp, "frida_live", details={"memory_dump": True})

        # 3. Subsequent query should prioritize the learned 'frida_live' strategy
        second_suggest = self.engine.suggest_strategy(fp, available_strategies=["passthrough", "gups", "frida_live"])
        self.assertEqual(second_suggest, "frida_live")

        # 4. Record a failure and verify metrics tracking
        self.engine.record_strategy_failure(fp, "gups", "Ramp checksum failure")
        fps_data = self.engine._load_json(self.engine.fingerprints_file)
        proven = fps_data["fingerprints"][fp.key]["proven_strategies"]
        self.assertEqual(proven["frida_live"]["success_count"], 1)
        self.assertEqual(proven["gups"]["failure_count"], 1)

    # --------------------------------------------------------------------------
    # 3. Alias Mapping & Obfuscation Detection
    # --------------------------------------------------------------------------

    def test_alias_mapping_and_bidirectional_resolution(self):
        pkg = "net.f8games.royale"
        self.engine.record_alias_mapping(
            package=pkg,
            canonical_name="CharacterManager",
            alias_name="Obf_a1_Manager",
            confidence=0.95,
            evidence=["method_count=12", "string_ref=kAttackRange"]
        )

        # 1. Canonical -> Alias
        resolved_alias = self.engine.resolve_alias(pkg, "CharacterManager")
        self.assertEqual(resolved_alias, "Obf_a1_Manager")

        # 2. Alias -> Canonical
        resolved_canonical = self.engine.resolve_alias(pkg, "Obf_a1_Manager")
        self.assertEqual(resolved_canonical, "CharacterManager")

    def test_heuristic_alias_candidate_matcher(self):
        pkg = "com.test.obfuscated"
        target_sig = {
            "field_count": 8,
            "methods": [
                {"name": "Init", "param_count": 0},
                {"name": "SetHealth", "param_count": 1},
                {"name": "UpdatePosition", "param_count": 2}
            ],
            "strings": ["PlayerHealth", "MaxSpeed"]
        }

        candidates = [
            {
                "name": "Class_Unrelated",
                "field_count": 2,
                "methods": [{"name": "DoWork", "param_count": 1}],
                "strings": ["LoadingAssets"]
            },
            {
                "name": "Class_PlayerController_Obfuscated",
                "field_count": 8,
                "methods": [
                    {"name": "Init", "param_count": 0},
                    {"name": "SetHealth", "param_count": 1},
                    {"name": "UpdatePosition", "param_count": 2}
                ],
                "strings": ["PlayerHealth", "MaxSpeed", "ExtraDebug"]
            }
        ]

        result = self.engine.find_candidate_alias(pkg, target_sig, candidates, threshold=0.7)
        self.assertIsNotNone(result)
        matched_name, score, evidence = result
        self.assertEqual(matched_name, "Class_PlayerController_Obfuscated")
        self.assertGreaterEqual(score, 0.90)
        self.assertTrue(any("exact_field_count" in e for e in evidence))

    # --------------------------------------------------------------------------
    # 4. Drift Patterns & Offset Prediction
    # --------------------------------------------------------------------------

    def test_drift_pattern_recording_and_prediction(self):
        pkg = "net.f8games.royale"
        # Simulate an update where functions shifted by +0x1000 and fields remained unchanged
        shifts = {
            "CharacterManager_Update": 0x1000,
            "PlayerController_Move": 0x1000,
            "GameManager_Awake": 0x1000,
            "Offsets::Health": 0x0
        }

        rec = self.engine.record_drift_pattern(
            package=pkg,
            from_version="4.8",
            to_version="4.9",
            shifts=shifts
        )
        self.assertIsInstance(rec, DriftRecord)
        self.assertEqual(rec.median_shift, 0x1000)

        # Predict offset for a known symbol
        predicted_move = self.engine.predict_offset(
            package=pkg,
            symbol="PlayerController_Move",
            previous_offset=0x200000,
            from_version="4.8",
            to_version="4.9"
        )
        self.assertEqual(predicted_move, 0x201000)

        # Predict offset for an unknown symbol using median drift
        predicted_generic = self.engine.predict_offset(
            package=pkg,
            symbol="UnknownNewFunc",
            previous_offset=0x150000,
            from_version="4.8",
            to_version="4.9"
        )
        self.assertEqual(predicted_generic, 0x151000)

    # --------------------------------------------------------------------------
    # 5. Adaptive Recovery & Lessons Memory
    # --------------------------------------------------------------------------

    def test_lesson_recording_and_adaptive_recovery(self):
        lesson_id = self.engine.record_lesson(
            topic="frida_hook_remediation",
            problem="ERR_HOOK_FAILED",
            solution="Selinux permissive moduna geçin veya frida-server'ı root olarak çalıştırın.",
            stage_id=5,
            error_code="ERR_HOOK_FAILED",
            tags=["frida", "hook", "selinux"]
        )
        self.assertTrue(lesson_id.startswith("lesson_"))

        # Query recovery suggestions for ERR_HOOK_FAILED
        suggestions = self.engine.suggest_recovery(stage_id=5, error_code="ERR_HOOK_FAILED")
        self.assertTrue(len(suggestions) > 0)
        top = suggestions[0]
        self.assertIn("Selinux", top["solution"])
        self.assertEqual(top["id"], lesson_id)

    # --------------------------------------------------------------------------
    # 6. BaseStage Error Handler Integration
    # --------------------------------------------------------------------------

    def test_stage_base_adaptive_error_handling(self):
        stage = DummyFailingStage()
        # Inject our isolated test learning engine
        stage.learning_engine = self.engine

        res = stage.run_stage(self.test_dir, {"package": "net.f8games.royale"})
        self.assertEqual(res.status, "error")
        self.assertEqual(res.error_code, "ERR_DECRYPTION_FAILED")

        # Verify that BaseStage enriched the result suggestions with adaptive learned recommendations
        has_adaptive_tip = any("Öğrenilen Adaptif Çözüm" in s for s in res.suggestions)
        self.assertTrue(has_adaptive_tip, f"Expected adaptive tip in suggestions: {res.suggestions}")

    # --------------------------------------------------------------------------
    # 7. Knowledge Base Persistence & Reloading
    # --------------------------------------------------------------------------

    def test_knowledge_persistence_roundtrip(self):
        # 1. Write alias and lesson
        pkg = "com.persistence.test"
        self.engine.record_alias_mapping(pkg, "TestClass", "Obf_TestClass", confidence=0.88)
        self.engine.record_lesson("disk_test", "ERR_TEST", "Test resolution advice", error_code="ERR_TEST")

        # 2. Instantiate a second fresh LearningEngine instance pointing to the same knowledge_dir
        engine2 = LearningEngine(knowledge_dir=self.knowledge_dir)

        # 3. Verify data was preserved
        alias = engine2.resolve_alias(pkg, "TestClass")
        self.assertEqual(alias, "Obf_TestClass")

        knowledge = engine2.get_learned_knowledge(query="disk_test")
        self.assertEqual(len(knowledge.get("lessons", [])), 1)
        self.assertEqual(knowledge["lessons"][0]["solution"], "Test resolution advice")

    # --------------------------------------------------------------------------
    # 8. MCP Server Integration Functions
    # --------------------------------------------------------------------------

    def test_mcp_learning_tools(self):
        import mcp_server

        # Test record_learned_lesson tool
        rec_res = mcp_server.record_learned_lesson(
            topic="mcp_test",
            problem="ERR_MCP_SAMPLE",
            solution="Apply MCP patch buffer",
            stage_id=6,
            error_code="ERR_MCP_SAMPLE"
        )
        self.assertEqual(rec_res["status"], "success")

        # Test suggest_adaptation tool
        adapt_res = mcp_server.suggest_adaptation(
            package="net.f8games.royale",
            error_code="ERR_DECRYPTION_FAILED",
            stage_id=3
        )
        self.assertEqual(adapt_res["error_code"], "ERR_DECRYPTION_FAILED")
        self.assertTrue(len(adapt_res["recommended_solutions"]) > 0)

        # Test get_learned_knowledge tool
        know_res = mcp_server.get_learned_knowledge(query="MCP")
        self.assertIn("summary", know_res)


if __name__ == "__main__":
    unittest.main()
