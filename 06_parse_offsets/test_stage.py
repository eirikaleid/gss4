#!/usr/bin/env python3
"""
06_parse_offsets/test_stage.py - Isolated Unit Test for Stage 6
Tests generators (C++, Rust, C#) and data modeling.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from generators.cpp_gen import generate_cpp
from generators.csharp_gen import generate_csharp
from generators.rust_gen import generate_rust
from parse_offsets import Stage6Parse


class TestStage6Parse(unittest.TestCase):
    def setUp(self):
        self.sample_data = {
            "profile": "unit_test_game",
            "methods": {"PlayerController_Update": 0x1234560, "GameManager_Start": 0x7890ABC},
            "fields": {
                "PlayerController": {"HEALTH": 0x20, "IS_ALIVE": 0x24}
            },
            "typeinfos": {"PLAYER_CONTROLLER": 0x9988770},
            "native": {"EGL_SWAP_GOT_FILEOFF": 0x1122330}
        }

    def test_cpp_generation(self):
        code = generate_cpp(self.sample_data, namespace_name="TestOffsets")
        self.assertIn("namespace TestOffsets", code)
        self.assertIn("constexpr uintptr_t PlayerController_Update = 0x1234560;", code)
        self.assertIn("constexpr uintptr_t HEALTH = 0x20;", code)
        self.assertIn("constexpr uintptr_t EGL_SWAP_GOT_FILEOFF = 0x1122330;", code)

    def test_rust_generation(self):
        code = generate_rust(self.sample_data)
        self.assertIn("pub mod methods", code)
        self.assertIn("pub const PlayerController_Update: usize = 0x1234560;", code)
        self.assertIn("pub const HEALTH: usize = 0x20;", code)

    def test_csharp_generation(self):
        code = generate_csharp(self.sample_data)
        self.assertIn("namespace GSS4.Offsets", code)
        self.assertIn("public const ulong PlayerController_Update = 0x1234560;", code)
        self.assertIn("public const int HEALTH = 0x20;", code)

    def test_input_validation(self):
        stage = Stage6Parse()
        test_dir = tempfile.mkdtemp()
        try:
            valid, msg = stage.validate_inputs(test_dir, {})
            self.assertFalse(valid)
            self.assertIn("Missing dump.cs", msg)
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
