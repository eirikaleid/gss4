#!/usr/bin/env python3
"""
04_il2cpp_dump/test_stage.py - Isolated Unit Test for Stage 4
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dump import Stage4Dump


class TestStage4Dump(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gss4_stage4_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_input_validation(self):
        stage = Stage4Dump()
        # Should fail input validation if so_path and meta_path don't exist
        valid, msg = stage.validate_inputs(self.test_dir, {})
        self.assertFalse(valid)
        self.assertIn("Missing", msg)

    def test_input_validation_success(self):
        stage = Stage4Dump()
        bin_dir = os.path.join(self.test_dir, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        so_p = os.path.join(bin_dir, "libil2cpp.so")
        meta_p = os.path.join(bin_dir, "global-metadata.dec.dat")
        open(so_p, "wb").write(b"dummy")
        open(meta_p, "wb").write(b"dummy")

        valid, msg = stage.validate_inputs(self.test_dir, {})
        self.assertTrue(valid)

    def test_frida_adapter_lifecycle(self):
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


if __name__ == "__main__":
    unittest.main()
