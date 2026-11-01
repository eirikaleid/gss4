#!/usr/bin/env python3
"""
05_native_analysis/test_stage.py - Isolated Unit Test for Stage 5
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyze_native import Stage5Native, analyze


class TestStage5Native(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gss4_stage5_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_missing_lib_graceful_handling(self):
        # Should gracefully return empty dictionary without crashing if libunity is absent
        res = analyze(os.path.join(self.test_dir, "nonexistent.so"))
        self.assertEqual(res, {})

    def test_stage_lifecycle(self):
        stage = Stage5Native()
        res = stage.run_stage(self.test_dir, config={"native_rules": {"egl_swap_got": False}})
        self.assertEqual(res.status, "success")
        out_json = os.path.join(self.test_dir, "native.json")
        self.assertTrue(os.path.exists(out_json))
        with open(out_json, "r") as f:
            data = json.load(f)
            self.assertIsInstance(data, dict)


if __name__ == "__main__":
    unittest.main()
