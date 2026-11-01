#!/usr/bin/env python3
"""
01_apk_pull/test_stage.py - Isolated Unit Test for Stage 1
Tests local copying, manifest creation, and BaseStage validation.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pull import Stage1Pull, copy_local_apks


class TestStage1Pull(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gss4_stage1_test_")
        self.dummy_apk = os.path.join(self.test_dir, "base.apk")
        with open(self.dummy_apk, "wb") as f:
            f.write(b"PK\x03\x04dummyapkcontent")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_local_apk_copy(self):
        dest_dir = os.path.join(self.test_dir, "output")
        copied = copy_local_apks([self.dummy_apk], dest_dir)
        self.assertEqual(len(copied), 1)
        self.assertTrue(os.path.exists(copied[0]))

    def test_stage_lifecycle(self):
        stage = Stage1Pull()
        ws = os.path.join(self.test_dir, "workspace")
        res = stage.run_stage(ws, config={"apk_paths": [self.dummy_apk]})
        self.assertEqual(res.status, "success")
        self.assertTrue(os.path.exists(os.path.join(ws, "apk", "apk_manifest.json")))


if __name__ == "__main__":
    unittest.main()
