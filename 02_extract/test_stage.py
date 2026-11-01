#!/usr/bin/env python3
"""
02_extract/test_stage.py - Isolated Unit Test for Stage 2
"""

import os
import shutil
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from extract import Stage2Extract, extract_binaries


class TestStage2Extract(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gss4_stage2_test_")
        self.dummy_apk = os.path.join(self.test_dir, "test.apk")
        # Create a valid mock APK zip
        with zipfile.ZipFile(self.dummy_apk, "w") as z:
            z.writestr("lib/arm64-v8a/libil2cpp.so", b"\x7fELFfake_il2cpp")
            z.writestr("lib/arm64-v8a/libunity.so", b"\x7fELFfake_unity")
            z.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", b"\xaf\x1b\xb1\xfa\x1f\x00\x00\x00dummy_metadata")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_extract_binaries(self):
        out_bin = os.path.join(self.test_dir, "bin")
        res = extract_binaries([self.dummy_apk], out_bin, arch="arm64-v8a")
        self.assertIsNotNone(res)
        self.assertTrue(os.path.exists(res["il2cpp"]))
        self.assertTrue(os.path.exists(res["metadata"]))
        self.assertTrue(os.path.exists(res["unity"]))

    def test_stage_lifecycle(self):
        stage = Stage2Extract()
        ws = os.path.join(self.test_dir, "workspace")
        res = stage.run_stage(ws, config={"apks": [self.dummy_apk], "arch": "arm64-v8a"})
        self.assertEqual(res.status, "success")
        self.assertTrue(os.path.exists(os.path.join(ws, "bin", "libil2cpp.so")))


if __name__ == "__main__":
    unittest.main()
