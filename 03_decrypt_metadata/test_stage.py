#!/usr/bin/env python3
"""
03_decrypt_metadata/test_stage.py - Isolated Unit Test for Stage 3
Tests dynamic strategy discovery, passthrough validation, and BaseStage lifecycle.
"""

import os
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from decrypt import Stage3Decrypt, discover_strategies, run_decryption


class TestStage3Decrypt(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gss4_stage3_test_")
        self.dummy_plain = os.path.join(self.test_dir, "plain-metadata.dat")
        # Valid IL2CPP plaintext header (Magic 0xFAB11BAF + Version 29)
        with open(self.dummy_plain, "wb") as f:
            f.write(struct.pack("<II", 0xFAB11BAF, 29) + b"\x00" * 1024)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_discover_strategies(self):
        strats = discover_strategies()
        self.assertIn("passthrough", strats)
        self.assertIn("gups", strats)
        self.assertIn("frida_live", strats)

    def test_frida_live_mock_strategy(self):
        out_dec = os.path.join(self.test_dir, "frida_out.dat")
        rep = run_decryption("dummy_path_none.dat", out_dec, strategy="frida_live", mock=True)
        self.assertEqual(rep["status"], "success")
        self.assertEqual(rep["strategy"], "frida_live")
        self.assertEqual(rep["mode"], "mock")
        self.assertTrue(os.path.exists(out_dec))
        with open(out_dec, "rb") as f:
            magic = struct.unpack_from("<I", f.read(4), 0)[0]
        self.assertEqual(magic, 0xFAB11BAF)

    def test_passthrough_decryption(self):
        out_dec = os.path.join(self.test_dir, "out.dat")
        rep = run_decryption(self.dummy_plain, out_dec, strategy="passthrough")
        self.assertEqual(rep["status"], "success")
        self.assertTrue(os.path.exists(out_dec))

    def test_auto_detection_on_plaintext(self):
        out_dec = os.path.join(self.test_dir, "out_auto.dat")
        rep = run_decryption(self.dummy_plain, out_dec, strategy="auto")
        self.assertEqual(rep["strategy"], "passthrough")

    def test_stage_lifecycle(self):
        stage = Stage3Decrypt()
        ws = os.path.join(self.test_dir, "ws")
        bin_dir = os.path.join(ws, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        shutil.copy2(self.dummy_plain, os.path.join(bin_dir, "global-metadata.dat"))

        res = stage.run_stage(ws, config={"decrypt_strategy": "passthrough"})
        self.assertEqual(res.status, "success")
        self.assertTrue(os.path.exists(os.path.join(bin_dir, "global-metadata.dec.dat")))


if __name__ == "__main__":
    unittest.main()
