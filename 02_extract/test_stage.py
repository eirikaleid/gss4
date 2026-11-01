#!/usr/bin/env python3
"""
02_extract/test_stage.py - Isolated Unit Test Suite for Stage 2
Tests multi-format extraction (APK, XAPK, APKS, OBB), multi-engine support
(Unity IL2CPP, Unity Mono, Unreal Engine, Godot), and binary integrity verification.
"""

import os
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from extract import (
    Stage2Extract,
    extract_binaries,
    verify_elf_binary,
    verify_file_integrity,
    unpack_packages,
)
from core.errors import ExtractionError


class TestStage2Extract(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gss4_stage2_test_")

        # 1. Standard IL2CPP Mock APK (64-bit ELF ident: 0x7F 'E' 'L' 'F', EI_CLASS=2, EI_DATA=1)
        self.dummy_apk = os.path.join(self.test_dir, "test.apk")
        mock_elf64 = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"fake_arm64_elf_code"
        mock_meta = b"\xaf\x1b\xb1\xfa\x1f\x00\x00\x00dummy_metadata"

        with zipfile.ZipFile(self.dummy_apk, "w") as z:
            z.writestr("lib/arm64-v8a/libil2cpp.so", mock_elf64)
            z.writestr("lib/arm64-v8a/libunity.so", mock_elf64)
            z.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", mock_meta)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_extract_binaries_il2cpp(self):
        """Standard Unity IL2CPP extraction test."""
        out_bin = os.path.join(self.test_dir, "bin")
        res = extract_binaries([self.dummy_apk], out_bin, arch="arm64-v8a")
        self.assertIsNotNone(res)
        self.assertTrue(os.path.exists(res["il2cpp"]))
        self.assertTrue(os.path.exists(res["metadata"]))
        self.assertTrue(os.path.exists(res["unity"]))
        self.assertEqual(res["engine"], "unity_il2cpp")
        self.assertIn("libil2cpp.so", res["integrity"])
        self.assertTrue(res["integrity"]["libil2cpp.so"]["valid"])

    def test_stage_lifecycle(self):
        """Standard BaseStage run_stage execution."""
        stage = Stage2Extract()
        ws = os.path.join(self.test_dir, "workspace")
        res = stage.run_stage(ws, config={"apks": [self.dummy_apk], "arch": "arm64-v8a"})
        self.assertEqual(res.status, "success")
        self.assertTrue(os.path.exists(os.path.join(ws, "bin", "libil2cpp.so")))

    def test_xapk_and_obb_support(self):
        """XAPK package extraction with nested APKs and OBB data directory."""
        mock_elf64 = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"fake_arm64_elf_code"
        mock_meta = b"\xaf\x1b\xb1\xfa\x1f\x00\x00\x00dummy_metadata"

        # Inner base APK
        inner_base = os.path.join(self.test_dir, "inner_base.apk")
        with zipfile.ZipFile(inner_base, "w") as z:
            z.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", mock_meta)

        # Inner split config APK
        inner_split = os.path.join(self.test_dir, "inner_split.apk")
        with zipfile.ZipFile(inner_split, "w") as z:
            z.writestr("lib/arm64-v8a/libil2cpp.so", mock_elf64)
            z.writestr("lib/arm64-v8a/libunity.so", mock_elf64)

        # Pack into .xapk container with an OBB
        xapk_path = os.path.join(self.test_dir, "game.xapk")
        with zipfile.ZipFile(xapk_path, "w") as zx:
            zx.write(inner_base, "com.example.game.apk")
            zx.write(inner_split, "config.arm64_v8a.apk")
            zx.writestr("Android/obb/com.example.game/main.100.com.example.game.obb", b"OBB_PAYLOAD_DATA_BYTES")
            zx.writestr("manifest.json", '{"package_name":"com.example.game"}')

        out_bin = os.path.join(self.test_dir, "xapk_bin")
        res = extract_binaries([xapk_path], out_bin, arch="arm64-v8a")

        self.assertTrue(os.path.exists(res["il2cpp"]))
        self.assertTrue(os.path.exists(res["metadata"]))
        self.assertIn("obb_files", res)
        self.assertTrue(len(res["obb_files"]) > 0)
        self.assertTrue(os.path.exists(res["obb_files"][0]))

    def test_apks_bundle_support(self):
        """APKS (Bundletool / SAI) split APK extraction test."""
        mock_elf64 = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"fake_arm64_elf_code"
        mock_meta = b"\xaf\x1b\xb1\xfa\x1f\x00\x00\x00dummy_metadata"

        split_master = os.path.join(self.test_dir, "base-master.apk")
        with zipfile.ZipFile(split_master, "w") as z:
            z.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", mock_meta)

        split_arm64 = os.path.join(self.test_dir, "base-arm64_v8a.apk")
        with zipfile.ZipFile(split_arm64, "w") as z:
            z.writestr("lib/arm64-v8a/libil2cpp.so", mock_elf64)

        apks_path = os.path.join(self.test_dir, "game.apks")
        with zipfile.ZipFile(apks_path, "w") as z:
            z.write(split_master, "splits/base-master.apk")
            z.write(split_arm64, "splits/base-arm64_v8a.apk")

        out_bin = os.path.join(self.test_dir, "apks_bin")
        res = extract_binaries([apks_path], out_bin, arch="arm64-v8a")
        self.assertTrue(os.path.exists(res["il2cpp"]))
        self.assertTrue(os.path.exists(res["metadata"]))

    def test_unity_mono_extraction(self):
        """Multi-engine: Unity Mono (.NET Managed DLLs + libmonosgen-2.0.so)."""
        mono_apk = os.path.join(self.test_dir, "mono.apk")
        mock_elf64 = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"mono_runtime_arm64"
        mock_pe_dll = b"MZ\x90\x00fake_csharp_assembly"

        with zipfile.ZipFile(mono_apk, "w") as z:
            z.writestr("lib/arm64-v8a/libmonosgen-2.0.so", mock_elf64)
            z.writestr("assets/bin/Data/Managed/Assembly-CSharp.dll", mock_pe_dll)
            z.writestr("assets/bin/Data/Managed/UnityEngine.dll", mock_pe_dll)

        out_bin = os.path.join(self.test_dir, "mono_bin")
        res = extract_binaries([mono_apk], out_bin, arch="arm64-v8a", engine="unity_mono")
        self.assertEqual(res["engine"], "unity_mono")
        self.assertIn("managed_dir", res)
        self.assertTrue(os.path.exists(res["assembly_csharp"]))
        self.assertTrue(res["integrity"]["Assembly-CSharp.dll"]["valid"])

    def test_unreal_engine_extraction(self):
        """Multi-engine: Unreal Engine (libUE4.so + PAK archive)."""
        ue_apk = os.path.join(self.test_dir, "unreal.apk")
        mock_elf64 = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"unreal_engine_code"
        # Unreal pak footer with magic 0x5A6F12E1
        pak_data = b"DUMMY_UE_PAK_ASSET_CONTENT" + b"\x00" * 20 + struct.pack("<I", 0x5A6F12E1) + b"\x00" * 30

        with zipfile.ZipFile(ue_apk, "w") as z:
            z.writestr("lib/arm64-v8a/libUE4.so", mock_elf64)
            z.writestr("assets/main.pak", pak_data)

        out_bin = os.path.join(self.test_dir, "ue_bin")
        res = extract_binaries([ue_apk], out_bin, arch="arm64-v8a", engine="unreal")
        self.assertEqual(res["engine"], "unreal")
        self.assertTrue(os.path.exists(res["ue_so"]))
        self.assertTrue(os.path.exists(os.path.join(out_bin, "paks", "main.pak")))

    def test_godot_engine_extraction(self):
        """Multi-engine: Godot Engine (libgodot.so + PCK package)."""
        godot_apk = os.path.join(self.test_dir, "godot.apk")
        mock_elf64 = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"godot_runtime_code"
        mock_pck = b"GDPC\x01\x00\x00\x00godot_bytecode_and_scene_data"

        with zipfile.ZipFile(godot_apk, "w") as z:
            z.writestr("lib/arm64-v8a/libgodot.so", mock_elf64)
            z.writestr("assets/main.pck", mock_pck)

        out_bin = os.path.join(self.test_dir, "godot_bin")
        res = extract_binaries([godot_apk], out_bin, arch="arm64-v8a", engine="godot")
        self.assertEqual(res["engine"], "godot")
        self.assertTrue(os.path.exists(res["godot_so"]))
        self.assertTrue(os.path.exists(os.path.join(out_bin, "main.pck")))
        self.assertTrue(res["integrity"]["main.pck"]["valid"])

    def test_binary_integrity_verification(self):
        """Binary integrity checker: ELF 64-bit validation & corrupt rejection."""
        # 1. Valid ELF64
        valid_elf = os.path.join(self.test_dir, "valid.so")
        with open(valid_elf, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01" + b"\x00" * 9)
        ok, msg = verify_elf_binary(valid_elf, arch="arm64-v8a")
        self.assertTrue(ok)

        # 2. Corrupt ELF magic
        corrupt_elf = os.path.join(self.test_dir, "corrupt.so")
        with open(corrupt_elf, "wb") as f:
            f.write(b"NOT_AN_ELF_BINARY_HEADER")
        ok, msg = verify_elf_binary(corrupt_elf, arch="arm64-v8a")
        self.assertFalse(ok)
        self.assertIn("Geçersiz ELF", msg)

        # 3. 32-bit ELF given when 64-bit expected
        elf32 = os.path.join(self.test_dir, "elf32.so")
        with open(elf32, "wb") as f:
            f.write(b"\x7fELF\x01\x01\x01" + b"\x00" * 9)
        ok, msg = verify_elf_binary(elf32, arch="arm64-v8a")
        self.assertFalse(ok)
        self.assertIn("64-bit ELF bekleniyordu", msg)

        # 4. Corrupt ELF in APK triggers ExtractionError
        bad_apk = os.path.join(self.test_dir, "bad.apk")
        with zipfile.ZipFile(bad_apk, "w") as z:
            z.writestr("lib/arm64-v8a/libil2cpp.so", b"CORRUPTED_BYTES_HERE")
            z.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", b"\xaf\x1b\xb1\xfa\x00\x00")

        out_bin = os.path.join(self.test_dir, "bad_bin")
        with self.assertRaises(ExtractionError) as ctx:
            extract_binaries([bad_apk], out_bin, arch="arm64-v8a", verify_elf=True)
        self.assertEqual(ctx.exception.error_code, "ERR_INVALID_ELF_MAGIC")


if __name__ == "__main__":
    unittest.main()
