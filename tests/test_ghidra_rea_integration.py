#!/usr/bin/env python3
"""
tests/test_ghidra_rea_integration.py - Static Analysis Integration Test Suite
=============================================================================
Tests Ghidra Headless Bridge and REA (Reverse Engineer Anything) Client integration
in GSS4 without requiring external Ghidra or Node/Rust installations.
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
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Dynamic stage import to avoid Python decimal literal import error
ghidra_mod = importlib.import_module("05_native_analysis.ghidra.ghidra_bridge")
GhidraBridge = ghidra_mod.GhidraBridge

from tools.rea_bridge.rea_client import REAClient
from mcp_server import decompile_symbol, search_native_xrefs, inspect_metadata_rea


def make_mock_elf64(strings: list[bytes]) -> bytes:
    """Helper to synthesize a minimal valid 64-bit Little-Endian ELF fixture."""
    header = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)  # 16 bytes e_ident
    header += struct.pack("<HHIQQQIHHHHHH",
                          2,          # e_type = ET_EXEC
                          183,        # e_machine = EM_AARCH64
                          1,          # e_version
                          0x100000,   # e_entry
                          0x40,       # e_phoff
                          0,          # e_shoff
                          0,          # e_flags
                          0x40,       # e_ehsize
                          0x38,       # e_phentsize
                          1,          # e_phnum
                          0x40,       # e_shentsize
                          0,          # e_shnum
                          0           # e_shstrndx
                          )
    # Program header: PT_LOAD
    phdr = struct.pack("<IIQQQQQQ",
                       1,          # p_type = PT_LOAD
                       7,          # p_flags = PF_R | PF_W | PF_X
                       0,          # p_offset
                       0x100000,   # p_vaddr
                       0x100000,   # p_paddr
                       0x1000,     # p_filesz
                       0x1000,     # p_memsz
                       0x1000      # p_align
                       )
    data = header + phdr
    data += b"\x00" * (0x200 - len(data))
    for s in strings:
        data += s + b"\x00"
    data += b"\x00" * (0x1000 - len(data))
    return bytes(data)


class TestGhidraBridge(unittest.TestCase):
    """Tests for Ghidra Headless Bridge and C++/ARM64 mock decompiler."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gss4_ghidra_test_")
        self.mock_elf = os.path.join(self.test_dir, "libunity.so")
        with open(self.mock_elf, "wb") as f:
            f.write(make_mock_elf64([b"libswappywrapper", b"eglSwapBuffers", b"UnityPlayer"]))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_bridge_initialization(self):
        # Even without Ghidra installed, bridge initializes cleanly and provides fallback
        bridge = GhidraBridge()
        self.assertIsNotNone(bridge)
        # Should gracefully report false if not installed on machine
        self.assertIsInstance(bridge.is_installed, bool)

    def test_decompile_function_rva_hex(self):
        bridge = GhidraBridge(force_mock=True)
        res = bridge.decompile_function(self.mock_elf, "0x100004", arch="arm64")

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["rva"], "0x100004")
        self.assertIn("PlayerController$$Update", res["symbol"])
        self.assertIn("pseudocode", res)
        self.assertIn("void", res["pseudocode"])
        self.assertTrue(len(res["assembly"]) > 0)
        self.assertEqual(res["assembly"][0]["mnemonic"], "stp")

    def test_decompile_function_rva_int(self):
        bridge = GhidraBridge(force_mock=True)
        res = bridge.decompile_function(self.mock_elf, 0x100020)

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["rva"], "0x100020")
        self.assertIn("TakeDamage", res["symbol"])
        self.assertIn("damage_amount", res["pseudocode"])

    def test_get_string_xrefs(self):
        bridge = GhidraBridge(force_mock=True)
        xrefs = bridge.get_string_xrefs(self.mock_elf, needle="libswappywrapper")

        self.assertIsInstance(xrefs, list)
        self.assertTrue(len(xrefs) >= 1)
        self.assertEqual(xrefs[0]["target_string"], "libswappywrapper")
        self.assertIn("adrp", xrefs[0]["instruction"])
        self.assertIn("function_name", xrefs[0])

    def test_get_vtables(self):
        bridge = GhidraBridge(force_mock=True)
        vtables = bridge.get_vtables(self.mock_elf, class_filter="PlayerController")

        self.assertEqual(len(vtables), 1)
        v = vtables[0]
        self.assertEqual(v["class_name"], "PlayerController")
        self.assertIn("virtual_methods", v)
        self.assertTrue(len(v["virtual_methods"]) >= 3)
        self.assertEqual(v["virtual_methods"][0]["index"], 0)

    def test_analyze_full_report(self):
        bridge = GhidraBridge(force_mock=True)
        out_json = os.path.join(self.test_dir, "ghidra_report.json")
        rep = bridge.analyze(
            binary_path=self.mock_elf,
            output_path=out_json,
            target_rvas=[0x100004, 0x100020],
            search_strings=["libswappywrapper", "eglSwapBuffers"]
        )

        self.assertTrue(os.path.exists(out_json))
        self.assertIn("functions", rep)
        self.assertIn("xrefs", rep)
        self.assertIn("vtables", rep)
        self.assertEqual(len(rep["functions"]), 2)


class TestREABridge(unittest.TestCase):
    """Tests for REA Client, IL2CPP metadata inspection, and Ghidra seeds generation."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gss4_rea_test_")
        self.meta_file = os.path.join(self.test_dir, "global-metadata.dat")
        # Write valid IL2CPP metadata magic 0xFAB11BAF and version 29
        with open(self.meta_file, "wb") as f:
            f.write(struct.pack("<II", 0xFAB11BAF, 29) + b"\x00" * 1024)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_rea_client_init(self):
        client = REAClient()
        self.assertIsNotNone(client)
        # Should detect local REA dir if it exists
        if os.path.isdir(REAClient.DEFAULT_LOCAL_REA):
            self.assertEqual(client.rea_dir, os.path.abspath(REAClient.DEFAULT_LOCAL_REA))

    def test_inspect_il2cpp_metadata(self):
        client = REAClient(force_fallback=True)
        res = client.inspect_il2cpp_metadata(self.meta_file)

        self.assertEqual(res["status"], "success")
        self.assertTrue(res["is_valid_magic"])
        self.assertEqual(res["metadata_version"], 29)
        self.assertTrue(res["types_count"] > 0)
        self.assertTrue(res["methods_count"] > 0)
        self.assertEqual(res["types"][0]["name"], "PlayerController")

    def test_ghidra_seeds_generation(self):
        client = REAClient(force_fallback=True)
        seeds_path = os.path.join(self.test_dir, "seeds.txt")
        client.inspect_il2cpp_metadata(self.meta_file, ghidra_seeds=seeds_path)

        self.assertTrue(os.path.exists(seeds_path))
        with open(seeds_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("# REA_GHIDRA_SEED_FILE", content)
        self.assertIn("PlayerController$$Update", content)
        self.assertIn("0x100004", content)

    def test_decompile_and_xrefs(self):
        client = REAClient(force_fallback=True)
        decomp = client.decompile(self.meta_file, "0x100004")
        self.assertEqual(decomp["status"], "success")
        self.assertIn("pseudocode", decomp)

        xrefs = client.search_xrefs(self.meta_file, "libswappywrapper")
        self.assertIsInstance(xrefs, list)
        self.assertTrue(len(xrefs) > 0)

    def test_missing_metadata_raises(self):
        client = REAClient(force_fallback=True)
        with self.assertRaises(FileNotFoundError):
            client.inspect_il2cpp_metadata(os.path.join(self.test_dir, "nonexistent.dat"))


class TestMultiEngineSwitching(unittest.TestCase):
    """Tests switching between Ghidra and REA engines."""

    def test_engine_selection(self):
        # Ghidra selection
        res_ghidra = decompile_symbol("0x100004", engine="ghidra")
        self.assertIn("ghidra", res_ghidra.get("engine", "").lower())

        # REA selection
        res_rea = decompile_symbol("0x100004", engine="rea")
        self.assertIn("rea", res_rea.get("engine", "").lower())

        # Auto selection
        res_auto = decompile_symbol("0x100004", engine="auto")
        self.assertIn(res_auto.get("engine", "").lower(), ("ghidra", "ghidra_mock", "rea", "rea_fallback"))


class TestMCPServerIntegration(unittest.TestCase):
    """Tests the new MCP server tools: decompile_symbol, search_native_xrefs, inspect_metadata_rea."""

    def test_mcp_decompile_symbol(self):
        res = decompile_symbol(rva="0x100004", engine="ghidra")
        self.assertEqual(res["status"], "success")
        self.assertIn("pseudocode", res)
        self.assertIn("target_binary", res)

    def test_mcp_search_native_xrefs(self):
        xrefs = search_native_xrefs(needle="eglSwapBuffers", engine="auto")
        self.assertIsInstance(xrefs, list)
        self.assertTrue(len(xrefs) > 0)
        self.assertIn("eglSwapBuffers", xrefs[0]["target_string"])

    def test_mcp_inspect_metadata_rea(self):
        rep = inspect_metadata_rea()
        self.assertEqual(rep["status"], "success")
        self.assertTrue(rep["types_count"] > 0)
        self.assertIn("types", rep)


if __name__ == "__main__":
    unittest.main()
