#!/usr/bin/env python3
"""
07_verify_diff/test_stage.py - Isolated Unit Test for Stage 7
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from verify_diff import Stage7Verify, diff_headers, parse_header, verify_and_diff


class TestStage7Verify(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gss4_stage7_test_")
        self.sample_header = os.path.join(self.test_dir, "test_offsets.h")
        content = """#pragma once
#include <cstdint>
namespace Offsets {
    constexpr uintptr_t Player_Update = 0x1000;
    namespace Actor {
        constexpr uintptr_t HEALTH = 0x20;
    }
    namespace TypeInfo {
        constexpr uintptr_t PLAYER = 0x2000;
    }
}
"""
        with open(self.sample_header, "w") as f:
            f.write(content)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_parse_header(self):
        m = parse_header(self.sample_header)
        self.assertEqual(m["Player_Update"], 0x1000)
        self.assertEqual(m["Actor::HEALTH"], 0x20)
        self.assertEqual(m["TypeInfo::PLAYER"], 0x2000)

    def test_verify_diff_clean(self):
        res = verify_and_diff(self.sample_header)
        self.assertEqual(res["constants_count"], 3)

    def test_live_assert_mock(self):
        res = verify_and_diff(self.sample_header, live_assert=True, mock=True)
        self.assertEqual(res["constants_count"], 3)

    def test_diff_detection(self):
        old_map = {"Player_Update": 0x1000, "Old_Method": 0x500}
        new_map = {"Player_Update": 0x1010, "New_Method": 0x600}
        changes, added, removed = diff_headers(old_map, new_map)
        self.assertEqual(len(changes), 1)
        self.assertEqual(len(added), 1)
        self.assertEqual(len(removed), 1)


if __name__ == "__main__":
    unittest.main()
