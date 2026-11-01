"""
passthrough.py - Handles unencrypted / plaintext global-metadata.dat
"""

import os
import shutil
import struct

MAGIC = 0xFAB11BAF


def is_plaintext(data: bytes) -> bool:
    if len(data) < 8:
        return False
    magic, version = struct.unpack_from("<II", data, 0)
    return magic == MAGIC and 20 <= version <= 35


def run(in_path: str, out_path: str) -> dict:
    with open(in_path, "rb") as f:
        head = f.read(8)

    if not is_plaintext(head):
        raise ValueError("Data does not start with standard plaintext IL2CPP magic (0xFAB11BAF).")

    version = struct.unpack_from("<I", head, 4)[0]
    shutil.copy2(in_path, out_path)
    return {
        "strategy": "passthrough",
        "status": "success",
        "il2cpp_version": version,
        "size": os.path.getsize(out_path)
    }
