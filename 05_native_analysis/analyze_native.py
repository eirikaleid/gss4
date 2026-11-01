#!/usr/bin/env python3
"""
05_native_analysis/analyze_native.py - Stage 5: Native ELF Binary Offset Analyzer
Inspects native ELF shared libraries (e.g. libunity.so) to extract GOT slot file offsets
and .rodata string offsets.
Can be executed as a CLI script, imported as Stage5Native(BaseStage), or called via MCP.
"""

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core.stage_base import BaseStage, StageResult
except ImportError:
    BaseStage = object

PT_LOAD, PT_DYNAMIC = 1, 2
SHT_RELA, SHT_DYNSYM = 4, 11
DT_NULL, DT_PLTRELSZ, DT_STRTAB, DT_SYMTAB, DT_JMPREL = 0, 2, 5, 6, 23
R_AARCH64_JUMP_SLOT = 1026
R_AARCH64_GLOB_DAT = 1025


class Elf64:
    def __init__(self, data):
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a little-endian ELF64 file")
        self.d = data
        (self.e_phoff, self.e_shoff) = struct.unpack_from("<QQ", data, 0x20)
        (self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
         self.e_shstrndx) = struct.unpack_from("<HHHHH", data, 0x36)
        self.phdrs = [struct.unpack_from("<IIQQQQQQ", data, self.e_phoff + i * self.e_phentsize)
                      for i in range(self.e_phnum)]
        self.loads = [(p[2], p[3], p[5]) for p in self.phdrs if p[0] == PT_LOAD]
        self.shdrs = []
        if self.e_shoff and self.e_shnum and self.e_shoff + self.e_shnum * 64 <= len(data):
            raw = [struct.unpack_from("<IIQQQQIIQQ", data, self.e_shoff + i * self.e_shentsize)
                   for i in range(self.e_shnum)]
            names_off = raw[self.e_shstrndx][4] if self.e_shstrndx < len(raw) else 0
            for s in raw:
                self.shdrs.append({
                    "name": self.cstr(names_off + s[0]) if names_off else "",
                    "type": s[1], "addr": s[3], "off": s[4], "size": s[5],
                    "link": s[6], "entsize": s[9]
                })

    def cstr(self, off):
        end = self.d.index(b"\0", off)
        return self.d[off:end].decode("latin-1")

    def va_to_off(self, va):
        for off, seg_va, fsz in self.loads:
            if seg_va <= va < seg_va + fsz:
                return va - seg_va + off
        return None

    def section(self, name):
        for s in self.shdrs:
            if s["name"] == name:
                return s
        return None

    def _dynamic(self):
        out = {}
        for p in self.phdrs:
            if p[0] == PT_DYNAMIC:
                for k in range(p[5] // 16):
                    tag, val = struct.unpack_from("<qQ", self.d, p[2] + 16 * k)
                    if tag == DT_NULL:
                        break
                    out.setdefault(tag, val)
        return out

    def plt_relocs(self):
        rela = self.section(".rela.plt")
        if rela is not None and rela["type"] == SHT_RELA:
            dynsym = self.shdrs[rela["link"]]
            dynstr = self.shdrs[dynsym["link"]]
            rel_off, rel_size, sym_off, str_off = rela["off"], rela["size"], dynsym["off"], dynstr["off"]
        else:
            dyn = self._dynamic()
            if DT_JMPREL not in dyn:
                raise ValueError("no .rela.plt and no DT_JMPREL")
            rel_off, rel_size = self.va_to_off(dyn[DT_JMPREL]), dyn[DT_PLTRELSZ]
            sym_off, str_off = self.va_to_off(dyn[DT_SYMTAB]), self.va_to_off(dyn[DT_STRTAB])
        for k in range(rel_size // 24):
            r_offset, r_info, _ = struct.unpack_from("<QQq", self.d, rel_off + 24 * k)
            sym_idx, rtype = r_info >> 32, r_info & 0xFFFFFFFF
            st_name = struct.unpack_from("<I", self.d, sym_off + 24 * sym_idx)[0]
            yield r_offset, rtype, self.cstr(str_off + st_name)


def find_egl_swap_got(elf):
    hits = [(va, t) for va, t, name in elf.plt_relocs() if name == "eglSwapBuffers"]
    if len(hits) != 1:
        return None, None
    va, rtype = hits[0]
    if rtype != R_AARCH64_JUMP_SLOT:
        return None, None
    off = elf.va_to_off(va)
    return va, off


def find_swappy_name(elf, needle=b"libswappywrapper"):
    ro = elf.section(".rodata")
    lo, hi = (ro["off"], ro["off"] + ro["size"]) if ro else (0, len(elf.d))
    hits = []
    pos = elf.d.find(needle, lo, hi)
    while pos != -1:
        if elf.d[pos - 1] == 0 and elf.d[pos + len(needle)] == 0:
            hits.append(pos)
        pos = elf.d.find(needle, pos + 1, hi)
    if len(hits) != 1:
        return None
    return hits[0]


def analyze(lib_path, rules=None):
    if not os.path.exists(lib_path):
        print(f"[WARN] Native library not found: {lib_path}. Returning empty.")
        return {}

    with open(lib_path, "rb") as f:
        data = f.read()

    try:
        elf = Elf64(data)
    except Exception as e:
        print(f"[WARN] Failed to parse ELF: {e}")
        return {}

    res = {}
    rules = rules or {}

    if rules.get("egl_swap_got", True):
        va, off = find_egl_swap_got(elf)
        if off is not None:
            res["EGL_SWAP_GOT_FILEOFF"] = off
            res["EGL_SWAP_GOT_VA"] = va
            print(f"[OK] EGL_SWAP_GOT_FILEOFF = 0x{off:X} (VA 0x{va:X})")
        else:
            print("[WARN] Could not find eglSwapBuffers GOT slot in ELF.")

    swappy_needle = rules.get("swappy_string", "libswappywrapper")
    if swappy_needle:
        str_off = find_swappy_name(elf, swappy_needle.encode("latin-1"))
        if str_off is not None:
            res["SWAPPY_NAME_FILEOFF"] = str_off
            print(f"[OK] SWAPPY_NAME_FILEOFF  = 0x{str_off:X}")
        else:
            print(f"[WARN] String '{swappy_needle}' not found in binary.")

    return res


class Stage5Native(BaseStage):
    stage_id = 5
    name = "05_native_analysis"
    description = "Inspects native ELF shared libraries to extract GOT slots and .rodata strings."

    def validate_inputs(self, workspace: str, config: dict):
        return True, ""

    def execute(self, workspace: str, config: dict):
        lib_path = config.get("native_lib") or os.path.join(workspace, "bin", "libunity.so")
        out_json = config.get("native_json") or os.path.join(workspace, "native.json")
        rules = config.get("native_rules", {})

        offsets = analyze(lib_path, rules)
        os.makedirs(os.path.dirname(os.path.abspath(out_json)), exist_ok=True)
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(offsets, f, indent=2)

        return {
            "offsets": offsets,
            "json_path": out_json,
            "output_files": [out_json]
        }

    def validate_outputs(self, workspace: str, config: dict):
        out_json = config.get("native_json") or os.path.join(workspace, "native.json")
        if not os.path.exists(out_json):
            return False, f"Missing output {out_json}"
        return True, ""


def main():
    parser = argparse.ArgumentParser(description="Extract native offsets from ELF shared libraries.")
    parser.add_argument("--lib", required=True, help="Path to ELF .so (e.g. libunity.so)")
    parser.add_argument("--json", required=True, help="Output JSON path")
    parser.add_argument("--rules", help="JSON string or file path containing extraction rules")

    args = parser.parse_args()

    rules = {}
    if args.rules:
        if os.path.exists(args.rules):
            with open(args.rules, "r", encoding="utf-8") as rf:
                rules = json.load(rf)
        else:
            try:
                rules = json.loads(args.rules)
            except Exception:
                pass

    offsets = analyze(args.lib, rules)
    os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(offsets, f, indent=2)

    print(f"[OK] Native offsets written to: {args.json}")


if __name__ == "__main__":
    main()
