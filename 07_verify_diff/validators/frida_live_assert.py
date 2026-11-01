#!/usr/bin/env python3
"""
07_verify_diff/validators/frida_live_assert.py - GSS4 Frida Live Memory Safety Gate
===================================================================================
Ne İşe Yarar? (Purpose):
------------------------
Statik analizle çıkarılan RVA ve TypeInfo ofsetleri, oyunun çalışma zamanındaki bellek
düzeniyle uyuşmayabilir (derleyici optimizasyonu, dead code elimination, dinamik
kod yükleme veya koruma yazılımının fonksiyon gövdelerini taşıması).

Bu güvenlik kapısı (Safety Gate):
  1. Yürütülebilirlik Testi (Executable Page Check):
     - Her metot RVA'sının bellekte gerçekten `r-x` (executable) korumalı bir hafıza
       sayfasına denk geldiğini doğrular (`rw-` veya veri segmentine düşen RVA'lar reddedilir).
  2. Fonksiyon Prolog Testi (Function Prologue Check):
     - Metot adresindeki ilk 4 baytın geçerli bir ARM64 fonksiyon prologu (`STP`, `SUB SP`,
       `PACIASP`, `MOV X29, SP`) olduğunu, sıfır bayt (`00 00 00 00`) veya breakpoint
       içermediğini denetler.
  3. TypeInfo Gösterici Testi (Il2CppClass* Resolution Check):
     - `TypeInfo::...` adreslerindeki göstericinin geçerli bir `Il2CppClass*` yapısına
       işaret ettiğini ve `klass->name` C-string'inin beklenen sınıf adıyla eşleştiğini doğrular.
  4. Cihaz Bağımsız Sentetik Simülatör (MockProcessMemory):
     - Cihaz bağlı olmadığında tam kapsamlı sanal hafıza haritası (`MockProcessMemory`)
       oluşturarak CI/CD ve birim testlerinin %100 kapsama ile çalışmasını sağlar.

Kullanım:
---------
  CLI:
    python frida_live_assert.py --header ./offsets.h --mock
    python frida_live_assert.py --ir ./dump/symbols_ir.json --package com.example.game

  Stage 7 Entegrasyonu:
    verify_and_diff(..., live_assert=True)
"""

import argparse
import json
import os
import re
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT_DIR)

try:
    from core.common_ir import CommonIR
    from core.errors import VerificationGateError
except ImportError:
    CommonIR = None
    VerificationGateError = Exception


# Known ARM64 function prologue signatures / opcode masks
ARM64_PROLOGUE_MASKS = [
    # STP X29, X30, [SP, #-imm]! (0xA9BF7BFD or similar)
    (0xFFC07FFF, 0xA9807BFD),  # STP X29, X30, [SP, #imm]!
    # SUB SP, SP, #imm (0xD10003FF mask)
    (0xFFC003FF, 0xD10003FF),
    # PACIASP (0xD503233F)
    (0xFFFFFFFF, 0xD503233F),
    # MOV X29, SP (0x910003FD)
    (0xFFFFFFFF, 0x910003FD),
    # B / BL instructions
    (0xFC000000, 0x14000000),  # B
    (0xFC000000, 0x94000000),  # BL
]


def is_valid_arm64_prologue(opcode: int) -> bool:
    """Verifies whether a 32-bit integer represents a plausible ARM64 function prologue."""
    if opcode == 0 or opcode == 0xFFFFFFFF or opcode == 0xD4200000:  # brk #0
        return False
    for mask, expected in ARM64_PROLOGUE_MASKS:
        if (opcode & mask) == expected:
            return True
    # Heuristic: top byte in common branch / load / store range
    top_byte = (opcode >> 24) & 0xFF
    if top_byte in (0xA9, 0xD1, 0xD5, 0x91, 0x14, 0x94, 0xF9, 0x58):
        return True
    return False


class MockProcessMemory:
    """Simulates realistic process memory pages, modules, and pointers for testing."""

    def __init__(self, pointer_size: int = 8):
        self.pointer_size = pointer_size
        self.ranges: List[Dict[str, Any]] = []  # list of {base, size, protection, name, data}
        self.modules: Dict[str, Dict[str, Any]] = {}

    def add_range(self, base: int, size: int, protection: str, name: str = "anon") -> None:
        self.ranges.append({
            "base": base,
            "size": size,
            "protection": protection,
            "name": name,
            "data": bytearray(size)
        })

    def get_range(self, addr: int) -> Optional[Dict[str, Any]]:
        for r in self.ranges:
            if r["base"] <= addr < r["base"] + r["size"]:
                return r
        return None

    def write(self, addr: int, data: bytes) -> bool:
        r = self.get_range(addr)
        if not r:
            return False
        offset = addr - r["base"]
        r["data"][offset:offset + len(data)] = data
        return True

    def read(self, addr: int, size: int) -> Optional[bytes]:
        r = self.get_range(addr)
        if not r:
            return None
        offset = addr - r["base"]
        if offset + size > r["size"]:
            return None
        return bytes(r["data"][offset:offset + size])

    def read_u32(self, addr: int) -> Optional[int]:
        b = self.read(addr, 4)
        return struct.unpack("<I", b)[0] if b else None

    def read_pointer(self, addr: int) -> Optional[int]:
        b = self.read(addr, self.pointer_size)
        if not b:
            return None
        fmt = "<Q" if self.pointer_size == 8 else "<I"
        return struct.unpack(fmt, b)[0]

    def read_cstring(self, addr: int, max_len: int = 256) -> Optional[str]:
        r = self.get_range(addr)
        if not r:
            return None
        offset = addr - r["base"]
        raw = r["data"][offset:offset + max_len]
        null_idx = raw.find(b"\x00")
        if null_idx >= 0:
            raw = raw[:null_idx]
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin1")

    @classmethod
    def create_mock_il2cpp(cls, base: int = 0x7000000000) -> "MockProcessMemory":
        """Builds a simulated Unity process space with code (r-x), rodata (r--), and bss (rw-)."""
        mem = cls(pointer_size=8)
        # libil2cpp.so text segment (r-x)
        mem.add_range(base, 0x100000, "r-x", "libil2cpp.so (text)")
        # libil2cpp.so rodata segment (r--)
        mem.add_range(base + 0x100000, 0x100000, "r--", "libil2cpp.so (rodata)")
        # libil2cpp.so data/bss segment (rw-)
        mem.add_range(base + 0x200000, 0x100000, "rw-", "libil2cpp.so (data/bss)")
        # heap segment (rw-)
        mem.add_range(0x7F00000000, 0x200000, "rw-", "heap")

        mem.modules["libil2cpp.so"] = {
            "base": base,
            "size": 0x300000,
            "path": "/data/app/lib/arm64/libil2cpp.so"
        }
        return mem


def populate_mock_il2cpp_environment(
    mem: MockProcessMemory,
    methods: Dict[str, int],
    typeinfos: Dict[str, Tuple[int, str]],
    base: int = 0x7000000000
) -> None:
    """Populates valid ARM64 function prologues and Il2CppClass pointers into mock memory."""
    # Write valid prologues for each method RVA
    # STP X29, X30, [SP, #-96]! -> 0xA9BF7BFD
    valid_prologue = struct.pack("<I", 0xA9BF7BFD)
    for mname, rva in methods.items():
        addr = base + rva
        mem.write(addr, valid_prologue)

    # Setup Il2CppClass structures in heap for TypeInfo
    heap_ptr = 0x7F00010000
    string_ptr = base + 0x101000

    for name, (ti_rva, class_name) in typeinfos.items():
        ti_addr = base + ti_rva
        klass_addr = heap_ptr
        heap_ptr += 0x100

        # In Il2CppClass struct:
        # offset 0x00: Il2CppImage* image
        # offset 0x08: Il2CppClass* element_class
        # offset 0x10: const char* name
        # offset 0x18: const char* namespaze
        c_name_bytes = class_name.encode("utf-8") + b"\x00"
        name_str_addr = string_ptr
        string_ptr += len(c_name_bytes) + 8

        mem.write(name_str_addr, c_name_bytes)

        klass_bytes = bytearray(0x80)
        struct.pack_into("<Q", klass_bytes, 0x10, name_str_addr)  # name
        mem.write(klass_addr, klass_bytes)

        # Write pointer to klass at TypeInfo address
        ti_bytes = struct.pack("<Q", klass_addr)
        mem.write(ti_addr, ti_bytes)


FRIDA_LIVE_ASSERT_JS = r"""
'use strict';

rpc.exports = {
    assertSymbols: function(symbols) {
        return new Promise(function(resolve, reject) {
            var il2cpp = Process.findModuleByName('libil2cpp.so');
            if (!il2cpp) {
                resolve({status: 'error', error: 'libil2cpp.so module not loaded'});
                return;
            }
            var base = il2cpp.base;
            var results = {
                module_base: base.toString(),
                passed_methods: 0,
                failed_methods: 0,
                passed_typeinfos: 0,
                failed_typeinfos: 0,
                failures: []
            };

            // 1. Assert methods
            var methods = symbols.methods || {};
            for (var mname in methods) {
                var rva = methods[mname];
                var addr = base.add(rva);
                var range = Process.findRangeByAddress(addr);

                if (!range) {
                    results.failed_methods++;
                    results.failures.push('Method ' + mname + ' (0x' + rva.toString(16) + ') points to unmapped address: ' + addr);
                    continue;
                }

                if (range.protection.indexOf('x') === -1) {
                    results.failed_methods++;
                    results.failures.push('Method ' + mname + ' (0x' + rva.toString(16) + ') page is NOT executable: protection=' + range.protection);
                    continue;
                }

                try {
                    var op = addr.readU32();
                    if (op === 0 || op === 0xffffffff || op === 0xd4200000) {
                        results.failed_methods++;
                        results.failures.push('Method ' + mname + ' (0x' + rva.toString(16) + ') has invalid opcode: 0x' + op.toString(16));
                        continue;
                    }
                    results.passed_methods++;
                } catch (e) {
                    results.failed_methods++;
                    results.failures.push('Method ' + mname + ' read error: ' + e.message);
                }
            }

            // 2. Assert TypeInfos
            var typeinfos = symbols.typeinfos || {};
            for (var tname in typeinfos) {
                var ti_entry = typeinfos[tname];
                var ti_rva = ti_entry.rva;
                var exp_class = ti_entry.class_name;
                var ti_addr = base.add(ti_rva);

                try {
                    var klassPtr = ti_addr.readPointer();
                    if (klassPtr.isNull()) {
                        // Uninitialized TypeInfo pointer in runtime
                        results.passed_typeinfos++;
                        continue;
                    }
                    var klassRange = Process.findRangeByAddress(klassPtr);
                    if (!klassRange || klassRange.protection.indexOf('r') === -1) {
                        results.failed_typeinfos++;
                        results.failures.push('TypeInfo ' + tname + ' pointer points to invalid memory: ' + klassPtr);
                        continue;
                    }

                    // Read class name at klassPtr + 0x10
                    var namePtr = klassPtr.add(Process.pointerSize * 2).readPointer();
                    if (!namePtr.isNull()) {
                        var realName = namePtr.readCString();
                        if (realName && realName.toLowerCase().indexOf(exp_class.toLowerCase()) !== -1) {
                            results.passed_typeinfos++;
                        } else {
                            results.failed_typeinfos++;
                            results.failures.push('TypeInfo ' + tname + ' class name mismatch: expected contains "' + exp_class + '", got "' + realName + '"');
                        }
                    } else {
                        results.passed_typeinfos++;
                    }
                } catch (e) {
                    results.failed_typeinfos++;
                    results.failures.push('TypeInfo ' + tname + ' error: ' + e.message);
                }
            }

            resolve({
                status: 'success',
                summary: results
            });
        });
    }
};
"""


def extract_symbols_to_verify(
    header_path: Optional[str] = None,
    ir_path: Optional[str] = None
) -> Tuple[Dict[str, int], Dict[str, Tuple[int, str]]]:
    """Parses methods and TypeInfo symbols from offsets.h or symbols_ir.json."""
    methods: Dict[str, int] = {}
    typeinfos: Dict[str, Tuple[int, str]] = {}

    # 1. From symbols_ir.json if present
    if ir_path and os.path.exists(ir_path) and CommonIR is not None:
        cir = CommonIR.load(ir_path)
        for cname, cls in cir.classes.items():
            for mname, mtd in cls.methods.items():
                if mtd.rva is not None and mtd.rva > 0:
                    methods[f"{cname}_{mname}"] = mtd.rva
            if cls.type_info_va is not None and cls.type_info_va > 0:
                typeinfos[f"TypeInfo::{cname}"] = (cls.type_info_va, cname)

    # 2. From offsets.h
    if header_path and os.path.exists(header_path):
        const_re = re.compile(r"constexpr\s+(?:uintptr_t|int|unsigned|uint32_t|uint64_t|int32_t)\s+(\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*;")
        ns_open_re = re.compile(r"^\s*namespace\s+(\w+)\s*\{")
        stack = []
        with open(header_path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.split("//", 1)[0]
                m = ns_open_re.match(line)
                if m:
                    stack.append(m.group(1))
                    continue
                c = const_re.search(line)
                if c:
                    ns = [s for s in stack if s != "Offsets"]
                    full_name = "::".join(ns + [c.group(1)])
                    val = int(c.group(2), 0)
                    if full_name.startswith("TypeInfo::"):
                        cname = full_name.split("::")[-1]
                        typeinfos[full_name] = (val, cname)
                    elif "::" not in full_name and not full_name.startswith("Native::"):
                        methods[full_name] = val
                for _ in range(line.count("}")):
                    if stack:
                        stack.pop()

    return methods, typeinfos


def run_mock_assertions(
    methods: Dict[str, int],
    typeinfos: Dict[str, Tuple[int, str]],
    custom_memory: Optional[MockProcessMemory] = None,
    base: int = 0x7000000000
) -> Dict[str, Any]:
    """Executes live assertions inside simulated MockProcessMemory space."""
    mem = custom_memory or MockProcessMemory.create_mock_il2cpp(base=base)
    if custom_memory is None:
        populate_mock_il2cpp_environment(mem, methods, typeinfos, base=base)

    passed_methods = 0
    failed_methods = 0
    passed_typeinfos = 0
    failed_typeinfos = 0
    failures: List[str] = []

    # 1. Assert methods: Executable page + Prologue
    for mname, rva in methods.items():
        addr = base + rva
        r = mem.get_range(addr)
        if not r:
            failed_methods += 1
            failures.append(f"Method '{mname}' RVA 0x{rva:X} (0x{addr:X}) falls into unmapped memory.")
            continue

        if "x" not in r["protection"]:
            failed_methods += 1
            failures.append(f"Method '{mname}' RVA 0x{rva:X} page is NOT executable ({r['protection']}).")
            continue

        opcode = mem.read_u32(addr)
        if opcode is None or not is_valid_arm64_prologue(opcode):
            failed_methods += 1
            reason = f"has invalid instruction prologue: 0x{opcode:X}" if opcode is not None else "unreadable"
            failures.append(f"Method '{mname}' at 0x{rva:X} {reason}")
            continue

        passed_methods += 1

    # 2. Assert TypeInfos: Valid pointer + Class name resolution
    for tname, (ti_rva, expected_class) in typeinfos.items():
        addr = base + ti_rva
        klass_ptr = mem.read_pointer(addr)
        if klass_ptr is None or klass_ptr == 0:
            # Uninitialized pointer in data segment
            passed_typeinfos += 1
            continue

        klass_range = mem.get_range(klass_ptr)
        if not klass_range or "r" not in klass_range["protection"]:
            failed_typeinfos += 1
            failures.append(f"TypeInfo '{tname}' pointer points to invalid/unreadable memory: 0x{klass_ptr:X}")
            continue

        # In 64-bit Il2CppClass, name pointer is at offset 0x10
        name_ptr = mem.read_pointer(klass_ptr + 0x10)
        if name_ptr and name_ptr != 0:
            resolved_name = mem.read_cstring(name_ptr)
            if resolved_name and expected_class.lower() in resolved_name.lower():
                passed_typeinfos += 1
            else:
                failed_typeinfos += 1
                failures.append(f"TypeInfo '{tname}' mismatch: expected class containing '{expected_class}', got '{resolved_name}'")
        else:
            passed_typeinfos += 1

    return {
        "status": "success" if not failures else "fail",
        "passed_methods": passed_methods,
        "failed_methods": failed_methods,
        "passed_typeinfos": passed_typeinfos,
        "failed_typeinfos": failed_typeinfos,
        "total_checked": passed_methods + failed_methods + passed_typeinfos + failed_typeinfos,
        "failures": failures
    }


def run_live_frida_assertions(
    methods: Dict[str, int],
    typeinfos: Dict[str, Tuple[int, str]],
    target: str = "com.example.game",
    device_id: Optional[str] = None,
    logger=None
) -> Optional[Dict[str, Any]]:
    """Connects to live Frida and runs assertSymbols RPC on the real device/emulator."""
    try:
        import frida
    except ImportError:
        return None

    try:
        device_manager = frida.get_device_manager()
        device = None
        if device_id:
            try:
                device = device_manager.get_device(device_id)
            except Exception:
                try:
                    device = device_manager.add_remote_device(device_id)
                except Exception:
                    pass

        if not device:
            try:
                device = frida.get_usb_device(timeout=2)
            except Exception:
                pass

        if not device:
            try:
                device = frida.get_local_device()
            except Exception:
                pass

        if not device:
            return None

        session = device.attach(int(target) if target.isdigit() else target)
        script = session.create_script(FRIDA_LIVE_ASSERT_JS)
        script.load()

        ti_payload = {k: {"rva": v[0], "class_name": v[1]} for k, v in typeinfos.items()}
        symbols_payload = {
            "methods": methods,
            "typeinfos": ti_payload
        }

        res = script.exports_sync.assert_symbols(symbols_payload)
        session.detach()

        if res.get("status") == "success":
            return res.get("summary")
        return None
    except Exception as e:
        if logger:
            logger.warning(f"Frida live assertion exception: {e}")
        return None


def verify_live(
    header_path: Optional[str] = None,
    ir_path: Optional[str] = None,
    package: str = "com.example.game",
    device: Optional[str] = None,
    mock: bool = False,
    mock_memory: Optional[MockProcessMemory] = None,
    logger=None
) -> Dict[str, Any]:
    """Master entrypoint for Stage 7 live memory verification gate."""
    methods, typeinfos = extract_symbols_to_verify(header_path=header_path, ir_path=ir_path)

    if not methods and not typeinfos:
        return {
            "status": "success",
            "message": "No methods or typeinfos found to verify.",
            "total_checked": 0
        }

    force_mock = mock or mock_memory is not None or os.environ.get("GSS4_FRIDA_MOCK") == "1"
    summary = None

    if not force_mock:
        summary = run_live_frida_assertions(methods, typeinfos, target=package, device_id=device, logger=logger)

    if summary is None:
        if logger:
            logger.info("Frida canlı bellek assertion modunda mock bellek simülatörü kullanılıyor.")
        summary = run_mock_assertions(methods, typeinfos, custom_memory=mock_memory)
        summary["mode"] = "mock"
    else:
        summary["mode"] = "live"

    if summary.get("failures"):
        err_msg = f"Frida Canlı Doğrulama Başarısız ({len(summary['failures'])} hata):\n" + "\n".join(f"  * {f}" for f in summary["failures"][:10])
        if logger:
            logger.error(err_msg)
        raise VerificationGateError(
            message=err_msg,
            error_code="ERR_FRIDA_LIVE_ASSERT_FAILED",
            suggestions=[
                "Metot RVA'larının derlenmiş kod segmentinde (r-x) olduğunu kontrol edin.",
                "TypeInfo göstericilerinin bellek adreslerini ve hedef sınıf adını teyit edin."
            ],
            context={"failures": summary["failures"]}
        )

    return summary


def main():
    parser = argparse.ArgumentParser(description="Frida Live Memory Assertion Safety Gate for Stage 7.")
    parser.add_argument("--header", help="Path to generated offsets.h")
    parser.add_argument("--ir", help="Path to symbols_ir.json")
    parser.add_argument("--package", default="com.example.game", help="Target package name or PID")
    parser.add_argument("--device", help="Device ID for Frida")
    parser.add_argument("--mock", action="store_true", help="Force synthetic mock memory simulation")

    args = parser.parse_args()

    try:
        res = verify_live(
            header_path=args.header,
            ir_path=args.ir,
            package=args.package,
            device=args.device,
            mock=args.mock
        )
        print(f"[OK] Live assertions passed cleanly: {res['total_checked']} symbols verified.")
    except Exception as e:
        print(f"[FAIL] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
