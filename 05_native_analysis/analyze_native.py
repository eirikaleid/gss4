#!/usr/bin/env python3
"""
05_native_analysis/analyze_native.py - Stage 5: Native ELF Binary Offset Analyzer
================================================================================
Ne İşe Yarar? (Purpose):
------------------------
Unity oyunlarında render döngüsü (ImGui çizimleri, ESP kutuları, menü panelleri)
ve motor kancaları (hooks) genellikle `libunity.so` veya diğer native kütüphanelere dayanır.
Bu modül, saf Python ELF parser'ı ile:
  1. `libunity.so` 64-bit ELF ikilisini ayrıştırır (PT_LOAD, PT_DYNAMIC, SHT_RELA tabloları).
  2. `eglSwapBuffers` veya benzeri kritik fonksiyonların Global Offset Table (GOT) dosya ofsetlerini çıkarır.
  3. `.rodata` string aramaları yaparak Vulkan Swappy (`libswappywrapper`) gibi render bozan dizgilerin ofsetlerini bulur.
  4. Elde edilen değerleri C++ kodunda doğrudan kullanılacak `native.json` biçiminde sunar.

Neler Yapılabilir? (Extension Points):
--------------------------------------
1. Çoklu Kütüphane Taraması: libmain.so, libanogs.so ve libGLESv2.so gibi kütüphaneleri de tek seferde analiz etme.
2. ARM64 Gadget ve ROP Bulucu: Bellek korumalarını aşmak için yararlı ARM64 instruction (BLR x8, RET) tarayıcısı.
3. Otomatik Hex-Patch Üretici: Bellekte Vulkan Swappy'i devredışı bırakmak için byte patch listesi oluşturma.
4. DWARF Debug Tablosu Çözücü: Eğer kütüphanede soyulmamış (unstripped) debug bilgisi varsa fonksiyon imzalarını okuma.
5. PLT/GOT İkili Bağlantı Haritası: Lazy-binding ve non-lazy binding durumlarını görselleştiren analiz raporu.

Hata Yönetimi ve Loglama:
-------------------------
- 32-bit ELF, bozuk header veya aranan sembolün bulunamaması NativeAnalysisError ile yakalanır.
- Tüm ELF ayrıştırma adımları 'workspace/logs/stage_05_05_native_analysis.log' dosyasına kaydedilir.
"""

import argparse
import json
import os
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core.stage_base import BaseStage, StageResult
    from core.errors import NativeAnalysisError, StageInputError
    from core.logger import get_stage_logger
except ImportError:
    BaseStage = object
    NativeAnalysisError = Exception
    StageInputError = Exception
    get_stage_logger = None

PT_LOAD, PT_DYNAMIC = 1, 2
SHT_RELA, SHT_DYNSYM = 4, 11
DT_NULL, DT_PLTRELSZ, DT_STRTAB, DT_SYMTAB, DT_JMPREL = 0, 2, 5, 6, 23
R_AARCH64_JUMP_SLOT = 1026
R_AARCH64_GLOB_DAT = 1025


class Elf64:
    """Lightweight pure-python 64-bit ELF parser."""

    def __init__(self, data: bytes):
        if len(data) < 0x40 or data[:4] != b"\x7fELF":
            raise NativeAnalysisError(
                message="Geçerli bir ELF dosyası değil (ELF magic eksik).",
                error_code="ERR_INVALID_ELF_MAGIC",
                suggestions=["Dosyanın bozulmadığını kontrol edin."]
            )
        if data[4] != 2 or data[5] != 1:
            raise NativeAnalysisError(
                message=f"Desteklenmeyen ELF formatı (Sınıf: {data[4]}, Endian: {data[5]}). Yalnızca 64-bit Little-Endian desteklenir.",
                error_code="ERR_ELF_NOT_64BIT",
                suggestions=["Analiz edilen APK'nın arm64-v8a mimarisine ait olduğunu doğrulayın."]
            )
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

    def cstr(self, off: int) -> str:
        try:
            end = self.d.index(b"\0", off)
            return self.d[off:end].decode("latin-1")
        except Exception:
            return ""

    def va_to_off(self, va: int) -> Optional[int]:
        for off, seg_va, fsz in self.loads:
            if seg_va <= va < seg_va + fsz:
                return va - seg_va + off
        return None

    def section(self, name: str) -> Optional[Dict[str, Any]]:
        for s in self.shdrs:
            if s["name"] == name:
                return s
        return None

    def _dynamic(self) -> Dict[int, int]:
        out = {}
        for p in self.phdrs:
            if p[0] == PT_DYNAMIC:
                dyn_off = self.va_to_off(p[2])
                if dyn_off is None:
                    continue
                for i in range(p[5] // 16):
                    tag, val = struct.unpack_from("<QQ", self.d, dyn_off + i * 16)
                    if tag == DT_NULL:
                        break
                    out[tag] = val
                break
        return out

    def find_got_slot(self, sym_name: str) -> Optional[Dict[str, Any]]:
        dyn = self._dynamic()
        strtab_va = dyn.get(DT_STRTAB)
        symtab_va = dyn.get(DT_SYMTAB)
        jmprel_va = dyn.get(DT_JMPREL)
        pltrelsz = dyn.get(DT_PLTRELSZ, 0)

        if not (strtab_va and symtab_va and jmprel_va and pltrelsz):
            return None

        strtab_off = self.va_to_off(strtab_va)
        symtab_off = self.va_to_off(symtab_va)
        jmprel_off = self.va_to_off(jmprel_va)

        if strtab_off is None or symtab_off is None or jmprel_off is None:
            return None

        nrel = pltrelsz // 24
        for i in range(nrel):
            r_offset, r_info, _ = struct.unpack_from("<QQq", self.d, jmprel_off + i * 24)
            r_type = r_info & 0xFFFFFFFF
            r_sym = r_info >> 32
            if r_type not in (R_AARCH64_JUMP_SLOT, R_AARCH64_GLOB_DAT):
                continue

            sym_entry = symtab_off + r_sym * 24
            if sym_entry + 4 > len(self.d):
                continue
            st_name = struct.unpack_from("<I", self.d, sym_entry)[0]
            name = self.cstr(strtab_off + st_name)

            if name == sym_name:
                got_off = self.va_to_off(r_offset)
                return {
                    "symbol": sym_name,
                    "reloc_type": "R_AARCH64_JUMP_SLOT" if r_type == R_AARCH64_JUMP_SLOT else "R_AARCH64_GLOB_DAT",
                    "va": hex(r_offset),
                    "file_offset": hex(got_off) if got_off is not None else None,
                    "file_offset_int": got_off,
                }
        return None

    def find_string(self, needle: bytes) -> List[Dict[str, Any]]:
        hits = []
        off = 0
        while True:
            idx = self.d.find(needle, off)
            if idx == -1:
                break
            hits.append({"file_offset": hex(idx), "file_offset_int": idx})
            off = idx + len(needle)
        return hits


def analyze(lib_path: str, rules: Optional[Dict[str, Any]] = None, logger=None) -> Dict[str, Any]:
    """Inspects native library and returns analysis dictionary. Returns empty dict if file absent."""
    if not os.path.exists(lib_path):
        return {}
    return analyze_unity_binary(lib_path, logger=logger)


def analyze_unity_binary(unity_so_path: str, logger=None) -> Dict[str, Any]:
    """Analyze libunity.so for eglSwapBuffers GOT slot and Vulkan Swappy string."""
    if not os.path.exists(unity_so_path):
        raise NativeAnalysisError(
            message=f"libunity.so ikili dosyası bulunamadı: {unity_so_path}",
            error_code="ERR_UNITY_SO_MISSING",
            suggestions=["Stage 2'de (extract) libunity.so'nun ayıklandığından emin olun."]
        )

    def log(msg, level="info"):
        if logger:
            getattr(logger, level)(msg)
        else:
            print(msg)

    with open(unity_so_path, "rb") as f:
        data = f.read()

    log(f"ELF analizi başlatılıyor: {unity_so_path} ({len(data):,} bayt)...")
    elf = Elf64(data)

    results = {"library": os.path.basename(unity_so_path), "symbols": {}, "strings": {}}

    # 1. eglSwapBuffers GOT Slotu
    got = elf.find_got_slot("eglSwapBuffers")
    if got:
        log(f"  [+] eglSwapBuffers GOT slotu bulundu: VA={got['va']}, FileOffset={got['file_offset']}")
        results["symbols"]["eglSwapBuffers"] = got
    else:
        log("  [WARN] eglSwapBuffers GOT relocation kaydı bulunamadı.", level="warning")

    # 2. String analizi (Swappy Wrapper)
    swappy_hits = elf.find_string(b"libswappywrapper")
    if swappy_hits:
        log(f"  [+] 'libswappywrapper' string eşleşmesi: {len(swappy_hits)} adet. İlk ofset: {swappy_hits[0]['file_offset']}")
        results["strings"]["libswappywrapper"] = swappy_hits
    else:
        log("  [i] 'libswappywrapper' dizgisi bulunamadı (bu sürüm Swappy içermiyor olabilir).", level="debug")

    return results


class Stage5Native(BaseStage):
    """Stage 5: Native Analysis Implementation."""

    stage_id = 5
    name = "05_native_analysis"
    description = "Analyzes native ELF binaries (e.g. libunity.so) for GOT slots and rodata strings."
    purpose = "libunity.so kütüphanesini ayrıştırarak eglSwapBuffers GOT slotu ve Vulkan Swappy string ofsetlerini çıkarır."
    extension_points = [
        "libmain.so, libanogs.so ve libGLESv2.so gibi ek native kütüphaneleri analiz etme",
        "ARM64 ROP gadget ve register trampoline bulucu entegrasyonu",
        "Bellekte Vulkan Swappy'i susturacak otomatik byte patch listesi üretme",
        "Soyulmamış (unstripped) kütüphanelerde DWARF sembollerini çözümleme",
        "Relocation türlerine göre dynamic symbol bağlanma hız analizi"
    ]
    troubleshooting = [
        {"error": "ERR_UNITY_SO_MISSING", "fix": "Stage 2 çıktısı olan bin/libunity.so dosyasını kontrol edin."},
        {"error": "ERR_ELF_NOT_64BIT", "fix": "Uygulamanın 64-bit (arm64-v8a) olduğundan emin olun."},
        {"error": "ERR_INVALID_ELF_MAGIC", "fix": "libunity.so dosyasının bozulmadığını kontrol edin."}
    ]

    def validate_inputs(self, workspace: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        rules = config.get("native_rules", {})
        if rules.get("egl_swap_got") is False:
            return True, ""
        so_path = config.get("unity_so") or os.path.join(workspace, "bin", "libunity.so")
        if not os.path.exists(so_path):
            if config.get("optional", True):
                return True, ""
            return False, f"libunity.so bulunamadı: {so_path}. Stage 2 çalışmalı."
        return True, ""

    def execute(self, workspace: str, config: Dict[str, Any]) -> Dict[str, Any]:
        so_path = config.get("unity_so") or os.path.join(workspace, "bin", "libunity.so")
        out_json = config.get("out_json") or os.path.join(workspace, "native.json")

        self.logger.info(f"Stage 5 Başlatıldı: Kütüphane={so_path}")

        if os.path.exists(so_path):
            res = analyze_unity_binary(so_path, logger=self.logger)
        else:
            self.logger.warning(f"libunity.so bulunamadı ({so_path}), boş native veri üretiliyor.")
            res = {}

        os.makedirs(os.path.dirname(os.path.abspath(out_json)), exist_ok=True)
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)

        self.logger.info(f"Native analiz raporu kaydedildi: {out_json}")

        return {
            "native_analysis": res,
            "native_json": os.path.abspath(out_json),
            "output_files": [os.path.abspath(out_json)]
        }

    def validate_outputs(self, workspace: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        out_json = config.get("out_json") or os.path.join(workspace, "native.json")
        if not os.path.exists(out_json):
            return False, f"Beklenen çıktı dosyası bulunamadı: {out_json}"
        return True, ""


def main():
    parser = argparse.ArgumentParser(description="Analyze ELF GOT slots and rodata strings.")
    parser.add_argument("--so", required=True, help="Path to libunity.so (or target ELF)")
    parser.add_argument("--out", required=True, help="Path to output JSON")

    args = parser.parse_args()

    stage = Stage5Native()
    config = {"unity_so": args.so, "out_json": args.out}
    res = stage.run_stage(os.path.dirname(os.path.abspath(args.out)), config)
    if res.status != "success":
        sys.exit(1)


if __name__ == "__main__":
    main()
