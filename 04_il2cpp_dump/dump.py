#!/usr/bin/env python3
"""
04_il2cpp_dump/dump.py - Stage 4: Il2CppDumper Runner & Freshness Verifier
========================================================================
Ne İşe Yarar? (Purpose):
------------------------
Bu modül, deşifre edilmiş metadata ('global-metadata.dec.dat') ve native kütüphaneyi ('libil2cpp.so')
kullanarak headless modda Il2CppDumper motorunu koşturur.
Çalışma sonucunda tersine mühendisliğin temel yapı taşları üretilir:
  1. dump.cs: Tüm sınıflar, alan ofsetleri (// 0x...), metot RVA'ları ve TypeDef indeksleri (~70-100 MB).
  2. script.json: Ghidra ve IDA Pro için sembol isimlendirme betiği ve RVA eşleme tablosu.
  3. il2cpp.h: Native C++ struct ve typedef tanımlamaları.
  4. stringliteral.json: Oyundaki tüm string değerleri ve bellek göstericileri.

Neler Yapılabilir? (Extension Points):
--------------------------------------
1. Alternatif Dumper Desteği: Il2CppInspector CLI veya Zygisk / Frida bellekten dump motorlarını bağlama.
2. Dinamik Konfigürasyon: config.json (GenerateStruct, GenerateDummyDll) ayarlarını profil bazlı otomatik güncelleme.
3. Artımlı (Incremental) Önbellekleme: İkili dosya hash'leri değişmediyse dump aşamasını atlayarak süreden kazanma.
4. Çökme Kurtarıcısı (Crash Recovery): Dumper bilinmeyen bir TypeDef'te çökerse o metadata tablosunu izole edip yeniden başlatma.
5. Headless Terminal Yönetimi: Standart girdi (stdin) kilitlenmelerini bypass eden güvenli işlem havuzu.

Hata Yönetimi ve Loglama:
-------------------------
- Il2CppDumper.exe eksikliği, yürütme zaman aşımı, bozuk girdi veya sıfır bayt çıktı DumperError ile yakalanır.
- Dumper'ın stdout ve stderr çıktıları 'workspace/logs/il2cppdumper.log' ve 'workspace/logs/stage_04_04_il2cpp_dump.log' içine yazılır.
"""

import argparse
import datetime
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core.stage_base import BaseStage, StageResult
    from core.errors import DumperError, StageInputError
    from core.logger import get_stage_logger
except ImportError:
    BaseStage = object
    DumperError = Exception
    StageInputError = Exception
    get_stage_logger = None

DEFAULT_DUMPER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "tools", "Il2CppDumper", "Il2CppDumper.exe")


def run_dumper(
    so_path: str,
    meta_path: str,
    out_dir: str,
    dumper_exe: Optional[str] = None,
    log_path: Optional[str] = None,
    logger=None
) -> Dict[str, Any]:
    """Execute Il2CppDumper with the provided binary and decrypted metadata."""
    os.makedirs(out_dir, exist_ok=True)
    dumper_exe = dumper_exe or DEFAULT_DUMPER

    def log(msg, level="info"):
        if logger:
            getattr(logger, level)(msg)
        else:
            print(msg)

    if not os.path.exists(so_path):
        raise DumperError(
            message=f"libil2cpp.so ikili dosyası bulunamadı: {so_path}",
            error_code="ERR_DUMPER_SO_MISSING",
            suggestions=["Stage 2'nin (extract) başarılı olduğundan emin olun."]
        )
    if not os.path.exists(meta_path):
        raise DumperError(
            message=f"Metadata dosyası bulunamadı: {meta_path}",
            error_code="ERR_DUMPER_METADATA_MISSING",
            suggestions=["Stage 3'ün (decrypt) başarıyla 'global-metadata.dec.dat' ürettiğini doğrulayın."]
        )
    if not os.path.exists(dumper_exe):
        raise DumperError(
            message=f"Il2CppDumper çalıştırılabilir dosyası bulunamadı: {dumper_exe}",
            error_code="ERR_DUMPER_EXE_NOT_FOUND",
            suggestions=[
                "tools/Il2CppDumper/ dizininde Il2CppDumper.exe dosyasının bulunduğunu doğrulayın.",
                "Windows Defender veya antivirüsün dosyayı karantinaya alıp almadığını kontrol edin."
            ]
        )

    # Eski çıktıları temizle
    for f in ["dump.cs", "script.json", "il2cpp.h", "stringliteral.json"]:
        p = os.path.join(out_dir, f)
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass

    t0 = time.time()
    log_file = log_path or os.path.join(out_dir, "il2cppdumper.log")
    log(f"Il2CppDumper koşturuluyor...\n    SO: {so_path}\n    Metadata: {meta_path}\n    Çıktı: {out_dir}")

    cmd = [os.path.abspath(dumper_exe), os.path.abspath(so_path), os.path.abspath(meta_path), os.path.abspath(out_dir)]
    dumper_cwd = os.path.dirname(os.path.abspath(dumper_exe))

    try:
        with open(log_file, "w", encoding="utf-8", errors="replace") as lf:
            proc = subprocess.run(
                cmd,
                cwd=dumper_cwd,
                stdin=subprocess.DEVNULL,  # Prevent hanging on ReadKey
                stdout=lf,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=180  # 3 minutes timeout
            )
    except subprocess.TimeoutExpired:
        raise DumperError(
            message="Il2CppDumper işlemi zaman aşımına uğradı (180s).",
            error_code="ERR_DUMPER_TIMEOUT",
            suggestions=["Metadata dosyasının doğru çözüldüğünden veya sonsuz döngüye girmediğinden emin olun."]
        )

    elapsed = time.time() - t0
    dump_cs = os.path.join(out_dir, "dump.cs")
    script_json = os.path.join(out_dir, "script.json")

    log_content = ""
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8", errors="replace") as lf:
            log_content = lf.read()

    if not os.path.exists(dump_cs) or not os.path.exists(script_json):
        raise DumperError(
            message=f"Il2CppDumper başarısız oldu (Çıkış Kodu: {proc.returncode}). Çıktı dosyaları oluşturulamadı.\nSon loglar:\n{log_content[-600:]}",
            error_code="ERR_DUMPER_EXECUTION_FAILED",
            suggestions=[
                "Metadata şifre çözme işleminin (Stage 3) doğruluğunu kontrol edin.",
                "tools/Il2CppDumper/config.json ayarlarını kontrol edin (RequireAnyKey: false olmalı)."
            ],
            context={"returncode": proc.returncode, "log_tail": log_content[-300:]}
        )

    cs_size = os.path.getsize(dump_cs)
    sj_size = os.path.getsize(script_json)

    if cs_size < 1024 or sj_size < 1024:
        raise DumperError(
            message=f"Il2CppDumper çıktı dosyaları anormal derecede küçük: dump.cs={cs_size}B, script.json={sj_size}B",
            error_code="ERR_DUMPER_OUTPUT_TRUNCATED",
            suggestions=["Metadata'nın eksik çözülmüş olabileceğini değerlendirin."]
        )

    log(f"Dumper başarıyla tamamlandı ({elapsed:.2f}s). dump.cs: {cs_size / 1024 / 1024:.2f} MB, script.json: {sj_size / 1024 / 1024:.2f} MB")

    return {
        "status": "success",
        "dump_cs": os.path.abspath(dump_cs),
        "script_json": os.path.abspath(script_json),
        "il2cpp_h": os.path.abspath(os.path.join(out_dir, "il2cpp.h")) if os.path.exists(os.path.join(out_dir, "il2cpp.h")) else None,
        "elapsed_sec": round(elapsed, 2),
        "dump_cs_size_mb": round(cs_size / 1024 / 1024, 2)
    }


class Stage4Dump(BaseStage):
    """Stage 4: Il2CppDumper Implementation."""

    stage_id = 4
    name = "04_il2cpp_dump"
    description = "Executes Il2CppDumper to produce dump.cs, script.json, and il2cpp.h."
    purpose = "libil2cpp.so ve deşifre edilmiş metadata'yı birleştirerek dump.cs ve script.json sembol dosyalarını üretir."
    extension_points = [
        "Il2CppInspector veya alternatif dumper motorlarını bağlama desteği",
        "Dump konfigürasyonunu (config.json) profil bazlı otomatik ayarlama",
        "Artımlı (incremental) önbellekleme ile gereksiz tekrarları önleme",
        "Frida bellek dumper'ı ile korumalı runtime dump alabilme",
        "Zaman aşımı ve stdin kilitlenmelerini engelleyen otomatik izleme"
    ]
    troubleshooting = [
        {"error": "ERR_DUMPER_EXE_NOT_FOUND", "fix": "tools/Il2CppDumper/Il2CppDumper.exe dosyasının var olduğunu teyit edin."},
        {"error": "ERR_DUMPER_EXECUTION_FAILED", "fix": "Deşifre edilen metadatanın 0xFAB11BAF ile başladığını kontrol edin."},
        {"error": "ERR_DUMPER_TIMEOUT", "fix": "İşlem 180 saniyeyi aştı, girdi dosyalarının boyutunu ve sistem kaynaklarını kontrol edin."}
    ]

    def validate_inputs(self, workspace: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        so_path = config.get("so_path") or os.path.join(workspace, "bin", "libil2cpp.so")
        meta_path = config.get("meta_path") or os.path.join(workspace, "bin", "global-metadata.dec.dat")
        if not os.path.exists(meta_path):
            alt = os.path.join(workspace, "bin", "global-metadata.dat")
            if os.path.exists(alt):
                meta_path = alt
            else:
                return False, f"Missing metadata: Ne deşifre edilmiş metadata ({meta_path}) ne de ham metadata bulundu. Stage 2 ve 3 çalışmalı."
        if not os.path.exists(so_path):
            return False, f"Missing libil2cpp.so: libil2cpp.so bulunamadı: {so_path}. Stage 2 çalışmalı."
        return True, ""

    def execute(self, workspace: str, config: Dict[str, Any]) -> Dict[str, Any]:
        so_path = config.get("so_path") or os.path.join(workspace, "bin", "libil2cpp.so")
        meta_path = config.get("meta_path") or os.path.join(workspace, "bin", "global-metadata.dec.dat")
        if not os.path.exists(meta_path):
            meta_path = os.path.join(workspace, "bin", "global-metadata.dat")

        out_dir = config.get("dump_dir") or os.path.join(workspace, "dump")
        dumper_exe = config.get("dumper_exe") or DEFAULT_DUMPER
        log_path = os.path.join(workspace, "dump", "il2cppdumper.log")

        self.logger.info(f"Stage 4 Başlatıldı: Dumper='{dumper_exe}', Hedef='{out_dir}'")

        dump_res = run_dumper(
            so_path=so_path,
            meta_path=meta_path,
            out_dir=out_dir,
            dumper_exe=dumper_exe,
            log_path=log_path,
            logger=self.logger
        )

        output_files = [dump_res["dump_cs"], dump_res["script_json"]]
        if dump_res.get("il2cpp_h"):
            output_files.append(dump_res["il2cpp_h"])

        return {
            "dump_dir": out_dir,
            "dump_cs": dump_res["dump_cs"],
            "script_json": dump_res["script_json"],
            "il2cpp_h": dump_res.get("il2cpp_h"),
            "output_files": output_files
        }

    def validate_outputs(self, workspace: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        dump_cs = os.path.join(workspace, "dump", "dump.cs")
        script_json = os.path.join(workspace, "dump", "script.json")
        if not os.path.exists(dump_cs) or os.path.getsize(dump_cs) == 0:
            return False, f"Geçerli dump.cs oluşturulamadı: {dump_cs}"
        if not os.path.exists(script_json) or os.path.getsize(script_json) == 0:
            return False, f"Geçerli script.json oluşturulamadı: {script_json}"
        return True, ""


def main():
    parser = argparse.ArgumentParser(description="Run Il2CppDumper headlessly.")
    parser.add_argument("--so", required=True, help="Path to libil2cpp.so")
    parser.add_argument("--meta", required=True, help="Path to decrypted global-metadata.dat")
    parser.add_argument("--out", required=True, help="Output directory for dump files")
    parser.add_argument("--dumper", help="Optional path to Il2CppDumper.exe")

    args = parser.parse_args()

    stage = Stage4Dump()
    config = {
        "so_path": args.so,
        "meta_path": args.meta,
        "dump_dir": args.out,
        "dumper_exe": args.dumper
    }
    res = stage.run_stage(os.path.dirname(os.path.abspath(args.out)), config)
    if res.status != "success":
        sys.exit(1)


if __name__ == "__main__":
    main()
