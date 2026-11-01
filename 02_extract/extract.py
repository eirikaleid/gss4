#!/usr/bin/env python3
"""
02_extract/extract.py - Stage 2: Binary & Metadata Extractor
============================================================
Ne İşe Yarar? (Purpose):
------------------------
Bu modül, temin edilen APK (veya split APK) arşivlerini açarak Unity IL2CPP motorunun
kalbini oluşturan kritik dosyaları ayıklar ve çalışma alanının 'bin/' dizinine kaydeder:
  1. lib/<arch>/libil2cpp.so: Tüm oyun mantığının derlendiği native makine kodları.
  2. assets/bin/Data/Managed/Metadata/global-metadata.dat: Sınıf, metot, alan isimleri ve dizgileri.
  3. lib/<arch>/libunity.so: Unity motoru, eglSwapBuffers GOT bağlantıları ve motor kütüphaneleri.
  4. İsteğe bağlı ek kütüphaneler (libmain.so, libanogs.so vb.).

Neler Yapılabilir? (Extension Points):
--------------------------------------
1. Gelişmiş Format Desteği: XAPK, APKS, APKM ve OBB arşivlerini tek hamlede açan evrensel çıkartıcı.
2. Unity AssetBundle Ayıklayıcı: UnityPy / AssetStudio ile dokular, prefablar ve ses dosyalarını çıkartma.
3. Mimari Otomatik Fallback: İstenen mimari (arm64-v8a) yoksa otomatik armeabi-v7a'ya geçiş yapma.
4. Bellek Eşlemeli (mmap) Hızlı Çıkarma: Birkaç GB'lık devasa APK'larda disk I/O hızını optimize etme.
5. İkili Bütünlük Doğrulaması: Çıkarılan ELF dosyalarının ELF magic (0x7F 'E' 'L' 'F') kontrolünü anında yapma.

Hata Yönetimi ve Loglama:
-------------------------
- Bozuk ZIP arşivi, eksik libil2cpp veya eksik metadata durumları ExtractionError ile yakalanır.
- Tüm çıkarma detayları 'workspace/logs/stage_02_02_extract.log' dosyasına kaydedilir.
"""

import argparse
import json
import os
import sys
import zipfile
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core.stage_base import BaseStage, StageResult
    from core.errors import ExtractionError, StageInputError
    from core.logger import get_stage_logger
except ImportError:
    BaseStage = object
    ExtractionError = Exception
    StageInputError = Exception
    get_stage_logger = None


def extract_binaries(
    apks: List[str],
    out_dir: str,
    arch: str = "arm64-v8a",
    extra_libs: Optional[List[str]] = None,
    logger=None
) -> Dict[str, str]:
    """Extract libil2cpp.so, libunity.so, and global-metadata.dat from APK list."""
    os.makedirs(out_dir, exist_ok=True)
    extra_libs = extra_libs or []

    def log(msg, level="info"):
        if logger:
            getattr(logger, level)(msg)
        else:
            print(msg)

    wanted = {
        f"lib/{arch}/libil2cpp.so": os.path.join(out_dir, "libil2cpp.so"),
        "assets/bin/Data/Managed/Metadata/global-metadata.dat": os.path.join(out_dir, "global-metadata.dat"),
    }
    wanted[f"lib/{arch}/libunity.so"] = os.path.join(out_dir, "libunity.so")
    for lib in extra_libs:
        wanted[f"lib/{arch}/{lib}"] = os.path.join(out_dir, lib)

    # Clean existing
    for dst in wanted.values():
        if os.path.exists(dst):
            try:
                os.remove(dst)
            except OSError:
                pass

    log(f"İkili dosyalar taranıyor: {len(apks)} APK arşivi, mimari: '{arch}'...")
    found = set()

    for apk_path in apks:
        if not os.path.isfile(apk_path):
            log(f"APK dosyası bulunamadı: {apk_path}", level="warning")
            continue

        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                names = set(z.namelist())
                for target_entry, dst_path in wanted.items():
                    if target_entry in names and target_entry not in found:
                        log(f"Ayıklanıyor: {target_entry} -> {dst_path}")
                        with z.open(target_entry) as src, open(dst_path, "wb") as dst:
                            dst.write(src.read())
                        found.add(target_entry)
        except zipfile.BadZipFile as e:
            raise ExtractionError(
                message=f"Bozuk ZIP arşivi tespit edildi: {apk_path}. Hata: {e}",
                error_code="ERR_ZIP_CORRUPT",
                suggestions=["APK dosyasının indirilmesi yarıda kesilmiş olabilir, tekrar indirin."]
            )
        except Exception as e:
            raise ExtractionError(
                message=f"APK okunurken hata oluştu: {apk_path}. Hata: {e}",
                error_code="ERR_EXTRACTION_IO",
                suggestions=["Dosya okuma izinlerini kontrol edin."]
            )

    crit_il2cpp = f"lib/{arch}/libil2cpp.so"
    crit_meta = "assets/bin/Data/Managed/Metadata/global-metadata.dat"

    if crit_il2cpp not in found:
        raise ExtractionError(
            message=f"Kritik ikili dosya APK içinde bulunamadı: '{crit_il2cpp}'",
            error_code="ERR_MISSING_IL2CPP",
            suggestions=[
                f"APK'nın belirtilen mimariyi ({arch}) içerdiğinden emin olun.",
                "Eğer split APK sistemi varsa 'split_config.<arch>.apk' dosyasını da pipeline'a verin.",
                "Oyunun saf Unity IL2CPP olduğundan (Mono değil) emin olun."
            ]
        )

    if crit_meta not in found:
        raise ExtractionError(
            message=f"Kritik metadata dosyası APK içinde bulunamadı: '{crit_meta}'",
            error_code="ERR_MISSING_METADATA",
            suggestions=[
                "base.apk dosyasının verildiğinden emin olun (metadata assets/ klasöründe yer alır).",
                "Bazı oyunlar metadata'yı şifreli ek paketlerde saklayabilir."
            ]
        )

    # Return dictionary of extracted absolute paths
    res = {
        "il2cpp": os.path.abspath(os.path.join(out_dir, "libil2cpp.so")),
        "il2cpp_so": os.path.abspath(os.path.join(out_dir, "libil2cpp.so")),
        "metadata": os.path.abspath(os.path.join(out_dir, "global-metadata.dat")),
    }
    unity_path = os.path.join(out_dir, "libunity.so")
    if os.path.exists(unity_path):
        res["unity"] = os.path.abspath(unity_path)
        res["unity_so"] = os.path.abspath(unity_path)

    for lib in extra_libs:
        lp = os.path.join(out_dir, lib)
        if os.path.exists(lp):
            res[lib] = os.path.abspath(lp)

    return res


class Stage2Extract(BaseStage):
    """Stage 2: Binary & Metadata Extraction Implementation."""

    stage_id = 2
    name = "02_extract"
    description = "Extracts libil2cpp.so, libunity.so, and global-metadata.dat from APKs."
    purpose = "APK arşivlerinden tersine mühendislik için gerekli libil2cpp.so, libunity.so ve global-metadata.dat dosyalarını ayıklar."
    extension_points = [
        "XAPK, APKS ve APKM formatlarını otomatik çözümleme",
        "Unity AssetBundle ve doku ayıklayıcı (AssetStudio/UnityPy entegrasyonu)",
        "arm64 bulunamazsa otomatik armeabi-v7a mimari fallback sistemi",
        "ELF başlık doğrulama (0x7F ELF magic kontrolü)",
        "Büyük dosyalarda mmap ile disk I/O optimizasyonu"
    ]
    troubleshooting = [
        {"error": "ERR_ZIP_CORRUPT", "fix": "APK dosyasını yeniden indirin, dosya eksik inmiş olabilir."},
        {"error": "ERR_MISSING_IL2CPP", "fix": "Mimari split APK dosyasını (örn: split_config.arm64_v8a.apk) ekleyin."},
        {"error": "ERR_MISSING_METADATA", "fix": "base.apk dosyasının sağlandığını doğrulayın."}
    ]

    def validate_inputs(self, workspace: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        manifest_path = os.path.join(workspace, "apk", "apk_manifest.json")
        apks = config.get("apks")
        if not apks and not os.path.exists(manifest_path):
            return False, f"Ne 'apks' parametresi ne de manifest dosyası ({manifest_path}) bulunamadı. Önce Stage 1 çalışmalıdır."
        return True, ""

    def execute(self, workspace: str, config: Dict[str, Any]) -> Dict[str, Any]:
        out_dir = os.path.join(workspace, "bin")
        os.makedirs(out_dir, exist_ok=True)

        apks = config.get("apks")
        if not apks:
            manifest_path = os.path.join(workspace, "apk", "apk_manifest.json")
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                apks = data.get("apks", [])

        arch = config.get("arch", "arm64-v8a")
        extra_libs = config.get("extra_libs", [])

        self.logger.info(f"Stage 2 Başlatıldı: {len(apks)} APK taranıyor, Mimari: {arch}")

        extracted = extract_binaries(apks, out_dir, arch=arch, extra_libs=extra_libs, logger=self.logger)
        output_files = list(extracted.values())

        self.logger.info(f"Ayıklama tamamlandı. {len(output_files)} dosya çıkarıldı.")
        for k, v in extracted.items():
            self.logger.debug(f"  - {k}: {v} ({os.path.getsize(v):,} bayt)")

        return {
            "extracted": extracted,
            "bin_dir": out_dir,
            "output_files": output_files
        }

    def validate_outputs(self, workspace: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        il2cpp = os.path.join(workspace, "bin", "libil2cpp.so")
        meta = os.path.join(workspace, "bin", "global-metadata.dat")
        if not os.path.exists(il2cpp):
            return False, f"Beklenen çıktı dosyası bulunamadı: {il2cpp}"
        if not os.path.exists(meta):
            return False, f"Beklenen çıktı dosyası bulunamadı: {meta}"
        return True, ""


def main():
    parser = argparse.ArgumentParser(description="Extract native binaries and metadata from APKs.")
    parser.add_argument("--apk", nargs="+", required=True, help="Path(s) to APK file(s)")
    parser.add_argument("--out", required=True, help="Destination directory (e.g. workspace/bin)")
    parser.add_argument("--arch", default="arm64-v8a", help="Target architecture (default: arm64-v8a)")
    parser.add_argument("--extra-libs", nargs="*", default=[], help="Optional additional libraries to extract")

    args = parser.parse_args()

    stage = Stage2Extract()
    config = {
        "apks": args.apk,
        "arch": args.arch,
        "extra_libs": args.extra_libs,
    }
    res = stage.run_stage(os.path.dirname(os.path.abspath(args.out)), config)
    if res.status != "success":
        sys.exit(1)


if __name__ == "__main__":
    main()
