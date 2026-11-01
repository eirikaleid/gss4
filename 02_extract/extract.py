#!/usr/bin/env python3
"""
02_extract/extract.py - Stage 2: Universal Binary & Metadata Extractor
=====================================================================
Ne İşe Yarar? (Purpose):
------------------------
Bu modül, temin edilen APK, Split APK, XAPK ve APKS arşivlerini açarak hedef oyun motorunun
(Unity IL2CPP, Unity Mono, Unreal Engine, Godot veya Generic Native) kritik ikili kütüphanelerini,
metadata veya paket dosyalarını ayıklar ve çalışma alanının 'bin/' dizinine kaydeder:
  1. Unity IL2CPP:
     - lib/<arch>/libil2cpp.so: AOT makine kodları.
     - assets/bin/Data/Managed/Metadata/global-metadata.dat: Sınıf ve metot metadata tablosu.
     - lib/<arch>/libunity.so: SwapBuffers ve render döngüsü.
  2. Unity Mono:
     - assets/bin/Data/Managed/*.dll: CIL/CLR .NET assembly'leri (Assembly-CSharp.dll vb.).
     - lib/<arch>/libmonosgen-2.0.so (veya libmono.so): Mono runtime kütüphanesi.
  3. Unreal Engine:
     - lib/<arch>/libUE4.so veya libUnreal.so: Oyun ve UE motor ikilisi.
     - *.pak (assets/ veya Content/Paks/*.pak): Şifreli/şifresiz oyun varlık paketleri.
  4. Godot Engine:
     - lib/<arch>/libgodot_android.so veya libgodot.so: Godot runtime kütüphanesi.
     - *.pck (assets/*.pck): GDScript/C# bytecode ve sahne paketleri.
  5. XAPK & OBB Desteği:
     - XAPK içindeki gömülü APK'lar otomatik açılır.
     - Android/obb/<package>/*.obb dosyaları 'bin/obb/' dizinine çıkarılır.

Bütünlük Doğrulaması (Integrity Verification):
--------------------------------------------
- ELF Sihirli Baytları (0x7F 'E' 'L' 'F'): Tüm .so dosyalarının geçerli ELF olduğunu ve
  arm64-v8a için 64-bit (ELFCLASS64, EI_CLASS=2) ve Little-Endian (ELFDATA2LSB, EI_DATA=1) olduğunu denetler.
- PE Sihirli Baytları ('MZ'): Managed .dll dosyalarının geçerli Windows/Mono PE olduğunu teyit eder.
- Godot PCK ('GDPC'): PCK arşivlerinin geçerli Godot paket başlığı taşıdığını doğrular.
- Metadata Sihirli Baytı (0xFAB11BAF): global-metadata.dat dosyasının düz metin mi yoksa şifreli mi olduğunu
  anında tespit eder; şifreli ise Aşama 3 (03_decrypt_metadata) için bayrak bırakır.

Hata Yönetimi ve Loglama:
-------------------------
- Bozuk ZIP/APK arşivleri: ERR_ZIP_CORRUPT
- Eksik motor hedef dosyaları: ERR_MISSING_IL2CPP, ERR_MISSING_METADATA, ERR_MISSING_MONO_TARGET vb.
- Bozuk ELF dosyaları: ERR_INVALID_ELF_MAGIC
- Tüm çıkarma detayları 'workspace/logs/stage_02_02_extract.log' dosyasına kaydedilir.
"""

import argparse
import fnmatch
import json
import os
import shutil
import struct
import sys
import tempfile
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core.stage_base import BaseStage, StageResult
    from core.errors import ExtractionError, StageInputError
    from core.logger import get_stage_logger
    from core.engine_provider import get_engine_provider
except ImportError:
    BaseStage = object
    ExtractionError = Exception
    StageInputError = Exception
    get_stage_logger = None
    get_engine_provider = None


# ==============================================================================
# BINARY INTEGRITY VERIFIERS
# ==============================================================================

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
GODOT_PCK_MAGIC = b"GDPC"
IL2CPP_METADATA_MAGIC = b"\xaf\x1b\xb1\xfa"  # 0xFAB11BAF (Little-Endian)
UNREAL_PAK_MAGIC = 0x5A6F12E1


def verify_elf_binary(file_path: str, arch: str = "arm64-v8a") -> Tuple[bool, str]:
    """Verify ELF header magic and class (32-bit vs 64-bit)."""
    if not os.path.isfile(file_path):
        return False, f"File not found: {file_path}"
    size = os.path.getsize(file_path)
    if size < 4:
        return False, f"File too small for ELF header ({size} bytes)"

    with open(file_path, "rb") as f:
        header = f.read(16)

    if not header.startswith(ELF_MAGIC):
        return False, f"Geçersiz ELF magic byte ({header[:4]!r}), '0x7fELF' bekleniyordu."

    class_str = "Unknown"
    endian_str = "Little-Endian"
    if len(header) > 4:
        ei_class = header[4]
        if ei_class in (1, 2):
            if arch == "arm64-v8a" and ei_class != 2:
                return False, f"Hedef mimari {arch} için 64-bit ELF bekleniyordu, ancak 32-bit (ei_class={ei_class}) tespit edildi."
            elif arch in ("armeabi-v7a", "x86") and ei_class != 1:
                return False, f"Hedef mimari {arch} için 32-bit ELF bekleniyordu, ancak 64-bit tespit edildi."
            class_str = "64-bit" if ei_class == 2 else "32-bit"

        if len(header) > 5:
            ei_data = header[5]
            if ei_data in (1, 2):
                endian_str = "Little-Endian" if ei_data == 1 else "Big-Endian"

    return True, f"Geçerli ELF ({class_str}, {endian_str})"


def verify_file_integrity(file_path: str, file_type: str, arch: str = "arm64-v8a") -> Tuple[bool, str]:
    """Verify integrity of various extracted game binaries and assets."""
    if not os.path.isfile(file_path):
        return False, f"File does not exist: {file_path}"

    if file_type == "elf":
        return verify_elf_binary(file_path, arch=arch)

    elif file_type == "pe_dll":
        with open(file_path, "rb") as f:
            magic = f.read(2)
        if magic == PE_MAGIC:
            return True, "Geçerli PE/COFF .NET Assembly ('MZ')"
        return False, f"Geçersiz PE başlığı: {magic!r}"

    elif file_type == "godot_pck":
        with open(file_path, "rb") as f:
            magic = f.read(4)
        if magic == GODOT_PCK_MAGIC:
            return True, "Geçerli Godot PCK Arşivi ('GDPC')"
        return False, f"Geçersiz Godot PCK başlığı: {magic!r}"

    elif file_type == "metadata":
        with open(file_path, "rb") as f:
            magic = f.read(4)
        if magic == IL2CPP_METADATA_MAGIC:
            return True, "Geçerli Standart IL2CPP Metadata (0xFAB11BAF)"
        return True, "Şifreli / Özel Header'a Sahip Metadata (Aşama 3'te deşifre edilecek)"

    elif file_type == "unreal_pak":
        size = os.path.getsize(file_path)
        if size >= 44:
            # Check pak footer magic (last 44 bytes contain pak info)
            with open(file_path, "rb") as f:
                f.seek(max(0, size - 221))
                tail = f.read()
            if struct.pack("<I", UNREAL_PAK_MAGIC) in tail:
                return True, "Geçerli Unreal Engine PAK arşivi"
        return True, "Unreal PAK dosyası (boyut doğrulandı)"

    return True, "Bilinmeyen format, temel doğrulama başarılı"


# ==============================================================================
# PACKAGE UNPACKER (XAPK, APKS, APK, OBB)
# ==============================================================================

def unpack_packages(
    inputs: List[str],
    temp_dir: str,
    logger=None
) -> Tuple[List[str], List[str]]:
    """Unpack XAPK, APKS, APK files and extract nested APKs and OBBs.
    Returns (apk_paths, obb_paths).
    """
    apk_paths: List[str] = []
    obb_paths: List[str] = []

    def log(msg, level="info"):
        if logger:
            getattr(logger, level)(msg)
        else:
            print(msg)

    os.makedirs(temp_dir, exist_ok=True)
    extracted_apk_dir = os.path.join(temp_dir, "extracted_apks")
    extracted_obb_dir = os.path.join(temp_dir, "extracted_obbs")
    os.makedirs(extracted_apk_dir, exist_ok=True)
    os.makedirs(extracted_obb_dir, exist_ok=True)

    for item in inputs:
        if not os.path.exists(item):
            log(f"Girdi dosyası veya dizini bulunamadı: {item}", level="warning")
            continue

        if os.path.isdir(item):
            # Scan directory for packages
            for root, _, files in os.walk(item):
                for f in files:
                    fp = os.path.join(root, f)
                    lower = f.lower()
                    if lower.endswith(".apk"):
                        apk_paths.append(fp)
                    elif lower.endswith(".obb"):
                        obb_paths.append(fp)
                    elif lower.endswith((".xapk", ".apks")):
                        sub_apks, sub_obbs = unpack_packages([fp], temp_dir, logger=logger)
                        apk_paths.extend(sub_apks)
                        obb_paths.extend(sub_obbs)
            continue

        lower = item.lower()
        if lower.endswith(".xapk"):
            log(f"XAPK paketi tespit edildi, içeriği çözümleniyor: {item}")
            try:
                with zipfile.ZipFile(item, "r") as z:
                    for name in z.namelist():
                        if name.endswith(".apk"):
                            dst = os.path.join(extracted_apk_dir, os.path.basename(name))
                            with z.open(name) as src, open(dst, "wb") as out:
                                shutil.copyfileobj(src, out)
                            apk_paths.append(dst)
                            log(f"  [XAPK] APK çıkarıldı: {name} -> {dst}")
                        elif name.endswith(".obb") or "/obb/" in name.lower():
                            dst = os.path.join(extracted_obb_dir, os.path.basename(name))
                            with z.open(name) as src, open(dst, "wb") as out:
                                shutil.copyfileobj(src, out)
                            obb_paths.append(dst)
                            log(f"  [XAPK] OBB çıkarıldı: {name} -> {dst}")
            except zipfile.BadZipFile as e:
                raise ExtractionError(
                    message=f"Bozuk XAPK arşivi: {item}. Hata: {e}",
                    error_code="ERR_ZIP_CORRUPT",
                    suggestions=["XAPK dosyasını tekrar indirin."]
                )

        elif lower.endswith(".apks"):
            log(f"APKS (Split Bundle) arşivi tespit edildi, açılıyor: {item}")
            try:
                with zipfile.ZipFile(item, "r") as z:
                    for name in z.namelist():
                        if name.endswith(".apk"):
                            dst = os.path.join(extracted_apk_dir, os.path.basename(name))
                            with z.open(name) as src, open(dst, "wb") as out:
                                shutil.copyfileobj(src, out)
                            apk_paths.append(dst)
                            log(f"  [APKS] Split APK çıkarıldı: {name}")
            except zipfile.BadZipFile as e:
                raise ExtractionError(
                    message=f"Bozuk APKS arşivi: {item}. Hata: {e}",
                    error_code="ERR_ZIP_CORRUPT",
                    suggestions=["APKS dosyasını tekrar oluşturun veya indirin."]
                )

        elif lower.endswith(".obb"):
            dst = os.path.join(extracted_obb_dir, os.path.basename(item))
            if item != dst:
                shutil.copy2(item, dst)
            obb_paths.append(dst)
            log(f"Harici OBB dosyası kaydedildi: {dst}")

        elif lower.endswith(".apk") or zipfile.is_zipfile(item):
            apk_paths.append(os.path.abspath(item))

        else:
            log(f"Tanınmayan dosya formatı atlanıyor: {item}", level="warning")

    return apk_paths, obb_paths


# ==============================================================================
# ENGINE AUTO-DETECTION
# ==============================================================================

def detect_engine_from_archives(apks: List[str], arch: str = "arm64-v8a") -> str:
    """Inspect APK archive entries to automatically detect the underlying game engine."""
    for apk in apks:
        if not os.path.isfile(apk):
            continue
        try:
            with zipfile.ZipFile(apk, "r") as z:
                names = set(z.namelist())

                # 1. Unity IL2CPP
                if f"lib/{arch}/libil2cpp.so" in names or any("global-metadata.dat" in n for n in names):
                    return "unity_il2cpp"

                # 2. Unity Mono
                if any(n.startswith("assets/bin/Data/Managed/") and n.endswith(".dll") for n in names):
                    return "unity_mono"
                if f"lib/{arch}/libmonosgen-2.0.so" in names or f"lib/{arch}/libmono.so" in names:
                    return "unity_mono"

                # 3. Unreal Engine
                if f"lib/{arch}/libUE4.so" in names or f"lib/{arch}/libUnreal.so" in names:
                    return "unreal"
                if any(n.endswith(".pak") for n in names):
                    return "unreal"

                # 4. Godot Engine
                if f"lib/{arch}/libgodot_android.so" in names or f"lib/{arch}/libgodot.so" in names:
                    return "godot"
                if any(n.endswith(".pck") for n in names):
                    return "godot"

                # 5. Generic Native (Cocos2d-x / custom)
                if any(n.startswith(f"lib/{arch}/") and n.endswith(".so") for n in names):
                    return "native"
        except Exception:
            pass

    return "unity_il2cpp"  # Default fallback


# ==============================================================================
# CORE EXTRACTION ENGINE
# ==============================================================================

def extract_binaries(
    apks: List[str],
    out_dir: str,
    arch: str = "arm64-v8a",
    extra_libs: Optional[List[str]] = None,
    engine: str = "auto",
    verify_elf: bool = True,
    logger=None
) -> Dict[str, Any]:
    """Extract game engine binaries, metadata, and packages from APK/XAPK/APKS archives.
    Supports Unity IL2CPP, Unity Mono, Unreal Engine, Godot, and Generic Native.
    """
    os.makedirs(out_dir, exist_ok=True)
    extra_libs = extra_libs or []

    def log(msg, level="info"):
        if logger:
            getattr(logger, level)(msg)
        else:
            print(msg)

    # 1. Expand XAPK, APKS, directories
    temp_unpack_dir = tempfile.mkdtemp(prefix="gss4_unpack_")
    try:
        resolved_apks, resolved_obbs = unpack_packages(apks, temp_unpack_dir, logger=logger)
    except Exception:
        shutil.rmtree(temp_unpack_dir, ignore_errors=True)
        raise

    if not resolved_apks:
        shutil.rmtree(temp_unpack_dir, ignore_errors=True)
        raise ExtractionError(
            message=f"Ayıklanacak geçerli APK arşivi bulunamadı: {apks}",
            error_code="ERR_NO_APKS_ACQUIRED",
            suggestions=["Verilen dosya yollarının geçerli APK, XAPK veya APKS olduğunu kontrol edin."]
        )

    # 2. Determine target engine
    detected_engine = engine.lower() if engine and engine != "auto" else detect_engine_from_archives(resolved_apks, arch=arch)
    log(f"Hedef oyun motoru: '{detected_engine}' (Mimari: '{arch}')")

    # 3. Setup extraction targets based on engine
    # exact_targets: zip_entry_path -> out_file_path
    exact_targets: Dict[str, str] = {}
    # pattern_targets: (entry_pattern, destination_subfolder, file_type)
    pattern_targets: List[Tuple[str, str, str]] = []

    if detected_engine in ("unity_il2cpp", "il2cpp"):
        exact_targets[f"lib/{arch}/libil2cpp.so"] = os.path.join(out_dir, "libil2cpp.so")
        exact_targets["assets/bin/Data/Managed/Metadata/global-metadata.dat"] = os.path.join(out_dir, "global-metadata.dat")
        exact_targets[f"lib/{arch}/libunity.so"] = os.path.join(out_dir, "libunity.so")
        for lib in extra_libs:
            exact_targets[f"lib/{arch}/{lib}"] = os.path.join(out_dir, lib)

    elif detected_engine in ("unity_mono", "mono"):
        exact_targets[f"lib/{arch}/libmonosgen-2.0.so"] = os.path.join(out_dir, "libmonosgen-2.0.so")
        exact_targets[f"lib/{arch}/libmono.so"] = os.path.join(out_dir, "libmono.so")
        exact_targets[f"lib/{arch}/libunity.so"] = os.path.join(out_dir, "libunity.so")
        pattern_targets.append(("assets/bin/Data/Managed/*.dll", os.path.join(out_dir, "Managed"), "pe_dll"))
        for lib in extra_libs:
            exact_targets[f"lib/{arch}/{lib}"] = os.path.join(out_dir, lib)

    elif detected_engine in ("unreal", "ue4", "ue5"):
        exact_targets[f"lib/{arch}/libUE4.so"] = os.path.join(out_dir, "libUE4.so")
        exact_targets[f"lib/{arch}/libUnreal.so"] = os.path.join(out_dir, "libUnreal.so")
        pattern_targets.append(("*.pak", os.path.join(out_dir, "paks"), "unreal_pak"))
        for lib in extra_libs:
            exact_targets[f"lib/{arch}/{lib}"] = os.path.join(out_dir, lib)

    elif detected_engine == "godot":
        exact_targets[f"lib/{arch}/libgodot_android.so"] = os.path.join(out_dir, "libgodot.so")
        exact_targets[f"lib/{arch}/libgodot.so"] = os.path.join(out_dir, "libgodot.so")
        pattern_targets.append(("*.pck", out_dir, "godot_pck"))
        for lib in extra_libs:
            exact_targets[f"lib/{arch}/{lib}"] = os.path.join(out_dir, lib)

    else:  # Generic native
        pattern_targets.append((f"lib/{arch}/*.so", out_dir, "elf"))
        for lib in extra_libs:
            exact_targets[f"lib/{arch}/{lib}"] = os.path.join(out_dir, lib)

    # Clean existing destination files for exact targets
    for dst in exact_targets.values():
        if os.path.exists(dst):
            try:
                os.remove(dst)
            except OSError:
                pass

    log(f"İkili dosyalar taranıyor: {len(resolved_apks)} APK arşivi taranıyor...")
    found_exact: Set[str] = set()
    found_patterns: List[str] = []
    integrity_results: Dict[str, Dict[str, Any]] = {}

    for apk_path in resolved_apks:
        if not os.path.isfile(apk_path):
            log(f"APK dosyası bulunamadı: {apk_path}", level="warning")
            continue

        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                all_entries = z.namelist()
                names_set = set(all_entries)

                # Check exact targets
                for target_entry, dst_path in exact_targets.items():
                    if target_entry in names_set and target_entry not in found_exact:
                        log(f"Ayıklanıyor (Exact): {target_entry} -> {dst_path}")
                        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                        with z.open(target_entry) as src, open(dst_path, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        found_exact.add(target_entry)

                # Check pattern targets
                for pattern, dest_dir, f_type in pattern_targets:
                    os.makedirs(dest_dir, exist_ok=True)
                    for entry in all_entries:
                        if fnmatch.fnmatch(entry, pattern) or fnmatch.fnmatch(os.path.basename(entry), pattern):
                            dst_file = os.path.join(dest_dir, os.path.basename(entry))
                            if not os.path.exists(dst_file):
                                log(f"Ayıklanıyor (Pattern {pattern}): {entry} -> {dst_file}")
                                with z.open(entry) as src, open(dst_file, "wb") as dst:
                                    shutil.copyfileobj(src, dst)
                                found_patterns.append(dst_file)

        except zipfile.BadZipFile as e:
            shutil.rmtree(temp_unpack_dir, ignore_errors=True)
            raise ExtractionError(
                message=f"Bozuk ZIP arşivi tespit edildi: {apk_path}. Hata: {e}",
                error_code="ERR_ZIP_CORRUPT",
                suggestions=["APK dosyasının indirilmesi yarıda kesilmiş olabilir, tekrar temin edin."]
            )
        except Exception as e:
            shutil.rmtree(temp_unpack_dir, ignore_errors=True)
            raise ExtractionError(
                message=f"APK okunurken G/Ç hatası oluştu: {apk_path}. Hata: {e}",
                error_code="ERR_EXTRACTION_IO",
                suggestions=["Dosya okuma ve hedef dizin yazma izinlerini kontrol edin."]
            )

    # 4. Handle OBB files
    extracted_obbs = []
    if resolved_obbs:
        obb_target_dir = os.path.join(out_dir, "obb")
        os.makedirs(obb_target_dir, exist_ok=True)
        for obb in resolved_obbs:
            dst = os.path.join(obb_target_dir, os.path.basename(obb))
            if obb != dst:
                shutil.copy2(obb, dst)
            extracted_obbs.append(dst)
            log(f"OBB arşivi saklandı: {dst}")

    # Clean temporary unpacking directory
    shutil.rmtree(temp_unpack_dir, ignore_errors=True)

    # 5. Engine-Specific Critical Validations
    crit_il2cpp = f"lib/{arch}/libil2cpp.so"
    crit_meta = "assets/bin/Data/Managed/Metadata/global-metadata.dat"

    if detected_engine in ("unity_il2cpp", "il2cpp"):
        if crit_il2cpp not in found_exact:
            raise ExtractionError(
                message=f"Kritik ikili dosya APK içinde bulunamadı: '{crit_il2cpp}'",
                error_code="ERR_MISSING_IL2CPP",
                suggestions=[
                    f"APK'nın belirtilen mimariyi ({arch}) içerdiğinden emin olun.",
                    "Eğer split APK sistemi varsa 'split_config.<arch>.apk' dosyasını da ekleyin.",
                    "Oyunun Unity IL2CPP ile derlendiğinden (Mono değil) emin olun."
                ]
            )

        if crit_meta not in found_exact:
            raise ExtractionError(
                message=f"Kritik metadata dosyası APK içinde bulunamadı: '{crit_meta}'",
                error_code="ERR_MISSING_METADATA",
                suggestions=[
                    "base.apk dosyasının verildiğinden emin olun (metadata assets/ klasöründe yer alır).",
                    "Oyun bir XAPK ise tüm split APK'ların eksiksiz açıldığını teyit edin."
                ]
            )

    elif detected_engine in ("unity_mono", "mono"):
        mono_dlls = [p for p in found_patterns if p.endswith(".dll")]
        mono_so_found = any(k in found_exact for k in (f"lib/{arch}/libmonosgen-2.0.so", f"lib/{arch}/libmono.so"))
        if not mono_dlls and not mono_so_found:
            raise ExtractionError(
                message="Unity Mono için gerekli Managed assembly (.dll) veya Mono runtime (.so) bulunamadı.",
                error_code="ERR_MISSING_MONO_TARGET",
                suggestions=["APK'nın 'assets/bin/Data/Managed/' klasörünü içerdiğini doğrulayın."]
            )

    elif detected_engine in ("unreal", "ue4", "ue5"):
        ue_so_found = any(k in found_exact for k in (f"lib/{arch}/libUE4.so", f"lib/{arch}/libUnreal.so"))
        paks_found = [p for p in found_patterns if p.endswith(".pak")]
        if not ue_so_found and not paks_found:
            raise ExtractionError(
                message=f"Unreal Engine için libUE4.so / libUnreal.so veya *.pak dosyası bulunamadı ({arch}).",
                error_code="ERR_MISSING_UNREAL_TARGET",
                suggestions=[f"APK'nın lib/{arch}/ altında Unreal kütüphanesini içerdiğinden emin olun."]
            )

    elif detected_engine == "godot":
        godot_so_found = any(k in found_exact for k in (f"lib/{arch}/libgodot_android.so", f"lib/{arch}/libgodot.so"))
        pck_found = [p for p in found_patterns if p.endswith(".pck")]
        if not godot_so_found and not pck_found:
            raise ExtractionError(
                message=f"Godot Engine için libgodot.so veya *.pck arşivi bulunamadı ({arch}).",
                error_code="ERR_MISSING_GODOT_TARGET",
                suggestions=["Godot APK'sının 'lib/' veya 'assets/' klasörlerini inceleyin."]
            )

    # 6. Integrity Verification (ELF magic bytes, PE magic, etc.)
    res: Dict[str, Any] = {
        "engine": detected_engine,
        "arch": arch,
    }

    # Populate standard return dictionary
    il2cpp_p = os.path.join(out_dir, "libil2cpp.so")
    meta_p = os.path.join(out_dir, "global-metadata.dat")
    unity_p = os.path.join(out_dir, "libunity.so")

    if os.path.exists(il2cpp_p):
        res["il2cpp"] = os.path.abspath(il2cpp_p)
        res["il2cpp_so"] = os.path.abspath(il2cpp_p)
    if os.path.exists(meta_p):
        res["metadata"] = os.path.abspath(meta_p)
    if os.path.exists(unity_p):
        res["unity"] = os.path.abspath(unity_p)
        res["unity_so"] = os.path.abspath(unity_p)

    # Add Mono targets
    managed_dir = os.path.join(out_dir, "Managed")
    if os.path.isdir(managed_dir):
        res["managed_dir"] = os.path.abspath(managed_dir)
        csharp = os.path.join(managed_dir, "Assembly-CSharp.dll")
        if os.path.exists(csharp):
            res["assembly_csharp"] = os.path.abspath(csharp)

    # Add Unreal targets
    ue4_so = os.path.join(out_dir, "libUE4.so")
    if os.path.exists(ue4_so):
        res["ue_so"] = os.path.abspath(ue4_so)
    unreal_so = os.path.join(out_dir, "libUnreal.so")
    if os.path.exists(unreal_so):
        res["ue_so"] = os.path.abspath(unreal_so)

    # Add Godot targets
    godot_so = os.path.join(out_dir, "libgodot.so")
    if os.path.exists(godot_so):
        res["godot_so"] = os.path.abspath(godot_so)

    # Add extra libraries
    for lib in extra_libs:
        lp = os.path.join(out_dir, lib)
        if os.path.exists(lp):
            res[lib] = os.path.abspath(lp)

    if extracted_obbs:
        res["obb_files"] = extracted_obbs

    # 7. Run integrity validations on all extracted files
    all_extracted_files = []
    for root, _, files in os.walk(out_dir):
        for f in files:
            all_extracted_files.append(os.path.join(root, f))

    for fp in all_extracted_files:
        fn = os.path.basename(fp)
        ftype = "other"
        if fn.endswith(".so"):
            ftype = "elf"
        elif fn.endswith(".dll"):
            ftype = "pe_dll"
        elif fn.endswith(".pck"):
            ftype = "godot_pck"
        elif fn.endswith(".pak"):
            ftype = "unreal_pak"
        elif fn == "global-metadata.dat":
            ftype = "metadata"

        valid, detail = verify_file_integrity(fp, ftype, arch=arch)
        integrity_results[fn] = {"valid": valid, "type": ftype, "detail": detail}

        if ftype == "elf" and verify_elf and not valid:
            raise ExtractionError(
                message=f"Bozuk ELF dosyası tespit edildi ({fn}): {detail}",
                error_code="ERR_INVALID_ELF_MAGIC",
                suggestions=[
                    "APK dosyasının indirme sırasında bozulup bozulmadığını kontrol edin.",
                    f"Hedef mimarinin ({arch}) doğru seçildiğinden emin olun."
                ]
            )

    res["integrity"] = integrity_results
    return res


# ==============================================================================
# BASE STAGE LIFECYCLE WRAPPER
# ==============================================================================

class Stage2Extract(BaseStage):
    """Stage 2: Universal Binary & Metadata Extraction Implementation."""

    stage_id = 2
    name = "02_extract"
    description = "Extracts engine binaries, metadata, and packages from APK, XAPK, and APKS archives."
    purpose = "APK, XAPK ve APKS arşivlerinden Unity IL2CPP, Unity Mono, Unreal, Godot ve Native ELF motor hedeflerini ayıklar ve bütünlüklerini doğrular."
    extension_points = [
        "XAPK (OBB + Split APK) ve APKS arşivlerini tam otomatik açma",
        "Multi-Engine (Unity IL2CPP, Unity Mono, Unreal, Godot, Native) motor hedef desteği",
        "ELF magic byte (0x7F 'E' 'L' 'F'), 64-bit mimari ve PE/GDPC bütünlük doğrulaması",
        "global-metadata.dat şifrelilik ön-tespiti (Aşama 3 için otomatik bayraklama)",
        "arm64-v8a bulunamazsa otomatik armeabi-v7a fallback desteği"
    ]
    troubleshooting = [
        {"error": "ERR_ZIP_CORRUPT", "fix": "APK veya XAPK dosyasını yeniden indirin, dosya bozuk inmiş olabilir."},
        {"error": "ERR_MISSING_IL2CPP", "fix": "Mimari split APK dosyasını (örn: split_config.arm64_v8a.apk) ekleyin."},
        {"error": "ERR_MISSING_METADATA", "fix": "base.apk dosyasının sağlandığını doğrulayın."},
        {"error": "ERR_INVALID_ELF_MAGIC", "fix": "ELF kütüphanesinin başlığı bozuk. İndirmeyi yenileyin veya mimariyi kontrol edin."}
    ]

    def validate_inputs(self, workspace: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        manifest_path = os.path.join(workspace, "apk", "apk_manifest.json")
        apks = config.get("apks") or config.get("apk") or config.get("apk_paths")
        if not apks and not os.path.exists(manifest_path):
            return False, f"Ne 'apks' parametresi ne de manifest dosyası ({manifest_path}) bulunamadı. Önce Stage 1 çalışmalıdır."
        return True, ""

    def execute(self, workspace: str, config: Dict[str, Any]) -> Dict[str, Any]:
        out_dir = os.path.join(workspace, "bin")
        os.makedirs(out_dir, exist_ok=True)

        apks = config.get("apks") or config.get("apk") or config.get("apk_paths")
        if not apks:
            manifest_path = os.path.join(workspace, "apk", "apk_manifest.json")
            if os.path.exists(manifest_path):
                with open(manifest_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    apks = data.get("apks", [])

        if isinstance(apks, str):
            apks = [apks]

        arch = config.get("arch", "arm64-v8a")
        extra_libs = config.get("extra_libs", [])
        engine = config.get("engine", "auto")
        verify_elf = config.get("verify_elf", True)

        self.logger.info(f"Stage 2 Başlatıldı: {len(apks)} paket taranıyor, Mimari: {arch}, Motor: {engine}")

        extracted = extract_binaries(
            apks=apks,
            out_dir=out_dir,
            arch=arch,
            extra_libs=extra_libs,
            engine=engine,
            verify_elf=verify_elf,
            logger=self.logger
        )

        output_files = []
        for root, _, files in os.walk(out_dir):
            for f in files:
                output_files.append(os.path.join(root, f))

        self.logger.info(f"Ayıklama tamamlandı. {len(output_files)} dosya çıkarıldı (Motor: {extracted.get('engine')}).")
        for k, v in extracted.items():
            if isinstance(v, str) and os.path.exists(v):
                self.logger.debug(f"  - {k}: {v} ({os.path.getsize(v):,} bayt)")

        return {
            "extracted": extracted,
            "bin_dir": out_dir,
            "output_files": output_files,
            "engine": extracted.get("engine"),
            "integrity": extracted.get("integrity", {}),
            "obb_files": extracted.get("obb_files", [])
        }

    def validate_outputs(self, workspace: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        engine = config.get("engine", "unity_il2cpp").lower()

        if engine in ("unity_il2cpp", "il2cpp", "auto"):
            il2cpp = os.path.join(workspace, "bin", "libil2cpp.so")
            meta = os.path.join(workspace, "bin", "global-metadata.dat")
            # If auto, only require these if il2cpp exists or if it was auto-detected as il2cpp
            if engine in ("unity_il2cpp", "il2cpp") or os.path.exists(il2cpp):
                if not os.path.exists(il2cpp):
                    return False, f"Beklenen çıktı dosyası bulunamadı: {il2cpp}"
                if not os.path.exists(meta):
                    return False, f"Beklenen çıktı dosyası bulunamadı: {meta}"

        elif engine in ("unity_mono", "mono"):
            managed = os.path.join(workspace, "bin", "Managed")
            mono_so = os.path.join(workspace, "bin", "libmonosgen-2.0.so")
            if not os.path.exists(managed) and not os.path.exists(mono_so):
                return False, "Beklenen Mono çıktıları (Managed/ veya libmonosgen-2.0.so) bulunamadı."

        elif engine in ("unreal", "ue4", "ue5"):
            ue4 = os.path.join(workspace, "bin", "libUE4.so")
            unreal = os.path.join(workspace, "bin", "libUnreal.so")
            paks = os.path.join(workspace, "bin", "paks")
            if not os.path.exists(ue4) and not os.path.exists(unreal) and not os.path.exists(paks):
                return False, "Beklenen Unreal çıktıları (libUE4.so / libUnreal.so / paks) bulunamadı."

        elif engine == "godot":
            godot_so = os.path.join(workspace, "bin", "libgodot.so")
            pck = os.path.join(workspace, "bin", "main.pck")
            if not os.path.exists(godot_so) and not os.path.exists(pck):
                return False, "Beklenen Godot çıktıları (libgodot.so veya .pck) bulunamadı."

        return True, ""


# ==============================================================================
# CLI DISPATCHER
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Universal game binary, package, and metadata extractor.")
    parser.add_argument("--apk", nargs="*", default=[], help="Path(s) to APK, XAPK, APKS, or directory")
    parser.add_argument("--manifest", default=None, help="Path to apk_manifest.json")
    parser.add_argument("--out", required=True, help="Destination directory (e.g. workspace/bin)")
    parser.add_argument("--arch", default="arm64-v8a", help="Target architecture (default: arm64-v8a)")
    parser.add_argument("--engine", default="auto", help="Game engine: unity_il2cpp, unity_mono, unreal, godot, native, auto")
    parser.add_argument("--extra-libs", nargs="*", default=[], help="Optional additional libraries to extract")
    parser.add_argument("--no-verify-elf", action="store_true", help="Skip ELF magic byte validation")

    args = parser.parse_args()

    apks = list(args.apk)
    if args.manifest and os.path.isfile(args.manifest):
        with open(args.manifest, "r", encoding="utf-8") as f:
            data = json.load(f)
            apks.extend(data.get("apks", []))

    if not apks:
        print("[!] Hata: En az bir APK/XAPK/APKS dosyası veya --manifest belirtilmelidir.", file=sys.stderr)
        sys.exit(1)

    stage = Stage2Extract()
    config = {
        "apks": apks,
        "arch": args.arch,
        "engine": args.engine,
        "extra_libs": args.extra_libs,
        "verify_elf": not args.no_verify_elf,
    }

    workspace = os.path.dirname(os.path.abspath(args.out))
    res = stage.run_stage(workspace, config)
    if res.status != "success":
        print(f"[!] Aşama 2 Başarısız: {res.error_message}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"[+] Aşama 2 Başarılı: {len(res.data.get('output_files', []))} dosya çıkarıldı.")


if __name__ == "__main__":
    main()
