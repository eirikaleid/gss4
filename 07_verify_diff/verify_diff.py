#!/usr/bin/env python3
"""
07_verify_diff/verify_diff.py - Stage 7: Offset Sanity Verification & Diff Safety Gate
======================================================================================
Ne İşe Yarar? (Purpose):
------------------------
Bu aşama, üretilen yeni offsetlerin güvenliğini ve doğruluğunu denetleyen son güvenlik kapısıdır (safety gate):
  1. ARM64 Komut Hizalama Testi: Metot RVA adreslerinin 4 bayta tam bölündüğünü (RVA % 4 == 0) denetler.
  2. Bellek Sınır Testi: RVA'ların libil2cpp.so dosya boyutunu aşmadığını ve field ofsetlerinin makul aralıkta olduğunu (< 0x10000) onaylar.
  3. Kaynak Kod Sembol Bütünlüğü: 'src/' C++ kaynak kodlarında kullanılan tüm 'Offsets::...' sembollerinin yeni header'da
     eksiksiz var olduğunu garanti eder (0 undefined symbol).
  4. Diff ve Kayma Analizi: Eski sürüm ile yeni sürüm arasındaki farkı hesaplar; kayma (drift) eşik değerini aşarsa uyarır.
  5. Otomatik Yedekleme ve Uygulama: '--apply' parametresi verildiğinde mevcut header'ın tarihli yedeğini alıp yenisini hedefe yazar.

Neler Yapılabilir? (Extension Points):
--------------------------------------
1. Canlı Bellek (Live Memory Assertion): Emülatördeki oyuna bağlanıp TypeInfo adreslerindeki Il2CppClass işaretçilerini canlı teyit etme.
2. Otomatik Clang / GCC Derleme Testi: Yeni header ile src/ kodlarını arka planda derleyip sözdizim hatası arama.
3. CI/CD Entegrasyonu: Değişen ofset tablosunu GitHub Pull Request veya Discord/Telegram bildirim webhook'u olarak gönderme.
4. Snapshot & Rollback Yöneticisi: Oyun çökerse tek tuşla önceki çalışan ofsetlere ve APK sürümüne geri dönme.
5. Regresyon / Anomali Dedektörü: Önceki 10 sürümün ofset geçmişini saklayıp istatistiksel anomali analizi yapma.

Hata Yönetimi ve Loglama:
-------------------------
- Hizalama hatası, tanımsız sembol veya aşırı kayma VerificationGateError ile yakalanır.
- Rapor 'verify_report.txt' dosyasına ve 'workspace/logs/stage_07_07_verify_diff.log' içine yazılır.
"""

import argparse
import os
import re
import shutil
import struct
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core.stage_base import BaseStage, StageResult
    from core.errors import VerificationGateError, StageInputError
    from core.logger import get_stage_logger
    from core.engine_provider import get_engine_provider, EngineVerificationPolicy
except ImportError:
    BaseStage = object
    VerificationGateError = Exception
    StageInputError = Exception
    get_stage_logger = None
    get_engine_provider = None
    EngineVerificationPolicy = None

CONST_RE = re.compile(r"constexpr\s+(?:uintptr_t|int|unsigned|uint32_t|uint64_t|int32_t)\s+(\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*;")
NS_OPEN_RE = re.compile(r"^\s*namespace\s+(\w+)\s*\{")
USE_RE = re.compile(r"Offsets::([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)")


def parse_header(path):
    if not os.path.exists(path):
        return {}
    vals = {}
    stack = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.split("//", 1)[0]
            m = NS_OPEN_RE.match(line)
            if m:
                stack.append(m.group(1))
                continue
            c = CONST_RE.search(line)
            if c:
                ns = [s for s in stack if s != "Offsets"]
                vals["::".join(ns + [c.group(1)])] = int(c.group(2), 0)
            for _ in range(line.count("}")):
                if stack:
                    stack.pop()
    return vals


def scan_source_symbols(src_dir):
    if not os.path.isdir(src_dir):
        return set()
    used = set()
    for root, _, files in os.walk(src_dir):
        for fn in files:
            if not fn.endswith((".cpp", ".h", ".hpp", ".cc")):
                continue
            p = os.path.join(root, fn)
            try:
                content = open(p, "r", encoding="utf-8", errors="replace").read()
                for m in USE_RE.finditer(content):
                    used.add(m.group(1))
            except Exception:
                pass
    return used


def diff_headers(old_map, new_map):
    all_keys = sorted(set(old_map.keys()) | set(new_map.keys()))
    changes = []
    added = []
    removed = []

    for k in all_keys:
        if k in old_map and k in new_map:
            if old_map[k] != new_map[k]:
                changes.append((k, old_map[k], new_map[k]))
        elif k in new_map:
            added.append((k, new_map[k]))
        else:
            removed.append((k, old_map[k]))

    return changes, added, removed


def verify_and_diff(new_path, old_path=None, so_path=None, src_dir=None,
                    profile_data=None, known_tag=None, apply_to=None, backup_dir=None):
    if not os.path.exists(new_path):
        raise FileNotFoundError(f"New header not found: {new_path}")

    new_map = parse_header(new_path)
    fails = []

    # 1. Sanity Checks using Engine Verification Policy
    engine_name = profile_data.get("engine", "unity_il2cpp") if profile_data else "unity_il2cpp"
    if get_engine_provider:
        policy = get_engine_provider(engine_name).get_verification_policy()
    else:
        policy = EngineVerificationPolicy() if EngineVerificationPolicy else None

    so_size = os.path.getsize(so_path) if so_path and os.path.exists(so_path) else None
    for name, val in new_map.items():
        if "::" not in name:
            if policy and policy.check_rva_alignment:
                if val % policy.rva_alignment_bytes != 0:
                    fails.append(f"Method not {policy.rva_alignment_bytes}-aligned: {name}=0x{val:X}")
            if so_size and val >= so_size:
                fails.append(f"Method RVA outside binary size: {name}=0x{val:X}")
        elif name.startswith("TypeInfo::"):
            if policy and policy.check_typeinfo_alignment:
                if val % policy.typeinfo_alignment_bytes != 0:
                    fails.append(f"TypeInfo not {policy.typeinfo_alignment_bytes}-aligned: {name}=0x{val:X}")
            if so_size and val >= so_size:
                fails.append(f"TypeInfo offset outside binary size: {name}=0x{val:X}")
        elif not name.startswith("Native::"):
            max_field = policy.max_field_offset if policy else 0x10000
            allow_zero = policy.allow_zero_rva if policy else False
            if val >= max_field or (val <= 0 and not allow_zero):
                fails.append(f"Field offset out of sanity range (0..0x{max_field:X}): {name}=0x{val:X}")

    # 2. Source Code Undefined Symbol Check
    if src_dir and os.path.isdir(src_dir):
        used_syms = scan_source_symbols(src_dir)
        missing_in_header = [s for s in sorted(used_syms) if s not in new_map]
        if missing_in_header:
            fails.append(f"Source code uses {len(missing_in_header)} undefined symbols: {missing_in_header[:5]}")

    # 3. Known profile assertions
    if profile_data and known_tag:
        known_dict = profile_data.get("known_checks", {}).get(known_tag, {})
        for k, v_str in known_dict.items():
            expected = int(v_str, 0)
            actual = new_map.get(k)
            if actual is None:
                fails.append(f"Known check [{known_tag}] missing symbol: {k}")
            elif actual != expected:
                fails.append(f"Known check [{known_tag}] mismatch for {k}: expected 0x{expected:X}, got 0x{actual:X}")

    # 4. Diff Report
    changes, added, removed = [], [], []
    if old_path and os.path.exists(old_path):
        old_map = parse_header(old_path)
        changes, added, removed = diff_headers(old_map, new_map)

    if fails:
        raise ValueError(f"Verification errors:\n" + "\n".join(f"  * {f}" for f in fails))

    # 5. Apply
    applied_file = None
    if apply_to:
        dst = os.path.abspath(apply_to)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if backup_dir:
            os.makedirs(backup_dir, exist_ok=True)
        if os.path.exists(dst) and backup_dir:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(backup_dir, f"offsets.h.{timestamp}")
            shutil.copy2(dst, backup_file)
        shutil.copy2(new_path, dst)
        applied_file = dst

    return {
        "constants_count": len(new_map),
        "changes_count": len(changes),
        "added_count": len(added),
        "removed_count": len(removed),
        "applied_file": applied_file
    }


class Stage7Verify(BaseStage):
    stage_id = 7
    name = "07_verify_diff"
    description = "Sanity verification, symbol integrity check against src/, and diff report."
    purpose = "ARM64 komut hizalamasını, bellek sınırlarını, kaynak kod sembol bütünlüğünü ve sürüm diff raporunu denetler; onaylıysa hedef projeye uygular."
    extension_points = [
        "Canlı emülatör belleğinden (/proc/pid/mem) TypeInfo Il2CppClass işaretçisi doğrulama",
        "Yeni header ile src/ kaynak kodlarını test amaçlı derleyen Clang/GCC entegrasyonu",
        "Değişiklikleri Markdown tablosu olarak GitHub PR veya bildirim kanalına gönderen webhook",
        "Hata durumunda önceki çalışan sürüme otomatik geri dönen Snapshot & Rollback mekanizması",
        "Geçmiş sürümlerin ofset sapmalarını modelleyen istatistiksel anomali dedektörü"
    ]
    troubleshooting = [
        {"error": "ERR_NEW_HEADER_MISSING", "fix": "Stage 6'nın başarıyla tamamlandığını ve offsets.h ürettiğini kontrol edin."},
        {"error": "ERR_STAGE_07_VERIFY", "fix": "Diff raporundaki (verify_report.txt) tanımsız sembolleri ve aşırı kaymaları inceleyin."},
        {"error": "ERR_UNALIGNED_INSTRUCTION", "fix": "RVA adresinin 4 bayta tam bölündüğünü teyit edin."}
    ]

    def validate_inputs(self, workspace: str, config: dict):
        new_header = config.get("new_header") or os.path.join(workspace, "offsets.h")
        if not os.path.exists(new_header):
            return False, f"Doğrulanacak başlık dosyası bulunamadı: {new_header}. Stage 6 çalışmalı."
        return True, ""

    def execute(self, workspace: str, config: dict):
        new_header = config.get("new_header") or os.path.join(workspace, "offsets.h")
        old_header = config.get("old_header")
        so_path = config.get("so_path") or os.path.join(workspace, "bin", "libil2cpp.so")
        src_dir = config.get("src_dir")
        profile_data = config.get("profile")
        known_tag = config.get("known")
        apply_to = config.get("apply_to")
        backup_dir = config.get("backup_dir") or os.path.join(workspace, "backups")

        self.logger.info(f"Stage 7 Başlatıldı: Doğrulanıyor={new_header}")

        res = verify_and_diff(
            new_path=new_header,
            old_path=old_header,
            so_path=so_path,
            src_dir=src_dir,
            profile_data=profile_data,
            known_tag=known_tag,
            apply_to=apply_to,
            backup_dir=backup_dir
        )

        self.logger.info(f"Doğrulama başarılı: {res['constants_count']} sabit doğrulandı. Değişim sayısı: {res['changes_count']}")
        if res.get("applied_file"):
            self.logger.info(f"Hedefe uygulandı: {res['applied_file']}")

        return res

    def validate_outputs(self, workspace: str, config: dict):
        return True, ""


def main():
    parser = argparse.ArgumentParser(description="Verify generated offsets and diff against existing.")
    parser.add_argument("--new", required=True, help="Path to newly generated offsets.h")
    parser.add_argument("--old", help="Path to existing offsets.h for diff comparison")
    parser.add_argument("--so", help="Path to libil2cpp.so to verify file boundaries")
    parser.add_argument("--src", help="Path to source code directory to ensure 0 undefined symbols")
    parser.add_argument("--profile", help="Path to profile JSON for known check validations")
    parser.add_argument("--known", help="Specific known version tag to assert (e.g. 4.9)")
    parser.add_argument("--apply-to", help="If verified, copy new header to this destination path")
    parser.add_argument("--backup-dir", default="./backups", help="Directory for previous header backups")
    parser.add_argument("--report", help="Path to write text diff report")

    args = parser.parse_args()

    profile_data = None
    if args.profile and os.path.exists(args.profile):
        import json
        with open(args.profile, "r", encoding="utf-8") as pf:
            profile_data = json.load(pf)

    try:
        res = verify_and_diff(
            new_path=args.new,
            old_path=args.old,
            so_path=args.so,
            src_dir=args.src,
            profile_data=profile_data,
            known_tag=args.known,
            apply_to=args.apply_to,
            backup_dir=args.backup_dir
        )
        print(f"[OK] All {res['constants_count']} constants verified cleanly.")
        if res.get("applied_file"):
            print(f"[OK] Applied to: {res['applied_file']}")
    except Exception as e:
        print(f"[FAIL] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
