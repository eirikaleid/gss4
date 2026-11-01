#!/usr/bin/env python3
"""
01_apk_pull/pull.py - Stage 1: APK Puller & Local Importer
==========================================================
Ne İşe Yarar? (Purpose):
------------------------
Bu modül, tersine mühendislik yapılacak Android uygulamasının APK dosyalarını
(varsa split APK'lar dahil) bağlı bir emülatör/fiziksel cihazdan ADB protokolüyle çeker
veya kullanıcı tarafından belirtilen yerel APK dosyalarını pipeline çalışma alanına kopyalar.
Elde edilen APK'ların fihristini içeren 'apk_manifest.json' dosyasını üretir.

Neler Yapılabilir? (Extension Points):
--------------------------------------
1. Web İndiricisi Eklentisi: APKPure, APKMirror veya QooApp üzerinden doğrudan paket adına göre son APK'yı indirme.
2. Split Merge Aracı: Split APK'ları tek bir standalone APK'da birleştiren (APK Editor / zip merge) araç entegrasyonu.
3. Obb / Asset Dosyası Desteği: Oyun ek veri dosyalarını (/sdcard/Android/obb/<package>) otomatik çekme.
4. ADB WiFi Otomatik Tarama: Yerel ağdaki açık ADB portlarını (5555, 7555 vb.) otomatik keşfetme.
5. Cihaz Sürüm / Mimari Tespiti: Hedef cihazın gerçek ABI ve Android sürümünü sorgulayıp profili dinamik ayarlama.

Hata Yönetimi ve Loglama:
-------------------------
- Cihaz bağlantı kopukluğu, paket bulunamaması, depolama alanı yetersizliği gibi durumlar
  DevicePullError sınıfı ile yapılandırılmış hata kodları ve çözüm önerileriyle yakalanır.
- Tüm adımlar 'workspace/logs/stage_01_01_apk_pull.log' dosyasına anlık kaydedilir.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from core.stage_base import BaseStage, StageResult
    from core.errors import DevicePullError, StageInputError
    from core.logger import get_stage_logger
except ImportError:
    BaseStage = object
    DevicePullError = Exception
    StageInputError = Exception
    get_stage_logger = None


def run_cmd(cmd: List[str]) -> Tuple[int, str, str]:
    """Execute a subprocess command returning returncode, stdout, and stderr."""
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def pull_from_device(package: str, out_dir: str, device: Optional[str] = None, arch: str = "arm64", logger=None) -> List[str]:
    """Pull target APKs from connected Android device via ADB."""
    os.makedirs(out_dir, exist_ok=True)
    adb_cmd = ["adb"]
    if device:
        adb_cmd.extend(["-s", device])

    def log(msg, level="info"):
        if logger:
            getattr(logger, level)(msg)
        else:
            print(msg)

    # 1. Cihaz bağlantısı kontrolü
    rc, stdout, stderr = run_cmd(adb_cmd + ["devices"])
    if rc != 0:
        raise DevicePullError(
            message=f"ADB çalıştırılamadı: {stderr}",
            error_code="ERR_ADB_BINARY",
            suggestions=["ADB'nin PATH ortam değişkeninde tanımlı olduğunu doğrulayın.", "Platform-tools kurulu mu kontrol edin."]
        )

    # Cihaz listesinde ilgili cihaz var mı?
    device_lines = [l for l in stdout.splitlines()[1:] if l.strip()]
    if not device_lines:
        raise DevicePullError(
            message=f"Hiçbir ADB cihazı bulunamadı. Hedef: '{device or 'varsayılan'}'",
            error_code="ERR_ADB_NO_DEVICE",
            suggestions=[
                "Emülatörün (MuMu, LDPlayer, Nox vb.) veya telefonun açık olduğunu kontrol edin.",
                f"Bağlantı komutunu çalıştırın: 'adb connect {device or '127.0.0.1:7555'}'",
                "USB hata ayıklamanın açık olduğunu doğrulayın."
            ]
        )

    log(f"Paket yolları sorgulanıyor: '{package}' (Cihaz: {device or 'varsayılan'})...")
    rc, stdout, stderr = run_cmd(adb_cmd + ["shell", "pm", "path", package])
    if rc != 0 or not stdout:
        raise DevicePullError(
            message=f"'{package}' paketi cihazda bulunamadı. stderr: {stderr}",
            error_code="ERR_PACKAGE_NOT_INSTALLED",
            suggestions=[
                f"Paket adının doğru yazıldığını kontrol edin: '{package}'",
                "Cihazda uygulamanın yüklü olduğunu doğrulayın: 'adb shell pm list packages | grep <ad>'",
                "Eğer elinizde APK dosyası varsa '--apk-path' parametresini kullanın."
            ]
        )

    lines = [line.strip() for line in stdout.splitlines() if line.strip().startswith("package:")]
    pulled_apks = []

    for line in lines:
        remote_path = line.replace("package:", "").strip()
        leaf = os.path.basename(remote_path)

        if leaf != "base.apk" and arch not in leaf:
            log(f"İlgisiz split atlanıyor: {leaf}", level="debug")
            continue

        local_path = os.path.join(out_dir, leaf)
        log(f"Çekiliyor: {remote_path} -> {local_path} ...")
        rc, _, err = run_cmd(adb_cmd + ["pull", remote_path, local_path])
        if rc != 0 or not os.path.exists(local_path):
            raise DevicePullError(
                message=f"'{remote_path}' cihazdan çekilemedi: {err}",
                error_code="ERR_ADB_PULL_FAILED",
                suggestions=[
                    "Cihaz depolama alanını ve PC disk alanını kontrol edin.",
                    "Dosya izinlerini veya cihaz kilit durumunu kontrol edin."
                ]
            )

        pulled_apks.append(os.path.abspath(local_path))

    return pulled_apks


def copy_local_apks(apk_paths: List[str], out_dir: str, logger=None) -> List[str]:
    """Copy local APKs into the target workspace directory."""
    os.makedirs(out_dir, exist_ok=True)
    pulled_apks = []
    for p in apk_paths:
        if not os.path.exists(p):
            raise DevicePullError(
                message=f"Belirtilen yerel APK bulunamadı: {p}",
                error_code="ERR_LOCAL_APK_NOT_FOUND",
                suggestions=[f"Dosya yolunun varlığını doğrulayın: {p}", "Yol yazımını (slash / backslash) kontrol edin."]
            )
        dst = os.path.join(out_dir, os.path.basename(p))
        if os.path.abspath(p) != os.path.abspath(dst):
            shutil.copy2(p, dst)
        pulled_apks.append(os.path.abspath(dst))
        if logger:
            logger.info(f"Yerel APK kopyalandı: {dst}")
    return pulled_apks


class Stage1Pull(BaseStage):
    """Stage 1: APK Puller Implementation."""

    stage_id = 1
    name = "01_apk_pull"
    description = "Pulls target APK (and split APKs) via ADB or copies from local filesystem."
    purpose = "Hedef uygulamanın APK dosyalarını ADB üzerinden çeker veya yerel dosyalardan çalışma alanına aktarır."
    extension_points = [
        "APKPure / APKMirror / QooApp üzerinden doğrudan web API ile APK indirme modülü",
        "Split APK'ları tek bir standalone APK'da birleştiren otomatik merge aracı",
        "Obb veri dosyalarını (/sdcard/Android/obb/) otomatik çekme desteği",
        "ADB WiFi cihazlarını otomatik tarama ve bağlanma mekanizması",
        "Hedef cihazın donanım mimarisini (arm64, armeabi) otomatik algılama"
    ]
    troubleshooting = [
        {"error": "ERR_ADB_NO_DEVICE", "fix": "Emülatörün açık olduğunu kontrol edin veya 'adb connect 127.0.0.1:7555' çalıştırın."},
        {"error": "ERR_PACKAGE_NOT_INSTALLED", "fix": "Oyunun cihazda yüklü olduğunu kontrol edin veya '--apk-path' ile yerel dosya verin."},
        {"error": "ERR_ADB_PULL_FAILED", "fix": "PC diskinde ve cihazda yeterli boş alan olduğunu doğrulayın."}
    ]

    def validate_inputs(self, workspace: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        if not config.get("apk_paths") and not config.get("package"):
            return False, "Ya 'package' (Android paket adı) ya da 'apk_paths' (yerel APK dosyaları) belirtilmelidir."
        return True, ""

    def execute(self, workspace: str, config: Dict[str, Any]) -> Dict[str, Any]:
        out_dir = os.path.join(workspace, "apk")
        os.makedirs(out_dir, exist_ok=True)

        apk_paths = config.get("apk_paths")
        package = config.get("package")
        device = config.get("device", "127.0.0.1:7555")
        arch = config.get("arch", "arm64-v8a").split("-")[0]

        self.logger.info(f"Stage 1 Başlatıldı: Paket='{package}', Yerel='{apk_paths}', Cihaz='{device}'")

        if apk_paths:
            apks = copy_local_apks(apk_paths, out_dir, logger=self.logger)
        else:
            apks = pull_from_device(package, out_dir, device=device, arch=arch, logger=self.logger)

        if not apks:
            raise DevicePullError(
                message=f"Hiçbir APK dosyası temin edilemedi: {package or apk_paths}",
                error_code="ERR_NO_APKS_ACQUIRED"
            )

        manifest_path = os.path.join(out_dir, "apk_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump({"apks": apks, "package": package, "device": device, "arch": arch}, f, indent=2)

        self.logger.info(f"APK Manifest oluşturuldu: {manifest_path} ({len(apks)} adet APK)")

        return {
            "apks": apks,
            "manifest": manifest_path,
            "output_files": apks + [manifest_path]
        }

    def validate_outputs(self, workspace: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        manifest_path = os.path.join(workspace, "apk", "apk_manifest.json")
        if not os.path.exists(manifest_path):
            return False, f"Beklenen çıktı manifest dosyası bulunamadı: {manifest_path}"
        return True, ""


def main():
    parser = argparse.ArgumentParser(description="Pull APKs from device or copy local APKs.")
    parser.add_argument("--package", help="Target Android package name")
    parser.add_argument("--device", default="127.0.0.1:7555", help="ADB device identifier")
    parser.add_argument("--arch", default="arm64", help="Target architecture (e.g. arm64, armeabi-v7a)")
    parser.add_argument("--apk-path", nargs="+", help="One or more local APK paths")
    parser.add_argument("--out", required=True, help="Output directory for APKs")
    parser.add_argument("--manifest", help="Optional output JSON path for APK manifest")

    args = parser.parse_args()

    stage = Stage1Pull()
    config = {
        "package": args.package,
        "device": args.device,
        "arch": args.arch,
        "apk_paths": args.apk_path,
    }

    res = stage.run_stage(os.path.dirname(os.path.abspath(args.out)), config)
    if res.status != "success":
        sys.exit(1)


if __name__ == "__main__":
    main()
