#!/usr/bin/env python3
"""
03_decrypt_metadata/decrypt.py - Stage 3: Universal Metadata Decryptor Dispatcher
================================================================================
Ne İşe Yarar? (Purpose):
------------------------
Modern mobil Unity oyunlarının büyük çoğunluğu tersine mühendisliği engellemek amacıyla
'global-metadata.dat' dosyasını şifreler (header maskeleme, section-wise XOR rampa, custom tablo yerleşimi).
Bu aşama, tak-çıkar strateji mimarisiyle (strategies/ dizini altındaki modüller):
  1. Dosyanın şifreli olup olmadığını header magic (0xFAB11BAF) ile otomatik tespit eder.
  2. Gerekli deşifre stratejisini dinamik olarak yükler (örn: 'gups', 'passthrough' veya özel anticheat).
  3. Il2CppDumper'ın kabul edeceği standart formatta 'global-metadata.dec.dat' dosyasını ve deşifre raporunu üretir.

Neler Yapılabilir? (Extension Points):
--------------------------------------
1. Yeni Anticheat Modülleri: 'strategies/' klasörüne tek bir .py ekleyerek Tencent Legu, Bangcle, VMP vb. çözücüler ekleme.
2. Entropi Haritalayıcı (Shannon Entropy): Şifreli ve düz metin bölümlerini byte dağılımından otomatik saptama.
3. Çok Çekirdekli Brute-Force: Bilinmeyen XOR anahtarlarını tüm CPU çekirdekleriyle paralel tarayan solver.
4. Canlı Bellek (Live Memory) Fallback: Eğer offline deşifre edilemezse emülatör belleğinden (/proc/pid/mem) deşifre edilmiş metadata'yı canlı kopyalama.
5. Versiyon Otomatik Yamalama: Metadata versiyon numarasını (v24, v29) hedef Il2CppDumper ile uyumlu hale getirme.

Hata Yönetimi ve Loglama:
-------------------------
- Yanlış strateji, deşifre sonrası bozuk magic byte tespiti gibi durumlar DecryptionError ile yakalanır.
- Tüm loglar 'workspace/logs/stage_03_03_decrypt_metadata.log' dosyasına kaydedilir.
"""

import argparse
import importlib
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from core.stage_base import BaseStage, StageResult
    from core.errors import DecryptionError, StageInputError
    from core.logger import get_stage_logger
except ImportError:
    BaseStage = object
    DecryptionError = Exception
    StageInputError = Exception
    get_stage_logger = None

STRATEGIES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "strategies")


def discover_strategies(logger=None) -> Dict[str, Any]:
    """Dynamically discover all strategy modules inside strategies/ directory."""
    strategies = {}
    if not os.path.exists(STRATEGIES_DIR):
        return strategies

    for fn in os.listdir(STRATEGIES_DIR):
        if fn.endswith(".py") and not fn.startswith("__"):
            mod_name = fn[:-3]
            try:
                mod = importlib.import_module(f"strategies.{mod_name}")
                if hasattr(mod, "run"):
                    strategies[mod_name] = mod
            except Exception as e:
                if logger:
                    logger.warning(f"Strateji modülü yüklenemedi '{mod_name}': {e}")
                else:
                    print(f"[WARN] Failed to load strategy '{mod_name}': {e}", file=sys.stderr)

    return strategies


def run_decryption(
    in_path: str,
    out_path: str,
    strategy: str = "auto",
    report_path: Optional[str] = None,
    custom_words: Optional[List[str]] = None,
    logger=None
) -> Dict[str, Any]:
    """Execute decryption on metadata using configured or auto-detected strategy."""
    strategies = discover_strategies(logger=logger)
    if not os.path.exists(in_path):
        raise DecryptionError(
            message=f"Girdi metadata dosyası bulunamadı: {in_path}",
            error_code="ERR_INPUT_METADATA_NOT_FOUND",
            suggestions=["Stage 2'nin (extract) başarıyla çalıştığından emin olun."]
        )

    selected_strategy = strategy
    with open(in_path, "rb") as f:
        head = f.read(16)

    def log(msg, level="info"):
        if logger:
            getattr(logger, level)(msg)
        else:
            print(msg)

    # Otomatik algılama: Düz metin mi şifreli mi?
    if selected_strategy == "auto":
        passthrough_mod = strategies.get("passthrough")
        if passthrough_mod and hasattr(passthrough_mod, "is_plaintext") and passthrough_mod.is_plaintext(head):
            log("Metadata standart IL2CPP düz metin (şifresiz) -> 'passthrough' stratejisi seçildi.")
            selected_strategy = "passthrough"
        else:
            log("Metadata başlığı şifreli/özel formatta -> 'gups' stratejisi seçildi.")
            selected_strategy = "gups"

    strat_mod = strategies.get(selected_strategy)
    if not strat_mod:
        raise DecryptionError(
            message=f"Bilinmeyen veya yüklenemeyen strateji: '{selected_strategy}'. Mevcut stratejiler: {list(strategies.keys())}",
            error_code="ERR_UNKNOWN_STRATEGY",
            suggestions=[f"'strategies/' klasörüne '{selected_strategy}.py' ekleyin veya olanlardan birini seçin: {list(strategies.keys())}"]
        )

    log(f"Strateji koşturuluyor: '{selected_strategy}' ...")
    try:
        if selected_strategy == "gups":
            report = strat_mod.run(in_path, out_path, custom_words=custom_words)
        else:
            report = strat_mod.run(in_path, out_path)
    except Exception as e:
        raise DecryptionError(
            message=f"'{selected_strategy}' deşifre motorunda hata oluştu: {e}",
            error_code="ERR_DECRYPTION_FAILED",
            suggestions=[
                "Oyunun anticheat sürümü güncellenmiş olabilir; yeni XOR anahtarlarını kontrol edin.",
                "Özel kelime listesi (--words) ekleyerek string aramasını genişletin."
            ]
        )

    # Çıktı dosyasının magic kontrolü (0xFAB11BAF)
    if os.path.exists(out_path):
        with open(out_path, "rb") as f:
            out_magic = f.read(4)
        if out_magic != b"\xaf\x1b\xb1\xfa":
            log(f"Uyarı: Deşifre edilen dosyanın magic byte'ı standart IL2CPP ile eşleşmiyor: {out_magic.hex()}", level="warning")

    if report_path and report:
        os.makedirs(os.path.dirname(os.path.abspath(report_path)), exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        log(f"Deşifre raporu kaydedildi: {report_path}")

    return report


class Stage3Decrypt(BaseStage):
    """Stage 3: Metadata Decryptor Dispatcher Implementation."""

    stage_id = 3
    name = "03_decrypt_metadata"
    description = "Deobfuscates/decrypts global-metadata.dat using modular strategies."
    purpose = "Şifreli veya maskelenmiş global-metadata.dat dosyasını modüler stratejilerle (GUPS, passthrough vb.) standart IL2CPP formatına dönüştürür."
    extension_points = [
        "Yeni anticheat koruma stratejileri (strategies/yeni_koruma.py) ekleme",
        "Shannon entropisi ile dosyadaki şifreli section'ları otomatik haritalama",
        "CPU çok çekirdekli paralel XOR / rampa anahtar çözücü",
        "Canlı emülatör belleğinden (/proc/pid/mem) deşifre edilmiş metadata çekme fallback'ı",
        "Eski Unity sürümleri için metadata header sürüm yamalama"
    ]
    troubleshooting = [
        {"error": "ERR_UNKNOWN_STRATEGY", "fix": "Profilde belirtilen 'decrypt_strategy' adını kontrol edin."},
        {"error": "ERR_DECRYPTION_FAILED", "fix": "Oyun güncellemesiyle XOR rampa parametreleri değişmiş olabilir, analiz edin."},
        {"error": "ERR_INPUT_METADATA_NOT_FOUND", "fix": "Stage 2 çıktısı olan global-metadata.dat dosyasının varlığını doğrulayın."}
    ]

    def validate_inputs(self, workspace: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        in_meta = config.get("metadata_in") or os.path.join(workspace, "bin", "global-metadata.dat")
        if not os.path.exists(in_meta):
            return False, f"Girdi metadata dosyası bulunamadı: {in_meta}. Önce Stage 2 çalışmalıdır."
        return True, ""

    def execute(self, workspace: str, config: Dict[str, Any]) -> Dict[str, Any]:
        in_meta = config.get("metadata_in") or os.path.join(workspace, "bin", "global-metadata.dat")
        out_meta = config.get("metadata_out") or os.path.join(workspace, "bin", "global-metadata.dec.dat")
        report_path = config.get("report_out") or os.path.join(workspace, "gups_report.json")
        strategy = config.get("decrypt_strategy", "auto")
        custom_words = config.get("custom_words")

        self.logger.info(f"Stage 3 Başlatıldı: Strateji='{strategy}', Girdi={in_meta}")

        report = run_decryption(
            in_path=in_meta,
            out_path=out_meta,
            strategy=strategy,
            report_path=report_path,
            custom_words=custom_words,
            logger=self.logger
        )

        output_files = [os.path.abspath(out_meta)]
        if os.path.exists(report_path):
            output_files.append(os.path.abspath(report_path))

        self.logger.info(f"Deşifre başarıyla tamamlandı: {out_meta} ({os.path.getsize(out_meta):,} bayt)")

        return {
            "strategy": strategy,
            "decrypted_metadata": os.path.abspath(out_meta),
            "report": report,
            "output_files": output_files
        }

    def validate_outputs(self, workspace: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        out_meta = config.get("metadata_out") or os.path.join(workspace, "bin", "global-metadata.dec.dat")
        if not os.path.exists(out_meta) or os.path.getsize(out_meta) == 0:
            return False, f"Deşifre edilmiş metadata dosyası üretilemedi veya boş: {out_meta}"
        return True, ""


def main():
    parser = argparse.ArgumentParser(description="Decrypt or pass through global-metadata.dat.")
    parser.add_argument("--in", dest="in_path", required=True, help="Path to input encrypted global-metadata.dat")
    parser.add_argument("--out", dest="out_path", required=True, help="Path to output decrypted global-metadata.dec.dat")
    parser.add_argument("--strategy", default="auto", help="Strategy name ('auto', 'gups', 'passthrough' or custom)")
    parser.add_argument("--report", help="Optional output JSON path for decryption report")
    parser.add_argument("--words", nargs="*", help="Optional expected string words for solver verification")

    args = parser.parse_args()

    stage = Stage3Decrypt()
    config = {
        "metadata_in": args.in_path,
        "metadata_out": args.out_path,
        "decrypt_strategy": args.strategy,
        "report_out": args.report,
        "custom_words": args.words,
    }
    res = stage.run_stage(os.path.dirname(os.path.abspath(args.out_path)), config)
    if res.status != "success":
        sys.exit(1)


if __name__ == "__main__":
    main()
