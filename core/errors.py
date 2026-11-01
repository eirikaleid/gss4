"""
core/errors.py - Standardized Exceptions and Diagnostic Error Handlers for GSS4
Provides structured exceptions with error codes, diagnostics, and actionable remediation suggestions.
"""

from typing import Any, Dict, List, Optional


class GSS4BaseError(Exception):
    """Base exception for all GSS4 pipeline errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ERR_UNKNOWN",
        suggestions: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.suggestions = suggestions or []
        self.context = context or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_code": self.error_code,
            "message": self.message,
            "suggestions": self.suggestions,
            "context": self.context,
        }

    def format_diagnostic(self) -> str:
        lines = [
            f"[\033[1;31mERROR {self.error_code}\033[0m] {self.message}",
        ]
        if self.suggestions:
            lines.append("\033[1;33m  Çözüm Önerileri (Remediation Tips):\033[0m")
            for tip in self.suggestions:
                lines.append(f"    - {tip}")
        if self.context:
            lines.append(f"\033[1;30m  Bağlam Bilgisi (Context): {self.context}\033[0m")
        return "\n".join(lines)


# ==============================================================================
# STAGE-SPECIFIC EXCEPTIONS
# ==============================================================================

class StageInputError(GSS4BaseError):
    """Raised when stage input validation fails."""
    def __init__(self, message: str, stage_id: int, suggestions: Optional[List[str]] = None, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code=f"ERR_STAGE_{stage_id:02d}_INPUT_INVALID",
            suggestions=suggestions or ["Girdi dosyalarının varlığını ve yolunu doğrulayın."],
            context=context
        )


class StageOutputError(GSS4BaseError):
    """Raised when expected stage output artifacts were not produced."""
    def __init__(self, message: str, stage_id: int, suggestions: Optional[List[str]] = None, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code=f"ERR_STAGE_{stage_id:02d}_OUTPUT_MISSING",
            suggestions=suggestions or ["Aşama log dosyasını inceleyin."],
            context=context
        )


# --- Stage 1 ---
class DevicePullError(GSS4BaseError):
    """Stage 1: ADB or APK acquisition failure."""
    def __init__(self, message: str, error_code: str = "ERR_STAGE_01_PULL", suggestions: Optional[List[str]] = None, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code=error_code,
            suggestions=suggestions or [
                "Cihazın bağlı ve açık olduğundan emin olun: 'adb devices'",
                "Paketin cihazda kurulu olup olmadığını test edin: 'adb shell pm list packages | grep <paket>'",
                "Gerekirse cihazdan çekmek yerine '--apk-path' ile yerel APK verin."
            ],
            context=context
        )


# --- Stage 2 ---
class ExtractionError(GSS4BaseError):
    """Stage 2: Archive unpacking or binary extraction failure."""
    def __init__(self, message: str, error_code: str = "ERR_STAGE_02_EXTRACT", suggestions: Optional[List[str]] = None, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code=error_code,
            suggestions=suggestions or [
                "APK dosyasının bozulmamış geçerli bir ZIP arşivi olduğunu doğrulayın.",
                "Hedef mimarinin (örn: arm64-v8a) APK içinde lib/<arch>/ altında mevcut olduğunu kontrol edin.",
                "Eğer split APK kullanılıyorsa mimari splitini de ekleyin (örn: split_config.arm64_v8a.apk)."
            ],
            context=context
        )


# --- Stage 3 ---
class DecryptionError(GSS4BaseError):
    """Stage 3: Metadata decryption / de-obfuscation failure."""
    def __init__(self, message: str, error_code: str = "ERR_STAGE_03_DECRYPT", suggestions: Optional[List[str]] = None, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code=error_code,
            suggestions=suggestions or [
                "global-metadata.dat dosyasının doğru çıkartıldığından emin olun (boyut kontrolü).",
                "Oyunun özel bir koruma motoru kullanıp kullanmadığını kontrol edin (GUPS, Tencent, Bangcle vb.).",
                "--strategy passthrough ile şifresiz deneme yapın veya yeni bir deşifre stratejisi ekleyin."
            ],
            context=context
        )


# --- Stage 4 ---
class DumperError(GSS4BaseError):
    """Stage 4: Il2CppDumper process crash or failure."""
    def __init__(self, message: str, error_code: str = "ERR_STAGE_04_DUMP", suggestions: Optional[List[str]] = None, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code=error_code,
            suggestions=suggestions or [
                "tools/Il2CppDumper/Il2CppDumper.exe dosyasının mevcut olduğunu doğrulayın.",
                "Deşifre edilmiş metadata dosyasının (global-metadata.dec.dat) geçerli olduğunu (magic 0xFAB11BAF) test edin.",
                "build/dump/il2cppdumper.log dosyasını açıp dumper hata çıktısını inceleyin."
            ],
            context=context
        )


# --- Stage 5 ---
class NativeAnalysisError(GSS4BaseError):
    """Stage 5: ELF header, GOT or native string analysis failure."""
    def __init__(self, message: str, error_code: str = "ERR_STAGE_05_NATIVE", suggestions: Optional[List[str]] = None, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code=error_code,
            suggestions=suggestions or [
                "libunity.so veya hedeflenen native kütüphanenin 64-bit ELF olduğunu doğrulayın.",
                "Sembolün dynamic symbol tablosunda veya relocation tablosunda mevcut olduğunu kontrol edin."
            ],
            context=context
        )


# --- Stage 6 ---
class OffsetParseError(GSS4BaseError):
    """Stage 6: dump.cs parsing or offset code generation failure."""
    def __init__(self, message: str, error_code: str = "ERR_STAGE_06_PARSE", suggestions: Optional[List[str]] = None, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code=error_code,
            suggestions=suggestions or [
                "dump.cs dosyasının boş olmadığını ve tamamlandığını doğrulayın.",
                "Profil JSON dosyasındaki 'priority_classes' sınıf isimlerinin oyunda değişip değişmediğini kontrol edin.",
                "dump.cs içinde 'class <SinifAdi>' araması yaparak isim değişikliğini tespit edin."
            ],
            context=context
        )


# --- Stage 7 ---
class VerificationGateError(GSS4BaseError):
    """Stage 7: Sanity verification or diff safety gate violation."""
    def __init__(self, message: str, error_code: str = "ERR_STAGE_07_VERIFY", suggestions: Optional[List[str]] = None, context: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code=error_code,
            suggestions=suggestions or [
                "Değişen offsetlerin aşırı büyük kayma (drift) yapıp yapmadığını inceleyin.",
                "src/ kaynak kodunda kullanılan ve artık dump'ta bulunmayan eksik sembolleri tamamlayın.",
                "Diff raporunu (verify_report.txt) inceleyerek onaylamadan önce değişiklikleri gözden geçirin."
            ],
            context=context
        )
