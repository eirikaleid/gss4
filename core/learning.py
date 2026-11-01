"""
core/learning.py - Self-Learning & Persistent Knowledge Engine for GSS4
=======================================================================
Provides autonomous learning, fingerprinting, adaptive decision-making,
and cross-version memory for reverse engineering pipelines:
1. Persistent Knowledge Storage (knowledge/ directory):
   - memory.json: General experience log, run history, and error recovery lessons.
   - fingerprints.json: Binary/metadata signatures mapped to proven decryption strategies.
   - alias_mappings.json: Renamed/obfuscated class & method mappings across versions.
   - drift_patterns.json: Verified offset delta shifts across game releases.
2. Binary & Metadata Fingerprinting:
   - Shannon entropy, header magic, section layout, size, and hash characteristics.
3. Feedback Loop:
   - Strategy success & failure tracking for Stage 3.
   - Obfuscation / alias resolution for Stage 6.
   - Offset drift pattern analysis for Stage 7.
4. Adaptive Recovery Recommender:
   - Automatically provides intelligent solutions when stages fail.
"""

import json
import math
import os
import re
import hashlib
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple, Union

# Root directory of GSS4
CORE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CORE_DIR)
DEFAULT_KNOWLEDGE_DIR = os.environ.get("GSS4_KNOWLEDGE_DIR", os.path.join(ROOT_DIR, "knowledge"))


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (bits per byte, 0.0 to 8.0) of given byte array."""
    if not data:
        return 0.0
    length = len(data)
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


@dataclass
class BinaryFingerprint:
    key: str
    file_name: str
    file_size: int
    sha256_prefix: str
    magic_hex: str
    entropy: float
    is_encrypted_heuristic: bool
    engine_hint: str = "unity_il2cpp"
    arch: str = "arm64-v8a"
    package: Optional[str] = None
    metadata_version: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "BinaryFingerprint":
        return cls(**d)


@dataclass
class StrategyRecord:
    strategy_name: str
    success_count: int = 1
    failure_count: int = 0
    last_success_time: float = field(default_factory=time.time)
    last_used_time: float = field(default_factory=time.time)
    success_rate: float = 1.0
    proven_configurations: List[Dict[str, Any]] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "StrategyRecord":
        return cls(**d)


@dataclass
class AliasRecord:
    canonical_name: str
    alias_name: str
    package: str
    kind: str = "class"  # "class", "method", "field"
    confidence: float = 1.0
    evidence: List[str] = field(default_factory=list)
    discovered_version: str = "unknown"
    last_verified_time: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AliasRecord":
        return cls(**d)


@dataclass
class DriftRecord:
    package: str
    from_version: str
    to_version: str
    timestamp: float
    average_shift: int
    median_shift: int
    min_shift: int
    max_shift: int
    symbol_shifts: Dict[str, int]
    consistent_ratio: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DriftRecord":
        return cls(**d)


@dataclass
class LearnedLesson:
    id: str
    topic: str
    problem: str
    solution: str
    stage_id: Optional[int] = None
    error_code: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    confidence: float = 1.0
    hit_count: int = 0
    created_time: float = field(default_factory=time.time)
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "LearnedLesson":
        return cls(**d)


def extract_fingerprint(
    file_path_or_bytes: Union[str, bytes],
    package: Optional[str] = None,
    arch: Optional[str] = None,
    file_name: Optional[str] = None,
    engine_hint: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None
) -> BinaryFingerprint:
    """Extract a unique, deterministic fingerprint from an APK file, ELF library, or global-metadata.dat."""
    sample_size = 65536
    metadata_version = None

    if isinstance(file_path_or_bytes, bytes):
        raw_bytes = file_path_or_bytes
        total_size = len(raw_bytes)
        fn = file_name or "in_memory_buffer"
        head = raw_bytes[:16]
        sample = raw_bytes[:sample_size]
        h = hashlib.sha256()
        h.update(sample)
        if total_size > sample_size:
            h.update(raw_bytes[-min(total_size, sample_size):])
        h.update(str(total_size).encode())
        sha256_prefix = h.hexdigest()[:16]
    else:
        path = str(file_path_or_bytes)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Cannot fingerprint non-existent file: {path}")
        total_size = os.path.getsize(path)
        fn = file_name or os.path.basename(path)
        with open(path, "rb") as f:
            head = f.read(16)
            f.seek(0)
            sample = f.read(sample_size)
            h = hashlib.sha256()
            h.update(sample)
            if total_size > sample_size:
                f.seek(max(0, total_size - sample_size))
                h.update(f.read(sample_size))
            h.update(str(total_size).encode())
            sha256_prefix = h.hexdigest()[:16]

    magic_hex = head[:4].hex()
    entropy = calculate_shannon_entropy(sample)

    # Heuristic detection for Unity IL2CPP global-metadata
    is_metadata = fn.endswith(".dat") or "metadata" in fn.lower()
    is_elf = head.startswith(b"\x7fELF")

    detected_engine = engine_hint or "unity_il2cpp"
    detected_arch = arch or "arm64-v8a"
    is_encrypted = False

    if is_metadata:
        # Standard unencrypted IL2CPP magic is 0xAF 0x1B 0xB1 0xFA (0xFAB11BAF little endian)
        if head.startswith(b"\xaf\x1b\xb1\xfa"):
            is_encrypted = False
            if len(head) >= 8:
                import struct
                metadata_version = struct.unpack_from("<I", head, 4)[0]
        else:
            # Masked or XOR encrypted
            is_encrypted = True
    elif is_elf:
        # ELF header analysis: byte 4 is EI_CLASS (1=32bit, 2=64bit)
        if len(head) >= 5:
            ei_class = head[4]
            if ei_class == 2:
                detected_arch = arch or "arm64-v8a"
            elif ei_class == 1:
                detected_arch = arch or "armeabi-v7a"

    # Encrypted heuristic based on high entropy sample (> 7.4) when expected format is not matched
    if not is_metadata and not is_elf and entropy > 7.4:
        is_encrypted = True

    key = f"fp_{sha256_prefix}_{total_size}"

    return BinaryFingerprint(
        key=key,
        file_name=fn,
        file_size=total_size,
        sha256_prefix=sha256_prefix,
        magic_hex=magic_hex,
        entropy=entropy,
        is_encrypted_heuristic=is_encrypted,
        engine_hint=detected_engine,
        arch=detected_arch,
        package=package,
        metadata_version=metadata_version,
        extra=extra or {}
    )


class LearningEngine:
    """Core autonomous learning and persistent memory manager for GSS4."""

    _instance: Optional["LearningEngine"] = None

    def __init__(self, knowledge_dir: Optional[str] = None):
        self.knowledge_dir = os.path.abspath(knowledge_dir or DEFAULT_KNOWLEDGE_DIR)
        self._lock = threading.RLock()

        self.memory_file = os.path.join(self.knowledge_dir, "memory.json")
        self.fingerprints_file = os.path.join(self.knowledge_dir, "fingerprints.json")
        self.aliases_file = os.path.join(self.knowledge_dir, "alias_mappings.json")
        self.drift_file = os.path.join(self.knowledge_dir, "drift_patterns.json")

        self._ensure_storage_initialized()

    def _ensure_storage_initialized(self):
        """Create knowledge directory and initialize store files with base schemas."""
        with self._lock:
            os.makedirs(self.knowledge_dir, exist_ok=True)

            # 1. memory.json (Run history, general lessons, error solutions)
            if not os.path.exists(self.memory_file):
                base_memory = {
                    "version": "1.0.0",
                    "created_at": time.time(),
                    "runs_count": 0,
                    "runs_history": [],
                    "lessons": [
                        {
                            "id": "lesson_init_001",
                            "topic": "decryption_magic",
                            "problem": "ERR_UNKNOWN_STRATEGY",
                            "solution": "Profil ayarlarındaki 'decrypt_strategy' parametresini 'auto' veya hedef oyunun korumasına uygun strateji olarak yapılandırın.",
                            "stage_id": 3,
                            "error_code": "ERR_UNKNOWN_STRATEGY",
                            "tags": ["stage3", "decrypt", "strategy"],
                            "confidence": 1.0,
                            "hit_count": 1,
                            "created_time": time.time(),
                            "context": {}
                        },
                        {
                            "id": "lesson_init_002",
                            "topic": "xor_ramp_failure",
                            "problem": "ERR_DECRYPTION_FAILED",
                            "solution": "Oyun güncellemesiyle XOR rampa parametreleri değiştiğinde 'frida_live' bellek dökümü stratejisini fallback olarak devreye alın.",
                            "stage_id": 3,
                            "error_code": "ERR_DECRYPTION_FAILED",
                            "tags": ["stage3", "decrypt", "gups", "frida"],
                            "confidence": 1.0,
                            "hit_count": 1,
                            "created_time": time.time(),
                            "context": {}
                        },
                        {
                            "id": "lesson_init_003",
                            "topic": "arm64_instruction_alignment",
                            "problem": "ERR_UNALIGNED_INSTRUCTION",
                            "solution": "ARM64 mimarisinde metot RVA adresleri 4 bayta tam bölünmelidir (RVA % 4 == 0). Adresin veri alanı veya Thumb değil, 64-bit opcode olduğunu doğrulayın.",
                            "stage_id": 7,
                            "error_code": "ERR_UNALIGNED_INSTRUCTION",
                            "tags": ["stage7", "verify", "alignment"],
                            "confidence": 1.0,
                            "hit_count": 1,
                            "created_time": time.time(),
                            "context": {}
                        },
                        {
                            "id": "lesson_init_004",
                            "topic": "metadata_input_missing",
                            "problem": "ERR_INPUT_METADATA_NOT_FOUND",
                            "solution": "global-metadata.dat eksik. Stage 2 (extract) çıktısının workspace/bin dizininde doğru oluştuğunu ve APK mimarisini (--arch) kontrol edin.",
                            "stage_id": 3,
                            "error_code": "ERR_INPUT_METADATA_NOT_FOUND",
                            "tags": ["stage3", "extract", "inputs"],
                            "confidence": 1.0,
                            "hit_count": 1,
                            "created_time": time.time(),
                            "context": {}
                        },
                        {
                            "id": "lesson_init_005",
                            "topic": "undefined_source_symbols",
                            "problem": "ERR_STAGE_07_VERIFY",
                            "solution": "Kaynak kodda kullanılan semboller yeni header'da bulunamadı. dump.cs içinde sınıf yeniden adlandırma (obfuscation) kontrolü yapın veya alias haritasını güncelleyin.",
                            "stage_id": 7,
                            "error_code": "ERR_STAGE_07_VERIFY",
                            "tags": ["stage7", "verify", "symbols", "alias"],
                            "confidence": 1.0,
                            "hit_count": 1,
                            "created_time": time.time(),
                            "context": {}
                        }
                    ]
                }
                self._save_json(self.memory_file, base_memory)

            # 2. fingerprints.json (Binary fingerprints to strategy mappings)
            if not os.path.exists(self.fingerprints_file):
                base_fingerprints = {
                    "version": "1.0.0",
                    "fingerprints": {
                        "fp_generic_plaintext": {
                            "description": "Standard unencrypted IL2CPP global-metadata.dat",
                            "magic_hex": "af1bb1fa",
                            "proven_strategies": {
                                "passthrough": {
                                    "strategy_name": "passthrough",
                                    "success_count": 10,
                                    "failure_count": 0,
                                    "success_rate": 1.0,
                                    "last_success_time": time.time(),
                                    "last_used_time": time.time(),
                                    "proven_configurations": [],
                                    "details": {"notes": "Default standard Unity plaintext metadata"}
                                }
                            }
                        },
                        "fp_royale_gups": {
                            "description": "F8 Games Royale encrypted metadata",
                            "package": "net.f8games.royale",
                            "proven_strategies": {
                                "gups": {
                                    "strategy_name": "gups",
                                    "success_count": 5,
                                    "failure_count": 0,
                                    "success_rate": 1.0,
                                    "last_success_time": time.time(),
                                    "last_used_time": time.time(),
                                    "proven_configurations": [],
                                    "details": {"notes": "Multi-round XOR ramp deobfuscation"}
                                }
                            }
                        }
                    }
                }
                self._save_json(self.fingerprints_file, base_fingerprints)

            # 3. alias_mappings.json (Obfuscated or renamed classes across updates)
            if not os.path.exists(self.aliases_file):
                base_aliases = {
                    "version": "1.0.0",
                    "packages": {
                        "net.f8games.royale": {
                            "aliases": {
                                "CharacterManager": {
                                    "canonical_name": "CharacterManager",
                                    "alias_name": "CharacterManager",
                                    "package": "net.f8games.royale",
                                    "kind": "class",
                                    "confidence": 1.0,
                                    "evidence": ["field_count=18", "canonical_symbol_match"],
                                    "discovered_version": "4.9",
                                    "last_verified_time": time.time(),
                                    "metadata": {}
                                }
                            }
                        }
                    }
                }
                self._save_json(self.aliases_file, base_aliases)

            # 4. drift_patterns.json (Version-to-version offset shifts)
            if not os.path.exists(self.drift_file):
                base_drift = {
                    "version": "1.0.0",
                    "packages": {
                        "net.f8games.royale": {
                            "patterns": []
                        }
                    }
                }
                self._save_json(self.drift_file, base_drift)

    def _load_json(self, path: str) -> Dict[str, Any]:
        with self._lock:
            if not os.path.exists(path):
                return {}
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}

    def _save_json(self, path: str, data: Dict[str, Any]):
        with self._lock:
            tmp_path = f"{path}.tmp"
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, path)

    # --------------------------------------------------------------------------
    # FINGERPRINTING & DECRYPTION STRATEGY LEARNING
    # --------------------------------------------------------------------------

    def extract_fingerprint(
        self,
        file_path_or_bytes: Union[str, bytes],
        package: Optional[str] = None,
        arch: Optional[str] = None,
        file_name: Optional[str] = None,
        engine_hint: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None
    ) -> BinaryFingerprint:
        """Utility wrapper around extract_fingerprint function."""
        return extract_fingerprint(
            file_path_or_bytes,
            package=package,
            arch=arch,
            file_name=file_name,
            engine_hint=engine_hint,
            extra=extra
        )

    def record_strategy_success(
        self,
        fingerprint: Union[str, BinaryFingerprint, Dict[str, Any]],
        strategy: str,
        details: Optional[Dict[str, Any]] = None
    ):
        """Record successful decryption strategy execution associated with a binary/metadata fingerprint."""
        fp_dict = self._normalize_fingerprint_dict(fingerprint)
        fp_key = fp_dict.get("key", "fp_unknown")
        dt = details or {}

        with self._lock:
            store = self._load_json(self.fingerprints_file)
            fps = store.setdefault("fingerprints", {})

            entry = fps.setdefault(fp_key, {
                "fingerprint": fp_dict,
                "proven_strategies": {}
            })
            entry["fingerprint"] = fp_dict
            entry["last_updated"] = time.time()

            proven = entry.setdefault("proven_strategies", {})
            if strategy in proven:
                rec = proven[strategy]
                rec["success_count"] += 1
                rec["last_success_time"] = time.time()
                rec["last_used_time"] = time.time()
                total = rec["success_count"] + rec["failure_count"]
                rec["success_rate"] = round(rec["success_count"] / total, 4)
                if dt:
                    rec.setdefault("proven_configurations", []).append(dt)
            else:
                proven[strategy] = {
                    "strategy_name": strategy,
                    "success_count": 1,
                    "failure_count": 0,
                    "last_success_time": time.time(),
                    "last_used_time": time.time(),
                    "success_rate": 1.0,
                    "proven_configurations": [dt] if dt else [],
                    "details": dt
                }

            self._save_json(self.fingerprints_file, store)

    def record_strategy_failure(
        self,
        fingerprint: Union[str, BinaryFingerprint, Dict[str, Any]],
        strategy: str,
        error: str
    ):
        """Record a strategy failure so the learning engine avoids or deprioritizes it."""
        fp_dict = self._normalize_fingerprint_dict(fingerprint)
        fp_key = fp_dict.get("key", "fp_unknown")

        with self._lock:
            store = self._load_json(self.fingerprints_file)
            fps = store.setdefault("fingerprints", {})
            if fp_key in fps:
                proven = fps[fp_key].setdefault("proven_strategies", {})
                if strategy in proven:
                    rec = proven[strategy]
                    rec["failure_count"] += 1
                    rec["last_used_time"] = time.time()
                    total = rec["success_count"] + rec["failure_count"]
                    rec["success_rate"] = round(rec["success_count"] / total, 4)
                else:
                    proven[strategy] = {
                        "strategy_name": strategy,
                        "success_count": 0,
                        "failure_count": 1,
                        "last_success_time": 0.0,
                        "last_used_time": time.time(),
                        "success_rate": 0.0,
                        "proven_configurations": [],
                        "details": {"last_error": str(error)}
                    }
                self._save_json(self.fingerprints_file, store)

    def suggest_strategy(
        self,
        fingerprint: Union[str, BinaryFingerprint, Dict[str, Any]],
        available_strategies: Optional[List[str]] = None
    ) -> Optional[str]:
        """Suggest the best-known decryption strategy for a fingerprint based on prior proven success."""
        fp_dict = self._normalize_fingerprint_dict(fingerprint)
        fp_key = fp_dict.get("key")
        pkg = fp_dict.get("package")
        magic_hex = fp_dict.get("magic_hex")
        is_encrypted = fp_dict.get("is_encrypted_heuristic", False)

        with self._lock:
            store = self._load_json(self.fingerprints_file)
            fps = store.get("fingerprints", {})

            # 1. Exact fingerprint key match
            if fp_key and fp_key in fps:
                proven = fps[fp_key].get("proven_strategies", {})
                best = self._pick_highest_ranking_strategy(proven, available_strategies)
                if best:
                    return best

            # 2. Package-specific historical match
            if pkg:
                for entry in fps.values():
                    e_fp = entry.get("fingerprint", {})
                    if e_fp.get("package") == pkg or entry.get("package") == pkg:
                        proven = entry.get("proven_strategies", {})
                        best = self._pick_highest_ranking_strategy(proven, available_strategies)
                        if best:
                            return best

            # 3. Magic & Plaintext heuristic match
            if magic_hex == "af1bb1fa" or not is_encrypted:
                if not available_strategies or "passthrough" in available_strategies:
                    return "passthrough"

            # 4. Check encrypted heuristics
            if is_encrypted:
                if not available_strategies or "gups" in available_strategies:
                    return "gups"

        return None

    def _pick_highest_ranking_strategy(
        self,
        proven: Dict[str, Dict[str, Any]],
        available: Optional[List[str]] = None
    ) -> Optional[str]:
        candidates = []
        for strat_name, rec in proven.items():
            if available and strat_name not in available:
                continue
            rate = rec.get("success_rate", 0.0)
            count = rec.get("success_count", 0)
            last_t = rec.get("last_success_time", 0.0)
            if count > 0 and rate >= 0.5:
                # Rank score: weight success rate + log(count) + recency
                score = (rate * 100) + count + (last_t / 1e10)
                candidates.append((score, strat_name))

        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            return candidates[0][1]
        return None

    def _normalize_fingerprint_dict(self, fp: Union[str, BinaryFingerprint, Dict[str, Any]]) -> Dict[str, Any]:
        if isinstance(fp, str):
            return {"key": fp}
        elif isinstance(fp, BinaryFingerprint):
            return fp.to_dict()
        elif isinstance(fp, dict):
            return fp
        return {"key": str(fp)}

    # --------------------------------------------------------------------------
    # ALIAS MAPPING & OBFUSCATION HEURISTICS
    # --------------------------------------------------------------------------

    def record_alias_mapping(
        self,
        package: str,
        canonical_name: str,
        alias_name: str,
        confidence: float = 1.0,
        kind: str = "class",
        evidence: Optional[List[str]] = None,
        discovered_version: str = "current",
        metadata: Optional[Dict[str, Any]] = None
    ) -> AliasRecord:
        """Record an alias mapping between canonical code symbols and renamed/obfuscated symbols."""
        rec = AliasRecord(
            canonical_name=canonical_name,
            alias_name=alias_name,
            package=package,
            kind=kind,
            confidence=max(0.0, min(1.0, confidence)),
            evidence=evidence or [],
            discovered_version=discovered_version,
            last_verified_time=time.time(),
            metadata=metadata or {}
        )

        with self._lock:
            store = self._load_json(self.aliases_file)
            pkgs = store.setdefault("packages", {})
            pkg_data = pkgs.setdefault(package, {"aliases": {}})
            pkg_aliases = pkg_data.setdefault("aliases", {})
            pkg_aliases[canonical_name] = rec.to_dict()
            self._save_json(self.aliases_file, store)

        return rec

    def resolve_alias(self, package: str, query_name: str) -> Optional[str]:
        """Resolve a symbol name: canonical -> alias or alias -> canonical."""
        with self._lock:
            store = self._load_json(self.aliases_file)
            pkgs = store.get("packages", {})

            # Try exact package first, then all packages
            target_packages = [pkgs.get(package, {})] if package in pkgs else []
            if not target_packages:
                target_packages = list(pkgs.values())

            for p_entry in target_packages:
                aliases = p_entry.get("aliases", {})
                # Direct canonical match
                if query_name in aliases:
                    return aliases[query_name].get("alias_name")
                # Reverse alias match
                for c_name, rec in aliases.items():
                    if rec.get("alias_name") == query_name:
                        return c_name

        return None

    def find_candidate_alias(
        self,
        package: str,
        target_signature: Dict[str, Any],
        candidates: List[Dict[str, Any]],
        threshold: float = 0.65
    ) -> Optional[Tuple[str, float, List[str]]]:
        """Match an obfuscated class by comparing field counts, method signatures, and string references."""
        best_match = None
        highest_score = 0.0
        best_evidence: List[str] = []

        target_field_count = target_signature.get("field_count", 0)
        target_methods = target_signature.get("methods", [])
        target_strings = set(target_signature.get("strings", []))

        for cand in candidates:
            score = 0.0
            evidence = []
            cand_name = cand.get("name", "")

            # 1. Field Count Proximity (up to 30 points)
            c_fields = cand.get("field_count", 0)
            if target_field_count > 0 and c_fields > 0:
                diff = abs(target_field_count - c_fields)
                if diff == 0:
                    score += 0.30
                    evidence.append(f"exact_field_count={c_fields}")
                elif diff <= 2:
                    score += 0.20
                    evidence.append(f"close_field_count(diff={diff})")

            # 2. Method Signatures & Param Match (up to 40 points)
            c_methods = cand.get("methods", [])
            if target_methods and c_methods:
                match_count = 0
                for tm in target_methods:
                    tm_params = tm.get("param_count") if isinstance(tm, dict) else None
                    tm_name = tm.get("name") if isinstance(tm, dict) else tm
                    for cm in c_methods:
                        cm_name = cm.get("name") if isinstance(cm, dict) else cm
                        cm_params = cm.get("param_count") if isinstance(cm, dict) else None
                        if tm_name == cm_name or (tm_params is not None and tm_params == cm_params):
                            match_count += 1
                            break
                ratio = match_count / max(len(target_methods), 1)
                score += ratio * 0.40
                if ratio > 0.5:
                    evidence.append(f"method_match_ratio={ratio:.2f}")

            # 3. String References Overlap (up to 30 points)
            c_strings = set(cand.get("strings", []))
            if target_strings and c_strings:
                intersect = target_strings.intersection(c_strings)
                if intersect:
                    str_ratio = len(intersect) / len(target_strings)
                    score += str_ratio * 0.30
                    evidence.append(f"shared_strings={list(intersect)[:3]}")

            if score > highest_score and score >= threshold:
                highest_score = score
                best_match = cand_name
                best_evidence = evidence

        if best_match:
            return best_match, round(highest_score, 3), best_evidence
        return None

    def get_all_aliases(self, package: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve all recorded alias mappings."""
        with self._lock:
            store = self._load_json(self.aliases_file)
            pkgs = store.get("packages", {})
            if package:
                return pkgs.get(package, {}).get("aliases", {})
            return pkgs

    # --------------------------------------------------------------------------
    # DRIFT PATTERNS & OFFSET PREDICTION
    # --------------------------------------------------------------------------

    def record_drift_pattern(
        self,
        package: str,
        from_version: str,
        to_version: str,
        shifts: Dict[str, int],
        metadata: Optional[Dict[str, Any]] = None
    ) -> DriftRecord:
        """Analyze and record offset shifts between game versions to learn delta patterns."""
        if not shifts:
            vals = [0]
        else:
            vals = list(shifts.values())

        vals_sorted = sorted(vals)
        n = len(vals_sorted)
        avg_shift = int(sum(vals_sorted) / max(n, 1))
        median_shift = vals_sorted[n // 2]
        min_shift = vals_sorted[0]
        max_shift = vals_sorted[-1]

        # Calculate consistency ratio (how many shifts equal the median shift)
        consistent_count = sum(1 for v in vals if v == median_shift)
        consistent_ratio = round(consistent_count / max(n, 1), 4)

        rec = DriftRecord(
            package=package,
            from_version=from_version,
            to_version=to_version,
            timestamp=time.time(),
            average_shift=avg_shift,
            median_shift=median_shift,
            min_shift=min_shift,
            max_shift=max_shift,
            symbol_shifts=shifts,
            consistent_ratio=consistent_ratio,
            metadata=metadata or {}
        )

        with self._lock:
            store = self._load_json(self.drift_file)
            pkgs = store.setdefault("packages", {})
            pkg_data = pkgs.setdefault(package, {"patterns": []})
            pkg_data.setdefault("patterns", []).append(rec.to_dict())
            self._save_json(self.drift_file, store)

        return rec

    def predict_offset(
        self,
        package: str,
        symbol: str,
        previous_offset: int,
        from_version: Optional[str] = None,
        to_version: Optional[str] = None
    ) -> Optional[int]:
        """Predict expected offset using learned drift deltas when a symbol cannot be directly parsed."""
        with self._lock:
            store = self._load_json(self.drift_file)
            pkg_data = store.get("packages", {}).get(package, {})
            patterns = pkg_data.get("patterns", [])
            if not patterns:
                return None

            # Look for matching or most recent pattern
            selected = None
            if from_version and to_version:
                for p in reversed(patterns):
                    if p.get("from_version") == from_version and p.get("to_version") == to_version:
                        selected = p
                        break
            if not selected and patterns:
                selected = patterns[-1]

            if selected:
                # If exact symbol delta was recorded:
                sym_shifts = selected.get("symbol_shifts", {})
                if symbol in sym_shifts:
                    return previous_offset + sym_shifts[symbol]
                # Fallback to median shift if consistent
                if selected.get("consistent_ratio", 0) >= 0.5:
                    return previous_offset + selected.get("median_shift", 0)

        return None

    def get_drift_history(self, package: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            store = self._load_json(self.drift_file)
            pkgs = store.get("packages", {})
            if package:
                return pkgs.get(package, {}).get("patterns", [])
            all_patterns = []
            for p_dict in pkgs.values():
                all_patterns.extend(p_dict.get("patterns", []))
            return all_patterns

    # --------------------------------------------------------------------------
    # ADAPTIVE RECOVERY & GENERAL LESSONS MEMORY
    # --------------------------------------------------------------------------

    def record_lesson(
        self,
        topic: str,
        problem: str,
        solution: str,
        stage_id: Optional[int] = None,
        error_code: Optional[str] = None,
        tags: Optional[List[str]] = None,
        confidence: float = 1.0,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Record an explicit diagnostic or domain insight into persistent memory."""
        lesson_id = f"lesson_{int(time.time() * 1000) % 1000000:06d}"
        rec = LearnedLesson(
            id=lesson_id,
            topic=topic,
            problem=problem,
            solution=solution,
            stage_id=stage_id,
            error_code=error_code,
            tags=tags or [],
            confidence=confidence,
            hit_count=0,
            created_time=time.time(),
            context=context or {}
        )

        with self._lock:
            mem = self._load_json(self.memory_file)
            lessons = mem.setdefault("lessons", [])
            lessons.append(rec.to_dict())
            self._save_json(self.memory_file, mem)

        return lesson_id

    def suggest_recovery(
        self,
        stage_id: Optional[int] = None,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Search memory for solutions proven to fix similar stage errors and rank them by confidence."""
        with self._lock:
            mem = self._load_json(self.memory_file)
            lessons = mem.get("lessons", [])

            matches = []
            ctx_str = str(context or "").lower()

            for idx, item in enumerate(lessons):
                score = 0
                reasons = []

                # Error code exact match
                if error_code and item.get("error_code") == error_code:
                    score += 50
                    reasons.append("exact_error_code")

                # Stage ID match
                if stage_id is not None and item.get("stage_id") == stage_id:
                    score += 25
                    reasons.append("matching_stage")

                # Keyword match in tags or problem text
                for tag in item.get("tags", []):
                    if tag.lower() in ctx_str:
                        score += 10
                        reasons.append(f"tag_match:{tag}")

                prob = item.get("problem", "").lower()
                if error_code and error_code.lower() in prob:
                    score += 20

                if score > 0:
                    matches.append((score, idx, item, reasons))

            matches.sort(key=lambda x: x[0], reverse=True)
            results = []

            for score, idx, item, reasons in matches[:5]:
                # Increment hit count on matched lesson
                lessons[idx]["hit_count"] = lessons[idx].get("hit_count", 0) + 1
                results.append({
                    "id": item.get("id"),
                    "topic": item.get("topic"),
                    "solution": item.get("solution"),
                    "score": score,
                    "relevance_reasons": reasons,
                    "confidence": item.get("confidence", 1.0)
                })

            if matches:
                self._save_json(self.memory_file, mem)

            return results

    def record_stage_run(
        self,
        stage_id: int,
        stage_name: str,
        status: str,
        elapsed_sec: float,
        context: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None
    ):
        """Record stage execution outcome in run history for telemetry and learning."""
        with self._lock:
            mem = self._load_json(self.memory_file)
            runs = mem.setdefault("runs_history", [])
            mem["runs_count"] = mem.get("runs_count", 0) + 1

            record = {
                "timestamp": time.time(),
                "stage_id": stage_id,
                "stage_name": stage_name,
                "status": status,
                "elapsed_sec": round(elapsed_sec, 3),
                "error_code": error_code,
                "error_message": error_message,
                "context_summary": {
                    "workspace": (context or {}).get("workspace"),
                    "package": ((context or {}).get("config") or {}).get("package")
                }
            }
            runs.append(record)
            # Keep the last 100 runs
            if len(runs) > 100:
                mem["runs_history"] = runs[-100:]
            self._save_json(self.memory_file, mem)

    def learn_from_run(self, run_context: Dict[str, Any], results: Dict[str, Any]):
        """Holistic pipeline run analysis: updates metrics, records successful configurations."""
        with self._lock:
            mem = self._load_json(self.memory_file)
            status = results.get("status", "unknown")
            app_name = run_context.get("profile") or run_context.get("app_name") or "unknown"

            history = mem.setdefault("pipeline_history", [])
            history.append({
                "timestamp": time.time(),
                "app_name": app_name,
                "package": run_context.get("package"),
                "status": status,
                "elapsed_sec": results.get("elapsed_sec"),
                "header_path": results.get("header_path")
            })
            if len(history) > 50:
                mem["pipeline_history"] = history[-50:]
            self._save_json(self.memory_file, mem)

    def get_learned_knowledge(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None
    ) -> Dict[str, Any]:
        """Aggregate and query knowledge base contents (strategies, aliases, drift, lessons)."""
        with self._lock:
            mem = self._load_json(self.memory_file)
            fps = self._load_json(self.fingerprints_file)
            aliases = self._load_json(self.aliases_file)
            drift = self._load_json(self.drift_file)

            result: Dict[str, Any] = {
                "summary": {
                    "total_runs": mem.get("runs_count", 0),
                    "total_lessons": len(mem.get("lessons", [])),
                    "fingerprinted_targets": len(fps.get("fingerprints", {})),
                    "alias_packages": len(aliases.get("packages", {})),
                    "drift_packages": len(drift.get("packages", {}))
                }
            }

            q_lower = query.lower() if query else None

            # Filter or include lessons
            if not category or category in ("lessons", "memory"):
                all_lessons = mem.get("lessons", [])
                if q_lower:
                    all_lessons = [
                        l for l in all_lessons
                        if q_lower in l.get("topic", "").lower()
                        or q_lower in l.get("problem", "").lower()
                        or q_lower in l.get("solution", "").lower()
                        or any(q_lower in t.lower() for t in l.get("tags", []))
                    ]
                result["lessons"] = all_lessons

            # Filter or include fingerprints
            if not category or category in ("fingerprints", "strategies"):
                fp_items = fps.get("fingerprints", {})
                if q_lower:
                    fp_items = {
                        k: v for k, v in fp_items.items()
                        if q_lower in k.lower() or q_lower in str(v).lower()
                    }
                result["fingerprints"] = fp_items

            # Filter or include aliases
            if not category or category in ("aliases", "obfuscation"):
                alias_pkgs = aliases.get("packages", {})
                if q_lower:
                    filtered_pkgs = {}
                    for p_name, p_data in alias_pkgs.items():
                        matched_aliases = {
                            ak: av for ak, av in p_data.get("aliases", {}).items()
                            if q_lower in ak.lower() or q_lower in str(av).lower()
                        }
                        if matched_aliases:
                            filtered_pkgs[p_name] = {"aliases": matched_aliases}
                    result["aliases"] = filtered_pkgs
                else:
                    result["aliases"] = alias_pkgs

            # Filter or include drift patterns
            if not category or category in ("drift", "offsets"):
                drift_pkgs = drift.get("packages", {})
                result["drift_patterns"] = drift_pkgs

            return result


# Global Singleton
_GLOBAL_LEARNING_ENGINE: Optional[LearningEngine] = None
_INIT_LOCK = threading.Lock()


def get_learning_engine(knowledge_dir: Optional[str] = None) -> LearningEngine:
    """Get or create singleton instance of GSS4 LearningEngine."""
    global _GLOBAL_LEARNING_ENGINE
    with _INIT_LOCK:
        if _GLOBAL_LEARNING_ENGINE is None or knowledge_dir is not None:
            _GLOBAL_LEARNING_ENGINE = LearningEngine(knowledge_dir=knowledge_dir)
        return _GLOBAL_LEARNING_ENGINE
