"""Core framework for GSS4 modular stages."""

from .stage_base import BaseStage, StageResult
from .errors import (
    GSS4BaseError,
    StageInputError,
    StageOutputError,
    DevicePullError,
    ExtractionError,
    DecryptionError,
    DumperError,
    NativeAnalysisError,
    OffsetParseError,
    VerificationGateError,
)
from .logger import get_stage_logger
from .common_ir import CommonIR, ClassIR, FieldIR, MethodIR, NativeSymbolIR
from .engine_provider import (
    BaseEngineProvider,
    EngineVerificationPolicy,
    get_engine_provider,
    list_supported_engines
)
from .learning import (
    LearningEngine,
    get_learning_engine,
    extract_fingerprint,
    calculate_shannon_entropy,
    BinaryFingerprint,
    StrategyRecord,
    AliasRecord,
    DriftRecord,
    LearnedLesson
)

__all__ = [
    "BaseStage",
    "StageResult",
    "get_stage_logger",
    "GSS4BaseError",
    "StageInputError",
    "StageOutputError",
    "DevicePullError",
    "ExtractionError",
    "DecryptionError",
    "DumperError",
    "NativeAnalysisError",
    "OffsetParseError",
    "VerificationGateError",
    "CommonIR",
    "ClassIR",
    "FieldIR",
    "MethodIR",
    "NativeSymbolIR",
    "BaseEngineProvider",
    "EngineVerificationPolicy",
    "get_engine_provider",
    "list_supported_engines",
    "LearningEngine",
    "get_learning_engine",
    "extract_fingerprint",
    "calculate_shannon_entropy",
    "BinaryFingerprint",
    "StrategyRecord",
    "AliasRecord",
    "DriftRecord",
    "LearnedLesson",
]
