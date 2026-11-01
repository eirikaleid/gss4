"""
core/stage_base.py - Standard Base Interface & Lifecycle for GSS4 Stages
Provides an isolated, extensible lifecycle for each stage:
- Documentation & metadata (purpose, extension points, troubleshooting)
- Structured logging (console + stage-specific log file)
- Diagnostic error handling (custom exceptions, remediation hints, on_error hooks)
- Input validation -> pre-hooks -> core execution -> output validation -> post-hooks
"""

import abc
import os
import sys
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.errors import (
    GSS4BaseError,
    StageInputError,
    StageOutputError,
)
from core.logger import get_stage_logger


@dataclass
class StageResult:
    stage_name: str
    status: str  # "success" or "error"
    elapsed_sec: float
    data: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    suggestions: List[str] = field(default_factory=list)
    output_files: List[str] = field(default_factory=list)
    log_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_name": self.stage_name,
            "status": self.status,
            "elapsed_sec": round(self.elapsed_sec, 3),
            "data": self.data,
            "error_message": self.error_message,
            "error_code": self.error_code,
            "suggestions": self.suggestions,
            "output_files": self.output_files,
            "log_file": self.log_file,
        }


class BaseStage(abc.ABC):
    """Abstract Base Class for every pipeline stage.

    Subclasses must implement:
        - stage_id (int): 1 through 7
        - name (str): stage name (e.g. '01_apk_pull')
        - purpose (str): detailed description of what the stage does
        - extension_points (List[str]): list of what can be developed/extended
        - execute(workspace, config) -> dict
    """

    stage_id: int = 0
    name: str = "base_stage"
    description: str = "Base stage description"
    purpose: str = "Açıklanmamış aşama görevi."
    extension_points: List[str] = []
    troubleshooting: List[Dict[str, str]] = []

    def __init__(self):
        self._pre_hooks: List[Callable[[str, Dict[str, Any]], None]] = []
        self._post_hooks: List[Callable[[StageResult], None]] = []
        self._error_hooks: List[Callable[[Exception, Dict[str, Any]], None]] = []
        self.logger = get_stage_logger(self.stage_id, self.name)
        try:
            from core.learning import get_learning_engine
            self.learning_engine = get_learning_engine()
        except Exception:
            self.learning_engine = None

    def before_run(self, hook: Callable[[str, Dict[str, Any]], None]):
        """Register a callback hook before stage executes."""
        self._pre_hooks.append(hook)
        return hook

    def after_run(self, hook: Callable[[StageResult], None]):
        """Register a callback hook after stage finishes successfully."""
        self._post_hooks.append(hook)
        return hook

    def on_error(self, hook: Callable[[Exception, Dict[str, Any]], None]):
        """Register a callback hook when stage encounters an error."""
        self._error_hooks.append(hook)
        return hook

    def get_info(self) -> Dict[str, Any]:
        """Returns structured information about this stage: purpose, extension points, troubleshooting."""
        return {
            "stage_id": self.stage_id,
            "name": self.name,
            "description": self.description,
            "purpose": self.purpose,
            "extension_points": self.extension_points,
            "troubleshooting": self.troubleshooting,
        }

    def validate_inputs(self, workspace: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate whether prerequisites for this stage exist.

        Override in subclass to check needed files/configs.
        """
        return True, ""

    def validate_outputs(self, workspace: str, config: Dict[str, Any]) -> Tuple[bool, str]:
        """Validate whether expected artifacts were created.

        Override in subclass to check generated files.
        """
        return True, ""

    @abc.abstractmethod
    def execute(self, workspace: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Core stage execution logic. Returns data dict."""
        pass

    def handle_error(self, exc: Exception, context: Dict[str, Any]) -> StageResult:
        """Centralized stage error handler. Invokes error hooks, logs diagnostics, and formats result."""
        for hook in self._error_hooks:
            try:
                hook(exc, context)
            except Exception as hook_err:
                self.logger.warning(f"Error hook failed: {hook_err}")

        # Extract structured details if it's a GSS4BaseError
        if isinstance(exc, GSS4BaseError):
            err_code = exc.error_code
            err_msg = exc.message
            suggestions = exc.suggestions
            self.logger.error(f"[{err_code}] {err_msg}")
            for tip in suggestions:
                self.logger.warning(f"  -> Çözüm Önerisi: {tip}")
        else:
            err_code = f"ERR_STAGE_{self.stage_id:02d}_EXECUTION"
            err_msg = str(exc)
            suggestions = [
                f"Aşama log dosyasını inceleyin: workspace/logs/stage_{self.stage_id:02d}_{self.name}.log",
                "Girdi parametrelerinin doğruluğunu kontrol edin."
            ]
            self.logger.error(f"Beklenmeyen Hata ({err_code}): {err_msg}")
            self.logger.debug(traceback.format_exc())

        elapsed = time.time() - context.get("t0", time.time())
        log_file = os.path.join(context.get("workspace", ""), "logs", f"stage_{self.stage_id:02d}_{self.name}.log")

        # Query Learning Engine for adaptive recovery suggestions based on previous lessons
        if self.learning_engine:
            try:
                adaptive_solutions = self.learning_engine.suggest_recovery(
                    stage_id=self.stage_id,
                    error_code=err_code,
                    context=context
                )
                for item in adaptive_solutions:
                    sol = item.get("solution")
                    if sol:
                        tip_str = f"[Öğrenilen Adaptif Çözüm]: {sol}"
                        if tip_str not in suggestions:
                            suggestions.append(tip_str)
                            self.logger.info(f"  -> {tip_str}")

                # Record stage failure in persistent memory
                self.learning_engine.record_stage_run(
                    stage_id=self.stage_id,
                    stage_name=self.name,
                    status="error",
                    elapsed_sec=elapsed,
                    context=context,
                    error_code=err_code,
                    error_message=err_msg
                )
            except Exception as le_err:
                self.logger.debug(f"Learning engine recovery suggestion failed: {le_err}")

        return StageResult(
            stage_name=self.name,
            status="error",
            elapsed_sec=elapsed,
            error_message=err_msg,
            error_code=err_code,
            suggestions=suggestions,
            log_file=log_file if os.path.exists(log_file) else None
        )

    def run_stage(self, workspace: str, config: Optional[Dict[str, Any]] = None) -> StageResult:
        """Runs the stage in complete isolation with full logging, validation, error handling, and hooks."""
        cfg = config or {}
        t0 = time.time()
        context = {"workspace": workspace, "config": cfg, "t0": t0}

        # Initialize workspace logger
        self.logger = get_stage_logger(self.stage_id, self.name, workspace=workspace)
        self.logger.info(f"\033[1;36m=== [Stage {self.stage_id}: {self.name}] ===\033[0m")
        self.logger.debug(f"Aşama Başlatıldı. Amaç: {self.purpose}")

        # 1. Input Validation
        try:
            valid_in, in_msg = self.validate_inputs(workspace, cfg)
            if not valid_in:
                raise StageInputError(in_msg, stage_id=self.stage_id, context={"workspace": workspace})
        except Exception as e:
            return self.handle_error(e, context)

        # 2. Pre-hooks
        for h in self._pre_hooks:
            try:
                h(workspace, cfg)
            except Exception as e:
                self.logger.warning(f"Pre-hook uyarısı: {e}")

        # 3. Execution
        try:
            data = self.execute(workspace, cfg) or {}
        except Exception as e:
            return self.handle_error(e, context)

        # 4. Output Validation
        try:
            valid_out, out_msg = self.validate_outputs(workspace, cfg)
            if not valid_out:
                raise StageOutputError(out_msg, stage_id=self.stage_id, context={"workspace": workspace})
        except Exception as e:
            return self.handle_error(e, context)

        elapsed = time.time() - t0
        output_files = data.get("output_files", [])
        log_file = os.path.join(workspace, "logs", f"stage_{self.stage_id:02d}_{self.name}.log")

        result = StageResult(
            stage_name=self.name,
            status="success",
            elapsed_sec=elapsed,
            data=data,
            output_files=output_files,
            log_file=log_file if os.path.exists(log_file) else None
        )

        # 5. Post-hooks
        for h in self._post_hooks:
            try:
                h(result)
            except Exception as e:
                self.logger.warning(f"Post-hook uyarısı: {e}")

        # 6. Record success in Learning Engine
        if self.learning_engine:
            try:
                self.learning_engine.record_stage_run(
                    stage_id=self.stage_id,
                    stage_name=self.name,
                    status="success",
                    elapsed_sec=elapsed,
                    context=context,
                    data=data
                )
            except Exception as le_err:
                self.logger.debug(f"Learning engine record_stage_run failed: {le_err}")

        self.logger.info(f"\033[1;32m[OK]\033[0m {self.name} başarıyla tamamlandı ({elapsed:.2f}s).")
        return result
