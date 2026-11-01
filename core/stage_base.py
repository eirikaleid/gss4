"""
core/stage_base.py - Standard Base Interface & Lifecycle for GSS4 Stages
Provides an isolated, extensible lifecycle for each stage:
- Input validation
- Pre-execution hooks
- Core execution
- Output validation
- Post-execution hooks
"""

import abc
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class StageResult:
    stage_name: str
    status: str  # "success" or "error"
    elapsed_sec: float
    data: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    output_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_name": self.stage_name,
            "status": self.status,
            "elapsed_sec": round(self.elapsed_sec, 3),
            "data": self.data,
            "error_message": self.error_message,
            "output_files": self.output_files
        }


class BaseStage(abc.ABC):
    """Abstract Base Class for every pipeline stage.

    Subclasses must implement:
        - stage_id (int): 1 through 7
        - name (str): stage name (e.g. '01_apk_pull')
        - execute(workspace, config) -> dict
    """

    stage_id: int = 0
    name: str = "base_stage"
    description: str = "Base stage description"

    def __init__(self):
        self._pre_hooks: List[Callable[[str, Dict[str, Any]], None]] = []
        self._post_hooks: List[Callable[[StageResult], None]] = []

    def before_run(self, hook: Callable[[str, Dict[str, Any]], None]):
        """Register a callback hook before stage executes."""
        self._pre_hooks.append(hook)
        return hook

    def after_run(self, hook: Callable[[StageResult], None]):
        """Register a callback hook after stage finishes."""
        self._post_hooks.append(hook)
        return hook

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

    def run_stage(self, workspace: str, config: Optional[Dict[str, Any]] = None) -> StageResult:
        """Runs the stage in complete isolation with full validation and hooks."""
        cfg = config or {}
        t0 = time.time()
        print(f"\n\033[1;36m=== [Stage {self.stage_id}: {self.name}] ===\033[0m")

        # 1. Input Validation
        valid_in, in_msg = self.validate_inputs(workspace, cfg)
        if not valid_in:
            err = f"Input validation failed for {self.name}: {in_msg}"
            print(f"\033[1;31m[FAIL]\033[0m {err}", file=sys.stderr)
            return StageResult(self.name, "error", time.time() - t0, error_message=err)

        # 2. Pre-hooks
        for h in self._pre_hooks:
            try:
                h(workspace, cfg)
            except Exception as e:
                print(f"[WARN] Pre-hook error in {self.name}: {e}", file=sys.stderr)

        # 3. Execution
        try:
            data = self.execute(workspace, cfg) or {}
        except Exception as e:
            err = f"Execution error in {self.name}: {e}"
            print(f"\033[1;31m[FAIL]\033[0m {err}", file=sys.stderr)
            return StageResult(self.name, "error", time.time() - t0, error_message=err)

        # 4. Output Validation
        valid_out, out_msg = self.validate_outputs(workspace, cfg)
        if not valid_out:
            err = f"Output validation failed for {self.name}: {out_msg}"
            print(f"\033[1;31m[FAIL]\033[0m {err}", file=sys.stderr)
            return StageResult(self.name, "error", time.time() - t0, error_message=err)

        elapsed = time.time() - t0
        output_files = data.get("output_files", [])
        result = StageResult(self.name, "success", elapsed, data=data, output_files=output_files)

        # 5. Post-hooks
        for h in self._post_hooks:
            try:
                h(result)
            except Exception as e:
                print(f"[WARN] Post-hook error in {self.name}: {e}", file=sys.stderr)

        print(f"\033[1;32m[OK]\033[0m {self.name} completed successfully in {elapsed:.2f}s.")
        return result
