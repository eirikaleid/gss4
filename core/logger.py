"""
core/logger.py - Unified Stage & Pipeline Logging Subsystem for GSS4
Provides structured terminal logging (with ANSI styling) and per-stage persistent file logs.
"""

import logging
import os
import sys
from typing import Optional

# ANSI Colors
C_RESET = "\033[0m"
C_CYAN = "\033[1;36m"
C_GREEN = "\033[1;32m"
C_YELLOW = "\033[1;33m"
C_RED = "\033[1;31m"
C_GRAY = "\033[1;30m"
C_MAGENTA = "\033[1;35m"


class ColoredConsoleFormatter(logging.Formatter):
    """Format console logs with readable icons and ANSI colors."""

    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        if record.levelno >= logging.ERROR:
            prefix = f"{C_RED}[FAIL]{C_RESET}"
        elif record.levelno >= logging.WARNING:
            prefix = f"{C_YELLOW}[WARN]{C_RESET}"
        elif record.levelno == logging.INFO:
            if msg.startswith("[+]") or msg.startswith("[OK]") or msg.startswith("[*]"):
                prefix = ""
            else:
                prefix = f"{C_CYAN}[*]{C_RESET}"
        elif record.levelno <= logging.DEBUG:
            prefix = f"{C_GRAY}[DEBUG]{C_RESET}"
        else:
            prefix = f"[{record.levelname}]"

        formatted = f"{prefix} {msg}" if prefix else msg
        if record.exc_info:
            formatted += "\n" + self.formatException(record.exc_info)
        return formatted


class FileLogFormatter(logging.Formatter):
    """Detailed timestamped format for persistent log files."""

    def __init__(self):
        super().__init__(
            fmt="%(asctime)s [%(levelname)-7s] [%(name)s:%(lineno)d] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )


def get_stage_logger(
    stage_id: int,
    stage_name: str,
    workspace: Optional[str] = None,
    level: int = logging.INFO
) -> logging.Logger:
    """Creates or retrieves a logger configured for a specific stage.

    Logs to:
      1. Console (Standard Output / Error with colors)
      2. workspace/logs/stage_{stage_id:02d}_{stage_name}.log (Detailed persistent log)
      3. workspace/logs/pipeline.log (Unified master log)
    """
    logger_name = f"stage_{stage_id:02d}_{stage_name}"
    logger = logging.getLogger(logger_name)
    logger.setLevel(level)

    # Avoid duplicate handlers if already initialized
    if logger.handlers:
        return logger

    # 1. Console Handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(ColoredConsoleFormatter())
    logger.addHandler(ch)

    # 2. File Handlers (if workspace provided)
    if workspace:
        logs_dir = os.path.join(workspace, "logs")
        os.makedirs(logs_dir, exist_ok=True)

        # Stage-specific log file
        stage_log_path = os.path.join(logs_dir, f"{logger_name}.log")
        fh_stage = logging.FileHandler(stage_log_path, mode="a", encoding="utf-8")
        fh_stage.setLevel(logging.DEBUG)  # Always log DEBUG to file
        fh_stage.setFormatter(FileLogFormatter())
        logger.addHandler(fh_stage)

        # Pipeline master log file
        pipeline_log_path = os.path.join(logs_dir, "pipeline.log")
        fh_master = logging.FileHandler(pipeline_log_path, mode="a", encoding="utf-8")
        fh_master.setLevel(logging.DEBUG)
        fh_master.setFormatter(FileLogFormatter())
        logger.addHandler(fh_master)

    return logger
