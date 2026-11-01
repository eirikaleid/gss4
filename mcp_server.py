#!/usr/bin/env python3
"""
mcp_server.py - Model Context Protocol (MCP) Server for GSS4
Exposes the IL2CPP offset extraction pipeline, individual stages, profile management,
and dump inspection tools to AI assistants (Claude, Gemini, Antigravity, Cursor, etc.).

Usage:
    python mcp_server.py
"""

import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

from mcp.server.mcpserver import MCPServer

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILES_DIR = os.path.join(ROOT_DIR, "profiles")
SRC_HEADER = os.path.join(ROOT_DIR, "src", "core", "offsets.h")

# Initialize MCP Server
app = MCPServer("gss4-offset-pipeline")


# ==============================================================================
# PIPELINE & PROFILE TOOLS
# ==============================================================================

@app.tool()
def list_profiles() -> List[str]:
    """List all available application profile names in the GSS4 repository."""
    if not os.path.exists(PROFILES_DIR):
        return []
    profiles = []
    for f in os.listdir(PROFILES_DIR):
        if f.endswith(".json"):
            profiles.append(f[:-5])
    return sorted(profiles)


@app.tool()
def get_profile(name: str) -> Dict[str, Any]:
    """Retrieve the JSON configuration for a specific application profile.

    Args:
        name: Profile name (e.g. 'royale', 'template_generic')
    """
    path = os.path.join(PROFILES_DIR, f"{name}.json")
    if not os.path.exists(path):
        raise ValueError(f"Profile '{name}' not found at {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@app.tool()
def save_profile(name: str, config: Dict[str, Any]) -> str:
    """Create or update an application profile JSON file.

    Args:
        name: Profile name (e.g. 'my_game')
        config: Full profile configuration dictionary
    """
    os.makedirs(PROFILES_DIR, exist_ok=True)
    path = os.path.join(PROFILES_DIR, f"{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    return f"Profile successfully saved to: {path}"


@app.tool()
def run_pipeline(
    profile: str = "royale",
    package: Optional[str] = None,
    device: Optional[str] = "127.0.0.1:7555",
    arch: Optional[str] = "arm64-v8a",
    apk_paths: Optional[List[str]] = None,
    stage: Optional[int] = None,
    from_stage: int = 1,
    apply: bool = False,
    known: Optional[str] = None,
    workspace: Optional[str] = None
) -> Dict[str, Any]:
    """Execute the end-to-end offset extraction pipeline (or a single stage).

    Args:
        profile: Application profile name (e.g. 'royale', 'template_generic')
        package: Android package name override (e.g. 'net.f8games.royale')
        device: ADB device identifier (default: '127.0.0.1:7555')
        arch: Target ABI (e.g. 'arm64-v8a', 'armeabi-v7a')
        apk_paths: Optional list of local APK paths to bypass device pull
        stage: Run only a specific stage number (1..7), or None for all
        from_stage: Start execution from stage N (1..7, default: 1)
        apply: If True, copies verified header to destination (e.g. src/core/offsets.h)
        known: Known version tag for sanity assertion (e.g. '4.9')
        workspace: Custom build directory path
    """
    from run_pipeline import execute_pipeline

    try:
        result = execute_pipeline(
            profile=profile,
            package=package,
            device=device,
            arch=arch,
            apk=apk_paths,
            stage=stage,
            from_stage=from_stage,
            apply=apply,
            workspace=workspace,
            known=known
        )
        return result
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


# ==============================================================================
# INDIVIDUAL STAGE DEVELOPMENT TOOLS
# ==============================================================================

@app.tool()
def run_stage(
    stage_id: int,
    workspace: str,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Run an individual pipeline stage (1 to 7) in complete isolation for development and testing.

    Args:
        stage_id: Stage number (1: Pull, 2: Extract, 3: Decrypt, 4: Dump, 5: Native, 6: Parse, 7: Verify)
        workspace: Directory path where stage inputs and outputs reside
        config: Optional dictionary of stage parameters and overrides
    """
    cfg = config or {}
    stage_modules = {
        1: ("01_apk_pull.pull", "Stage1Pull"),
        2: ("02_extract.extract", "Stage2Extract"),
        3: ("03_decrypt_metadata.decrypt", "Stage3Decrypt"),
        4: ("04_il2cpp_dump.dump", "Stage4Dump"),
        5: ("05_native_analysis.analyze_native", "Stage5Native"),
        6: ("06_parse_offsets.parse_offsets", "Stage6Parse"),
        7: ("07_verify_diff.verify_diff", "Stage7Verify"),
    }

    if stage_id not in stage_modules:
        raise ValueError(f"Invalid stage_id: {stage_id}. Must be 1..7.")

    mod_name, cls_name = stage_modules[stage_id]
    import importlib
    mod = importlib.import_module(mod_name)
    stage_cls = getattr(mod, cls_name)
    stage_instance = stage_cls()
    result = stage_instance.run_stage(workspace, cfg)
    return result.to_dict()


@app.tool()
def run_stage_tests(stage_id: Optional[int] = None) -> Dict[str, Any]:
    """Execute unit tests for a specific stage or all stages (1..7).

    Args:
        stage_id: Target stage number (1..7), or None to run all stage test suites
    """
    from test_all_stages import STAGES

    results = {}
    targets = STAGES if stage_id is None else [STAGES[stage_id - 1]]

    for title, test_script in targets:
        proc = subprocess.run([sys.executable, test_script], cwd=os.path.dirname(test_script),
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        results[title] = {
            "status": "passed" if proc.returncode == 0 else "failed",
            "output": proc.stdout.strip()
        }

    return results


@app.tool()
def list_stage_plugins(stage_id: int) -> List[str]:
    """List available plugins/strategies/generators for an extensible stage.

    Args:
        stage_id: 3 for Decrypt Strategies, 6 for Code Generators
    """
    if stage_id == 3:
        strat_dir = os.path.join(ROOT_DIR, "03_decrypt_metadata", "strategies")
        return [f[:-3] for f in os.listdir(strat_dir) if f.endswith(".py") and not f.startswith("__")]
    elif stage_id == 6:
        gen_dir = os.path.join(ROOT_DIR, "06_parse_offsets", "generators")
        return [f[:-3] for f in os.listdir(gen_dir) if f.endswith(".py") and not f.startswith("__")]
    else:
        return [f"Stage {stage_id} uses core modular architecture."]


@app.tool()
def get_stage_info(stage_id: int) -> Dict[str, Any]:
    """Get full documentation, purpose, extension points, and troubleshooting guide for a specific stage.

    Args:
        stage_id: Stage number (1 to 7)
    """
    stage_modules = {
        1: ("01_apk_pull.pull", "Stage1Pull"),
        2: ("02_extract.extract", "Stage2Extract"),
        3: ("03_decrypt_metadata.decrypt", "Stage3Decrypt"),
        4: ("04_il2cpp_dump.dump", "Stage4Dump"),
        5: ("05_native_analysis.analyze_native", "Stage5Native"),
        6: ("06_parse_offsets.parse_offsets", "Stage6Parse"),
        7: ("07_verify_diff.verify_diff", "Stage7Verify"),
    }
    if stage_id not in stage_modules:
        raise ValueError(f"Invalid stage_id: {stage_id}. Must be 1..7.")

    mod_name, cls_name = stage_modules[stage_id]
    import importlib
    mod = importlib.import_module(mod_name)
    stage_cls = getattr(mod, cls_name)
    stage_inst = stage_cls()
    info = stage_inst.get_info()

    # Add plugin details
    if stage_id in (3, 6):
        info["plugins"] = list_stage_plugins(stage_id)

    return info


@app.tool()
def get_stage_logs(stage_id: int, profile: str = "royale", tail_lines: int = 50) -> Dict[str, Any]:
    """Retrieve the latest persistent log output for a specific stage.

    Args:
        stage_id: Stage number (1 to 7)
        profile: Application profile name (to locate workspace)
        tail_lines: Number of trailing log lines to read (default: 50)
    """
    ws = os.path.join(ROOT_DIR, "build", profile)
    logs_dir = os.path.join(ws, "logs")

    if not os.path.exists(logs_dir):
        return {"status": "no_logs", "message": f"Logs directory not found at {logs_dir}. Stage has not run yet."}

    # Find matching stage log
    stage_prefix = f"stage_{stage_id:02d}_"
    target_log = None
    for fn in os.listdir(logs_dir):
        if fn.startswith(stage_prefix) and fn.endswith(".log"):
            target_log = os.path.join(logs_dir, fn)
            break

    if not target_log or not os.path.exists(target_log):
        # Fallback to pipeline.log
        pipeline_log = os.path.join(logs_dir, "pipeline.log")
        if os.path.exists(pipeline_log):
            target_log = pipeline_log
        else:
            return {"status": "not_found", "message": f"No log file found matching {stage_prefix}* in {logs_dir}"}

    with open(target_log, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    return {
        "status": "success",
        "log_file": os.path.basename(target_log),
        "total_lines": len(lines),
        "lines": [l.rstrip() for l in lines[-tail_lines:]]
    }


# ==============================================================================
# DUMP INSPECTION & OFFSET TOOLS
# ==============================================================================

@app.tool()
def inspect_dump(
    query: str,
    profile: str = "royale",
    search_type: str = "class",
    max_results: int = 20
) -> List[str]:
    """Search for classes, methods, or fields inside the generated dump.cs without loading the entire 70MB file.

    Args:
        query: Search term (e.g. 'CharacterManager', 'GetPosition', 'Health')
        profile: Profile name to locate the dump folder (default: 'royale')
        search_type: Type of search - 'class', 'method', 'field', or 'any'
        max_results: Maximum matching lines to return (default: 20)
    """
    dump_path = os.path.join(ROOT_DIR, "build", profile, "dump", "dump.cs")
    if not os.path.exists(dump_path):
        alt_path = os.path.join(ROOT_DIR, "build", "test", "dump", "dump.cs")
        if os.path.exists(alt_path):
            dump_path = alt_path
        else:
            raise FileNotFoundError(f"dump.cs not found for profile '{profile}'. Run pipeline first.")

    q_lower = query.lower()
    matches = []

    with open(dump_path, "r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f, 1):
            line_str = line.strip()
            if not line_str:
                continue

            matched = False
            if search_type == "class" and ("class " in line or "struct " in line):
                matched = q_lower in line_str.lower()
            elif search_type == "method" and ("// RVA:" in line or "Offset:" in line or "(" in line):
                matched = q_lower in line_str.lower()
            elif search_type == "field" and "// 0x" in line:
                matched = q_lower in line_str.lower()
            elif search_type == "any":
                matched = q_lower in line_str.lower()

            if matched:
                matches.append(f"L{idx}: {line_str}")
                if len(matches) >= max_results:
                    break

    return matches


@app.tool()
def get_offsets(profile: str = "royale", format: str = "json") -> Any:
    """Retrieve the latest extracted offsets.

    Args:
        profile: Profile name (default: 'royale')
        format: Return format - 'json', 'header', 'rust', or 'csharp'
    """
    ws = os.path.join(ROOT_DIR, "build", profile)
    if not os.path.exists(ws):
        ws = os.path.join(ROOT_DIR, "build", "test")

    file_map = {
        "json": "offsets.json",
        "header": "offsets.h",
        "rust": "offsets.rs",
        "csharp": "Offsets.cs"
    }

    target_file = file_map.get(format, "offsets.json")
    target_path = os.path.join(ws, target_file)

    if not os.path.exists(target_path) and format == "header":
        target_path = SRC_HEADER

    if not os.path.exists(target_path):
        raise FileNotFoundError(f"{target_file} not found in {ws}")

    with open(target_path, "r", encoding="utf-8") as f:
        if format == "json":
            return json.load(f)
        return f.read()


@app.tool()
def diff_offsets(old_header: Optional[str] = None, new_header: Optional[str] = None) -> str:
    """Compare two offsets.h files and produce a diff report.

    Args:
        old_header: Path to old offsets.h (defaults to src/core/offsets.h)
        new_header: Path to new offsets.h (defaults to latest generated in build/)
    """
    old_p = old_header or SRC_HEADER
    new_p = new_header or os.path.join(ROOT_DIR, "build", "test", "offsets.h")

    if not os.path.exists(old_p) or not os.path.exists(new_p):
        return f"One or both files not found: old={old_p}, new={new_p}"

    cmd = [sys.executable, os.path.join(ROOT_DIR, "07_verify_diff", "verify_diff.py"),
           "--new", new_p, "--old", old_p]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    return res.stdout


# ==============================================================================
# RESOURCES & PROMPTS
# ==============================================================================

@app.resource("offsets://current")
def resource_current_offsets() -> str:
    """Returns the content of the currently applied src/core/offsets.h."""
    if os.path.exists(SRC_HEADER):
        with open(SRC_HEADER, "r", encoding="utf-8") as f:
            return f.read()
    return "// No offsets.h applied yet."


@app.resource("profiles://list")
def resource_profiles_list() -> str:
    """Returns the list of available profiles formatted as JSON."""
    return json.dumps(list_profiles(), indent=2)


@app.prompt()
def develop_stage(stage_id: int = 3) -> str:
    """Prompt template for developing or extending a specific stage."""
    return f"""You are developing GSS4 Stage {stage_id}. Follow these best practices:
1. Call `list_stage_plugins(stage_id={stage_id})` to see current modules.
2. Edit or add files in stage directory `0{stage_id}_.../`.
3. Call `run_stage_tests(stage_id={stage_id})` to verify your changes.
4. Call `run_stage(stage_id={stage_id}, workspace='build/test')` to run with real data."""


def main():
    app.run(transport="stdio")


if __name__ == "__main__":
    main()
