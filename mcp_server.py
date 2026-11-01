#!/usr/bin/env python3
"""
mcp_server.py - Model Context Protocol (MCP) Server for GSS4
Exposes the IL2CPP offset extraction pipeline, profile management, and dump inspection tools
to AI assistants (Claude, Gemini, Antigravity, Cursor, etc.).

Usage:
    python mcp_server.py
"""

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

from mcp.server.mcpserver import MCPServer

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PROFILES_DIR = os.path.join(ROOT_DIR, "profiles")
SRC_HEADER = os.path.join(ROOT_DIR, "src", "core", "offsets.h")

# Initialize MCP Server
app = MCPServer("gss4-offset-pipeline")


# ==============================================================================
# TOOLS
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
        # Check test workspace
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
        format: Return format - 'json' for structured dict, 'header' for C++ text
    """
    ws = os.path.join(ROOT_DIR, "build", profile)
    if not os.path.exists(ws):
        ws = os.path.join(ROOT_DIR, "build", "test")

    if format == "json":
        json_path = os.path.join(ws, "offsets.json")
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        raise FileNotFoundError(f"offsets.json not found in {ws}")
    else:
        header_path = os.path.join(ws, "offsets.h")
        if not os.path.exists(header_path):
            header_path = SRC_HEADER
        if os.path.exists(header_path):
            with open(header_path, "r", encoding="utf-8") as f:
                return f.read()
        raise FileNotFoundError("offsets.h not found.")


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

    import subprocess
    cmd = [sys.executable, os.path.join(ROOT_DIR, "07_verify_diff", "verify_diff.py"),
           "--new", new_p, "--old", old_p]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    return res.stdout


# ==============================================================================
# RESOURCES
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


# ==============================================================================
# PROMPTS
# ==============================================================================

@app.prompt()
def analyze_game_update(game_name: str = "royale") -> str:
    """Prompt template for updating offsets when a game releases a new patch."""
    return f"""A new update was released for {game_name}. Follow these steps using the GSS4 MCP tools:
1. Call `get_profile(name='{game_name}')` to inspect the target configuration.
2. Call `run_pipeline(profile='{game_name}')` to pull the new APK, decrypt metadata, run Il2CppDumper, and generate new offsets.
3. Call `diff_offsets()` to review the changed RVAs, added fields, or removed symbols.
4. If the sanity gates pass cleanly, call `run_pipeline(profile='{game_name}', apply=True)` to update the C++ project header with automatic backup."""


def main():
    # Run MCP server using standard stdio transport
    app.run(transport="stdio")


if __name__ == "__main__":
    main()
