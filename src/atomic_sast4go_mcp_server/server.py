import json
import os
import re
import sys
import uuid
from pathlib import Path
from subprocess import CalledProcessError, check_output
from tempfile import gettempdir
from typing import Literal

from fastmcp import FastMCP
from magika import Magika

from atomic_sast_mcp_common import dependency_report, ensure_dependency_report, missing_command_error


mcp = FastMCP("Local-Atomic-SAST-Go")
file_type_mapping_by_project = {}


DEPENDENCY_CHECKS = [
    {
        "name": "magika",
        "type": "python",
        "required": True,
        "checker": "magika",
        "install_hint": "Installed automatically from pyproject.toml.",
    },
    {
        "name": "semgrep",
        "type": "cli",
        "required": True,
        "command": "semgrep",
        "install_hint": "Install semgrep CLI and ensure semgrep is on PATH.",
    },
    {
        "name": "ast-grep",
        "type": "cli",
        "required": True,
        "command": "ast-grep",
        "install_hint": "Install ast-grep CLI and ensure ast-grep is on PATH.",
    },
    {
        "name": "ripgrep",
        "type": "cli",
        "required": True,
        "command": "rg",
        "install_hint": "Install ripgrep and ensure rg is on PATH.",
    },
    {
        "name": "go",
        "type": "cli",
        "required": False,
        "command": "go",
        "install_hint": "Install the Go toolchain if go-aware analysis is needed.",
    },
]


def _safe_filename_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def _semgrep_rules_directory() -> str:
    return str(Path(__file__).with_name("rules") / "semgrep")


def _dependency_report() -> list[dict]:
    return dependency_report(DEPENDENCY_CHECKS)


def _missing_command_error(command: str) -> dict | None:
    return missing_command_error(command, DEPENDENCY_CHECKS)


def _decode_process_output(error: CalledProcessError) -> str:
    output = error.output or error.stderr or b""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return str(output)


def _line_range(result: dict) -> list[int]:
    start = result.get("range", {}).get("start", {}).get("line", 0)
    end = result.get("range", {}).get("end", {}).get("line", start)
    return [start + 1, end + 1]


def _run_astgrep(analyzing_directory: str, pattern: str, text_key: str = "definition") -> list[dict] | dict:
    missing = _missing_command_error("ast-grep")
    if missing:
        return missing
    try:
        raw_results = check_output(
            ["ast-grep", "run", "-p", pattern, "--lang", "go", "--json", "."],
            shell=False,
            cwd=analyzing_directory,
        )
    except CalledProcessError as error:
        output = _decode_process_output(error)
        try:
            results = json.loads(output)
        except json.JSONDecodeError:
            return {"error": f"Ast-grep scan failed: {output}"}
    except json.JSONDecodeError as error:
        return {"error": f"Ast-grep failed to provide a valid json: {error}"}
    else:
        try:
            results = json.loads(raw_results)
        except json.JSONDecodeError as error:
            return {"error": f"Ast-grep failed to provide a valid json: {error}"}

    llm_readable_results = []
    for result in results:
        try:
            llm_readable_results.append(
                {
                    text_key: result["text"],
                    "path": result["file"],
                    "code_line_range": _line_range(result),
                }
            )
        except KeyError as error:
            return {"error": f"Ast-grep failed to provide a complete json result: {error}"}
    return llm_readable_results


def _run_semgrep_rule(
    analyzing_directory: str,
    rule_filename: str,
    replacements: dict[str, str],
) -> list[dict] | dict:
    missing = _missing_command_error("semgrep")
    if missing:
        return missing

    semgrep_rules_directory = _semgrep_rules_directory()
    output_file_path = os.path.join(gettempdir(), f"semgrep_{uuid.uuid4().hex}.json")
    rule_path = os.path.join(semgrep_rules_directory, rule_filename)
    safe_name = "_".join(_safe_filename_part(value) for value in replacements.values())
    temp_rule_path = os.path.join(gettempdir(), f"semgrep_go_{safe_name}_{uuid.uuid4().hex}.yaml")

    with open(rule_path) as rule_file:
        content = rule_file.read()
    for key, value in replacements.items():
        content = content.replace(key, value)
    with open(temp_rule_path, "w") as temp_rule_file:
        temp_rule_file.write(content)

    try:
        check_output(
            [
                "semgrep",
                "scan",
                "--config",
                temp_rule_path,
                "--quiet",
                "--json",
                f"--json-output={output_file_path}",
                analyzing_directory,
            ],
            shell=False,
        )
        with open(output_file_path) as output_file:
            semgrep_results: dict = json.load(output_file)
    except CalledProcessError as error:
        return {"error": f"Semgrep scan failed: {_decode_process_output(error)}"}
    except FileNotFoundError as error:
        return {"error": f"Semgrep output file not found: {output_file_path} with {error}"}
    except json.JSONDecodeError as error:
        return {"error": f"Semgrep failed to provide a valid json: {error}"}

    if "results" not in semgrep_results:
        return {"error": f"Semgrep scan failed: {semgrep_results}"}

    return [
        {
            "definition": result["extra"]["lines"],
            "path": result["path"],
            "code_line_range": [result["start"]["line"], result["end"]["line"]],
        }
        for result in semgrep_results["results"]
    ]


def _astgrep_or_semgrep(
    analyzing_directory: str,
    astgrep_patterns: list[str],
    semgrep_rule: str,
    replacements: dict[str, str],
) -> list[dict] | dict:
    astgrep_errors = []
    for pattern in astgrep_patterns:
        result = _run_astgrep(analyzing_directory, pattern)
        if isinstance(result, list) and result:
            return result
        if isinstance(result, dict) and "error" in result:
            astgrep_errors.append(result["error"])

    semgrep_result = _run_semgrep_rule(analyzing_directory, semgrep_rule, replacements)
    if isinstance(semgrep_result, list) and semgrep_result:
        return semgrep_result
    if isinstance(semgrep_result, dict) and "error" in semgrep_result and astgrep_errors:
        semgrep_result["astgrep_errors"] = astgrep_errors
    return semgrep_result


@mcp.tool("check_dependencies")
def check_dependencies(auto_install: bool = True, install_optional: bool = False):
    """Check dependencies and install missing required CLI tools when auto_install is true.

    Args:
        auto_install: Whether to install missing required dependencies automatically
        install_optional: Whether to also install optional dependencies automatically
    """
    return ensure_dependency_report(
        DEPENDENCY_CHECKS,
        auto_install=auto_install,
        install_optional=install_optional,
    )


@mcp.tool("collect_files_types")
def collect_files_types(analyzing_directory: str):
    """Collect all file types in the analyzing directory.

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
    """
    m = Magika()
    if analyzing_directory in file_type_mapping_by_project:
        return file_type_mapping_by_project[analyzing_directory]
    file_type_mapping_by_project[analyzing_directory] = {}
    for root, _, files in os.walk(analyzing_directory):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.islink(file_path):
                continue
            result = m.identify_path(file_path)
            file_type_mapping_by_project[analyzing_directory].setdefault(result.output.label, []).append(file_path)
    return file_type_mapping_by_project[analyzing_directory]


@mcp.tool("get_function_definition")
def get_function_definition(analyzing_directory: str, function_name: str):
    """Get Go free function definitions by name.

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
        function_name: The function name to find
    """
    patterns = [
        f"func {function_name}($$$PARAMS) $$$RET {{ $$$BODY }}",
        f"func {function_name}($$$PARAMS) {{ $$$BODY }}",
    ]
    return _astgrep_or_semgrep(
        analyzing_directory,
        patterns,
        "get_function_definition.yaml",
        {"$FUNCTION": function_name},
    )


@mcp.tool("get_method_definition")
def get_method_definition(analyzing_directory: str, method_name: str, receiver_type: str = ""):
    """Get Go method definitions by method name and optional receiver type.

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
        method_name: The method name to find
        receiver_type: Optional receiver type name, such as Client or *Client
    """
    if receiver_type:
        receiver_type = receiver_type.strip()
        patterns = [
            f"func ($$$RECEIVER {receiver_type}) {method_name}($$$PARAMS) $$$RET {{ $$$BODY }}",
            f"func ($$$RECEIVER {receiver_type}) {method_name}($$$PARAMS) {{ $$$BODY }}",
        ]
    else:
        patterns = [
            f"func ($$$RECEIVER $$$TYPE) {method_name}($$$PARAMS) $$$RET {{ $$$BODY }}",
            f"func ($$$RECEIVER $$$TYPE) {method_name}($$$PARAMS) {{ $$$BODY }}",
        ]
    return _astgrep_or_semgrep(
        analyzing_directory,
        patterns,
        "get_function_definition.yaml",
        {"$FUNCTION": method_name},
    )


@mcp.tool("get_struct_definition")
def get_struct_definition(analyzing_directory: str, struct_name: str):
    """Get Go struct type definitions by name.

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
        struct_name: The struct type name to find
    """
    patterns = [
        f"type {struct_name} struct {{ $$$BODY }}",
    ]
    return _astgrep_or_semgrep(
        analyzing_directory,
        patterns,
        "get_type_definition.yaml",
        {"$TYPE": struct_name},
    )


@mcp.tool("get_interface_definition")
def get_interface_definition(analyzing_directory: str, interface_name: str):
    """Get Go interface type definitions by name.

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
        interface_name: The interface type name to find
    """
    patterns = [
        f"type {interface_name} interface {{ $$$BODY }}",
    ]
    return _astgrep_or_semgrep(
        analyzing_directory,
        patterns,
        "get_type_definition.yaml",
        {"$TYPE": interface_name},
    )


@mcp.tool("get_type_definition")
def get_type_definition(analyzing_directory: str, type_name: str):
    """Get Go type definitions, including struct, interface, alias, or named primitive types.

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
        type_name: The type name to find
    """
    patterns = [
        f"type {type_name} struct {{ $$$BODY }}",
        f"type {type_name} interface {{ $$$BODY }}",
        f"type {type_name} $$$TARGET",
    ]
    return _astgrep_or_semgrep(
        analyzing_directory,
        patterns,
        "get_type_definition.yaml",
        {"$TYPE": type_name},
    )


@mcp.tool("get_function_call")
def get_function_call(
    analyzing_directory: str,
    function_name: str,
    context_range: int = 2,
    role: Literal["callee"] = "callee",
):
    """Find Go call sites for a callee function or method name.

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
        function_name: The callee function or method name to find
        context_range: The number of context lines around each match
        role: Only "callee" is supported for Go in this server version
    """
    if role != "callee":
        return {"error": "Go caller discovery is not supported yet; use role='callee' to find call sites."}

    patterns = [
        f"{function_name}($$$ARGS)",
        f"$$$RECEIVER.{function_name}($$$ARGS)",
    ]
    call_sites = []
    errors = []
    seen = set()
    for pattern in patterns:
        result = _run_astgrep(analyzing_directory, pattern, text_key="call")
        if isinstance(result, dict) and "error" in result:
            errors.append(result["error"])
            continue
        for item in result:
            key = (item["path"], tuple(item["code_line_range"]), item["call"])
            if key not in seen:
                seen.add(key)
                call_sites.append(item)
    if call_sites:
        return call_sites

    missing = _missing_command_error("rg")
    if missing:
        return {"error": "; ".join(errors + [missing["error"]])}

    grep_pattern = rf"(\.\s*{re.escape(function_name)}|\b{re.escape(function_name)})\s*\("
    try:
        grep_results = check_output(
            ["rg", "-n", "--glob", "*.go", grep_pattern, "."],
            shell=False,
            cwd=analyzing_directory,
        ).decode("utf-8", errors="replace")
    except CalledProcessError as error:
        message = f"RipGrep failed: {_decode_process_output(error)}"
        return {"error": "; ".join(errors + [message])}

    call_candidates = []
    for line in grep_results.splitlines():
        match = re.match(r"^(.*?):(\d+):(.*)$", line)
        if not match:
            continue
        path, line_number, code = match.groups()
        stripped_code = code.strip()
        if stripped_code.startswith(("func ", "type ")):
            continue
        if re.match(rf"^{re.escape(function_name)}\s*\([^)]*\)\s*[\w*.[\]]*$", stripped_code):
            continue
        call_candidates.append(
            {
                "call": stripped_code,
                "path": path,
                "code_line_range": [int(line_number), int(line_number)],
            }
        )
    return call_candidates


@mcp.tool("grep_code")
def grep_code(analyzing_directory: str, pattern: str, context_range: int = 50):
    """Use RipGrep to find matched Go code in the analyzing directory.

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
        pattern: The regex pattern or word to search
        context_range: The number of context lines around each match
    """
    missing = _missing_command_error("rg")
    if missing:
        return missing
    try:
        return check_output(
            ["rg", "-n", "-A", str(context_range), "--glob", "*.go", pattern, "."],
            shell=False,
            cwd=analyzing_directory,
        ).decode("utf-8", errors="replace")
    except CalledProcessError as error:
        return {"error": f"RipGrep failed: {_decode_process_output(error)}"}


def main():
    missing_required = [
        item for item in _dependency_report()
        if item["required"] and not item["available"]
    ]
    if missing_required:
        names = ", ".join(item["name"] for item in missing_required)
        print(
            f"atomic-sast4go-mcp-server dependency warning: missing {names}. "
            "Use the check_dependencies MCP tool for details.",
            file=sys.stderr,
        )
    mcp.run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
