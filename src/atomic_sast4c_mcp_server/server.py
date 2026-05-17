import os
import re
import json
import uuid
import sys

from magika import Magika
from typing import Literal
from pathlib import Path
from tempfile import gettempdir
from fastmcp import FastMCP
from subprocess import check_output, CalledProcessError

from atomic_sast_mcp_common import dependency_report, ensure_dependency_report, missing_command_error


mcp = FastMCP("Local-Atomic-SAST-C")
file_type_mapping_by_project = dict()


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
        "name": "weggli",
        "type": "cli",
        "required": True,
        "command": "weggli",
        "install_hint": "Install weggli and ensure weggli is on PATH.",
    },
    {
        "name": "ripgrep",
        "type": "cli",
        "required": True,
        "command": "rg",
        "install_hint": "Install ripgrep and ensure rg is on PATH.",
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


@mcp.tool("collect_files_types")
def collect_files_types(analyzing_directory: str):
    """Collect all file types in the analyzing directory

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
    """
    m = Magika()
    if analyzing_directory in file_type_mapping_by_project.keys():
        return file_type_mapping_by_project[analyzing_directory]
    file_type_mapping_by_project[analyzing_directory] = dict()
    for root, dirs, files in os.walk(analyzing_directory):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.islink(file_path):
                continue
            result = m.identify_path(file_path)
            file_type_mapping_by_project[analyzing_directory].setdefault(result.output.label, []).append(file_path)
    return file_type_mapping_by_project[analyzing_directory]


def get_function_definition_by_semgrep(analyzing_directory: str, function_name: str):
    missing = _missing_command_error("semgrep")
    if missing:
        return missing
    function_name = _safe_filename_part(function_name)
    semgrep_rules_directory = _semgrep_rules_directory()
    output_file_path = os.path.join(gettempdir(), f'semgrep_{uuid.uuid4().hex}.json')
    find_function_definition_rule = os.path.join(semgrep_rules_directory, "get_function_definition.yaml")
    temp_find_function_definition_rule = os.path.join(gettempdir(), f'semgrep_get_{function_name}_{uuid.uuid4().hex}.yaml')
    with open(find_function_definition_rule, 'r') as f_r:
        content = f_r.read()
        content = content.replace("$FUNCTION", function_name)
        with open(temp_find_function_definition_rule, 'w') as f_w:
            f_w.write(content)
    try:
        _ = check_output(
            [
                "semgrep", "scan",
                "--config", f"{temp_find_function_definition_rule}",
                "--quiet", "--json", f"--json-output={output_file_path}",
                analyzing_directory
            ], shell=False
        )
        with open(output_file_path, 'r') as f:
            semgrep_results: dict = json.load(f)
            llm_readable_results = list()
            if "results" in semgrep_results.keys():
                for result in semgrep_results["results"]:
                    llm_readable_results.append({
                        "definition": result["extra"]["lines"],
                        "path": result["path"],
                        "code_line_range": [result["start"]["line"], result["end"]["line"]]
                    })
                return llm_readable_results
            else:
                return {"error": f"Semgrep scan failed: {semgrep_results}"}
    except CalledProcessError as e:
        return {"error": f"Semgrep scan failed: {e.output.decode('utf-8')}"}
    except FileNotFoundError as e:
        return {"error": f"Semgrep output file not found: {output_file_path} with {str(e)}"}


def get_function_definition_by_astgrep(analyzing_directory: str, function_name: str):
    missing = _missing_command_error("ast-grep")
    if missing:
        return missing
    astgrep_raw_rule = "$$$TYPE $FUNCTION($$$PARAMS) { $$$BODY }".replace("$FUNCTION", function_name)
    try:
        astgrep_raw_results = check_output(
            [
                "ast-grep", "run", "-p", astgrep_raw_rule, "--lang", "c", "--json", "."
            ], shell=False, cwd=analyzing_directory
        )
        try:
            astgrep_tmp_results = json.loads(astgrep_raw_results)
            llm_readable_results = list()
            for result in astgrep_tmp_results:
                llm_readable_results.append({
                    "definition": result["text"],
                    "path": result["file"],
                    "code_line_range": [result["range"]["start"]["line"], result["range"]["end"]["line"]]
                })
            return llm_readable_results
        except json.JSONDecodeError as e:
            return {"error": f"Ast-grep failed to provide a valid json: {astgrep_raw_results} with {e}"}
        except KeyError as e:
            return {"error": f"Ast-grep failed to provide a complete json: {astgrep_raw_results} with {e}"}
    except CalledProcessError as e:
        return {"error": f"Ast-grep scan failed: {e.output.decode('utf-8')}"}


@mcp.tool("get_function_definition")
def get_function_definition(analyzing_directory: str, function_name: str):
    """Get the definition of the function in the analyzing directory

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
        function_name: The name of the function to get the definition
    """
    astgrep_result = get_function_definition_by_astgrep(analyzing_directory, function_name)
    if isinstance(astgrep_result, list) and len(astgrep_result) == 0:
        return get_function_definition_by_semgrep(analyzing_directory, function_name)
    if isinstance(astgrep_result, dict) and "error" in astgrep_result.keys():
        return get_function_definition_by_semgrep(analyzing_directory, function_name)
    else:
        return astgrep_result


@mcp.tool("get_variable_definition")
def get_variable_definition(analyzing_directory: str, variable_name: str):
    """Get the definition of the global variable in the analyzing directory

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
        variable_name: The name of the variable to get the definition
    """
    missing = _missing_command_error("semgrep")
    if missing:
        return missing
    safe_variable_name = _safe_filename_part(variable_name)
    semgrep_rules_directory = _semgrep_rules_directory()
    output_file_path = os.path.join(gettempdir(), f'semgrep_{uuid.uuid4().hex}.json')
    find_variable_definition_rule = os.path.join(semgrep_rules_directory, "get_variable_definition.yaml")
    temp_find_variable_definition_rule = os.path.join(gettempdir(), f'semgrep_get_{safe_variable_name}_{uuid.uuid4().hex}.yaml')
    with open(find_variable_definition_rule, 'r') as f_r:
        content = f_r.read()
        content = content.replace("$VAR_NAME", variable_name)
        with open(temp_find_variable_definition_rule, 'w') as f_w:
            f_w.write(content)
    try:
        _ = check_output(
            [
                "semgrep", "scan",
                "--config", f"{temp_find_variable_definition_rule}",
                "--quiet", "--json", f"--json-output={output_file_path}",
                analyzing_directory
            ], shell=False
        )
        with open(output_file_path, 'r') as f:
            semgrep_results: dict = json.load(f)
            llm_readable_results = []
            if "results" in semgrep_results.keys():
                for result in semgrep_results["results"]:
                    llm_readable_results.append({
                        "type": result["extra"]["metavars"]["$TYPE"]["abstract_content"],
                        "value": result["extra"]["metavars"]["$VALUE"]["abstract_content"],
                        "path": result["path"],
                        "code_line_range": [result["start"]["line"], result["end"]["line"]]
                    })
                return llm_readable_results
            else:
                return {"error": f"Semgrep scan failed: {semgrep_results}"}
    except CalledProcessError as e:
        return {"error": f"Semgrep scan failed: {e.output.decode('utf-8')}"}
    except FileNotFoundError as e:
        return {"error": f"Semgrep output file not found: {output_file_path} with {str(e)}"}



@mcp.tool("get_macro_definition")
def get_macro_definition(analyzing_directory: str, macro_name: str):
    """Get the definition of the macro in the analyzing directory

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
        macro_name: The name of the macro to get the definition
    """
    missing = _missing_command_error("semgrep")
    if missing:
        return missing
    macro_name = _safe_filename_part(macro_name)
    semgrep_rules_directory = _semgrep_rules_directory()
    output_file_path = os.path.join(gettempdir(), f'semgrep_{uuid.uuid4().hex}.json')
    find_macro_definition_rule = os.path.join(semgrep_rules_directory, "get_macro_definition.yaml")
    temp_find_macro_definition_rule = os.path.join(gettempdir(), f'semgrep_get_{macro_name}_{uuid.uuid4().hex}.yaml')
    with open(find_macro_definition_rule, 'r') as f_r:
        content = f_r.read()
        content = content.replace("$MACRO", macro_name)
        with open(temp_find_macro_definition_rule, 'w') as f_w:
            f_w.write(content)
    try:
        _ = check_output(
            [
                "semgrep", "scan",
                "--config", f"{temp_find_macro_definition_rule}",
                "--quiet", "--json", f"--json-output={output_file_path}",
                analyzing_directory
            ], shell=False
        )
        with open(output_file_path, 'r') as f:
            semgrep_results: dict = json.load(f)
            llm_readable_results = []
            if "results" in semgrep_results.keys():
                for result in semgrep_results["results"]:
                    llm_readable_results.append({
                        "definition": result["extra"]["lines"],
                        "path": result["path"],
                        "code_line_range": [result["start"]["line"], result["end"]["line"]]
                    })
                return llm_readable_results
            else:
                return {"error": f"Semgrep scan failed: {semgrep_results}"}
    except CalledProcessError as e:
        return {"error": f"Semgrep scan failed: {e.output.decode('utf-8')}"}
    except FileNotFoundError as e:
        return {"error": f"Semgrep output file not found: {output_file_path} with {str(e)}"}


@mcp.tool("get_structure_definition")
def get_structure_definition(project_root_directory: str, structure_name: str):
    """Get the definition of the structure in the project root directory

    Args:
        project_root_directory: The project root directory, which must be an absolute path
        structure_name: The name of the structure to get the definition
    """
    missing = _missing_command_error("semgrep")
    if missing:
        return missing
    structure_name = _safe_filename_part(structure_name)
    semgrep_rules_directory = _semgrep_rules_directory()
    output_file_path = os.path.join(gettempdir(), f'semgrep_{uuid.uuid4().hex}.json')
    find_structure_definition_rule = os.path.join(semgrep_rules_directory, "get_structure_definition.yaml")
    temp_find_structure_definition_rule = os.path.join(gettempdir(), f'semgrep_get_{structure_name}_{uuid.uuid4().hex}.yaml')
    with open(find_structure_definition_rule, 'r') as f_r:
        content = f_r.read()
        content = content.replace("$STRUCTURE", structure_name)
        with open(temp_find_structure_definition_rule, 'w') as f_w:
            f_w.write(content)
    try:
        _ = check_output(
            [
                "semgrep", "scan",
                "--config", f"{temp_find_structure_definition_rule}",
                "--quiet", "--json", f"--json-output={output_file_path}",
                project_root_directory
            ], shell=False
        )
        with open(output_file_path, 'r') as f:
            semgrep_results: dict = json.load(f)
            llm_readable_results = []
            if "results" in semgrep_results.keys():
                for result in semgrep_results["results"]:
                    llm_readable_results.append({
                        "definition": result["extra"]["lines"],
                        "path": result["path"],
                        "code_line_range": [result["start"]["line"], result["end"]["line"]]
                    })
                return llm_readable_results
            else:
                return {"error": f"Semgrep scan failed: {semgrep_results}"}
    except CalledProcessError as e:
        return {"error": f"Semgrep scan failed: {e.output.decode('utf-8')}"}
    except FileNotFoundError as e:
        return {"error": f"Semgrep output file not found: {output_file_path} with {str(e)}"}


@mcp.tool("get_function_call")
def get_function_call(analyzing_directory: str, role: Literal["caller", "callee"], function_name: str):
    """Get all caller-callee relationship in the analyzing directory

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
        role: The role of the function to get, must be "caller" or "callee"
        function_name: The name of the function to get the caller-callee relationship
    """
    missing = _missing_command_error("weggli")
    if missing:
        return missing
    weggli_raw_rule = '_ $caller{$callee(_);}'.replace('$callee', function_name) if role == "caller" else '_ $caller{$callee(_);}'.replace('$caller', function_name)
    try:
        weggli_result = check_output(
            [
                "weggli", weggli_raw_rule, ".", "-f", "-C"
            ], shell=False, cwd=analyzing_directory
        ).decode()
        function_set = set(re.findall(r'\x1b\[31m(.*?)\x1b\[0m', weggli_result)) - {function_name}
        return list(function_set)
    except CalledProcessError as e:
        return {"error": f"Weggli scan failed: {e.output.decode('utf-8')}"}


@mcp.tool("get_variable_consumer")
def get_variable_consumer(analyzing_directory: str, variable_name: str):
    """Get all functions that consume the variable in the analyzing directory

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
        variable_name: The name of the variable to get the consumer
    """
    missing = _missing_command_error("weggli")
    if missing:
        return missing
    weggli_raw_rule = '_ $caller{$variable(_);}'.replace('$variable', variable_name)
    try:
        weggli_result = check_output(
            [
                "weggli", weggli_raw_rule, ".", "-f", "-C"
            ], shell=False, cwd=analyzing_directory
        ).decode()
        function_set = set(re.findall(r'\x1b\[31m(.*?)\x1b\[0m', weggli_result))
        return list(function_set)
    except CalledProcessError as e:
        return {"error": f"Weggli scan failed: {e.output.decode('utf-8')}"}


@mcp.tool("grep_code")
def grep_code(analyzing_directory: str, pattern: str, context_range: int = 50):
    """Use RipGrep to find matched code in the analyzing directory, mostly used to find function definition after "get_function_definition" failure.

    Args:
        analyzing_directory: The directory to analyze, which must be an absolute path
        pattern: The pattern to grep, which can be a regex pattern or a word, e.g. abc or 'abc|def|ghi'
        context_range: The number of lines to grep after the hit, default is 10 lines up and down
    """
    missing = _missing_command_error("rg")
    if missing:
        return missing
    try:
        grep_results = check_output(
            ["rg", "-n", "-A", str(context_range), pattern, "."],
            shell=False, cwd=analyzing_directory
        ).decode()
        return grep_results
    except CalledProcessError as e:
        return {"error": f"RipGrep failed: {e.output.decode('utf-8')}"}


def main():
    dependency_result = ensure_dependency_report(DEPENDENCY_CHECKS, auto_install=True)
    missing_required = [
        item for item in dependency_result["dependencies"]
        if item["required"] and not item["available"]
    ]
    if missing_required:
        names = ", ".join(item["name"] for item in missing_required)
        print(
            f"atomic-sast-mcp-server dependency warning: missing {names}. "
            "Automatic installation failed or could not find a usable installer. "
            "Check startup logs for installation details.",
            file=sys.stderr,
        )
    mcp.run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
