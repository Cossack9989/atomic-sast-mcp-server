import importlib.util
import shutil
import subprocess
import sys
from collections.abc import Sequence
from typing import Any


DependencySpec = dict[str, Any]
DependencyReport = dict[str, Any]
InstallPlan = dict[str, Any]


def dependency_report(dependencies: Sequence[DependencySpec]) -> list[DependencyReport]:
    report = []
    for dependency in dependencies:
        details = {
            "name": dependency["name"],
            "type": dependency["type"],
            "required": dependency.get("required", True),
            "available": True,
            "install_hint": dependency["install_hint"],
        }
        checker = dependency.get("checker")
        command = dependency.get("command")
        if checker:
            details["python_module_available"] = importlib.util.find_spec(checker) is not None
            details["available"] = details["available"] and details["python_module_available"]
        if command:
            command_path = shutil.which(command)
            details["command"] = command
            details["command_path"] = command_path
            details["command_available"] = command_path is not None
            details["available"] = details["available"] and details["command_available"]
        report.append(details)
    return report


def missing_command_error(command: str, dependencies: Sequence[DependencySpec]) -> dict | None:
    if shutil.which(command):
        return None
    dependency = next(
        (item for item in dependencies if item.get("command") == command),
        None,
    )
    hint = dependency["install_hint"] if dependency else f"Install {command} and ensure it is on PATH."
    return {"error": f"Required command '{command}' is not available. {hint}"}


def _current_platform() -> str:
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform.startswith(("win32", "cygwin", "msys")):
        return "windows"
    return sys.platform


def _command_plan(command: list[str], platforms: set[str] | None = None) -> InstallPlan:
    return {"command": command, "platforms": platforms}


def _default_install_plans(command: str) -> list[InstallPlan]:
    plans = {
        "semgrep": [
            _command_plan([sys.executable, "-m", "pip", "install", "semgrep"]),
            _command_plan([sys.executable, "-m", "pip", "install", "semgrep", "--break-system-packages"]),
            _command_plan(["uv", "tool", "install", "semgrep"]),
            _command_plan(["pipx", "install", "semgrep"]),
        ],
        "ast-grep": [
            _command_plan([sys.executable, "-m", "pip", "install", "ast-grep-cli"]),
            _command_plan([sys.executable, "-m", "pip", "install", "ast-grep-cli", "--break-system-packages"]),
            _command_plan(["npm", "install", "--global", "@ast-grep/cli"]),
            _command_plan(["cargo", "install", "ast-grep", "--locked"]),
            _command_plan(["brew", "install", "ast-grep"], {"darwin"}),
        ],
        "rg": [
            _command_plan(["apt", "install", "-y", "ripgrep"]),
            _command_plan(["cargo", "install", "ripgrep"]),
            _command_plan(["brew", "install", "ripgrep"], {"darwin"}),
            _command_plan(["choco", "install", "ripgrep"], {"windows"}),
            _command_plan(["scoop", "install", "ripgrep"], {"windows"}),
            _command_plan(["winget", "install", "BurntSushi.ripgrep.MSVC"], {"windows"})
        ],
        "weggli": [
            _command_plan(["cargo", "install", "weggli"]),
            _command_plan(["brew", "install", "weggli"], {"darwin"}),
        ],
    }
    return plans.get(command, [])


def _normalize_install_plan(raw_plan: Any) -> InstallPlan:
    if isinstance(raw_plan, dict):
        return raw_plan
    return _command_plan(list(raw_plan))


def install_missing_dependencies(
    dependencies: Sequence[DependencySpec],
    include_optional: bool = False,
) -> list[dict[str, Any]]:
    attempts = []
    for dependency in dependencies:
        if not dependency.get("required", True) and not include_optional:
            continue

        command = dependency.get("command")
        checker = dependency.get("checker")
        command_missing = command and shutil.which(command) is None
        module_missing = checker and importlib.util.find_spec(checker) is None
        if not command_missing and not module_missing:
            continue

        install_plans = dependency.get("install_commands")
        if install_plans is None and command:
            install_plans = _default_install_plans(command)

        attempt = {
            "name": dependency["name"],
            "installed": False,
            "commands": [],
        }
        for raw_plan in install_plans or []:
            plan = _normalize_install_plan(raw_plan)
            install_command = plan["command"]
            platforms = plan.get("platforms")
            current_platform = _current_platform()
            if platforms and current_platform not in platforms:
                attempt["commands"].append(
                    {
                        "command": install_command,
                        "skipped": True,
                        "reason": f"Installer is only supported on: {', '.join(sorted(platforms))}.",
                    }
                )
                continue

            executable = install_command[0]
            if not (shutil.which(str(executable)) or str(executable) == sys.executable):
                attempt["commands"].append(
                    {
                        "command": install_command,
                        "skipped": True,
                        "reason": f"Installer '{executable}' is not available.",
                    }
                )
                continue

            result = subprocess.run(
                install_command,
                check=False,
                capture_output=True,
                text=True,
            )
            attempt["commands"].append(
                {
                    "command": install_command,
                    "returncode": result.returncode,
                    "stdout": result.stdout[-4000:],
                    "stderr": result.stderr[-4000:],
                }
            )
            if result.returncode == 0:
                command_ok = not command or shutil.which(command) is not None
                checker_ok = not checker or importlib.util.find_spec(checker) is not None
                if command_ok and checker_ok:
                    attempt["installed"] = True
                    break
        attempts.append(attempt)
    return attempts


def ensure_dependency_report(
    dependencies: Sequence[DependencySpec],
    auto_install: bool = True,
    install_optional: bool = False,
) -> dict[str, Any]:
    before = dependency_report(dependencies)
    install_attempts = []
    if auto_install and any(
        not item["available"] and (item["required"] or install_optional)
        for item in before
    ):
        install_attempts = install_missing_dependencies(dependencies, include_optional=install_optional)

    after = dependency_report(dependencies)
    return {
        "ok": all(item["available"] for item in after if item["required"]),
        "dependencies": after,
        "install_attempts": install_attempts,
    }
