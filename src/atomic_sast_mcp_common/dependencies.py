import importlib.util
import shutil
from collections.abc import Sequence
from typing import Any


DependencySpec = dict[str, Any]
DependencyReport = dict[str, Any]


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
