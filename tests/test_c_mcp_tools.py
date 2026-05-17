import json
from pathlib import Path

import atomic_sast4c_mcp_server.server as server


class _FakeMagikaResult:
    def __init__(self, label):
        self.output = type("Output", (), {"label": label})()


class _FakeMagika:
    calls = []

    def identify_path(self, file_path):
        self.calls.append(file_path)
        suffix = Path(file_path).suffix
        return _FakeMagikaResult("c" if suffix == ".c" else "text")


def _semgrep_result(lines, path="src/demo.c", start=3, end=5, metavars=None):
    extra = {"lines": lines}
    if metavars is not None:
        extra["metavars"] = metavars
    return {"path": path, "start": {"line": start}, "end": {"line": end}, "extra": extra}


def _patch_semgrep(monkeypatch, payload):
    def fake_check_output(command, shell=False, cwd=None):
        assert command[:2] == ["semgrep", "scan"]
        output_arg = next(item for item in command if item.startswith("--json-output="))
        output_path = output_arg.split("=", 1)[1]
        Path(output_path).write_text(json.dumps(payload), encoding="utf-8")
        return b""

    monkeypatch.setattr(server, "_missing_command_error", lambda command: None)
    monkeypatch.setattr(server, "check_output", fake_check_output)


def test_collect_files_types_uses_magika_and_cache(monkeypatch, tmp_path):
    source = tmp_path / "main.c"
    readme = tmp_path / "README.md"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    readme.write_text("demo\n", encoding="utf-8")

    server.file_type_mapping_by_project.clear()
    fake_magika = _FakeMagika()
    monkeypatch.setattr(server, "Magika", lambda: fake_magika)

    first = server.collect_files_types(str(tmp_path))
    second = server.collect_files_types(str(tmp_path))

    assert first == second
    assert str(source) in first["c"]
    assert str(readme) in first["text"]
    assert len(fake_magika.calls) == 2


def test_get_function_definition_falls_back_to_semgrep(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "get_function_definition_by_astgrep", lambda *_: [])
    monkeypatch.setattr(
        server,
        "get_function_definition_by_semgrep",
        lambda analyzing_directory, function_name: [
            {
                "definition": f"int {function_name}(void) {{ return 1; }}",
                "path": "src/demo.c",
                "code_line_range": [7, 9],
            }
        ],
    )

    result = server.get_function_definition(str(tmp_path), "target")

    assert result == [
        {
            "definition": "int target(void) { return 1; }",
            "path": "src/demo.c",
            "code_line_range": [7, 9],
        }
    ]


def test_get_variable_definition_parses_semgrep_metavars(monkeypatch, tmp_path):
    payload = {
        "results": [
            _semgrep_result(
                "static int g_count = 42;",
                metavars={
                    "$TYPE": {"abstract_content": "int"},
                    "$VALUE": {"abstract_content": "42"},
                },
            )
        ]
    }
    _patch_semgrep(monkeypatch, payload)

    result = server.get_variable_definition(str(tmp_path), "g_count")

    assert result == [
        {"type": "int", "value": "42", "path": "src/demo.c", "code_line_range": [3, 5]}
    ]


def test_get_macro_and_structure_definitions_parse_semgrep(monkeypatch, tmp_path):
    payload = {"results": [_semgrep_result("#define MAX_SIZE 16")]}
    _patch_semgrep(monkeypatch, payload)

    macro = server.get_macro_definition(str(tmp_path), "MAX_SIZE")
    assert macro == [
        {"definition": "#define MAX_SIZE 16", "path": "src/demo.c", "code_line_range": [3, 5]}
    ]

    payload["results"] = [_semgrep_result("struct User { int id; };")]
    structure = server.get_structure_definition(str(tmp_path), "User")
    assert structure == [
        {"definition": "struct User { int id; };", "path": "src/demo.c", "code_line_range": [3, 5]}
    ]


def test_get_function_call_parses_weggli_highlighted_functions(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_missing_command_error", lambda command: None)

    def fake_check_output(command, shell=False, cwd=None):
        assert command[0] == "weggli"
        assert cwd == str(tmp_path)
        return b"\x1b[31mcaller_a\x1b[0m calls \x1b[31mtarget\x1b[0m\n"

    monkeypatch.setattr(server, "check_output", fake_check_output)

    result = server.get_function_call(str(tmp_path), "caller", "target")

    assert result == ["caller_a"]


def test_get_variable_consumer_parses_weggli_results(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_missing_command_error", lambda command: None)
    monkeypatch.setattr(
        server,
        "check_output",
        lambda command, shell=False, cwd=None: b"\x1b[31mconsume_config\x1b[0m\n",
    )

    result = server.get_variable_consumer(str(tmp_path), "global_config")

    assert result == ["consume_config"]


def test_grep_code_runs_ripgrep(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_missing_command_error", lambda command: None)

    def fake_check_output(command, shell=False, cwd=None):
        assert command == ["rg", "-n", "-A", "3", "target", "."]
        assert cwd == str(tmp_path)
        return b"main.c:4:target();\n"

    monkeypatch.setattr(server, "check_output", fake_check_output)

    assert server.grep_code(str(tmp_path), "target", context_range=3) == "main.c:4:target();\n"
