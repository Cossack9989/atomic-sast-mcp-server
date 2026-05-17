from pathlib import Path

import atomic_sast4go_mcp_server.server as server


class _FakeMagikaResult:
    def __init__(self, label):
        self.output = type("Output", (), {"label": label})()


class _FakeMagika:
    def identify_path(self, file_path):
        return _FakeMagikaResult("go" if Path(file_path).suffix == ".go" else "text")


def _definition(text, path="main.go", start=2, end=4):
    return {"definition": text, "path": path, "code_line_range": [start, end]}


def test_collect_files_types_for_go_project(monkeypatch, tmp_path):
    source = tmp_path / "main.go"
    source.write_text("package main\n", encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text("demo\n", encoding="utf-8")

    server.file_type_mapping_by_project.clear()
    monkeypatch.setattr(server, "Magika", _FakeMagika)

    result = server.collect_files_types(str(tmp_path))

    assert str(source) in result["go"]
    assert str(readme) in result["text"]


def test_definition_tools_delegate_to_astgrep_or_semgrep(monkeypatch, tmp_path):
    calls = []

    def fake_astgrep_or_semgrep(analyzing_directory, patterns, semgrep_rule, replacements):
        calls.append((patterns, semgrep_rule, replacements))
        return [_definition(patterns[0])]

    monkeypatch.setattr(server, "_astgrep_or_semgrep", fake_astgrep_or_semgrep)

    assert server.get_function_definition(str(tmp_path), "NewUser")[0]["definition"].startswith("func NewUser")
    method = server.get_method_definition(str(tmp_path), "Name", receiver_type="*User")
    assert method[0]["definition"].startswith("func ($$$RECEIVER *User) Name")
    assert server.get_struct_definition(str(tmp_path), "User")[0]["definition"] == "type User struct { $$$BODY }"
    assert server.get_interface_definition(str(tmp_path), "Named")[0]["definition"] == "type Named interface { $$$BODY }"
    assert server.get_type_definition(str(tmp_path), "UserID")[0]["definition"] == "type UserID struct { $$$BODY }"

    assert calls[0][1] == "get_function_definition.yaml"
    assert calls[1][2] == {"$FUNCTION": "Name"}
    assert calls[2][1] == "get_type_definition.yaml"
    assert calls[3][2] == {"$TYPE": "Named"}
    assert calls[4][2] == {"$TYPE": "UserID"}


def test_get_method_definition_without_receiver_matches_any_receiver(monkeypatch, tmp_path):
    monkeypatch.setattr(
        server,
        "_astgrep_or_semgrep",
        lambda analyzing_directory, patterns, semgrep_rule, replacements: [_definition(patterns[0])],
    )

    result = server.get_method_definition(str(tmp_path), "Name")

    assert result[0]["definition"].startswith("func ($$$RECEIVER $$$TYPE) Name")


def test_get_function_call_deduplicates_astgrep_call_sites(monkeypatch, tmp_path):
    def fake_run_astgrep(analyzing_directory, pattern, text_key="definition"):
        assert text_key == "call"
        return [
            {"call": "user.Name()", "path": "main.go", "code_line_range": [12, 12]},
            {"call": "user.Name()", "path": "main.go", "code_line_range": [12, 12]},
        ]

    monkeypatch.setattr(server, "_run_astgrep", fake_run_astgrep)

    result = server.get_function_call(str(tmp_path), "Name")

    assert result == [{"call": "user.Name()", "path": "main.go", "code_line_range": [12, 12]}]


def test_get_function_call_rejects_unsupported_caller_role(tmp_path):
    result = server.get_function_call(str(tmp_path), "Name", role="caller")

    assert "Go caller discovery is not supported" in result["error"]


def test_get_function_call_falls_back_to_ripgrep_and_filters_definitions(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_run_astgrep", lambda *_, **__: [])
    monkeypatch.setattr(server, "_missing_command_error", lambda command: None)

    def fake_check_output(command, shell=False, cwd=None):
        assert command == ["rg", "-n", "--glob", "*.go", r"(\.\s*Name|\bName)\s*\(", "."]
        assert cwd == str(tmp_path)
        return b"\n".join(
            [
                b"main.go:5:func (u *User) Name() string {",
                b"main.go:10:    fmt.Println(user.Name())",
                b"main.go:15:Name() string",
            ]
        )

    monkeypatch.setattr(server, "check_output", fake_check_output)

    result = server.get_function_call(str(tmp_path), "Name")

    assert result == [{"call": "fmt.Println(user.Name())", "path": "main.go", "code_line_range": [10, 10]}]


def test_grep_code_limits_search_to_go_files(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_missing_command_error", lambda command: None)

    def fake_check_output(command, shell=False, cwd=None):
        assert command == ["rg", "-n", "-A", "1", "--glob", "*.go", "type User", "."]
        assert cwd == str(tmp_path)
        return b"main.go:3:type User struct { ID int }\n"

    monkeypatch.setattr(server, "check_output", fake_check_output)

    result = server.grep_code(str(tmp_path), "type User", context_range=1)

    assert "type User struct" in result
