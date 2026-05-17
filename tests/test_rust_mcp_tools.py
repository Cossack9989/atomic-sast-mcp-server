from pathlib import Path

import atomic_sast4rust_mcp_server.server as server


class _FakeMagikaResult:
    def __init__(self, label):
        self.output = type("Output", (), {"label": label})()


class _FakeMagika:
    def identify_path(self, file_path):
        return _FakeMagikaResult("rust" if Path(file_path).suffix == ".rs" else "text")


def _definition(text, path="src/lib.rs", start=1, end=3):
    return {"definition": text, "path": path, "code_line_range": [start, end]}


def test_collect_files_types_for_rust_project(monkeypatch, tmp_path):
    source = tmp_path / "lib.rs"
    source.write_text("pub fn greet() {}\n", encoding="utf-8")
    notes = tmp_path / "notes.txt"
    notes.write_text("notes\n", encoding="utf-8")

    server.file_type_mapping_by_project.clear()
    monkeypatch.setattr(server, "Magika", _FakeMagika)

    result = server.collect_files_types(str(tmp_path))

    assert str(source) in result["rust"]
    assert str(notes) in result["text"]


def test_definition_tools_delegate_to_astgrep_or_semgrep(monkeypatch, tmp_path):
    calls = []

    def fake_astgrep_or_semgrep(analyzing_directory, patterns, semgrep_rule, replacements):
        calls.append((patterns, semgrep_rule, replacements))
        return [_definition(patterns[0])]

    monkeypatch.setattr(server, "_astgrep_or_semgrep", fake_astgrep_or_semgrep)

    assert server.get_function_definition(str(tmp_path), "greet")[0]["definition"].startswith("fn greet")
    assert server.get_struct_definition(str(tmp_path), "User")[0]["definition"].startswith("struct User")
    assert server.get_enum_definition(str(tmp_path), "Role")[0]["definition"].startswith("enum Role")
    assert server.get_trait_definition(str(tmp_path), "Named")[0]["definition"].startswith("trait Named")
    assert server.get_impl_blocks(str(tmp_path), "User")[0]["definition"].startswith("impl User")

    assert calls[0][1] == "get_function_definition.yaml"
    assert calls[1][1] == "get_item_definition.yaml"
    assert calls[2][2] == {"$ITEM": "Role"}
    assert calls[3][2] == {"$ITEM": "Named"}
    assert calls[4][1] == "get_impl_block.yaml"


def test_get_function_call_deduplicates_astgrep_call_sites(monkeypatch, tmp_path):
    def fake_run_astgrep(analyzing_directory, pattern, text_key="definition"):
        assert text_key == "call"
        return [
            {"call": "user.id()", "path": "src/lib.rs", "code_line_range": [10, 10]},
            {"call": "user.id()", "path": "src/lib.rs", "code_line_range": [10, 10]},
        ]

    monkeypatch.setattr(server, "_run_astgrep", fake_run_astgrep)

    result = server.get_function_call(str(tmp_path), "id")

    assert result == [{"call": "user.id()", "path": "src/lib.rs", "code_line_range": [10, 10]}]


def test_get_function_call_rejects_unsupported_caller_role(tmp_path):
    result = server.get_function_call(str(tmp_path), "id", role="caller")

    assert "Rust caller discovery is not supported" in result["error"]


def test_get_function_call_falls_back_to_ripgrep(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_run_astgrep", lambda *_, **__: [])
    monkeypatch.setattr(server, "_missing_command_error", lambda command: None)

    def fake_check_output(command, shell=False, cwd=None):
        assert command == ["rg", "-n", "-C", "4", "--glob", "*.rs", r"\bid\s*(::\s*[A-Za-z_][A-Za-z0-9_]*\s*)?\(", "."]
        assert cwd == str(tmp_path)
        return b"src/lib.rs:10:    user.id();\n"

    monkeypatch.setattr(server, "check_output", fake_check_output)

    result = server.get_function_call(str(tmp_path), "id", context_range=4)

    assert result == {"grep_results": "src/lib.rs:10:    user.id();\n", "astgrep_errors": []}


def test_grep_code_limits_search_to_rust_files(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_missing_command_error", lambda command: None)

    def fake_check_output(command, shell=False, cwd=None):
        assert command == ["rg", "-n", "-A", "2", "--glob", "*.rs", "struct User", "."]
        assert cwd == str(tmp_path)
        return b"src/lib.rs:1:pub struct User { id: u64 }\n"

    monkeypatch.setattr(server, "check_output", fake_check_output)

    result = server.grep_code(str(tmp_path), "struct User", context_range=2)

    assert "pub struct User" in result
