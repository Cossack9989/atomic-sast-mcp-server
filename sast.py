import sys
from pathlib import Path

src_path = Path(__file__).resolve().parent / "src"
if src_path.exists():
    sys.path.insert(0, str(src_path))


SERVER_MAIN_BY_LANGUAGE = {
    "c": "atomic_sast4c_mcp_server.server",
    "rust": "atomic_sast4rust_mcp_server.server",
    "go": "atomic_sast4go_mcp_server.server",
    "golang": "atomic_sast4go_mcp_server.server",
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] in {"-h", "--help"}:
        languages = ", ".join(SERVER_MAIN_BY_LANGUAGE)
        print(f"Usage: python sast.py <language>\nAvailable languages: {languages}", file=sys.stderr)
        raise SystemExit(2)

    language = sys.argv.pop(1).lower()
    module_name = SERVER_MAIN_BY_LANGUAGE.get(language)
    if module_name is None:
        languages = ", ".join(SERVER_MAIN_BY_LANGUAGE)
        print(f"Unsupported language: {language}. Available languages: {languages}", file=sys.stderr)
        raise SystemExit(2)

    module = __import__(module_name, fromlist=["main"])
    module.main()


if __name__ == "__main__":
    main()
