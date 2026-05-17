# atomic-sast-mcp-server

Local Atomic SAST MCP servers for C, Rust, and Go projects.

This project provides language-specific FastMCP servers that help LLM agents inspect source code with local static-analysis tools such as `semgrep`, `ast-grep`, `weggli`, `ripgrep`, and `magika`.

## Features

- C server: function, variable, macro, structure, call relationship, and grep helpers.
- Rust server: function, struct, enum, trait, impl block, call site, and grep helpers.
- Go server: function, method, struct, interface, type, call site, and grep helpers.
- Startup dependency check with automatic installation attempts for missing required CLI tools.

## Run With uvx

```bash
uvx --from git+https://github.com/Cossack9989/atomic-sast-mcp-server atomic-sast4c-mcp-server
uvx --from git+https://github.com/Cossack9989/atomic-sast-mcp-server atomic-sast4rust-mcp-server
uvx --from git+https://github.com/Cossack9989/atomic-sast-mcp-server atomic-sast4go-mcp-server
```

The default command currently points to the C server:

```bash
uvx --from git+https://github.com/Cossack9989/atomic-sast-mcp-server atomic-sast-mcp-server
```

## Local Run

```bash
python sast_c.py
python sast_rust.py
python sast_go.py
```

Or use the dispatcher:

```bash
python sast.py c
python sast.py rust
python sast.py go
```

## Dependencies

Python dependencies are installed from `pyproject.toml`:

- `fastmcp`
- `magika`

External CLI tools should be available in `PATH`:

- Common: `semgrep`, `ast-grep`, `rg`
- C only: `weggli`
- Optional: `cargo` for Rust projects, `go` for Go projects. These language toolchains are checked only and are not installed by this MCP server.

At startup, each MCP server installs missing required CLI tools automatically. It prefers user/tool-level installers first, and only uses platform-specific installers when applicable.

- `semgrep`: `pip`, `pip --break-system-packages`, `uv tool`, then `pipx`
- `ast-grep`: `pip`, `pip --break-system-packages`, `npm`, `cargo`, then `brew` on macOS
- `rg`: `apt`, `cargo`, `brew` on macOS, or Windows package managers
- `weggli`: `cargo`, then `brew` on macOS
- `cargo` / `go`: checked only, never auto-installed

## Build

```bash
python3 -m pip wheel --no-deps . -w build
```

The wheel will be generated under `build/`.

## Package Layout

```text
src/
├── atomic_sast_mcp_common/
├── atomic_sast4c_mcp_server/
├── atomic_sast4rust_mcp_server/
└── atomic_sast4go_mcp_server/
```
