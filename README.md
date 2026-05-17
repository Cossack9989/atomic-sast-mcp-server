# atomic-sast-mcp-server

Local Atomic SAST MCP servers for C, Rust, and Go projects.

This project provides language-specific FastMCP servers that help LLM agents inspect source code with local static-analysis tools such as `semgrep`, `ast-grep`, `weggli`, `ripgrep`, and `magika`.

## Features

- C server: function, variable, macro, structure, call relationship, and grep helpers.
- Rust server: function, struct, enum, trait, impl block, call site, and grep helpers.
- Go server: function, method, struct, interface, type, call site, and grep helpers.
- Dependency self-check via the `check_dependencies` MCP tool.

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
- Optional: `cargo` for Rust projects, `go` for Go projects

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
