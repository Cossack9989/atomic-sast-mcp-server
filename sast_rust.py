import sys
from pathlib import Path

src_path = Path(__file__).resolve().parent / "src"
if src_path.exists():
    sys.path.insert(0, str(src_path))

from atomic_sast4rust_mcp_server.server import *  # noqa: F403
from atomic_sast4rust_mcp_server.server import main


if __name__ == "__main__":
    main()
