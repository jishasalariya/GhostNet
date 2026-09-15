from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def start_server() -> None:
    print("=" * 60)
    print("GhostNet -- The Ghost That Browses Before You")
    print("=" * 60)

    backend_dir = Path(__file__).resolve().parent / "backend"

    if sys.platform == "win32":
        python_exe = backend_dir / "venv" / "Scripts" / "python.exe"
        uvicorn_exe = backend_dir / "venv" / "Scripts" / "uvicorn.exe"
    else:
        python_exe = backend_dir / "venv" / "bin" / "python"
        uvicorn_exe = backend_dir / "venv" / "bin" / "uvicorn"

    if not python_exe.exists():
        print(f"Error: Virtual environment not found at {backend_dir / 'venv'}")
        print("Please check your setup or re-run setup commands.")
        raise SystemExit(1)

    print("\nStarting GhostNet FastAPI backend...")
    print("Open your browser and navigate to: http://127.0.0.1:8000")
    print("Press Ctrl+C to terminate the server.\n")
    print("-" * 60)

    try:
        subprocess.run(
            [
                os.fspath(uvicorn_exe),
                "main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8000",
                "--reload",
            ],
            cwd=os.fspath(backend_dir),
            check=False,
        )
    except KeyboardInterrupt:
        print("\nGhostNet server stopped. Safe browsing!")
    except Exception as exc:
        print(f"Error starting uvicorn: {exc}")


if __name__ == "__main__":
    start_server()
