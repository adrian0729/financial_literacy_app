#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Helper script to run Uvicorn with optional DB reset."
    )
    parser.add_argument(
        "--restart",
        action="store_true",
        help="Delete the local data/ directory before starting (fresh DB + sessions).",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Run Uvicorn with --reload for autoreload during development.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind Uvicorn to (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        default="8000",
        help="Port to bind Uvicorn to (default: 8000).",
    )
    return parser.parse_args()


def maybe_restart() -> None:
    data_dir = Path("data")
    if data_dir.exists():
        shutil.rmtree(data_dir)
    print("Removed data/ directory. Fresh database/session secret will be generated.")


def main() -> None:
    args = parse_args()
    if args.restart:
        maybe_restart()

    env_python = os.fspath(Path("venv") / "bin" / "python")
    python_executable = env_python if Path(env_python).exists() else sys.executable

    command = [
        python_executable,
        "-m",
        "uvicorn",
        "main:app",
        "--host",
        args.host,
        "--port",
        str(args.port),
    ]

    if args.reload:
        command.append("--reload")

    try:
        subprocess.run(command, check=True)
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode) from exc


if __name__ == "__main__":
    main()
