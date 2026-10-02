#!/usr/bin/env python3
"""Resume remaining 2026 shards, then verify the 2024 and 2025 raw ZIPs.

Each child runner owns its atomic state and logs. A nonzero 2026 audit verdict
still advances to historical datasets once every 2026 shard was fully scanned;
input errors or interruptions stop the sequence instead.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SHARD_RUNNER = HERE / "verify_shards.py"
ARCHIVE_RUNNER = HERE / "verify_archives.py"


class StopRequested(Exception):
    def __init__(self, signum: int):
        self.signum = signum


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def interrupt_child(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGINT)
        else:
            process.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
        process.wait(timeout=60)
        return
    except (ProcessLookupError, subprocess.TimeoutExpired):
        pass
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            process.kill()
            process.wait()


def run_phase(label: str, command: list[str]) -> int:
    print(f"Starting phase: {label}", flush=True)
    options: dict[str, Any] = {}
    if os.name == "posix":
        options["start_new_session"] = True
    elif hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    process = subprocess.Popen(command, **options)
    try:
        result = process.wait()
    except StopRequested:
        interrupt_child(process)
        raise
    print(f"Phase finished: {label}; exit={result}", flush=True)
    return result


def logged_exclusions(state_path: Path, key: str) -> set[str]:
    state = json.loads(state_path.read_text(encoding="utf-8"))
    found: set[str] = set()
    pattern = re.compile(r"excluded ballot: ([^;\s]+);")
    for entry in state.get(key, {}).values():
        log_path = Path(entry.get("log", ""))
        if not log_path.is_file():
            continue
        for line in log_path.read_text(encoding="utf-8", errors="replace").replace("\r", "\n").splitlines():
            match = pattern.search(line)
            if match:
                found.add(match.group(1))
    return found


def all_2026_shards_scanned(root: Path, state_path: Path) -> bool:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    state = json.loads(state_path.read_text(encoding="utf-8"))
    for chain in manifest["active_chains"]:
        entry = state.get("shards", {}).get(chain["name"], {})
        identity = entry.get("identity", {})
        checked = entry.get("checked_files", [])
        if (entry.get("status") not in {"verified", "failed", "incomplete"}
                or not entry.get("summary")
                or len(checked) != identity.get("chunk_count")):
            return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--2026-root", dest="root", type=Path, required=True)
    parser.add_argument("--2026-state", type=Path, required=True)
    parser.add_argument("--archives-state", type=Path, required=True)
    parser.add_argument("--archives", type=Path, nargs=2, required=True,
                        metavar=("EDG2024.ZIP", "EDG2025.ZIP"))
    parser.add_argument("--workers", type=positive_int, default=os.cpu_count() or 1,
                        help="workers per verifier; default uses all logical CPUs")
    parser.add_argument("--results-only", action="store_true",
                        help="skip ballot proofs and check aggregate result decryption")
    parser.add_argument("--exclude-ballots", type=Path, required=True,
                        help="JSON mapping previously failed ballot tx IDs to reasons")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    state_2026 = args.__dict__["2026_state"].resolve()
    state_archives = args.archives_state.resolve()
    archives = [path.resolve() for path in args.archives]
    exclusions_path = args.exclude_ballots.resolve()
    if not args.results_only:
        parser.error("--exclude-ballots requires --results-only")
    if not exclusions_path.is_file():
        parser.error(f"missing ballot exclusion file: {exclusions_path}")
    try:
        exclusions = json.loads(exclusions_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        parser.error(f"cannot read ballot exclusion JSON: {error}")
    if (not isinstance(exclusions, dict) or
            any(not isinstance(tx_id, str) or not isinstance(reason, str) or not reason
                for tx_id, reason in exclusions.items())):
        parser.error("exclusions must map transaction IDs to nonempty reason strings")
    if not (root / "manifest.json").is_file():
        parser.error(f"missing 2026 manifest below {root}")
    if any(not path.is_file() for path in archives):
        parser.error("one or more historical ZIPs are missing")

    def stop(signum: int, _frame: Any) -> None:
        raise StopRequested(signum)

    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)

    try:
        shard_command = [
            sys.executable, "-B", str(SHARD_RUNNER), str(root),
            "--state", str(state_2026), "--workers", str(args.workers),
            "--results-only", "--exclude-ballots", str(exclusions_path),
        ]
        shard_return = run_phase("remaining 2026 shards", shard_command)
        if not all_2026_shards_scanned(root, state_2026):
            print("Stopping before 2024–2025: 2026 still has an unscanned/interrupted shard.",
                  flush=True)
            return shard_return or 1

        archive_command = [
            sys.executable, "-B", str(ARCHIVE_RUNNER),
            *(str(path) for path in archives),
            "--state", str(state_archives), "--workers", str(args.workers),
            "--results-only", "--exclude-ballots", str(exclusions_path),
        ]
        archive_return = run_phase("2024 then 2025 raw archives", archive_command)
        seen_exclusions = (
            logged_exclusions(state_2026, "shards") |
            logged_exclusions(state_archives, "archives")
        )
        missing_exclusions = set(exclusions) - seen_exclusions
        if missing_exclusions:
            print("Known failed ballot IDs not encountered in the new pass: "
                  + ", ".join(sorted(missing_exclusions)), flush=True)
            return 1
        print(f"Confirmed excluded prior failures: {len(set(exclusions) & seen_exclusions)}",
              flush=True)
    except StopRequested as stop_request:
        print(f"Interrupted by signal {stop_request.signum}; child runner saved its state.",
              flush=True)
        return 128 + stop_request.signum

    return 0 if shard_return == 0 and archive_return == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
