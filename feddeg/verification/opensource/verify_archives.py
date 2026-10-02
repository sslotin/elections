#!/usr/bin/env python3
"""Resume full verification of raw JSONL-in-ZIP exports, one archive at a time.

The input ZIPs are read-only. State and logs must live elsewhere, e.g. under
/tmp. Completed archives are skipped only while their file/member metadata and
verifier source remain unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
VERIFIER = HERE / "verify.py"
MOSCOW = timezone(timedelta(hours=3))
TERMINAL = {"verified", "failed", "incomplete", "error"}


class StopRequested(Exception):
    def __init__(self, signum: int):
        self.signum = signum


def now() -> str:
    return datetime.now(MOSCOW).isoformat(timespec="seconds")


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def raw_member(name: str) -> bool:
    name = name.lower()
    return (Path(name).name != "state.json"
            and name.endswith((".json", ".jsonl", ".json.gz", ".jsonl.gz")))


def archive_identity(path: Path) -> dict[str, Any]:
    """Inspect the ZIP directory only; do not scan/hash its many GB of payload."""
    if not path.is_file() or path.suffix.lower() != ".zip":
        raise ValueError(f"expected a raw .zip dump: {path}")
    stat = path.stat()
    with zipfile.ZipFile(path) as archive:
        members = [info for info in archive.infolist()
                   if not info.is_dir() and raw_member(info.filename)]
    if not members:
        raise ValueError(f"no JSON/JSONL member in {path}")
    return {
        "path": str(path.resolve()),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "inode": getattr(stat, "st_ino", None),
        "members": [{"name": item.filename, "size": item.file_size,
                     "compressed_size": item.compress_size, "crc": item.CRC}
                    for item in members],
    }


def verifier_fingerprint(results_only: bool = False,
                         exclusions_sha256: str = "") -> str:
    digest = hashlib.sha256()
    for source in [VERIFIER, *sorted((HERE / "crypto").glob("*.py"))]:
        digest.update(source.relative_to(HERE).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(source.read_bytes())
        digest.update(b"\0")
    digest.update(f"results_only={results_only}\nexclusions={exclusions_sha256}".encode())
    return digest.hexdigest()


def atomic_save(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        json.dump(state, output, ensure_ascii=False, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema": 1, "archives": {}}
    state = json.loads(path.read_text(encoding="utf-8"))
    if state.get("schema") != 1:
        raise ValueError(f"unsupported state schema in {path}")
    state.setdefault("archives", {})
    return state


def tail_summary(path: Path) -> str | None:
    if not path.exists():
        return None
    with path.open("rb") as stream:
        stream.seek(max(0, path.stat().st_size - 32768))
        lines = stream.read().decode("utf-8", errors="replace").splitlines()
    return next((line for line in reversed(lines) if line.startswith("finished: ")), None)


def stop_child(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGINT)
        else:
            process.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM))
        process.wait(timeout=45)
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


def run_archive(path: Path, identity: dict[str, Any], state: dict[str, Any],
                state_path: Path, log_dir: Path, workers: int,
                source_hash: str, results_only: bool,
                exclusions_path: Path | None) -> int:
    key = str(path.resolve())
    entry = state["archives"].setdefault(key, {})
    attempts = entry.setdefault("attempts", [])
    log_path = log_dir / f"{path.stem}.attempt-{len(attempts) + 1}.log"
    attempt: dict[str, Any] = {"started_at": now(), "status": "running",
                               "workers": workers, "log": str(log_path)}
    attempts.append(attempt)
    entry.update({"identity": identity, "verifier_sha256": source_hash,
                  "status": "running", "log": str(log_path)})
    state["updated_at"] = now()
    atomic_save(state_path, state)
    log_dir.mkdir(parents=True, exist_ok=True)

    command = [sys.executable, str(VERIFIER), str(path), "--workers", str(workers)]
    if results_only:
        command.append("--results-only")
    if exclusions_path is not None:
        command.extend(["--exclude-ballots", str(exclusions_path)])
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    options: dict[str, Any] = {"stderr": subprocess.STDOUT, "env": environment}
    if os.name == "posix":
        options["start_new_session"] = True
    elif hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    try:
        with log_path.open("wb") as output:
            options["stdout"] = output
            print(f"[{now()}] start {path.name}: {identity['size'] / 1e9:.2f} GB ZIP, "
                  f"JSON members={len(identity['members'])}, workers={workers}", flush=True)
            process = subprocess.Popen(command, **options)
            try:
                returncode = process.wait()
            except StopRequested as stop:
                stop_child(process)
                attempt.update({"status": "interrupted", "finished_at": now(),
                                "signal": stop.signum})
                entry.update({"status": "interrupted", "returncode": None})
                state["updated_at"] = now()
                atomic_save(state_path, state)
                print(f"[{now()}] interrupted {path.name}; rerun to restart this archive",
                      flush=True)
                return 128 + stop.signum
    except OSError as error:
        attempt.update({"status": "error", "finished_at": now(), "error": str(error)})
        entry.update({"status": "error", "returncode": None, "error": str(error)})
        state["updated_at"] = now()
        atomic_save(state_path, state)
        print(f"[{now()}] could not launch verifier for {path}: {error}", flush=True)
        return 1

    status = "verified" if returncode == 0 else "incomplete" if returncode == 2 else "failed"
    summary = tail_summary(log_path)
    checked = [member["name"] for member in identity["members"]] if summary else []
    attempt.update({"status": status, "finished_at": now(), "returncode": returncode,
                    "summary": summary, "checked_members": checked})
    entry.update({"status": status, "finished_at": now(), "returncode": returncode,
                  "summary": summary, "checked_members": checked})
    state["updated_at"] = now()
    atomic_save(state_path, state)
    print(f"[{now()}] {path.name}: {status}, exit={returncode}; "
          f"{summary or 'no final summary'}", flush=True)
    return returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="raw ZIP dump(s), processed in order")
    parser.add_argument("--state", type=Path, help="resume state JSON (outside raw data)")
    parser.add_argument("--log-dir", type=Path, help="default: <state-dir>/logs")
    parser.add_argument("--workers", type=positive_int, default=os.cpu_count() or 1,
                        help="ballot worker processes; default uses all logical CPUs")
    parser.add_argument("--retry-unverified", action="store_true",
                        help="retry unchanged archives whose prior exit code was nonzero")
    parser.add_argument("--results-only", action="store_true",
                        help="skip ballot/transaction proofs; verify result decryption")
    parser.add_argument("--exclude-ballots", type=Path,
                        help="JSON mapping known failed ballot tx IDs to reasons (requires results-only)")
    parser.add_argument("--check-only", action="store_true",
                        help="validate ZIP members without starting verification")
    args = parser.parse_args(argv)

    inputs = [path.resolve() for path in args.inputs]
    identities = [archive_identity(path) for path in inputs]
    print(f"validated {len(inputs)} raw ZIP(s):", flush=True)
    for identity in identities:
        print(f"  {Path(identity['path']).name}: {identity['size'] / 1e9:.2f} GB, "
              f"members={[(m['name'], m['size']) for m in identity['members']]}", flush=True)
    if args.check_only:
        return 0
    if args.exclude_ballots and not args.results_only:
        parser.error("--exclude-ballots requires --results-only")
    exclusions_path = args.exclude_ballots.resolve() if args.exclude_ballots else None
    if exclusions_path is not None:
        try:
            exclusions = json.loads(exclusions_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            parser.error(f"cannot read --exclude-ballots JSON: {error}")
        if (not isinstance(exclusions, dict) or
                any(not isinstance(tx_id, str) or not isinstance(reason, str) or not reason
                    for tx_id, reason in exclusions.items())):
            parser.error("--exclude-ballots must map transaction IDs to nonempty reason strings")
    if args.state is None:
        parser.error("--state is required unless --check-only is used")
    if not VERIFIER.is_file():
        parser.error(f"verifier not found: {VERIFIER}")

    state_path = args.state.resolve()
    log_dir = (args.log_dir or state_path.parent / "logs").resolve()
    state = load_state(state_path)
    exclusions_sha256 = (hashlib.sha256(exclusions_path.read_bytes()).hexdigest()
                         if exclusions_path is not None else "")
    source_hash = verifier_fingerprint(args.results_only, exclusions_sha256)
    state["workers"] = args.workers
    state["mode"] = "results-only" if args.results_only else "full"
    state["exclude_ballots_sha256"] = exclusions_sha256 or None
    state["verifier_sha256"] = source_hash
    state["updated_at"] = now()
    atomic_save(state_path, state)

    def stop(signum: int, _frame: Any) -> None:
        raise StopRequested(signum)

    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)

    had_errors = False
    for path, identity in zip(inputs, identities):
        key = str(path)
        old = state["archives"].get(key, {})
        unchanged = (old.get("identity") == identity
                     and old.get("verifier_sha256") == source_hash)
        status = old.get("status")
        if unchanged and status in TERMINAL and (
            status == "verified" or not args.retry_unverified
        ):
            print(f"[{now()}] skip {path.name}: already {status}", flush=True)
            if status != "verified":
                had_errors = True
            continue
        returncode = run_archive(path, identity, state, state_path,
                                 log_dir, args.workers, source_hash,
                                 args.results_only, exclusions_path)
        if returncode in (130, 143):
            return returncode
        if returncode != 0:
            had_errors = True

    summary = {"expected_archives": len(inputs), "verified": 0,
               "failed": 0, "incomplete": 0, "interrupted": 0, "error": 0}
    for path in inputs:
        status = state["archives"].get(str(path), {}).get("status", "error")
        summary[status if status in summary else "error"] += 1
    state["summary"] = summary
    state["updated_at"] = now()
    atomic_save(state_path, state)
    print(f"[{now()}] overall: {summary}", flush=True)
    return 1 if had_errors or summary["verified"] != len(inputs) else 0


if __name__ == "__main__":
    raise SystemExit(main())
