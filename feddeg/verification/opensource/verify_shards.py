#!/usr/bin/env python3
"""Resume a full audit over complete per-shard raw JSONL chunk directories.

The shard directories are read-only. Progress, state, and per-shard logs go to
an explicit state path (normally under /tmp), never beside the raw data.

Example:
    python3 verify_shards.py /data/edg2026/block-dump \
        --state /tmp/edg2026-verifier/state.json --workers 16

A shard is marked verified only when verify.py exits 0. Interrupted shards are
restarted from their first block; already completed, unchanged shards are
skipped. The state records each input chunk's path, size, and mtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
VERIFIER = HERE / "verify.py"
CHUNK_NAME = re.compile(r"^(\d+)-(\d+)\.jsonl(?:\.gz)?$", re.IGNORECASE)
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


def atomic_save(path: Path, data: dict[str, Any]) -> None:
    """Replace the state atomically so a power loss cannot half-write JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        json.dump(data, output, ensure_ascii=False, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def load_state(path: Path, root: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema": 1, "input_root": str(root), "shards": {}}
    state = json.loads(path.read_text(encoding="utf-8"))
    if state.get("schema") != 1:
        raise ValueError(f"unsupported state schema in {path}")
    if state.get("input_root") != str(root):
        raise ValueError(
            f"state belongs to {state.get('input_root')}, not {root}; choose another --state"
        )
    state.setdefault("shards", {})
    return state


def verifier_fingerprint(results_only: bool = False,
                         exclusions_sha256: str = "") -> str:
    """Bind resume state to verifier code, mode, and ballot exclusions."""
    sources = [VERIFIER, *sorted((HERE / "crypto").glob("*.py"))]
    digest = hashlib.sha256()
    for source in sources:
        digest.update(source.relative_to(HERE).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(source.read_bytes())
        digest.update(b"\0")
    digest.update(f"results_only={results_only}\nexclusions={exclusions_sha256}".encode())
    return digest.hexdigest()


def discover_shards(root: Path) -> list[tuple[Path, dict[str, Any], list[Path]]]:
    """Use the dump manifest and reject missing, extra, or gapped shard inputs."""
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"missing shard manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    chains = manifest.get("active_chains")
    if not isinstance(chains, list) or not chains:
        raise ValueError(f"no active chains in {manifest_path}")
    by_name = {entry.get("name"): entry for entry in chains}
    if len(by_name) != len(chains) or None in by_name:
        raise ValueError("manifest has missing or duplicate chain names")

    directories = {path.name: path for path in root.iterdir()
                   if path.is_dir() and path.name.startswith("shard-")}
    if set(directories) != set(by_name):
        raise ValueError(
            f"shard directories differ from manifest; missing={sorted(set(by_name)-set(directories))}, "
            f"extra={sorted(set(directories)-set(by_name))}"
        )

    inputs = []
    for name in sorted(by_name, key=lambda value: [
        int(part) if part.isdigit() else part for part in re.split(r"(\d+)", value)
    ]):
        directory = directories[name]
        chain = by_name[name]
        shard_state_path = directory / "state.json"
        if not shard_state_path.is_file():
            raise ValueError(f"missing collector state: {shard_state_path}")
        shard_state = json.loads(shard_state_path.read_text(encoding="utf-8"))
        expected_height = int(chain["height"])
        if shard_state.get("shard") != name:
            raise ValueError(f"{shard_state_path} names another shard")
        if shard_state.get("chain_fingerprint") != chain.get("chain_fingerprint"):
            raise ValueError(f"chain fingerprint mismatch for {name}")
        if int(shard_state.get("completed_through", -1)) != expected_height:
            raise ValueError(f"collector state height mismatch for {name}")

        candidates = sorted(
            path for path in directory.iterdir()
            if path.is_file() and path.name.lower().endswith((".json", ".jsonl", ".jsonl.gz"))
            and path.name.lower() != "state.json"
        )
        chunks: list[tuple[int, int, Path]] = []
        for path in candidates:
            match = CHUNK_NAME.fullmatch(path.name)
            if not match:
                raise ValueError(f"unexpected JSON input in {directory}: {path.name}")
            start, end = int(match.group(1)), int(match.group(2))
            if end < start:
                raise ValueError(f"invalid block range in {path.name}")
            chunks.append((start, end, path))
        chunks.sort(key=lambda item: (item[0], item[1], item[2].name))
        if not chunks:
            raise ValueError(f"no JSONL chunks in {directory}")
        next_height = 1
        for start, end, path in chunks:
            if start != next_height:
                relation = "overlap/duplicate" if start < next_height else "gap"
                raise ValueError(f"{name} has a {relation} before {path.name}; expected {next_height}")
            next_height = end + 1
        if next_height - 1 != expected_height:
            raise ValueError(
                f"{name} chunks end at {next_height - 1}, manifest says {expected_height}"
            )
        inputs.append((directory, chain, [path for _, _, path in chunks]))
    return inputs


def input_identity(directory: Path, chain: dict[str, Any], chunks: list[Path]) -> dict[str, Any]:
    """Capture cheap change-detection metadata without re-reading 53 GB of data."""
    files = []
    for path in chunks:
        stat = path.stat()
        files.append({
            "name": path.name,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "inode": getattr(stat, "st_ino", None),
        })
    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "path": str(directory),
        "chain_fingerprint": chain["chain_fingerprint"],
        "height": int(chain["height"]),
        "chunk_count": len(files),
        "compressed_bytes": sum(item["size"] for item in files),
        "chunks_sha256_metadata": hashlib.sha256(encoded).hexdigest(),
        "files": files,
    }


def tail_summary(path: Path) -> str | None:
    if not path.exists():
        return None
    with path.open("rb") as stream:
        stream.seek(max(0, path.stat().st_size - 32768))
        lines = stream.read().decode("utf-8", errors="replace").splitlines()
    return next((line for line in reversed(lines) if line.startswith("finished: ")), None)


def stop_child(process: subprocess.Popen[bytes]) -> None:
    """Stop the verifier and its worker pool together after Ctrl-C/SIGTERM."""
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


def run_shard(
    directory: Path,
    identity: dict[str, Any],
    state: dict[str, Any],
    state_path: Path,
    log_dir: Path,
    workers: int,
    source_hash: str,
    results_only: bool,
    exclusions_path: Path | None,
) -> int:
    name = directory.name
    entry = state["shards"].setdefault(name, {})
    attempts = entry.setdefault("attempts", [])
    log_path = log_dir / f"{name}.attempt-{len(attempts) + 1}.log"
    attempt: dict[str, Any] = {
        "started_at": now(), "status": "running", "workers": workers,
        "log": str(log_path),
    }
    attempts.append(attempt)
    entry.update({
        "identity": identity,
        "verifier_sha256": source_hash,
        "status": "running",
        "log": str(log_path),
    })
    state["updated_at"] = now()
    atomic_save(state_path, state)
    log_dir.mkdir(parents=True, exist_ok=True)

    command = [sys.executable, str(VERIFIER), str(directory), "--workers", str(workers)]
    if results_only:
        command.append("--results-only")
    if exclusions_path is not None:
        command.extend(["--exclude-ballots", str(exclusions_path)])
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    popen_options: dict[str, Any] = {
        "stdout": None,
        "stderr": subprocess.STDOUT,
        "env": environment,
    }
    if os.name == "posix":
        popen_options["start_new_session"] = True
    elif hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

    try:
        with log_path.open("wb") as output:
            popen_options["stdout"] = output
            print(f"[{now()}] start {name}: {identity['chunk_count']} chunks, "
                  f"{identity['compressed_bytes'] / 1e9:.2f} GB, workers={workers}", flush=True)
            process = subprocess.Popen(command, **popen_options)
            try:
                returncode = process.wait()
            except StopRequested as stop:
                stop_child(process)
                attempt.update({"status": "interrupted", "finished_at": now(),
                                "signal": stop.signum})
                entry.update({"status": "interrupted", "returncode": None})
                state["updated_at"] = now()
                atomic_save(state_path, state)
                print(f"[{now()}] interrupted {name}; it will restart from block 1", flush=True)
                return 128 + stop.signum
    except OSError as error:
        attempt.update({"status": "error", "finished_at": now(), "error": str(error)})
        entry.update({"status": "error", "returncode": None, "error": str(error)})
        state["updated_at"] = now()
        atomic_save(state_path, state)
        print(f"[{now()}] could not launch verifier for {name}: {error}", flush=True)
        return 1

    status = "verified" if returncode == 0 else "incomplete" if returncode == 2 else "failed"
    summary = tail_summary(log_path)
    checked_files = ([item["name"] for item in identity["files"]]
                     if summary is not None else [])
    attempt.update({"status": status, "finished_at": now(), "returncode": returncode,
                    "summary": summary, "checked_files": checked_files})
    entry.update({"status": status, "returncode": returncode,
                  "finished_at": now(), "summary": summary,
                  "checked_files": checked_files})
    state["updated_at"] = now()
    atomic_save(state_path, state)
    print(f"[{now()}] {name}: {status}, exit={returncode}; {summary or 'no final summary'}",
          flush=True)
    return returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="root with manifest.json and shard-* directories")
    parser.add_argument("--state", type=Path, help="resume state JSON (keep outside raw data)")
    parser.add_argument("--log-dir", type=Path, help="log directory (default: <state-dir>/logs)")
    parser.add_argument("--workers", type=positive_int, default=os.cpu_count() or 1,
                        help="ballot worker processes; default uses all logical CPUs")
    parser.add_argument("--retry-unverified", action="store_true",
                        help="retry unchanged shards whose previous run did not exit 0")
    parser.add_argument("--results-only", action="store_true",
                        help="skip ballot/transaction proofs; verify result decryption")
    parser.add_argument("--exclude-ballots", type=Path,
                        help="JSON mapping known failed ballot tx IDs to reasons (requires results-only)")
    parser.add_argument("--check-only", action="store_true",
                        help="validate manifest and chunk coverage, but do not run verification")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    inputs = discover_shards(root)
    total_chunks = sum(len(chunks) for _, _, chunks in inputs)
    total_bytes = sum(path.stat().st_size for _, _, chunks in inputs for path in chunks)
    print(f"validated {len(inputs)} shards, {total_chunks} chunks, "
          f"{total_bytes / 1e9:.2f} GB compressed", flush=True)
    for directory, chain, chunks in inputs:
        print(f"  {directory.name}: height={chain['height']}, chunks={len(chunks)}, "
              f"bytes={sum(p.stat().st_size for p in chunks) / 1e9:.2f} GB", flush=True)
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
    state = load_state(state_path, root)
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
    for directory, chain, chunks in inputs:
        identity = input_identity(directory, chain, chunks)
        previous = state["shards"].get(directory.name, {})
        unchanged = (previous.get("identity") == identity
                     and previous.get("verifier_sha256") == source_hash)
        old_status = previous.get("status")
        if unchanged and old_status in TERMINAL and (
            old_status == "verified" or not args.retry_unverified
        ):
            print(f"[{now()}] skip {directory.name}: already {old_status}", flush=True)
            if old_status != "verified":
                had_errors = True
            continue

        rc = run_shard(directory, identity, state, state_path, log_dir,
                        args.workers, source_hash, args.results_only, exclusions_path)
        if rc == 130 or rc == 143:
            return rc
        if rc != 0:
            had_errors = True

    summary = {"expected_shards": len(inputs), "verified": 0,
               "failed": 0, "incomplete": 0, "interrupted": 0, "error": 0}
    for directory, _, _ in inputs:
        status = state["shards"].get(directory.name, {}).get("status", "error")
        summary[status if status in summary else "error"] += 1
    state["summary"] = summary
    state["updated_at"] = now()
    atomic_save(state_path, state)
    print(f"[{now()}] overall: {summary}", flush=True)
    return 1 if had_errors or summary["verified"] != len(inputs) else 0


if __name__ == "__main__":
    raise SystemExit(main())
