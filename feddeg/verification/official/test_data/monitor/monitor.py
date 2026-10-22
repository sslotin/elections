#!/usr/bin/env python3
"""Follow the DEG blockchain and print one summary line per block.

The raw blocks are saved in the same resumable JSONL chunk layout as
``dump-chunked.py``::

    block-monitor/<shard>/<start>-<end>.jsonl

The program follows the chain by default.  Use ``--once`` for a finite pass.
Lines describing blocks go to stdout and diagnostics go to stderr, so stdout
can be redirected to a log without mixing it with retry messages.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import requests


# Observer replicas.  Hosts in one tuple are fallbacks for one logical chain;
# they must not be treated as separate shards or their blocks would be counted twice.
SHARDS: dict[str, tuple[str, ...]] = {
    "shard-0": ("172.25.26.139", "172.25.202.132"),
    "shard-1": (
        "172.25.10.133",
        "172.25.154.135",
        "172.25.138.146",
        "172.25.218.135",
    ),
}

DEFAULT_OUTPUT_DIR = Path("block-monitor")
DEFAULT_CHUNK_SIZE = 100
DEFAULT_PORT = 6862
# Keep the checkpoint schema aligned with dump-chunked.py so either script can
# resume a directory produced by the other one.
STATE_SCHEMA = 2
CHUNK_NAME = re.compile(r"^(\d+)-(\d+)\.jsonl$")
MSK = timezone(timedelta(hours=3), name="MSK")


class MonitorError(RuntimeError):
    """A permanent data/configuration error."""


class TemporaryObserverError(MonitorError):
    """All currently configured observer requests failed; retry in follow mode."""


@dataclass(frozen=True)
class ChainInfo:
    name: str
    configured_nodes: tuple[str, ...]
    nodes: tuple[str, ...]
    height: int
    probe_heights: tuple[int, ...]
    probe_markers: tuple[str, ...]

    @property
    def fingerprint(self) -> str:
        # The first block is stable while the chain grows; later probe heights
        # are checked for replica agreement but are not persisted as identity.
        return self.probe_markers[0]


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def atomic_write(path: Path, content: str) -> None:
    """Replace a small text file atomically and flush it to disk first."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def block_fingerprint(block: dict[str, Any]) -> str:
    encoded = json.dumps(
        block,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_block(block: Any, expected_height: int) -> dict[str, Any]:
    """Reject malformed or out-of-order API data before saving it."""
    if not isinstance(block, dict):
        raise ValueError(f"block {expected_height} is not an object")
    if block.get("height") != expected_height:
        raise ValueError(
            f"expected block height {expected_height}, got {block.get('height')!r}"
        )
    transactions = block.get("transactions")
    if not isinstance(transactions, list):
        raise ValueError(f"block {expected_height} has no transaction list")
    advertised_count = block.get("transactionCount")
    if advertised_count is not None and advertised_count != len(transactions):
        raise ValueError(
            f"block {expected_height} advertises {advertised_count} transactions, "
            f"received {len(transactions)}"
        )
    return block


def validate_blocks(payload: Any, start: int, end: int) -> list[dict[str, Any]]:
    expected_count = end - start + 1
    if not isinstance(payload, list) or len(payload) != expected_count:
        actual = len(payload) if isinstance(payload, list) else type(payload).__name__
        raise ValueError(f"expected {expected_count} blocks for {start}-{end}, got {actual}")
    return [validate_block(block, start + offset) for offset, block in enumerate(payload)]


def chunk_paths(shard_dir: Path) -> list[tuple[Path, int, int]]:
    chunks: list[tuple[Path, int, int]] = []
    for path in shard_dir.glob("*.jsonl"):
        match = CHUNK_NAME.match(path.name)
        if match:
            chunks.append((path, int(match.group(1)), int(match.group(2))))
    return sorted(chunks, key=lambda item: item[1])


def completed_through(shard_dir: Path) -> int:
    """Return the last height in the contiguous sequence of chunk files."""
    expected_start = 1
    for _path, start, end in chunk_paths(shard_dir):
        if start != expected_start or end < start:
            break
        expected_start = end + 1
    return expected_start - 1


def validate_existing_chunks(shard_dir: Path) -> int:
    """Validate legacy/untrusted chunks and return their contiguous height."""
    expected_height = 1
    for path, start, end in chunk_paths(shard_dir):
        if start != expected_height or end < start:
            raise MonitorError(
                f"{shard_dir}: chunk sequence is not contiguous before {path.name}"
            )
        lines = 0
        line_number = 0
        try:
            with path.open(encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, 1):
                    if not line.strip():
                        raise ValueError("blank JSONL line")
                    validate_block(json.loads(line), expected_height)
                    expected_height += 1
                    lines += 1
        except (OSError, json.JSONDecodeError, ValueError) as error:
            raise MonitorError(f"invalid block data in {path}:{line_number}: {error}") from error
        expected_lines = end - start + 1
        if lines != expected_lines:
            raise MonitorError(
                f"{path}: filename promises {expected_lines} lines, found {lines}"
            )
    return expected_height - 1


def first_existing_block_fingerprint(shard_dir: Path) -> str | None:
    for path, start, _end in chunk_paths(shard_dir):
        if start != 1:
            continue
        try:
            with path.open(encoding="utf-8") as stream:
                first_line = stream.readline()
            return block_fingerprint(validate_block(json.loads(first_line), 1))
        except (OSError, json.JSONDecodeError, ValueError) as error:
            raise MonitorError(f"cannot inspect first block in {path}: {error}") from error
    return None


def write_chunk(path: Path, blocks: list[dict[str, Any]], start: int, end: int) -> None:
    # The final filename becomes visible only after every block is complete.
    valid_blocks = validate_blocks(blocks, start, end)
    content = "".join(
        json.dumps(block, ensure_ascii=False, separators=(",", ":")) + "\n"
        for block in valid_blocks
    )
    atomic_write(path, content)


def read_json_file(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MonitorError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise MonitorError(f"{path} does not contain a JSON object")
    return value


def write_state(path: Path, chain: ChainInfo, completed: int) -> None:
    atomic_write(
        path,
        json.dumps(
            {
                "schema": STATE_SCHEMA,
                "shard": chain.name,
                "configured_nodes": list(chain.configured_nodes),
                "nodes": list(chain.nodes),
                "chain_fingerprint": chain.fingerprint,
                "probe_heights": list(chain.probe_heights),
                "completed_through": completed,
                "observed_height": chain.height,
                "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )


class ShardClient:
    def __init__(self, nodes: tuple[str, ...], port: int, timeout: tuple[float, float]) -> None:
        self.nodes = nodes
        self.port = port
        self.timeout = timeout
        self.session = requests.Session()
        # Observer addresses are private/local.  Do not accidentally send them
        # through HTTP(S)_PROXY inherited from the operator's environment.
        self.session.trust_env = False

    def get_node_json(self, node: str, path: str) -> Any:
        response = self.session.get(
            f"http://{node}:{self.port}{path}",
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def inspect_chain(self, name: str, configured_nodes: tuple[str, ...]) -> ChainInfo:
        """Find replicas that agree on the chain and return the highest height."""
        heights: dict[str, int] = {}
        for node in configured_nodes:
            try:
                payload = self.get_node_json(node, "/blocks/height")
                height = payload.get("height") if isinstance(payload, dict) else None
                if not isinstance(height, int) or isinstance(height, bool) or height < 1:
                    raise ValueError(f"invalid height response: {payload!r}")
                heights[node] = height
            except (requests.RequestException, ValueError, TypeError) as error:
                log(f"{name}: observer {node} unavailable for height: {error}")

        if not heights:
            raise TemporaryObserverError(
                f"{name}: all configured observers failed for /blocks/height"
            )

        minimum_height = min(heights.values())
        probe_heights = tuple(dict.fromkeys((1, max(1, minimum_height // 2), minimum_height)))
        observations: list[tuple[str, int, tuple[str, ...]]] = []
        for node, height in heights.items():
            try:
                markers: list[str] = []
                for probe_height in probe_heights:
                    payload = self.get_node_json(
                        node,
                        f"/blocks/seq/{probe_height}/{probe_height}",
                    )
                    blocks = validate_blocks(payload, probe_height, probe_height)
                    markers.append(block_fingerprint(blocks[0]))
                observations.append((node, height, tuple(markers)))
            except (requests.RequestException, ValueError, TypeError) as error:
                log(f"{name}: observer {node} failed chain probe: {error}")

        if not observations:
            raise TemporaryObserverError(f"{name}: no observer passed the chain probes")

        marker_sets = {observation[2] for observation in observations}
        if len(marker_sets) != 1:
            details = ", ".join(
                f"{node}={markers[0][:12]}..." for node, _height, markers in observations
            )
            raise MonitorError(f"{name}: configured observers disagree about the chain: {details}")

        usable_nodes = tuple(observation[0] for observation in observations)
        return ChainInfo(
            name=name,
            configured_nodes=configured_nodes,
            nodes=usable_nodes,
            height=max(observation[1] for observation in observations),
            probe_heights=probe_heights,
            probe_markers=observations[0][2],
        )

    def get_blocks(
        self,
        chain: ChainInfo,
        start: int,
        end: int,
    ) -> tuple[list[dict[str, Any]], str]:
        """Fetch a range, falling back to every replica that passed the probes."""
        errors: list[str] = []
        for node in chain.nodes:
            try:
                payload = self.get_node_json(node, f"/blocks/seq/{start}/{end}")
                return validate_blocks(payload, start, end), node
            except (requests.RequestException, ValueError, TypeError) as error:
                errors.append(f"{node}: {type(error).__name__}: {error}")
        raise TemporaryObserverError(
            f"{chain.name}: all verified observers failed for {start}-{end}: "
            + "; ".join(errors)
        )

    def close(self) -> None:
        self.session.close()


def parameter_value(parameter: Any) -> Any:
    if not isinstance(parameter, dict):
        return None
    # ``value`` is used by the current observer API; the typed names cover
    # older/exported representations found in archived dumps.
    for key in ("value", "stringValue", "intValue", "boolValue", "booleanValue", "binaryValue"):
        if key in parameter:
            return parameter[key]
    return None


def transaction_kind(transaction: Any) -> str:
    """Return a useful operation/type label for one outer transaction."""
    if not isinstance(transaction, dict):
        return "invalid"

    outer_type = transaction.get("type")
    if outer_type == 105:
        inner = transaction.get("tx")
        if isinstance(inner, dict):
            inner_type = inner.get("type")
            if inner_type == 103:
                return "createContract"
            if inner_type == 104:
                for parameter in inner.get("params") or []:
                    if isinstance(parameter, dict) and parameter.get("key") == "operation":
                        operation = parameter_value(parameter)
                        if operation not in (None, ""):
                            return str(operation)
                return "contractCall"
            return f"inner-type-{inner_type}"

    if outer_type is None:
        return "unknown"
    return f"type-{outer_type}"


def block_timestamp(value: Any) -> str:
    """Format observer millisecond timestamps in Moscow time."""
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return "unknown"
    if numeric != numeric or numeric in (float("inf"), float("-inf")):
        return "unknown"

    # Blockchain timestamps are milliseconds; accepting seconds makes the
    # formatter useful with old fixtures without changing normal output.
    milliseconds = abs(numeric) >= 100_000_000_000
    seconds = numeric / 1000 if milliseconds else numeric
    try:
        moment = datetime.fromtimestamp(seconds, tz=timezone.utc).astimezone(MSK)
    except (OverflowError, OSError, ValueError):
        return "unknown"
    return moment.isoformat(timespec="milliseconds" if milliseconds else "seconds")


def format_block(block: dict[str, Any], shard: str) -> str:
    counts = Counter(transaction_kind(transaction) for transaction in block["transactions"])
    kinds = ",".join(f"{kind}:{count}" for kind, count in sorted(counts.items())) or "-"
    return (
        f"height={block['height']} shard={shard} "
        f"timestamp={block_timestamp(block.get('timestamp'))} "
        f"transactions={len(block['transactions'])} kinds={kinds}"
    )


def monitor_shard(
    name: str,
    nodes: tuple[str, ...],
    output_dir: Path,
    chunk_size: int,
    port: int,
    timeout: tuple[float, float],
    emit: Callable[[str], None],
) -> ChainInfo:
    shard_dir = output_dir / name
    shard_dir.mkdir(parents=True, exist_ok=True)
    state_path = shard_dir / "state.json"
    client = ShardClient(nodes, port, timeout)
    try:
        chain = client.inspect_chain(name, nodes)
        state = read_json_file(state_path) if state_path.exists() else {}
        completed = completed_through(shard_dir)

        # Files made by an older dump have no trusted monitor state.  Validate
        # them once before appending; new chunks are atomic and height-checked.
        if completed and (
            state.get("schema") != STATE_SCHEMA or not state.get("chain_fingerprint")
        ):
            completed = validate_existing_chunks(shard_dir)
            log(f"{name}: validated legacy chunks through {completed}")

        existing_first = first_existing_block_fingerprint(shard_dir)
        if existing_first is not None and existing_first != chain.fingerprint:
            raise MonitorError(f"{name}: existing files belong to a different chain")
        saved_fingerprint = state.get("chain_fingerprint")
        if saved_fingerprint is not None and saved_fingerprint != chain.fingerprint:
            raise MonitorError(f"{name}: state file belongs to a different chain")
        if completed > chain.height:
            raise MonitorError(
                f"{name}: saved height {completed} exceeds observed height {chain.height}"
            )

        start = completed + 1
        log(
            f"{name}: height {chain.height}; resuming at {start}; "
            f"verified observers: {', '.join(chain.nodes)}"
        )
        write_state(state_path, chain, completed)

        while start <= chain.height:
            end = min(start + chunk_size - 1, chain.height)
            chunk_path = shard_dir / f"{start:09d}-{end:09d}.jsonl"
            if chunk_path.exists():
                # This should already have been included by completed_through;
                # refusing to overwrite it is safer than silently duplicating data.
                raise MonitorError(f"{name}: unexpected existing chunk {chunk_path}")

            blocks, source_node = client.get_blocks(chain, start, end)
            write_chunk(chunk_path, blocks, start, end)
            completed = end
            # Persist the checkpoint before emitting.  If stdout is interrupted,
            # the durable raw blocks still make the next run resumable.
            write_state(state_path, chain, completed)
            for block in blocks:
                emit(format_block(block, name))
            log(f"{name}: saved {chunk_path.name} from {source_node}")
            start = end + 1
    finally:
        client.close()
    return chain


def write_manifest(output_dir: Path, chains: list[ChainInfo]) -> None:
    atomic_write(
        output_dir / "manifest.json",
        json.dumps(
            {
                "schema": STATE_SCHEMA,
                "active_shards": [
                    {
                        "name": chain.name,
                        "nodes": list(chain.nodes),
                        "height": chain.height,
                        "chain_fingerprint": chain.fingerprint,
                    }
                    for chain in chains
                ],
                "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )


def parse_node_overrides(values: list[str] | None) -> dict[str, tuple[str, ...]]:
    overrides: dict[str, tuple[str, ...]] = {}
    for value in values or []:
        name, separator, raw_nodes = value.partition("=")
        nodes = tuple(node.strip() for node in raw_nodes.split(",") if node.strip())
        if not separator or not name or not nodes:
            raise ValueError(
                f"invalid --nodes value {value!r}; expected SHARD=HOST[,HOST...]"
            )
        if name in overrides:
            raise ValueError(f"duplicate --nodes override for {name}")
        overrides[name] = nodes
    return overrides


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"directory for raw block chunks (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"blocks per durable chunk (default: {DEFAULT_CHUNK_SIZE})",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--connect-timeout", type=float, default=5.0)
    parser.add_argument("--read-timeout", type=float, default=60.0)
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=30.0,
        help="delay between passes in follow mode (default: 30)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--once",
        action="store_true",
        help="process the current heights and exit instead of following",
    )
    mode.add_argument(
        "--follow",
        action="store_true",
        help="keep polling after catching up (the default)",
    )
    parser.add_argument(
        "--only-shard",
        action="append",
        metavar="NAME",
        help="monitor only this shard; may be repeated",
    )
    parser.add_argument(
        "--nodes",
        action="append",
        metavar="SHARD=HOST[,HOST...]",
        help="override observer hosts for a shard; may be repeated",
    )
    args = parser.parse_args()
    if (
        args.chunk_size < 1
        or not 1 <= args.port <= 65535
        or args.connect_timeout <= 0
        or args.read_timeout <= 0
        or args.poll_seconds <= 0
    ):
        parser.error("chunk size, port, timeouts, and poll interval must be positive")
    try:
        overrides = parse_node_overrides(args.nodes)
    except ValueError as error:
        parser.error(str(error))

    shards = dict(SHARDS)
    shards.update(overrides)
    selected = args.only_shard or list(shards)
    missing = [name for name in selected if name not in shards]
    if missing:
        parser.error(f"unknown shard(s): {', '.join(missing)}")
    args.shards = [(name, shards[name]) for name in selected]
    return args


def main() -> int:
    args = parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    log(f"saving raw blocks to {output_dir}")

    while True:
        chains: list[ChainInfo] = []
        try:
            for name, nodes in args.shards:
                chains.append(
                    monitor_shard(
                        name,
                        nodes,
                        output_dir,
                        args.chunk_size,
                        args.port,
                        (args.connect_timeout, args.read_timeout),
                        lambda line: print(line, flush=True),
                    )
                )
            write_manifest(output_dir, chains)
        except TemporaryObserverError as error:
            if args.once:
                raise
            log(f"temporary observer failure: {error}; retrying in {args.poll_seconds:g}s")
            time.sleep(args.poll_seconds)
            continue

        if args.once:
            return 0
        log(f"all selected shards caught up; waiting {args.poll_seconds:g}s")
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        log("stopped")
        raise SystemExit(130)
    except BrokenPipeError:
        # A consumer such as ``head`` can intentionally close stdout.
        raise SystemExit(0)
    except Exception as error:  # noqa: BLE001 - command-line boundary
        log(f"failed: {type(error).__name__}: {error}")
        raise SystemExit(1)
