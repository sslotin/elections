#!/usr/bin/env python3
"""Resumable, chunked dump of the DEG blockchain.

The configured observer hosts are discovered at startup.  Hosts that return the
same blocks at several shared heights are treated as replicas of one logical
chain; hosts that disagree are written to separate output directories instead
of being merged and double-counted.

Every downloaded block is validated before an atomic rename.  Existing chunks
from an older run are validated before they are resumed.
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import requests


# Keep all known observers in deterministic order.  The old script assumed that
# fixed pairs were logical shards; the captured data showed that this can be
# false when chains share a long prefix or the observer topology changes.
OBSERVER_NODES = (
    "172.25.26.139",
    "172.25.202.132",
    "172.25.10.133",
    "172.25.154.135",
    "172.25.138.146",
    "172.25.218.135",
)
DEFAULT_CHUNK_SIZE = 100
STATE_SCHEMA = 3
CHUNK_NAME = re.compile(r"^(\d+)-(\d+)\.jsonl$")


@dataclass(frozen=True)
class NodeObservation:
    node: str
    height: int
    probe_markers: tuple[str, ...]


@dataclass(frozen=True)
class ChainInfo:
    name: str
    nodes: tuple[str, ...]
    height: int
    probe_heights: tuple[int, ...]
    probe_markers: tuple[str, ...]

    @property
    def fingerprint(self) -> str:
        # The first block marker is stable as a persisted identity.  The other
        # probe markers are still checked live but their heights are dynamic.
        return self.probe_markers[0]


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def atomic_write(path: Path, content: str) -> None:
    """Durably replace a small text file without exposing a partial version."""
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
    """Hash a canonical block representation for replica/chain comparisons."""
    encoded = json.dumps(
        block,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_block(block: Any, expected_height: int) -> dict[str, Any]:
    """Reject malformed or out-of-order blocks before they become durable."""
    if not isinstance(block, dict):
        raise ValueError(f"block {expected_height} is not an object")
    if block.get("height") != expected_height:
        raise ValueError(
            f"expected block height {expected_height}, got {block.get('height')!r}"
        )
    transactions = block.get("transactions")
    if not isinstance(transactions, list):
        raise ValueError(f"block {expected_height} has no transaction list")
    transaction_count = block.get("transactionCount")
    if transaction_count is not None and transaction_count != len(transactions):
        raise ValueError(
            f"block {expected_height} advertises {transaction_count} transactions, "
            f"received {len(transactions)}"
        )
    return block


def validate_blocks(payload: Any, start: int, end: int) -> list[dict[str, Any]]:
    """Validate an observer response, including every inclusive block height."""
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
    """Return the end of the contiguous sequence of complete chunks."""
    expected_start = 1
    for _path, start, end in chunk_paths(shard_dir):
        if start != expected_start or end < start:
            break
        expected_start = end + 1
    return expected_start - 1


def validate_existing_chunks(shard_dir: Path) -> int:
    """Validate an old or untrusted directory and return its completed height."""
    expected_height = 1
    for path, start, end in chunk_paths(shard_dir):
        if start != expected_height or end < start:
            raise RuntimeError(
                f"{shard_dir}: chunk sequence is not contiguous before {path.name}"
            )
        lines = 0
        line_number = 0
        try:
            with path.open(encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, 1):
                    if not line.strip():
                        raise ValueError("blank JSONL line")
                    block = json.loads(line)
                    validate_block(block, expected_height)
                    expected_height += 1
                    lines += 1
        except (OSError, json.JSONDecodeError, ValueError) as error:
            raise RuntimeError(f"invalid block data in {path}:{line_number}: {error}") from error
        expected_lines = end - start + 1
        if lines != expected_lines:
            raise RuntimeError(
                f"{path}: filename promises {expected_lines} lines, found {lines}"
            )
    return expected_height - 1


def iter_blocks(shard_dir: Path) -> Iterator[dict[str, Any]]:
    """Yield blocks in height order; callers should validate the directory first."""
    for path, _start, _end in chunk_paths(shard_dir):
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                yield json.loads(line)


def write_chunk(path: Path, blocks: list[Any], start: int, end: int) -> None:
    # Validate before making the chunk visible under its final name.
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
        raise RuntimeError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} does not contain a JSON object")
    return value


def first_existing_block_fingerprint(shard_dir: Path) -> str | None:
    for path, start, _end in chunk_paths(shard_dir):
        if start != 1:
            continue
        try:
            with path.open(encoding="utf-8") as stream:
                line = stream.readline()
            block = validate_block(json.loads(line), 1)
        except (OSError, json.JSONDecodeError, ValueError) as error:
            raise RuntimeError(f"cannot inspect first block in {path}: {error}") from error
        return block_fingerprint(block)
    return None


class ShardClient:
    def __init__(self, nodes: tuple[str, ...], port: int, timeout: tuple[float, float]) -> None:
        self.nodes = nodes
        self.port = port
        self.timeout = timeout
        self.session = requests.Session()
        # The dump host is isolated; only the configured private addresses may
        # be contacted, even if a proxy variable appears in its environment.
        self.session.trust_env = False

    def get_node_json(self, node: str, path: str) -> Any:
        response = self.session.get(f"http://{node}:{self.port}{path}", timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def discover_chains(self) -> list[ChainInfo]:
        """Probe all observers and split them by their verified block sequence."""
        heights: dict[str, int] = {}
        for node in self.nodes:
            try:
                payload = self.get_node_json(node, "/blocks/height")
                height = payload.get("height") if isinstance(payload, dict) else None
                if not isinstance(height, int) or height < 1:
                    raise ValueError(f"invalid height response: {payload!r}")
                heights[node] = height
            except (requests.RequestException, ValueError) as error:
                log(f"observer {node} unavailable for height: {error}")

        if not heights:
            raise RuntimeError("all configured observers failed for /blocks/height")

        minimum_height = min(heights.values())
        probe_heights = tuple(
            dict.fromkeys((1, max(1, minimum_height // 2), minimum_height))
        )
        observations: list[NodeObservation] = []
        for node, height in heights.items():
            try:
                markers: list[str] = []
                for probe_height in probe_heights:
                    payload = self.get_node_json(
                        node, f"/blocks/seq/{probe_height}/{probe_height}"
                    )
                    blocks = validate_blocks(payload, probe_height, probe_height)
                    markers.append(block_fingerprint(blocks[0]))
                observations.append(NodeObservation(node, height, tuple(markers)))
            except (requests.RequestException, ValueError) as error:
                log(f"observer {node} failed chain probe: {error}")

        if not observations:
            raise RuntimeError("no observer passed the chain probes")

        groups: dict[tuple[str, ...], list[NodeObservation]] = {}
        for observation in observations:
            groups.setdefault(observation.probe_markers, []).append(observation)
        if len(groups) > 1:
            log(
                f"observers split into {len(groups)} distinct chain identities; "
                "writing separate chains instead of merging them"
            )

        order = {node: index for index, node in enumerate(self.nodes)}
        sorted_groups = sorted(groups.values(), key=lambda group: min(order[x.node] for x in group))
        chains: list[ChainInfo] = []
        used_names: set[str] = set()
        for group in sorted_groups:
            first_index = min(order[x.node] for x in group)
            base_name = f"shard-{first_index // 2}"
            name = base_name
            suffix = 2
            while name in used_names:
                name = f"{base_name}-fork-{suffix}"
                suffix += 1
            used_names.add(name)
            chain = ChainInfo(
                name=name,
                nodes=tuple(x.node for x in group),
                height=max(x.height for x in group),
                probe_heights=probe_heights,
                probe_markers=group[0].probe_markers,
            )
            chains.append(chain)
            log(
                f"{name}: height {chain.height}; observers: {', '.join(chain.nodes)}; "
                f"fingerprint {chain.fingerprint[:12]}"
            )
        return chains

    def get_blocks(self, chain: ChainInfo, start: int, end: int) -> tuple[list[dict[str, Any]], str]:
        """Fetch a validated range, trying every verified replica before failing."""
        errors: list[str] = []
        for node in chain.nodes:
            try:
                payload = self.get_node_json(node, f"/blocks/seq/{start}/{end}")
                return validate_blocks(payload, start, end), node
            except (requests.RequestException, ValueError) as error:
                errors.append(f"{node}: {type(error).__name__}: {error}")
        raise RuntimeError(
            f"{chain.name}: all verified observers failed for {start}-{end}: {'; '.join(errors)}"
        )

    def close(self) -> None:
        self.session.close()


def write_state(path: Path, chain: ChainInfo, completed: int) -> None:
    atomic_write(
        path,
        json.dumps(
            {
                "schema": STATE_SCHEMA,
                "shard": chain.name,
                "nodes": list(chain.nodes),
                "chain_fingerprint": chain.fingerprint,
                "probe_heights": list(chain.probe_heights),
                "completed_through": completed,
                "observed_height": chain.height,
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )


def dump_shard(
    chain: ChainInfo,
    output_dir: Path,
    chunk_size: int,
    client: ShardClient,
) -> ChainInfo:
    shard_dir = output_dir / chain.name
    state_path = shard_dir / "state.json"
    shard_dir.mkdir(parents=True, exist_ok=True)
    state = read_json_file(state_path) if state_path.exists() else {}
    completed = completed_through(shard_dir)

    # Old files predate chain fingerprints.  Validate them once, then write
    # schema-3 state so subsequent resumptions can rely on atomic chunks.
    if completed and (state.get("schema") != STATE_SCHEMA or not state.get("chain_fingerprint")):
        completed = validate_existing_chunks(shard_dir)
        log(f"{chain.name}: validated legacy chunks through {completed}")

    existing_first = first_existing_block_fingerprint(shard_dir)
    if existing_first is not None and existing_first != chain.probe_markers[0]:
        raise RuntimeError(f"{chain.name}: existing files belong to a different chain")
    saved_fingerprint = state.get("chain_fingerprint")
    if saved_fingerprint is not None and saved_fingerprint != chain.fingerprint:
        raise RuntimeError(f"{chain.name}: state file belongs to a different chain")
    if completed > chain.height:
        raise RuntimeError(
            f"{chain.name}: saved height {completed} exceeds observed height {chain.height}"
        )

    start = completed + 1
    log(f"{chain.name}: resuming at {start}; height {chain.height}")
    write_state(state_path, chain, completed)

    while start <= chain.height:
        end = min(start + chunk_size - 1, chain.height)
        chunk_path = shard_dir / f"{start:09d}-{end:09d}.jsonl"
        if chunk_path.exists():
            # A previous process may have completed the atomic rename just
            # before interruption; the contiguous-file check accepted it.
            log(f"{chain.name}: keeping existing {chunk_path.name}")
        else:
            blocks, source_node = client.get_blocks(chain, start, end)
            write_chunk(chunk_path, blocks, start, end)
            log(f"{chain.name}: wrote {chunk_path.name} from {source_node}")

        completed = end
        write_state(state_path, chain, completed)
        start = end + 1
    return chain


def check_existing_directories(output_dir: Path, chains: list[ChainInfo]) -> None:
    """Fail closed instead of silently mixing stale directories into new output."""
    active_names = {chain.name for chain in chains}
    unexpected = sorted(
        path.name
        for path in output_dir.glob("shard-*")
        if path.is_dir() and path.name not in active_names
    )
    if unexpected:
        raise RuntimeError(
            "unexpected existing chain directories: "
            + ", ".join(unexpected)
            + "; move them aside or use a fresh --output-dir"
        )


def write_manifest(output_dir: Path, chains: list[ChainInfo]) -> None:
    atomic_write(
        output_dir / "manifest.json",
        json.dumps(
            {
                "schema": STATE_SCHEMA,
                "active_chains": [
                    {
                        "name": chain.name,
                        "nodes": list(chain.nodes),
                        "height": chain.height,
                        "chain_fingerprint": chain.fingerprint,
                    }
                    for chain in chains
                ],
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("block-dump"),
        help="directory for per-chain JSONL chunks (default: %(default)s)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help="blocks per durable JSONL chunk (default: %(default)s)",
    )
    parser.add_argument("--port", type=int, default=6862, help="observer-node HTTP port (default: 6862)")
    parser.add_argument("--connect-timeout", type=float, default=5.0)
    parser.add_argument("--read-timeout", type=float, default=60.0)
    parser.add_argument(
        "--follow",
        action="store_true",
        help="keep polling for new blocks after each complete pass",
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=30.0,
        help="delay between --follow passes (default: %(default)s)",
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
    return args


def main() -> int:
    args = parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    log(f"writing unique chains to {output_dir}")
    client = ShardClient(OBSERVER_NODES, args.port, (args.connect_timeout, args.read_timeout))
    try:
        while True:
            chains = client.discover_chains()
            check_existing_directories(output_dir, chains)
            completed_chains = [
                dump_shard(chain, output_dir, args.chunk_size, client) for chain in chains
            ]
            write_manifest(output_dir, completed_chains)
            if not args.follow:
                return 0
            log(f"all chains caught up; waiting {args.poll_seconds:g} seconds")
            time.sleep(args.poll_seconds)
    finally:
        client.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, requests.RequestException) as error:
        log(f"stopped: {type(error).__name__}: {error}")
        raise SystemExit(130)
    except Exception as error:
        log(f"failed: {type(error).__name__}: {error}")
        raise SystemExit(1)
