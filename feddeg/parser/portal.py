"""Read-only portal client and the federal election metadata hierarchy."""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlencode

import requests

API = "https://stat.vybory.gov.ru/api"
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/140.0 Safari/537.36"}


class Portal:
    def __init__(self, cache_dir: Path, workers: int = 8, base: str = API,
                 cache_ttl: float = 300, refresh_cache: bool = False) -> None:
        if workers < 1 or not math.isfinite(cache_ttl) or cache_ttl < 0:
            raise ValueError("workers must be positive; cache TTL must be finite and nonnegative")
        self.cache_dir = cache_dir
        self.base = base.rstrip("/")
        self.cache_ttl = cache_ttl
        self.refresh_cache = refresh_cache
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.pool = ThreadPoolExecutor(workers)
        self.local = threading.local()
        self.lock = threading.Lock()
        self.sessions = []
        self.calls = 0
        self.cache_hits = 0

    def _session(self):
        # requests.Session is not shared across worker threads.
        if not hasattr(self.local, "session"):
            session = requests.Session()
            session.headers.update(HEADERS)
            self.local.session = session
            with self.lock:
                self.sessions.append(session)
        return self.local.session

    def path_to_file(self, path: str, method: str = "GET", body=None) -> Path:
        # Include the API host, full query and POST body; legacy truncated names
        # can collide and must not be reused across live and training portals.
        identity = json.dumps([self.base, method, path, body], sort_keys=True)
        digest = hashlib.sha256(identity.encode()).hexdigest()
        return self.cache_dir / f"{digest}.json"

    def _store(self, path: Path, payload) -> None:
        fd, name = tempfile.mkstemp(prefix=".portal-", dir=self.cache_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, ensure_ascii=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def request(self, method: str, path: str, body=None, attempts: int = 4):
        cached = self.path_to_file(path, method, body)
        if not self.refresh_cache and self.cache_ttl > 0:
            try:
                age = time.time() - cached.stat().st_mtime
                if 0 <= age < self.cache_ttl:
                    payload = json.loads(cached.read_text(encoding="utf-8"))
                    with self.lock:
                        self.cache_hits += 1
                    return payload
            except (OSError, ValueError):
                pass  # Missing/corrupt cache entries are fetched again.
        last_error = None
        for attempt in range(attempts):
            try:
                response = self._session().request(
                    method, f"{self.base}/{path}", json=body, timeout=45,
                )
                response.raise_for_status()
                payload = response.json()
                self._store(cached, payload)
                with self.lock:
                    self.calls += 1
                return payload
            except (requests.RequestException, ValueError) as error:
                last_error = error
                # Authorization/client errors are not transient; never conceal
                # a failed refresh with a stale result from disk.
                if isinstance(error, requests.HTTPError) and error.response is not None:
                    if 400 <= error.response.status_code < 500 and error.response.status_code != 429:
                        break
                if attempt + 1 < attempts:
                    time.sleep(1.0 + attempt)
        raise RuntimeError(f"failed to fetch {path}: {last_error}")

    def get(self, path: str, attempts: int = 4):
        return self.request("GET", path, attempts=attempts)

    def post(self, path: str, body):
        # Used only for the public, read-only UIK search endpoint.
        return self.request("POST", path, body)

    def get_many(self, paths: list[str]) -> list:
        return list(self.pool.map(self.get, paths))

    def close(self):
        self.pool.shutdown(wait=True)
        for session in self.sessions:
            session.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def add_cache_arguments(parser):
    parser.add_argument("--cache-ttl", type=float, default=300,
                        help="cache lifetime in seconds; 0 always refetches (default: 300)")
    parser.add_argument("--refresh-cache", action="store_true",
                        help="ignore existing cached responses for this run")


FEDERAL_COLUMNS = [
    "contract_id", "election_id", "region_code", "region", "election",
    "district_id", "district", "tik_id", "tik", "ballot_type", "time_offset",
    "collection_time_local", "has_results",
]


def collect_federal_metadata(portal: Portal) -> tuple[dict, dict]:
    """Return contract details and leaf-level counters; never sum parent totals.

    The top-level election list may mention only one region. Enumerate regions
    from the election statistics response instead. Identity is contractId,
    never a display name shared by SINGLE and UNION ballots.
    """
    elections = portal.get("elections?level=FEDERAL")["data"]["elections"]
    details, counters = {}, {}
    for election in elections:
        election_id = election["electionId"]
        summary = portal.get(f"statistics/v2/election/{election_id}")["data"]
        regions = summary["regions"]
        region_paths = ["statistics/v2/election/region?" + urlencode({
            "electionId": election_id, "regionCode": region["code"],
        }) for region in regions]
        districts = {}
        for region, payload in zip(regions, portal.get_many(region_paths)):
            for district in payload["data"]["districts"]:
                districts[(region["code"], district["id"])] = (region, district)
        district_values = list(districts.values())
        district_paths = ["statistics/v2/election/district?" + urlencode({
            "electionId": election_id, "districtId": district["id"],
        }) for region, district in district_values]
        leaves = {}
        for (region, district), payload in zip(district_values, portal.get_many(district_paths)):
            for tik in payload["data"]["tiks"]:
                path = "statistics/v2/election/tik?" + urlencode({
                    "electionId": election_id, "districtId": district["id"], "tikId": tik["tikId"],
                })
                leaves[path] = (region, district, tik)
        for context, payload in zip(leaves.values(), portal.get_many(list(leaves))):
            region, district, tik = context
            data = payload["data"]
            for voting in data["votings"]:
                contract = voting["contractId"]
                row = dict(zip(FEDERAL_COLUMNS, [
                    contract, election_id, region["code"],
                    data.get("regionDescription") or region["description"],
                    data.get("electionName") or election["electionName"],
                    voting.get("districtId") or data.get("districtId") or district["id"],
                    voting.get("districtName") or data.get("districtName") or district["name"],
                    data.get("tikId") or tik["tikId"], data.get("tikName") or tik["tikName"],
                    voting["type"], data.get("timeOffset"), data.get("collectionTime"),
                    voting.get("hasResults"),
                ]))
                if contract in details:
                    identity = ("election_id", "region_code", "district_id", "tik_id", "ballot_type")
                    if any(details[contract][key] != row[key] for key in identity):
                        raise ValueError(f"conflicting federal metadata for {contract}")
                details[contract] = row
                counters[contract] = voting["counters"]
    return details, counters
