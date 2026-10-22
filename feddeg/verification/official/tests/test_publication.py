"""Regression tests for the published Docker images and data adapters."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

OFFICIAL = Path(__file__).resolve().parents[1]
CASE = OFFICIAL / "unlinked_sum"
CONTRACT = "4BbdvzVdbyQES6ARbt4YDB4htfUYgwUVGpQYNa6dLj3u"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


adapter = load("official_adapter", OFFICIAL / "dump_to_official.py")
batches = load("official_batches", OFFICIAL / "make_batches.py")


class PublicationTests(unittest.TestCase):
    def test_sum_proof_case_is_flat(self):
        csv = CASE / "unlinked_sum.csv"
        rows = csv.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(rows), 10)
        self.assertEqual(sum('"operation","stringValue":"vote"' in row for row in rows), 1)
        self.assertFalse((CASE / "files").exists())
        self.assertFalse((CASE / "CASE.json").exists())
        separate = (CASE / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn(csv.name, separate)
        self.assertIn('"--no-tx-sig", "--verbose"', separate)

    def test_base_image_has_no_test_cases(self):
        base = (OFFICIAL / "Dockerfile").read_text(encoding="utf-8")
        self.assertNotIn("COPY bugs", base)
        self.assertIn('ENTRYPOINT ["node", "/app/dist/index.js"]', base)
        self.assertFalse((OFFICIAL / "bugs").exists())

    def test_adapter_and_relocatable_batches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "dump.jsonl"
            transaction = {"type": 105, "tx": {
                "type": 104, "id": "tx", "contractId": "contract", "version": 1,
                "timestamp": 1, "senderPublicKey": "public", "params": [
                    {"key": "operation", "type": "string", "value": "vote"},
                    {"key": "note", "type": "string", "value": "a;b"}],
            }, "results": [{"key": "zero", "type": "integer", "value": 0}]}
            source.write_text(json.dumps({"transactions": [transaction]}) + "\n")
            output = root / "converted"
            self.assertEqual(adapter.main(["--dump", str(source), "--out", str(output)]), 0)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["contracts"]["contract"]["lines"], 1)
            for copy in (False, True):
                arguments = ["--base", str(output), "--batches", "2"]
                if copy:
                    arguments += ["--copy", "--force"]
                self.assertEqual(batches.main(arguments), 0)
                batch = output / "batches" / "batch-00" / "files" / "contract_dump.zip"
                self.assertEqual(batch.read_bytes(), (output / "files" / "contract.zip").read_bytes())
            self.assertEqual(json.loads(source.read_text())["transactions"][0], transaction)


if __name__ == "__main__":
    unittest.main()
