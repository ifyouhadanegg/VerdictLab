import json
from pathlib import Path
from typing import Any


class SyntheticReputationStore:
    """Loads synthetic sample records from a local JSON file."""

    def __init__(self, data_file: Path | None = None) -> None:
        self._data_file = data_file or (
            Path(__file__).resolve().parent.parent / "data" / "synthetic_samples.json"
        )
        self._records_by_hash: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        with self._data_file.open("r", encoding="utf-8") as handle:
            rows = json.load(handle)
        self._records_by_hash = {row["metadata"]["sha256"]: row for row in rows}

    def get_by_sha256(self, sha256: str) -> dict[str, Any] | None:
        return self._records_by_hash.get(sha256)
