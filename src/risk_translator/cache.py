"""A small on-disk JSON cache in .cache/, so repeat runs reuse API responses.

Each entry is one file: .cache/<namespace>/<key>.json, holding the time it was
saved and the data. Keys are restricted to safe characters so a key can never
point outside the cache folder.
"""

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class DiskCache:
    """Read and write JSON entries under a cache folder."""

    def __init__(self, root: Path, refresh: bool = False) -> None:
        """Create a cache rooted at root. With refresh=True, reads always miss."""
        self.root = root
        self.refresh = refresh

    def _path(self, namespace: str, key: str) -> Path:
        for part in (namespace, key):
            if not SAFE_KEY.match(part):
                raise ValueError(f"Unsafe cache key: {part!r}")
        return self.root / namespace / f"{key}.json"

    def get(self, namespace: str, key: str, max_age: timedelta | None = None) -> Any | None:
        """Return the cached data, or None if missing, too old, unreadable or refreshing."""
        if self.refresh:
            return None
        path = self._path(namespace, key)
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
            saved_at = datetime.fromisoformat(entry["saved_at"])
            data = entry["data"]
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if max_age is not None and datetime.now(UTC) - saved_at > max_age:
            return None
        return data

    def set(self, namespace: str, key: str, data: Any) -> None:
        """Save data under namespace/key, replacing any existing entry."""
        path = self._path(namespace, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"saved_at": datetime.now(UTC).isoformat(), "data": data}
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(entry), encoding="utf-8")
        temp.replace(path)  # atomic, so a crash never leaves half a file
