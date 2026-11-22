#!/usr/bin/env python3
"""Local JSONL conversation storage for Moros AI agents."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

_SAFE_AGENT = re.compile(r"[^a-zA-Z0-9._-]+")


def safe_agent_name(agent: str) -> str:
    """Return a filesystem-safe, bounded agent identifier."""
    value = _SAFE_AGENT.sub("-", str(agent or "coordinator").strip()).strip(".-")
    return (value or "coordinator")[:80]


class ConversationStore:
    """Append-only conversation history stored under target/output/conversations."""

    def __init__(self, target_dir: Path):
        self.target_dir = Path(target_dir).resolve()
        self.root = self.target_dir / "output" / "conversations"
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, agent: str) -> Path:
        return self.root / f"{safe_agent_name(agent)}.jsonl"

    def append(self, agent: str, role: str, content: str, **metadata: Any) -> Dict[str, Any]:
        entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": safe_agent_name(agent),
            "role": role,
            "content": str(content or ""),
        }
        entry.update({k: v for k, v in metadata.items() if v is not None})
        with self._path(agent).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def list_agents(self) -> List[str]:
        return sorted(path.stem for path in self.root.glob("*.jsonl"))

    def read(self, agent: str = "coordinator", limit: int = 200) -> List[Dict[str, Any]]:
        path = self._path(agent)
        if not path.is_file():
            return []
        rows: List[Dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as stream:
            for line in stream:
                try:
                    item = json.loads(line)
                    if isinstance(item, dict):
                        rows.append(item)
                except json.JSONDecodeError:
                    continue
        return rows[-max(1, min(int(limit), 1000)):]
