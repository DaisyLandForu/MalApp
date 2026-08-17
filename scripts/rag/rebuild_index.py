"""Rebuild the knowledge-graph layer over the existing RAG document store."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malapp.rag import finalize_rag_snapshot, rag_status, rebuild_graph_index  # noqa: E402


def main() -> None:
    result = rebuild_graph_index()
    snapshot = finalize_rag_snapshot()
    print(
        json.dumps(
            {"rebuild": result, "status": rag_status(), "snapshot": snapshot},
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
