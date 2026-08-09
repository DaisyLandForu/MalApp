from __future__ import annotations

"""Rebuild the knowledge-graph layer over the existing RAG document store."""

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.rag import rag_status, rebuild_graph_index


def main() -> None:
    result = rebuild_graph_index()
    print(json.dumps({"rebuild": result, "status": rag_status()}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
