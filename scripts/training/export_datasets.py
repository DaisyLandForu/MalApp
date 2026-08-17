from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from training.datasets.export import export_all_datasets  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Export SFT/DPO/policy datasets from MalApp judgement history.")
    parser.add_argument("--limit", type=int, default=5000, help="Maximum report count to export.")
    parser.add_argument("--output-dir", default="", help="Optional output directory. Defaults to data/exports/<timestamp>.")
    args = parser.parse_args()
    result = export_all_datasets(output_dir=args.output_dir or None, limit=args.limit)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
