from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from training.datasets.corpus import TrainingCorpusTargets, build_training_corpora  # noqa: E402


def default_data_dir() -> Path:
    configured = os.getenv("MALAPP_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return ROOT / "data"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build leakage-safe SFT, DPO, RAG, Agent and calibration corpora from MalApp data."
    )
    parser.add_argument("--data-dir", default=str(default_data_dir()))
    parser.add_argument("--output-dir", default="")
    parser.add_argument("--sft-core", type=int, default=5000)
    parser.add_argument("--sft-expansion", type=int, default=5000)
    parser.add_argument("--dpo", type=int, default=3000)
    parser.add_argument("--rag", type=int, default=2000)
    parser.add_argument("--agent-success", type=int, default=1000)
    parser.add_argument("--agent-fault-recovery", type=int, default=400)
    parser.add_argument("--calibration", type=int, default=800)
    args = parser.parse_args()

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else (
        ROOT / "generated_training_datasets" / f"trainpack-{stamp}"
    )
    targets = TrainingCorpusTargets(
        sft_core=max(0, args.sft_core),
        sft_expansion=max(0, args.sft_expansion),
        dpo=max(0, args.dpo),
        rag=max(0, args.rag),
        agent_success=max(0, args.agent_success),
        agent_fault_recovery=max(0, args.agent_fault_recovery),
        calibration=max(0, args.calibration),
    )
    result = build_training_corpora(
        data_dir=args.data_dir,
        project_root=ROOT,
        output_dir=output_dir,
        targets=targets,
    )
    print(json.dumps({"output_dir": str(output_dir), "manifest": result}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
