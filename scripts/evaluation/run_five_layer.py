from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malapp.evaluation.five_layer import (  # noqa: E402
    build_structured_rag_corpus,
    five_layer_overview,
    generate_five_layer_suite,
    score_model_predictions,
    score_production_drift,
    source_inventory,
    validate_five_layer_suite,
)
from malapp.evaluation.framework import (  # noqa: E402
    DEFAULT_VALIDATION_CSV,
    build_rag_retrieval_scorecard,
)


def print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def cmd_inventory(args: argparse.Namespace) -> None:
    result = source_inventory(
        validation_csv=Path(args.validation_csv),
        data_dir=Path(args.data_dir).expanduser().resolve() if args.data_dir else None,
    )
    if args.output:
        path = Path(args.output).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(result, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    print_json(result)


def cmd_generate(args: argparse.Namespace) -> None:
    print_json(
        generate_five_layer_suite(
            name=args.name,
            validation_csv=Path(args.validation_csv),
            data_dir=Path(args.data_dir).expanduser().resolve() if args.data_dir else None,
            output_root=(
                Path(args.output_root).expanduser().resolve()
                if args.output_root
                else None
            ),
            model_size=args.model_size,
            rag_size=args.rag_size,
            agent_size=args.agent_size,
            challenge_size=args.challenge_size,
            fresh_candidate_size=args.fresh_candidate_size,
        )
    )


def cmd_build_rag_corpus(args: argparse.Namespace) -> None:
    print_json(
        build_structured_rag_corpus(
            validation_csv=Path(args.validation_csv),
            data_dir=Path(args.data_dir).expanduser().resolve() if args.data_dir else None,
            suite_dir=(
                Path(args.suite_dir).expanduser().resolve()
                if args.suite_dir
                else None
            ),
            size=args.size,
            rag_db_path=(
                Path(args.rag_db).expanduser().resolve()
                if args.rag_db
                else None
            ),
        )
    )


def cmd_overview(args: argparse.Namespace) -> None:
    print_json(
        five_layer_overview(
            validation_csv=Path(args.validation_csv),
            data_dir=Path(args.data_dir).expanduser().resolve() if args.data_dir else None,
        )
    )


def cmd_validate(args: argparse.Namespace) -> None:
    result = validate_five_layer_suite(Path(args.suite_dir))
    print_json(result)
    if not result["passed"]:
        raise SystemExit(2)


def cmd_score_model(args: argparse.Namespace) -> None:
    result = score_model_predictions(Path(args.dataset), Path(args.predictions))
    if args.output:
        path = Path(args.output).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print_json(result)


def cmd_score_rag(args: argparse.Namespace) -> None:
    result = build_rag_retrieval_scorecard(Path(args.dataset))
    if args.output:
        path = Path(args.output).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print_json(result)


def cmd_drift(args: argparse.Namespace) -> None:
    result = score_production_drift(Path(args.suite_dir), Path(args.current_csv))
    if args.output:
        path = Path(args.output).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print_json(result)
    if result["status"] == "blocked":
        raise SystemExit(2)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="MalApp five-layer evaluation dataset and baseline builder"
    )
    root.add_argument("--validation-csv", default=str(DEFAULT_VALIDATION_CSV))
    root.add_argument("--data-dir", default="")
    sub = root.add_subparsers(dest="command", required=True)

    inventory = sub.add_parser("inventory", help="audit all existing evaluation sources")
    inventory.add_argument("--output", default="")
    inventory.set_defaults(func=cmd_inventory)

    generate = sub.add_parser(
        "generate",
        help="generate all five versioned evaluation datasets and baselines",
    )
    generate.add_argument("--name", default="v1")
    generate.add_argument("--output-root", default="")
    generate.add_argument("--model-size", type=int, default=500)
    generate.add_argument("--rag-size", type=int, default=200)
    generate.add_argument("--agent-size", type=int, default=500)
    generate.add_argument("--challenge-size", type=int, default=300)
    generate.add_argument("--fresh-candidate-size", type=int, default=1000)
    generate.set_defaults(func=cmd_generate)

    rag_corpus = sub.add_parser(
        "build-rag-corpus",
        help="build a leakage-safe structured KG+vector corpus from operational records",
    )
    rag_corpus.add_argument("--suite-dir", default="")
    rag_corpus.add_argument("--rag-db", default="")
    rag_corpus.add_argument("--size", type=int, default=2000)
    rag_corpus.set_defaults(func=cmd_build_rag_corpus)

    overview = sub.add_parser("overview", help="show the latest five-layer suite")
    overview.set_defaults(func=cmd_overview)

    validate = sub.add_parser("validate", help="validate suite files and leakage rules")
    validate.add_argument("suite_dir")
    validate.set_defaults(func=cmd_validate)

    score_model = sub.add_parser(
        "score-model",
        help="score model A/B/candidate JSONL predictions on a layer-1 dataset",
    )
    score_model.add_argument("dataset")
    score_model.add_argument("predictions")
    score_model.add_argument("--output", default="")
    score_model.set_defaults(func=cmd_score_model)

    score_rag = sub.add_parser(
        "score-rag",
        help="score approved layer-2 retrieval annotations",
    )
    score_rag.add_argument("dataset")
    score_rag.add_argument("--output", default="")
    score_rag.set_defaults(func=cmd_score_rag)

    drift = sub.add_parser(
        "drift",
        help="compare a current CSV with the layer-5 frozen drift reference",
    )
    drift.add_argument("suite_dir")
    drift.add_argument("current_csv")
    drift.add_argument("--output", default="")
    drift.set_defaults(func=cmd_drift)
    return root


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
