"""CLI for P6 dataset, promotion and release governance."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from malapp.governance.datasets import build_dataset_manifest, validate_dataset_manifest
from malapp.governance.leakage import audit_dataset_manifest
from malapp.governance.promotion import (
    approve_candidate,
    evaluate_candidate,
    promote_candidate,
    record_shadow_result,
    register_candidate,
    rollback_champion,
)
from malapp.governance.release import build_release_snapshot, validate_release_snapshot


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    path.expanduser().resolve().write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def parse_inputs(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        partition, separator, path = value.partition("=")
        if not separator or not partition.strip() or not path.strip():
            raise ValueError(f"dataset input must use partition=path: {value}")
        if partition in result:
            raise ValueError(f"duplicate dataset partition: {partition}")
        result[partition.strip()] = Path(path.strip())
    return result


def parse_sources(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        role, separator, path = value.partition("=")
        if not separator or not role.strip() or not path.strip():
            raise ValueError(f"bound source must use role=path: {value}")
        clean_role = role.strip()
        if clean_role in result:
            raise ValueError(f"duplicate bound source role: {clean_role}")
        result[clean_role] = Path(path.strip())
    return result


def load_reserved_ids(paths: list[str]) -> set[str]:
    result: set[str] = set()
    for raw_path in paths:
        path = Path(raw_path).expanduser().resolve()
        with path.open("r", encoding="utf-8-sig") as handle:
            for line in handle:
                value = line.strip()
                if not value:
                    continue
                if value.startswith("{"):
                    item = json.loads(value)
                    value = str(item.get("sample_id") or item.get("id") or item.get("md5") or "")
                if value:
                    result.add(value)
    return result


def cmd_dataset_build(args: argparse.Namespace) -> None:
    result = build_dataset_manifest(
        dataset_name=args.name,
        dataset_version=args.version,
        inputs=parse_inputs(args.input),
        bound_sources=parse_sources(args.source),
        output_dir=Path(args.output_dir),
    )
    print_json(result)


def cmd_dataset_validate(args: argparse.Namespace) -> None:
    result = validate_dataset_manifest(Path(args.manifest), verify_sources=args.verify_sources)
    print_json({"status": "pass", "dataset": result["manifest"], "lineage_path": str(result["lineage_path"])})


def cmd_leakage(args: argparse.Namespace) -> None:
    result = audit_dataset_manifest(
        Path(args.manifest),
        reserved_sample_ids=load_reserved_ids(args.reserved),
        required_partitions=set(args.require_partition),
    )
    if args.output:
        write_json(Path(args.output), result)
    print_json(result)
    if result["status"] != "pass":
        raise SystemExit(1 if result["status"] == "fail" else 2)


def cmd_candidate_register(args: argparse.Namespace) -> None:
    print_json(
        register_candidate(
            Path(args.registry),
            candidate_id=args.candidate_id,
            component=args.component,
            artifact_manifests=[Path(value) for value in args.artifact_manifest],
            dataset_manifest_path=Path(args.dataset_manifest),
        )
    )


def cmd_candidate_evaluate(args: argparse.Namespace) -> None:
    result = evaluate_candidate(
        Path(args.registry),
        candidate_id=args.candidate_id,
        baseline_scorecard=Path(args.baseline),
        candidate_scorecard=Path(args.candidate_scorecard),
        policy_path=Path(args.policy) if args.policy else None,
    )
    print_json(result)
    status = result["gate"]["status"]
    if status != "pass":
        raise SystemExit(1 if status == "fail" else 2)


def cmd_candidate_shadow(args: argparse.Namespace) -> None:
    print_json(
        record_shadow_result(
            Path(args.registry),
            candidate_id=args.candidate_id,
            shadow_report_path=Path(args.report),
        )
    )


def cmd_candidate_approve(args: argparse.Namespace) -> None:
    print_json(
        approve_candidate(
            Path(args.registry),
            candidate_id=args.candidate_id,
            approver=args.approver,
            note=args.note,
        )
    )


def cmd_candidate_promote(args: argparse.Namespace) -> None:
    print_json(promote_candidate(Path(args.registry), candidate_id=args.candidate_id))


def cmd_candidate_rollback(args: argparse.Namespace) -> None:
    print_json(
        rollback_champion(
            Path(args.registry),
            component=args.component,
            actor=args.actor,
            target_candidate_id=args.target_candidate,
        )
    )


def cmd_release_build(args: argparse.Namespace) -> None:
    print_json(
        build_release_snapshot(
            version=args.version,
            component=args.component,
            registry_path=Path(args.registry),
            dataset_manifest_path=Path(args.dataset_manifest),
            baseline_scorecard_path=Path(args.baseline),
            candidate_scorecard_path=Path(args.candidate_scorecard),
            docker_image_digest=args.docker_digest,
            output_dir=Path(args.output_dir),
            runtime_snapshot_path=Path(args.runtime_snapshot) if args.runtime_snapshot else None,
            gate_policy_path=Path(args.policy) if args.policy else None,
        )
    )


def cmd_release_verify(args: argparse.Namespace) -> None:
    release = validate_release_snapshot(Path(args.manifest), verify_references=not args.no_references)
    print_json({"status": "pass", "release_id": release["release_id"], "sha256": release["sha256"]})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MalApp P6 training, promotion and release governance")
    subparsers = parser.add_subparsers(dest="command", required=True)

    dataset = subparsers.add_parser("dataset-build", help="build an immutable dataset lineage manifest")
    dataset.add_argument("--name", required=True)
    dataset.add_argument("--version", default="")
    dataset.add_argument("--input", action="append", required=True, help="partition=JSONL_PATH")
    dataset.add_argument("--source", action="append", default=[], help="role=ACTUAL_TRAINING_FILE")
    dataset.add_argument("--output-dir", required=True)
    dataset.set_defaults(handler=cmd_dataset_build)

    validate = subparsers.add_parser("dataset-validate", help="validate dataset lineage and digests")
    validate.add_argument("--manifest", required=True)
    validate.add_argument("--verify-sources", action="store_true")
    validate.set_defaults(handler=cmd_dataset_validate)

    leakage = subparsers.add_parser("leakage-audit", help="fail-closed cross-partition leakage audit")
    leakage.add_argument("--manifest", required=True)
    leakage.add_argument("--reserved", action="append", default=[])
    leakage.add_argument("--require-partition", action="append", default=["train", "test"])
    leakage.add_argument("--output")
    leakage.set_defaults(handler=cmd_leakage)

    register = subparsers.add_parser("candidate-register", help="register an immutable Challenger")
    register.add_argument("--registry", required=True)
    register.add_argument("--candidate-id", required=True)
    register.add_argument("--component", required=True)
    register.add_argument("--artifact-manifest", action="append", required=True)
    register.add_argument("--dataset-manifest", required=True)
    register.set_defaults(handler=cmd_candidate_register)

    evaluate = subparsers.add_parser("candidate-evaluate", help="run P5 Gate for a Challenger")
    evaluate.add_argument("--registry", required=True)
    evaluate.add_argument("--candidate-id", required=True)
    evaluate.add_argument("--baseline", required=True)
    evaluate.add_argument("--candidate-scorecard", required=True)
    evaluate.add_argument("--policy")
    evaluate.set_defaults(handler=cmd_candidate_evaluate)

    shadow = subparsers.add_parser("candidate-shadow", help="attach a passing shadow report")
    shadow.add_argument("--registry", required=True)
    shadow.add_argument("--candidate-id", required=True)
    shadow.add_argument("--report", required=True)
    shadow.set_defaults(handler=cmd_candidate_shadow)

    approve = subparsers.add_parser("candidate-approve", help="record explicit human release approval")
    approve.add_argument("--registry", required=True)
    approve.add_argument("--candidate-id", required=True)
    approve.add_argument("--approver", required=True)
    approve.add_argument("--note", default="")
    approve.set_defaults(handler=cmd_candidate_approve)

    promote = subparsers.add_parser("candidate-promote", help="atomically promote an approved Challenger")
    promote.add_argument("--registry", required=True)
    promote.add_argument("--candidate-id", required=True)
    promote.set_defaults(handler=cmd_candidate_promote)

    rollback = subparsers.add_parser("candidate-rollback", help="restore a previous Champion")
    rollback.add_argument("--registry", required=True)
    rollback.add_argument("--component", required=True)
    rollback.add_argument("--actor", required=True)
    rollback.add_argument("--target-candidate", default="")
    rollback.set_defaults(handler=cmd_candidate_rollback)

    release = subparsers.add_parser("release-build", help="build a governed immutable release snapshot")
    release.add_argument("--version", required=True)
    release.add_argument("--component", required=True)
    release.add_argument("--registry", required=True)
    release.add_argument("--dataset-manifest", required=True)
    release.add_argument("--baseline", required=True)
    release.add_argument("--candidate-scorecard", required=True)
    release.add_argument("--docker-digest", required=True)
    release.add_argument("--runtime-snapshot")
    release.add_argument("--policy")
    release.add_argument("--output-dir", required=True)
    release.set_defaults(handler=cmd_release_build)

    verify = subparsers.add_parser("release-verify", help="verify a release and all local references")
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--no-references", action="store_true")
    verify.set_defaults(handler=cmd_release_verify)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
