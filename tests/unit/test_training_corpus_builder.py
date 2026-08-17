from __future__ import annotations

from training.datasets.corpus import (
    RESERVED_SAMPLE_FIELD_PATTERN,
    extract_md5s_from_text,
    group_key,
    stable_stratified_select,
)


def sample(md5: str, label: str, package: str, quality: int = 10) -> dict:
    row = {
        "md5": md5,
        "label": label,
        "input": {"md5": md5, "package_name": package},
        "quality_rank": quality,
    }
    row["group_id"] = group_key(row)
    return row


def test_md5_extraction_does_not_take_sha256_fragments() -> None:
    md5 = "A" * 32
    sha256 = "B" * 64
    assert extract_md5s_from_text(f"md5={md5}; sha256={sha256}") == {md5}


def test_reserved_field_pattern_ignores_certificate_hashes() -> None:
    sample_id = "A" * 32
    certificate_id = "B" * 32
    text = f'{{"sample_id":"{sample_id}","certificate_fingerprint":"{certificate_id}"}}'
    assert {match.group(1) for match in RESERVED_SAMPLE_FIELD_PATTERN.finditer(text)} == {sample_id}


def test_group_key_groups_package_versions() -> None:
    first = sample("1" * 32, "malicious", "com.example.app")
    second = sample("2" * 32, "malicious", "com.example.app")
    assert first["group_id"] == second["group_id"]


def test_stratified_selection_respects_group_cap_and_is_deterministic() -> None:
    rows = [
        sample("1" * 32, "malicious", "pkg.same", 20),
        sample("2" * 32, "malicious", "pkg.same", 19),
        sample("3" * 32, "malicious", "pkg.three", 18),
        sample("4" * 32, "benign", "pkg.four", 17),
        sample("5" * 32, "benign", "pkg.five", 16),
    ]
    first = stable_stratified_select(rows, 4, {"malicious": 0.5, "benign": 0.5}, "seed", 1)
    second = stable_stratified_select(rows, 4, {"malicious": 0.5, "benign": 0.5}, "seed", 1)
    assert [row["md5"] for row in first] == [row["md5"] for row in second]
    assert len({row["group_id"] for row in first}) == len(first)
    assert {row["label"] for row in first} == {"malicious", "benign"}
