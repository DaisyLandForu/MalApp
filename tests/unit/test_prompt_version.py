from __future__ import annotations

from malapp.orchestration.debate import debate_prompt_manifest, run_debate


def test_debate_prompt_manifest_versions_every_prompt_family() -> None:
    first = debate_prompt_manifest()
    second = debate_prompt_manifest()

    assert first == second
    assert first["prompt_id"] == "malapp-dual-model-debate"
    assert first["version"] == "1.0.0"
    assert len(first["sha256"]) == 64
    assert set(first["components"]) == {
        "initial_testimony",
        "directed_debate",
        "closing_statement",
        "system_contract",
        "schema_repair",
    }
    for name, component in first["components"].items():
        assert component["prompt_id"].endswith(name)
        assert component["version"] == first["version"]
        assert len(component["sha256"]) == 64
        assert component["created_at"] == first["created_at"]


def test_debate_report_records_prompt_version(monkeypatch) -> None:
    monkeypatch.setenv("MALAPP_PROFILE", "demo")
    monkeypatch.setenv("MALAPP_DISABLE_LLM_RULE_FALLBACK", "0")
    monkeypatch.setenv("MALAPP_USE_SERVER_MODELS", "0")
    monkeypatch.setenv("MALAPP_USE_LOCAL_QWEN", "0")

    report = run_debate([])

    assert report["prompt_version"] == debate_prompt_manifest()
