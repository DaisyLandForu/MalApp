from __future__ import annotations

from malapp.observability.context import safe_digest, sanitized
from malapp.observability.trace import build_agent_trace


def test_sanitized_redacts_credentials_but_preserves_token_metrics() -> None:
    payload = {
        "api_key": "secret-key",
        "nested": {"authorization": "Bearer private", "prompt_tokens": 17},
    }
    clean = sanitized(payload)
    assert clean["api_key"] == "[REDACTED]"
    assert clean["nested"]["authorization"] == "[REDACTED]"
    assert clean["nested"]["prompt_tokens"] == 17
    assert "secret-key" not in safe_digest(payload)


def test_agent_trace_is_bound_to_run_and_contains_no_secret() -> None:
    trace = build_agent_trace(
        {
            "run_id": "run-observability",
            "report_id": "report-observability",
            "sample": {"sample_id": "sample", "api_key": "sample-secret"},
            "preprocess": {"agent_runtime": {"run_id": "run-observability"}},
            "debate": {
                "run_id": "run-observability",
                "providers": {"model_a": {"api_key": "provider-secret"}},
                "model_calls": [{"run_id": "run-observability", "prompt_tokens": 3}],
            },
            "execution": {"run_id": "run-observability", "pipeline": {"run_id": "run-observability"}},
            "runtime_snapshot": {"snapshot_id": "runtime-test"},
        }
    )
    assert trace["trace_id"] == "trace-observability"
    assert trace["run_id"] == "run-observability"
    assert trace["debate"]["model_calls"][0]["prompt_tokens"] == 3
    assert "provider-secret" not in str(trace)
    assert "sample-secret" not in str(trace)
