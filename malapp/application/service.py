"""One authoritative application service shared by every entrypoint."""

from __future__ import annotations

from typing import Any

from malapp.application.contracts import JudgementRequest


class JudgementService:
    pipeline = "malapp.agent-runtime.v2"

    def judge(self, request: JudgementRequest) -> dict[str, Any]:
        if not isinstance(request, JudgementRequest):
            raise TypeError("JudgementService expects JudgementRequest")
        from malapp.application.judgement import execute_judgement

        return execute_judgement(request.sample, entrypoint=request.source)


_DEFAULT_SERVICE = JudgementService()


def get_judgement_service() -> JudgementService:
    return _DEFAULT_SERVICE
