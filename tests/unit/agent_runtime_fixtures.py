from __future__ import annotations

import threading
import time

from malapp.agents.base import AgentContext, AgentResult, EvidenceBlock


def success_result(name: str, score: float = 0.5) -> AgentResult:
    block = EvidenceBlock(
        agent=name,
        claim=f"{name} completed",
        evidence=["fixture evidence"],
        confidence=0.8,
        score=score,
        rule_score=score,
    )
    return AgentResult(name, "completed", score, [block], 0.8)


class SleepingAgent:
    def __init__(self, name: str, sleep_seconds: float):
        self.name = name
        self.sleep_seconds = sleep_seconds

    def run(self, context: AgentContext) -> AgentResult:
        del context
        time.sleep(self.sleep_seconds)
        return success_result(self.name)

class FlakyAgent:
    def __init__(self, name: str, failures: int):
        self.name = name
        self.failures = failures
        self.calls = 0

    def run(self, context: AgentContext) -> AgentResult:
        del context
        self.calls += 1
        if self.calls <= self.failures:
            raise RuntimeError("transient failure")
        return success_result(self.name)


class FailingAgent:
    def __init__(self, name: str):
        self.name = name

    def run(self, context: AgentContext) -> AgentResult:
        del context
        raise ValueError("permanent failure")


class BarrierAgent:
    def __init__(self, name: str, barrier: threading.Barrier):
        self.name = name
        self.barrier = barrier

    def run(self, context: AgentContext) -> AgentResult:
        del context
        self.barrier.wait(timeout=0.5)
        return success_result(self.name)
