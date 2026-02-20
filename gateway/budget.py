"""Token bucket budget controls with precharge and refund."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class Bucket:
    capacity: float
    refill_per_second: float
    tokens: float
    last_ts: float

    def refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.last_ts)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        self.last_ts = now

    def consume(self, amount: float, now: float) -> bool:
        self.refill(now)
        if self.tokens < amount:
            return False
        self.tokens -= amount
        return True

    def adjust(self, delta: float, now: float) -> None:
        self.refill(now)
        self.tokens = max(0.0, min(self.capacity, self.tokens + delta))


@dataclass
class BudgetState:
    rpm_bucket: Bucket
    tpm_bucket: Bucket


class BudgetManager:
    """Maintain per-(sub,key_id) token buckets."""

    def __init__(self) -> None:
        self._state: dict[tuple[str, str], BudgetState] = {}

    def _get_or_create(
        self,
        sub: str,
        key_id: str,
        budget: dict[str, int],
        now: float,
    ) -> BudgetState:
        key = (sub, key_id)
        current = self._state.get(key)
        if current is not None:
            return current

        rpm = max(1, int(budget.get("rpm", 60)))
        tpm = max(1, int(budget.get("tpm", 60000)))
        burst = max(1, int(budget.get("burst", 1000)))
        current = BudgetState(
            rpm_bucket=Bucket(
                capacity=float(rpm),
                refill_per_second=float(rpm) / 60.0,
                tokens=float(rpm),
                last_ts=now,
            ),
            tpm_bucket=Bucket(
                capacity=float(burst),
                refill_per_second=float(tpm) / 60.0,
                tokens=float(burst),
                last_ts=now,
            ),
        )
        self._state[key] = current
        return current

    def precharge(
        self,
        *,
        sub: str,
        key_id: str,
        budget: dict[str, int],
        est_prompt_tokens: int,
        max_tokens: int,
    ) -> tuple[bool, int, str | None]:
        now = time.time()
        state = self._get_or_create(sub, key_id, budget, now)
        precharge_tokens = max(0, int(est_prompt_tokens) + max(0, int(max_tokens)))

        if not state.rpm_bucket.consume(1.0, now):
            return False, precharge_tokens, "rpm_exceeded"
        if not state.tpm_bucket.consume(float(precharge_tokens), now):
            state.rpm_bucket.adjust(1.0, now)
            return False, precharge_tokens, "tpm_exceeded"

        return True, precharge_tokens, None

    def refund_or_charge(
        self,
        *,
        sub: str,
        key_id: str,
        budget: dict[str, int],
        precharge: int,
        usage_total_tokens: int,
    ) -> int:
        now = time.time()
        state = self._get_or_create(sub, key_id, budget, now)
        delta = int(precharge) - int(usage_total_tokens)
        state.tpm_bucket.adjust(float(delta), now)
        return delta

    def bucket_pressure(
        self,
        *,
        sub: str,
        key_id: str,
        budget: dict[str, int],
    ) -> float:
        now = time.time()
        state = self._get_or_create(sub, key_id, budget, now)
        state.rpm_bucket.refill(now)
        state.tpm_bucket.refill(now)

        rpm_pressure = 1.0 - (state.rpm_bucket.tokens / max(1.0, state.rpm_bucket.capacity))
        tpm_pressure = 1.0 - (state.tpm_bucket.tokens / max(1.0, state.tpm_bucket.capacity))
        return max(0.0, min(1.0, max(rpm_pressure, tpm_pressure)))


def estimate_prompt_tokens(messages: list[dict]) -> int:
    total_chars = 0
    for message in messages:
        total_chars += len(str(message.get("content", "")))
    return max(1, total_chars // 4)
