"""Benchmarking utilities — measure throughput and latency of PKCS11 operations."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class BenchResult:
    name: str
    n_ops: int
    elapsed_s: float
    payload_bytes: int = 0

    @property
    def ops_per_sec(self) -> float:
        return self.n_ops / self.elapsed_s if self.elapsed_s > 0 else 0.0

    @property
    def latency_ms(self) -> float:
        return (self.elapsed_s / self.n_ops * 1000) if self.n_ops > 0 else 0.0

    @property
    def throughput_mbs(self) -> float:
        if self.elapsed_s <= 0 or self.payload_bytes <= 0:
            return 0.0
        return (self.n_ops * self.payload_bytes) / (self.elapsed_s * 1024 * 1024)

    def __str__(self) -> str:
        parts = [f"{self.name}: {self.ops_per_sec:,.0f} ops/s  ({self.latency_ms:.3f} ms/op)"]
        if self.payload_bytes:
            parts.append(f"  {self.throughput_mbs:.1f} MB/s")
        return "  ".join(parts)


def run_benchmark(
    fn: Callable,
    n_ops: int,
    name: str = "op",
    payload_bytes: int = 0,
    warmup: int = 3,
) -> BenchResult:
    for _ in range(warmup):
        fn()
    start = time.perf_counter()
    for _ in range(n_ops):
        fn()
    elapsed = time.perf_counter() - start
    return BenchResult(name=name, n_ops=n_ops, elapsed_s=elapsed, payload_bytes=payload_bytes)
