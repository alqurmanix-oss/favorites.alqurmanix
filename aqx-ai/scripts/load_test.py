#!/usr/bin/env python3
"""Measure AQX AI text moderation latency and overload responses on a running instance."""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import statistics
import time

import httpx


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
    return ordered[index]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.getenv("AQX_AI_BASE_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--requests", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=600.0)
    args = parser.parse_args()

    token = os.getenv("AQX_AI_INTERNAL_TOKEN", "")
    if len(token) < 32:
        parser.error("Set AQX_AI_INTERNAL_TOKEN to the private API token (at least 32 characters).")
    if args.requests < 1 or args.concurrency < 1 or args.timeout <= 0:
        parser.error("--requests, --concurrency, and --timeout must be positive.")

    endpoint = args.url.rstrip("/") + "/v1/analyze"
    headers = {"Authorization": "Bearer " + token}
    payload = "AQX AI load-test sample. This is a neutral product review used to measure service latency."

    def send_one(_: int) -> tuple[int, float]:
        started = time.perf_counter()
        try:
            with httpx.Client(timeout=args.timeout) as client:
                response = client.post(endpoint, headers=headers, data={"text": payload})
                return response.status_code, time.perf_counter() - started
        except Exception:
            return 0, time.perf_counter() - started

    started_all = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        results = list(pool.map(send_one, range(args.requests)))
    elapsed = time.perf_counter() - started_all

    statuses: dict[str, int] = {}
    latencies = []
    for status, latency in results:
        key = str(status) if status else "connection_error"
        statuses[key] = statuses.get(key, 0) + 1
        latencies.append(latency)

    successful = sum(count for status, count in statuses.items() if status.startswith("2"))
    print("AQX AI load test")
    print(f"Endpoint: {endpoint}")
    print(f"Requests: {args.requests} | concurrency: {args.concurrency}")
    print(f"Elapsed: {elapsed:.2f}s | throughput: {args.requests / elapsed:.2f} requests/s")
    print(f"Latency seconds: p50={percentile(latencies, 0.50):.2f}, p95={percentile(latencies, 0.95):.2f}, max={max(latencies, default=0):.2f}")
    print(f"HTTP results: {statuses}")
    print(f"2xx responses: {successful}/{args.requests}")
    return 0 if successful == args.requests else 2


if __name__ == "__main__":
    raise SystemExit(main())
