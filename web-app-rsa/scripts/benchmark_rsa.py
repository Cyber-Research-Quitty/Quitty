#!/usr/bin/env python3
import argparse
import csv
import json
import math
import os
import time
import urllib.error
import urllib.request
from collections import defaultdict
from typing import Any


def now_ms() -> float:
    return time.perf_counter() * 1000.0


def percentile(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (p / 100.0)
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[low]
    weight = rank - low
    return ordered[low] * (1 - weight) + ordered[high] * weight


def http_json(
    url: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)

    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(url=url, method=method, headers=request_headers, data=data)
    start = now_ms()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            latency_ms = now_ms() - start
            parsed = json.loads(body) if body else {}
            return {
                "ok": 200 <= response.status < 300,
                "status_code": response.status,
                "json": parsed,
                "latency_ms": latency_ms,
                "error": "",
            }
    except urllib.error.HTTPError as exc:
        latency_ms = now_ms() - start
        body = exc.read().decode("utf-8") if exc.fp else ""
        parsed = {}
        if body:
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                parsed = {"raw": body}
        return {
            "ok": False,
            "status_code": exc.code,
            "json": parsed,
            "latency_ms": latency_ms,
            "error": f"HTTPError {exc.code}",
        }
    except Exception as exc:  # noqa: BLE001
        latency_ms = now_ms() - start
        return {
            "ok": False,
            "status_code": 0,
            "json": {},
            "latency_ms": latency_ms,
            "error": str(exc),
        }


def run_phase(
    phase_name: str,
    requests_count: int,
    auth_base_url: str,
    protected_url: str,
    email: str,
    password: str,
    timeout: float,
    pause_ms: float,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    seed_login = http_json(
        url=f"{auth_base_url}/login",
        method="POST",
        payload={"email": email, "password": password},
        timeout=timeout,
    )
    if not seed_login["ok"]:
        raise RuntimeError(f"Cannot obtain seed token for phase={phase_name}: {seed_login}")
    seed_token = seed_login["json"].get("access_token", "")
    if not seed_token:
        raise RuntimeError(f"No access_token in seed login response for phase={phase_name}")

    for i in range(1, requests_count + 1):
        login_result = http_json(
            url=f"{auth_base_url}/login",
            method="POST",
            payload={"email": email, "password": password},
            timeout=timeout,
        )
        login_token = login_result["json"].get("access_token", "") if login_result["ok"] else ""
        login_token_size_chars = len(login_token) if login_token else 0
        login_token_size_bytes = len(login_token.encode("utf-8")) if login_token else 0
        rows.append(
            {
                "phase": phase_name,
                "requests": requests_count,
                "endpoint": "login",
                "iteration": i,
                "latency_ms": round(login_result["latency_ms"], 3),
                "status_code": login_result["status_code"],
                "ok": login_result["ok"],
                "error": login_result["error"],
                "token_size_chars": login_token_size_chars,
                "token_size_bytes": login_token_size_bytes,
            }
        )

        verify_result = http_json(
            url=f"{auth_base_url}/verify",
            method="POST",
            payload={"token": seed_token},
            timeout=timeout,
        )
        rows.append(
            {
                "phase": phase_name,
                "requests": requests_count,
                "endpoint": "verify",
                "iteration": i,
                "latency_ms": round(verify_result["latency_ms"], 3),
                "status_code": verify_result["status_code"],
                "ok": verify_result["ok"],
                "error": verify_result["error"],
                "token_size_chars": len(seed_token),
                "token_size_bytes": len(seed_token.encode("utf-8")),
            }
        )

        protected_result = http_json(
            url=protected_url,
            method="GET",
            headers={"Authorization": f"Bearer {seed_token}"},
            timeout=timeout,
        )
        rows.append(
            {
                "phase": phase_name,
                "requests": requests_count,
                "endpoint": "protected_me",
                "iteration": i,
                "latency_ms": round(protected_result["latency_ms"], 3),
                "status_code": protected_result["status_code"],
                "ok": protected_result["ok"],
                "error": protected_result["error"],
                "token_size_chars": len(seed_token),
                "token_size_bytes": len(seed_token.encode("utf-8")),
            }
        )

        if pause_ms > 0:
            time.sleep(pause_ms / 1000.0)

    return rows


def write_raw_csv(path: str, rows: list[dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fieldnames = [
        "phase",
        "requests",
        "endpoint",
        "iteration",
        "latency_ms",
        "status_code",
        "ok",
        "error",
        "token_size_chars",
        "token_size_bytes",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def build_summary(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, int, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row["phase"], int(row["requests"]), row["endpoint"])].append(row)

    summary_rows: list[dict[str, Any]] = []
    for (phase, requests_count, endpoint), entries in grouped.items():
        latencies = [float(e["latency_ms"]) for e in entries]
        successes = sum(1 for e in entries if e["ok"])
        failures = len(entries) - successes
        token_sizes = [int(e["token_size_bytes"]) for e in entries if int(e["token_size_bytes"]) > 0]

        summary_rows.append(
            {
                "phase": phase,
                "requests": requests_count,
                "endpoint": endpoint,
                "count": len(entries),
                "successes": successes,
                "failures": failures,
                "avg_ms": round(sum(latencies) / len(latencies), 3) if latencies else float("nan"),
                "min_ms": round(min(latencies), 3) if latencies else float("nan"),
                "max_ms": round(max(latencies), 3) if latencies else float("nan"),
                "p50_ms": round(percentile(latencies, 50), 3) if latencies else float("nan"),
                "p95_ms": round(percentile(latencies, 95), 3) if latencies else float("nan"),
                "p99_ms": round(percentile(latencies, 99), 3) if latencies else float("nan"),
                "token_size_avg_bytes": round(sum(token_sizes) / len(token_sizes), 3) if token_sizes else 0,
                "token_size_min_bytes": min(token_sizes) if token_sizes else 0,
                "token_size_max_bytes": max(token_sizes) if token_sizes else 0,
            }
        )

    summary_rows.sort(key=lambda r: (r["requests"], r["endpoint"], r["phase"]))
    return summary_rows


def write_summary_csv(path: str, summary_rows: list[dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fieldnames = [
        "phase",
        "requests",
        "endpoint",
        "count",
        "successes",
        "failures",
        "avg_ms",
        "min_ms",
        "max_ms",
        "p50_ms",
        "p95_ms",
        "p99_ms",
        "token_size_avg_bytes",
        "token_size_min_bytes",
        "token_size_max_bytes",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_rows)


def write_summary_json(path: str, summary_rows: list[dict[str, Any]], config: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "config": config,
        "summary": summary_rows,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="RS256 benchmark runner for web-app-rsa")
    parser.add_argument("--auth-base-url", default="http://localhost:8005")
    parser.add_argument("--protected-url", default="http://localhost:8005/me")
    parser.add_argument("--email", default="alice@example.com")
    parser.add_argument("--password", default="password123")
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--run-100", type=int, default=100)
    parser.add_argument("--run-500", type=int, default=500)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--pause-ms", type=float, default=0.0)
    parser.add_argument("--output-dir", default="benchmark_results_rsa")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    phases = [
        ("warmup", args.warmup),
        ("run_100", args.run_100),
        ("run_500", args.run_500),
    ]

    all_rows: list[dict[str, Any]] = []
    for phase_name, requests_count in phases:
        phase_rows = run_phase(
            phase_name=phase_name,
            requests_count=requests_count,
            auth_base_url=args.auth_base_url.rstrip("/"),
            protected_url=args.protected_url,
            email=args.email,
            password=args.password,
            timeout=args.timeout,
            pause_ms=args.pause_ms,
        )
        all_rows.extend(phase_rows)

    raw_csv_path = os.path.join(args.output_dir, "raw.csv")
    summary_csv_path = os.path.join(args.output_dir, "summary.csv")
    summary_json_path = os.path.join(args.output_dir, "summary.json")

    write_raw_csv(raw_csv_path, all_rows)
    summary_rows = build_summary(all_rows)
    write_summary_csv(summary_csv_path, summary_rows)
    write_summary_json(
        summary_json_path,
        summary_rows,
        config={
            "auth_base_url": args.auth_base_url,
            "protected_url": args.protected_url,
            "email": args.email,
            "warmup": args.warmup,
            "run_100": args.run_100,
            "run_500": args.run_500,
            "timeout": args.timeout,
            "pause_ms": args.pause_ms,
        },
    )

    print(f"Wrote {raw_csv_path}")
    print(f"Wrote {summary_csv_path}")
    print(f"Wrote {summary_json_path}")


if __name__ == "__main__":
    main()
