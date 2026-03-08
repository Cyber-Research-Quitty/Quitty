#!/usr/bin/env python3
import csv
import os
from typing import Any

import matplotlib.pyplot as plt
import numpy as np


SUMMARY_CSV = "benchmark_results_rsa/summary.csv"
OUT_DIR = "benchmark_results_rsa/charts"


def load_rows(path: str) -> list[dict[str, Any]]:
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return [r for r in rows if r["phase"] in {"run_100", "run_500"}]


def get_row(rows: list[dict[str, Any]], phase: str, endpoint: str) -> dict[str, Any]:
    for row in rows:
        if row["phase"] == phase and row["endpoint"] == endpoint:
            return row
    raise ValueError(f"Missing row for phase={phase}, endpoint={endpoint}")


def metric_series(rows: list[dict[str, Any]], endpoint: str, metric: str) -> list[float]:
    phases = ["run_100", "run_500"]
    return [float(get_row(rows, p, endpoint)[metric]) for p in phases]


def make_latency_chart(rows: list[dict[str, Any]], endpoint: str, title: str, out_name: str) -> str:
    phases = ["100 Requests", "500 Requests"]
    avg = metric_series(rows, endpoint, "avg_ms")
    p95 = metric_series(rows, endpoint, "p95_ms")
    p99 = metric_series(rows, endpoint, "p99_ms")

    x = np.arange(len(phases))
    w = 0.24

    plt.figure(figsize=(10, 6), dpi=180)
    plt.bar(x - w, avg, width=w, label="Average", color="#2A9D8F")
    plt.bar(x, p95, width=w, label="P95", color="#E9C46A")
    plt.bar(x + w, p99, width=w, label="P99", color="#E76F51")

    for i, v in enumerate(avg):
        plt.text(x[i] - w, v + 1, f"{v:.1f}", ha="center", va="bottom", fontsize=9)
    for i, v in enumerate(p95):
        plt.text(x[i], v + 1, f"{v:.1f}", ha="center", va="bottom", fontsize=9)
    for i, v in enumerate(p99):
        plt.text(x[i] + w, v + 1, f"{v:.1f}", ha="center", va="bottom", fontsize=9)

    plt.xticks(x, phases)
    plt.ylabel("Latency (ms)")
    plt.title(title)
    plt.legend()
    plt.grid(axis="y", alpha=0.2)
    plt.tight_layout()

    out_path = os.path.join(OUT_DIR, out_name)
    plt.savefig(out_path)
    plt.close()
    return out_path


def make_token_size_chart(rows: list[dict[str, Any]]) -> str:
    phases = ["100 Requests", "500 Requests"]
    token_sizes = [float(get_row(rows, p, "login")["token_size_avg_bytes"]) for p in ["run_100", "run_500"]]

    plt.figure(figsize=(8, 5), dpi=180)
    bars = plt.bar(phases, token_sizes, color=["#457B9D", "#1D3557"], width=0.55)
    for bar, val in zip(bars, token_sizes):
        plt.text(bar.get_x() + bar.get_width() / 2, val + 2, f"{val:.0f} B", ha="center", va="bottom", fontsize=10)
    plt.ylabel("Token Size (bytes)")
    plt.title("RS256 JWT Token Size (Average)")
    plt.grid(axis="y", alpha=0.2)
    plt.tight_layout()

    out_path = os.path.join(OUT_DIR, "token_size_comparison.png")
    plt.savefig(out_path)
    plt.close()
    return out_path


def make_summary_table(rows: list[dict[str, Any]]) -> str:
    columns = ["Endpoint", "Run", "Avg (ms)", "P95 (ms)", "P99 (ms)", "Token Avg (B)", "Failures"]
    endpoints = [("login", "Authentication (Login)"), ("verify", "Token Verification"), ("protected_me", "Protected Endpoint (/me)")]
    phases = [("run_100", "100"), ("run_500", "500")]

    table_rows: list[list[str]] = []
    for endpoint_key, endpoint_label in endpoints:
        for phase_key, phase_label in phases:
            row = get_row(rows, phase_key, endpoint_key)
            table_rows.append(
                [
                    endpoint_label,
                    phase_label,
                    f"{float(row['avg_ms']):.3f}",
                    f"{float(row['p95_ms']):.3f}",
                    f"{float(row['p99_ms']):.3f}",
                    f"{float(row['token_size_avg_bytes']):.0f}",
                    row["failures"],
                ]
            )

    fig, ax = plt.subplots(figsize=(14, 4.8), dpi=180)
    ax.axis("off")
    table = ax.table(cellText=table_rows, colLabels=columns, loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 1.6)

    for (r, c), cell in table.get_celld().items():
        if r == 0:
            cell.set_facecolor("#264653")
            cell.set_text_props(color="white", weight="bold")
        else:
            cell.set_facecolor("#F1FAEE" if r % 2 == 0 else "#FFFFFF")

    plt.title("RS256 Baseline Benchmark Summary Table", pad=14, fontsize=14, weight="bold")
    plt.tight_layout()

    out_path = os.path.join(OUT_DIR, "summary_table.png")
    plt.savefig(out_path)
    plt.close()
    return out_path


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    rows = load_rows(SUMMARY_CSV)

    generated = [
        make_latency_chart(
            rows,
            endpoint="login",
            title="Authentication Latency Comparison (RS256 Login: Avg vs P95 vs P99)",
            out_name="authentication_latency_comparison.png",
        ),
        make_latency_chart(
            rows,
            endpoint="verify",
            title="Token Verification Latency (RS256 /verify: Avg vs P95 vs P99)",
            out_name="verification_latency_comparison.png",
        ),
        make_latency_chart(
            rows,
            endpoint="protected_me",
            title="Protected Endpoint Latency (RS256 /me: Avg vs P95 vs P99)",
            out_name="protected_endpoint_latency_comparison.png",
        ),
        make_token_size_chart(rows),
        make_summary_table(rows),
    ]

    for path in generated:
        print(path)


if __name__ == "__main__":
    main()
