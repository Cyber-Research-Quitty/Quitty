from prometheus_client import Counter, Histogram

# total guarded requests (exclude /health and /metrics)
jwt_guard_requests_total = Counter(
    "jwt_guard_requests_total",
    "Total number of requests processed by JWT Guard (guarded paths only)",
)

# rejects by reason (reason must match JSON reason exactly)
jwt_guard_reject_total = Counter(
    "jwt_guard_reject_total",
    "Total number of JWT Guard rejections by reason",
    ["reason"],
)

# middleware overhead histogram in milliseconds
jwt_guard_overhead_ms = Histogram(
    "jwt_guard_overhead_ms",
    "JWT Guard middleware overhead (ms)",
    buckets=(0.5, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987),
)