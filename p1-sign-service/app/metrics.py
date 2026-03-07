from prometheus_client import Counter, Histogram

HTTP_REQUESTS_TOTAL = Counter(
    "p1_http_requests_total",
    "Total HTTP requests to P1",
    ["method", "path"],
)

HTTP_REQUEST_LATENCY_SECONDS = Histogram(
    "p1_http_request_latency_seconds",
    "HTTP request latency (seconds) for P1",
    ["path"],
)

SIGN_LATENCY_SECONDS = Histogram(
    "p1_sign_latency_seconds",
    "JWT signing latency (seconds)",
)

VERIFY_LATENCY_SECONDS = Histogram(
    "p1_verify_latency_seconds",
    "JWT verification latency (seconds)",
)

P1_ERRORS_TOTAL = Counter(
    "p1_errors_total",
    "Total P1 errors by type",
    ["type"],
)
