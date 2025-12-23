from prometheus_client import Counter

# HTTP request counters
requests_total = Counter("app_requests_total", "Total HTTP requests", ["method", "path", "status"])
request_errors_total = Counter("app_request_errors_total", "HTTP error responses", ["status"])

# Token refresh counters
token_refresh_total = Counter("app_token_refresh_total", "QuickBooks token refresh attempts", ["status"])
