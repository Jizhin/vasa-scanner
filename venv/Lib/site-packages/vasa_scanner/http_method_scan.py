import requests

METHODS = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "TRACE",
    "OPTIONS",
    "CONNECT"
]

PATHS = [
    "/",
    "/api/v1/",
    "/api/v1/wasa_probe_nonexistent",
    "/auth/company/user/login/other/"
]


def scan_http_methods(base_url):
    """
    Test HTTP method security on common endpoints.
    Detects unsafe methods like PUT, DELETE, PATCH, TRACE.
    """

    results = []

    for path in PATHS:

        url = base_url.rstrip("/") + path

        for method in METHODS:

            try:
                r = requests.request(method, url, timeout=10)
                status = r.status_code

                result = "PASS"
                detail = "Method restricted"

                if method in ["PUT", "DELETE", "PATCH", "TRACE"] and status == 200:
                    result = "FAIL"
                    detail = "Unsafe HTTP method accepted"

                results.append({
                    "test": f"{method} {url}",
                    "result": result,
                    "detail": f"Status Code: {status} | {detail}"
                })

            except Exception as e:

                results.append({
                    "test": f"{method} {url}",
                    "result": "ERROR",
                    "detail": str(e)
                })

    return results