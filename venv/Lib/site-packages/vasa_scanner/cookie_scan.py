import requests

def scan_cookie_security(url):
    """
    Scan cookie security flags:
    - Secure
    - HttpOnly
    - SameSite
    """

    results = []

    try:
        r = requests.get(url, allow_redirects=True, timeout=10)
    except Exception as e:
        results.append({
            "test": "Cookie Header",
            "result": "ERROR",
            "detail": str(e)
        })
        return results

    cookies = r.headers.get("Set-Cookie")

    if not cookies:
        results.append({
            "test": "Cookie Presence",
            "result": "FAIL",
            "detail": "No cookies returned"
        })
        return results

    secure = "Secure" in cookies
    httponly = "HttpOnly" in cookies
    samesite = "SameSite" in cookies

    results.append({
        "test": "Secure Flag",
        "result": "PASS" if secure else "FAIL",
        "detail": "Secure attribute present" if secure else "Secure flag missing"
    })

    results.append({
        "test": "HttpOnly Flag",
        "result": "PASS" if httponly else "FAIL",
        "detail": "HttpOnly attribute present" if httponly else "HttpOnly missing"
    })

    results.append({
        "test": "SameSite Flag",
        "result": "PASS" if samesite else "FAIL",
        "detail": "SameSite attribute present" if samesite else "SameSite missing"
    })

    return results