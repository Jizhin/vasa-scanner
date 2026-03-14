import requests
import time
import re


OTP_TEST_CODES = [
    "000000",
    "000001",
    "000002",
    "000003",
    "000004",
    "000005",
]


def scan_otp_security(base_url, email="test@yopmail.com"):
    """
    Test OTP authentication security.

    Tests:
    - OTP brute force protection
    - Boolean response markers
    - Missing field validation
    - OTP reuse
    - IP rotation brute force
    """

    results = []

    session = requests.Session()

    request_endpoint = base_url.rstrip("/") + "/auth/expert/user/login/other/"
    verify_endpoint = base_url.rstrip("/") + "/auth/expert/user/login/other/verify/"

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "VASA-Scanner"
    }

    # ------------------------------------------------
    # Test 1: Request OTP
    # ------------------------------------------------

    try:

        r = session.post(
            request_endpoint,
            json={"email": email},
            headers=headers,
            timeout=10
        )

        if r.status_code == 200:

            results.append({
                "test": "OTP Request Endpoint",
                "result": "PASS",
                "detail": "OTP request endpoint reachable"
            })

        else:

            results.append({
                "test": "OTP Request Endpoint",
                "result": "FAIL",
                "detail": f"Unexpected status {r.status_code}"
            })

    except Exception as e:

        results.append({
            "test": "OTP Request Endpoint",
            "result": "ERROR",
            "detail": str(e)
        })

        return results

    # ------------------------------------------------
    # Test 2: OTP brute force protection
    # ------------------------------------------------

    blocked = False

    for i, code in enumerate(OTP_TEST_CODES):

        try:

            r = session.post(
                verify_endpoint,
                json={"email": email, "otp": code},
                headers=headers,
                timeout=10
            )

            if r.status_code == 429:

                blocked = True
                break

            time.sleep(0.5)

        except:
            pass

    if blocked:

        results.append({
            "test": "OTP Brute Force Protection",
            "result": "PASS",
            "detail": "Rate limit detected"
        })

    else:

        results.append({
            "test": "OTP Brute Force Protection",
            "result": "FAIL",
            "detail": "No rate limiting detected"
        })

    # ------------------------------------------------
    # Test 3: Boolean response markers
    # ------------------------------------------------

    try:

        r = session.post(
            verify_endpoint,
            json={"email": email, "otp": "000000"},
            headers=headers
        )

        patterns = [
            r'"verified"\s*:\s*(true|false)',
            r'"success"\s*:\s*(true|false)',
            r'"authenticated"\s*:\s*(true|false)',
        ]

        vulnerable = False

        for p in patterns:
            if re.search(p, r.text, re.I):
                vulnerable = True
                break

        if vulnerable:

            results.append({
                "test": "Boolean Auth Marker",
                "result": "FAIL",
                "detail": "Boolean authentication marker detected"
            })

        else:

            results.append({
                "test": "Boolean Auth Marker",
                "result": "PASS",
                "detail": "No boolean auth markers found"
            })

    except Exception as e:

        results.append({
            "test": "Boolean Auth Marker",
            "result": "ERROR",
            "detail": str(e)
        })

    # ------------------------------------------------
    # Test 4: Missing field validation
    # ------------------------------------------------

    try:

        r = session.post(
            verify_endpoint,
            json={"otp": "000000"},
            headers=headers
        )

        if r.status_code == 400:

            results.append({
                "test": "Missing Field Validation",
                "result": "PASS",
                "detail": "Email field validation enforced"
            })

        else:

            results.append({
                "test": "Missing Field Validation",
                "result": "FAIL",
                "detail": "Missing field accepted"
            })

    except Exception as e:

        results.append({
            "test": "Missing Field Validation",
            "result": "ERROR",
            "detail": str(e)
        })

    # ------------------------------------------------
    # Test 5: OTP reuse
    # ------------------------------------------------

    try:

        r1 = session.post(
            verify_endpoint,
            json={"email": email, "otp": "111111"},
            headers=headers
        )

        r2 = session.post(
            verify_endpoint,
            json={"email": email, "otp": "111111"},
            headers=headers
        )

        if r2.status_code == 200:

            results.append({
                "test": "OTP Reuse Protection",
                "result": "FAIL",
                "detail": "OTP reuse allowed"
            })

        else:

            results.append({
                "test": "OTP Reuse Protection",
                "result": "PASS",
                "detail": "OTP cannot be reused"
            })

    except Exception as e:

        results.append({
            "test": "OTP Reuse Protection",
            "result": "ERROR",
            "detail": str(e)
        })

    # ------------------------------------------------
    # Test 6: IP rotation brute force
    # ------------------------------------------------

    blocked = False

    for i, code in enumerate(OTP_TEST_CODES):

        try:

            r = session.post(
                verify_endpoint,
                json={"email": email, "otp": code},
                headers={
                    **headers,
                    "X-Forwarded-For": f"10.0.0.{i+1}"
                }
            )

            if r.status_code == 429:
                blocked = True
                break

        except:
            pass

    if blocked:

        results.append({
            "test": "IP Rotation Protection",
            "result": "PASS",
            "detail": "Rate limit enforced across IPs"
        })

    else:

        results.append({
            "test": "IP Rotation Protection",
            "result": "FAIL",
            "detail": "IP rotation bypass possible"
        })

    return results