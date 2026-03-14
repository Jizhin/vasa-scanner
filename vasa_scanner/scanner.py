from .cookie_scan import scan_cookie_security
from .http_method_scan import scan_http_methods
from .otp_scan import scan_otp_security


def run_full_scan(target_url):
    """
    Runs all vulnerability scanners and combines results.
    """

    all_results = []

    print("\n==============================")
    print("VASA Security Scanner")
    print("==============================")

    print(f"\nTarget: {target_url}\n")

    # ------------------------------------------------
    # Cookie Security Scan
    # ------------------------------------------------

    print("[1] Cookie Security Scan")

    try:

        cookie_results = scan_cookie_security(target_url)

        for r in cookie_results:
            print(f"{r['result']} | {r['test']} | {r['detail']}")

        all_results.extend(cookie_results)

    except Exception as e:

        print("ERROR running cookie scanner:", str(e))

    print()

    # ------------------------------------------------
    # HTTP Method Scan
    # ------------------------------------------------

    print("[2] HTTP Method Security Scan")

    try:

        method_results = scan_http_methods(target_url)

        for r in method_results[:10]:   # limit console output
            print(f"{r['result']} | {r['test']}")

        all_results.extend(method_results)

    except Exception as e:

        print("ERROR running HTTP method scanner:", str(e))

    print()

    # ------------------------------------------------
    # OTP Security Scan
    # ------------------------------------------------

    print("[3] OTP Security Scan")

    try:

        otp_results = scan_otp_security(target_url)

        for r in otp_results:
            print(f"{r['result']} | {r['test']} | {r['detail']}")

        all_results.extend(otp_results)

    except Exception as e:

        print("ERROR running OTP scanner:", str(e))

    print()

    # ------------------------------------------------
    # Final Verdict
    # ------------------------------------------------

    failed = [r for r in all_results if r["result"] == "FAIL"]

    print("==============================")

    if failed:
        print("FINAL RESULT: VULNERABLE")
    else:
        print("FINAL RESULT: SECURE")

    print("==============================")

    return all_results