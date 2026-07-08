import requests

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

def scan_url(url):

    report = {
        "url": url,
        "headers": [],
        "score": 100
    }

    try:

        r = requests.get(url, timeout=8)

        report["status"] = r.status_code

        report["https"] = url.startswith("https://")

        for header in SECURITY_HEADERS:

            if header in r.headers:

                report["headers"].append({
                    "header": header,
                    "status": "OK",
                    "severity": "info"
                })

            else:

                report["headers"].append({
                    "header": header,
                    "status": "Missing",
                    "severity": "medium"
                })

                report["score"] -= 10

    except Exception as e:

        report["error"] = str(e)

    return report
