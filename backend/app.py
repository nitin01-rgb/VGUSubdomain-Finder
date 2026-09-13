from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import dns.resolver
import os
import re
import time


# =========================
# APP SETUP
# =========================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

app = Flask(__name__)
CORS(app)


# =========================
# DOMAIN CLEANER
# =========================

def clean_domain(value):
    domain = (value or "").strip().lower()

    domain = re.sub(
        r"^https?://",
        "",
        domain
    )

    domain = domain.split("/")[0]
    domain = domain.split(":")[0]

    return domain.strip(".")


# =========================
# HOME PAGE
# =========================

@app.get("/")
def home():
    return send_from_directory(
        BASE_DIR,
        "index.html"
    )


# =========================
# FRONTEND FILES
# =========================

@app.get("/<path:filename>")
def frontend_files(filename):

    allowed_files = {
        "style.css",
        "script.js",
        "logo.png"
    }

    if filename in allowed_files:
        return send_from_directory(
            BASE_DIR,
            filename
        )

    return jsonify({
        "error": "File not found"
    }), 404


# =========================
# CERT SPOTTER HELPER
# =========================

def certspotter_lookup(domain):

    url = (
        "https://api.certspotter.com/v1/issuances"
    )

    headers = {
        "Accept": "application/json",
        "User-Agent": "VGUSubdomain-Finder/1.0"
    }

    token = os.environ.get(
        "CERTSPOTTER_TOKEN"
    )

    if token:
        headers["Authorization"] = (
            f"Bearer {token}"
        )

    all_issuances = []
    after = None

    for _ in range(5):

        params = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names"
        }

        if after:
            params["after"] = after

        response = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=20
        )

        response.raise_for_status()

        data = response.json()

        if not isinstance(data, list):
            break

        if not data:
            break

        all_issuances.extend(data)

        if len(data) < 100:
            break

        last_id = data[-1].get("id")

        if not last_id:
            break

        after = str(last_id)

    return all_issuances


# =========================
# SUBDOMAIN FINDER
# =========================

@app.get("/api/subdomains")
def subdomains():

    domain = clean_domain(
        request.args.get("domain", "")
    )

    if not domain:
        return jsonify({
            "error": "Domain is required"
        }), 400

    found = set()

    try:

        issuances = certspotter_lookup(
            domain
        )

        for issuance in issuances:

            names = issuance.get(
                "dns_names",
                []
            )

            if isinstance(names, str):
                names = names.splitlines()

            for name in names:

                name = (
                    str(name)
                    .strip()
                    .lower()
                    .lstrip("*.")
                )

                if (
                    name == domain
                    or name.endswith(
                        "." + domain
                    )
                ):
                    found.add(name)

    except requests.RequestException as error:

        return jsonify({
            "error":
                "Certificate Transparency lookup failed",
            "details": str(error)
        }), 502

    except Exception as error:

        return jsonify({
            "error":
                "Unexpected lookup error",
            "details": str(error)
        }), 500

    results = sorted(found)

    return jsonify({
        "domain": domain,
        "count": len(results),
        "source":
            "Certificate Transparency (Cert Spotter)",
        "subdomains": results
    })


# =========================
# DNS LOOKUP
# =========================

@app.get("/api/dns")
def dns_lookup():

    domain = clean_domain(
        request.args.get("domain", "")
    )

    if not domain:
        return jsonify({
            "error": "Domain is required"
        }), 400

    record_types = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT"
    ]

    records = {}

    for record_type in record_types:

        try:

            answers = dns.resolver.resolve(
                domain,
                record_type
            )

            records[record_type] = [
                str(answer)
                for answer in answers
            ]

        except Exception:

            records[record_type] = []

    return jsonify({
        "domain": domain,
        "records": records,
        "source": "DNS"
    })


# =========================
# CERTIFICATE LOOKUP
# =========================

@app.get("/api/certificates")
def certificates():

    domain = clean_domain(
        request.args.get("domain", "")
    )

    if not domain:
        return jsonify({
            "error": "Domain is required"
        }), 400

    try:

        issuances = certspotter_lookup(
            domain
        )

        certificate_list = []
        seen = set()

        for item in issuances:

            cert_id = item.get("id")

            if cert_id in seen:
                continue

            seen.add(cert_id)

            names = item.get(
                "dns_names",
                []
            )

            if isinstance(names, str):
                names = names.splitlines()

            valid_names = []

            for name in names:

                name = (
                    str(name)
                    .strip()
                    .lower()
                    .lstrip("*.")
                )

                if (
                    name == domain
                    or name.endswith(
                        "." + domain
                    )
                ):
                    valid_names.append(name)

            certificate_list.append({
                "id": cert_id,
                "name": sorted(
                    set(valid_names)
                ),
                "issuer": item.get(
                    "issuer",
                    ""
                ),
                "not_before": item.get(
                    "not_before",
                    ""
                ),
                "not_after": item.get(
                    "not_after",
                    ""
                ),
                "revoked": item.get(
                    "revoked",
                    False
                )
            })

        return jsonify({
            "domain": domain,
            "count": len(certificate_list),
            "source":
                "Certificate Transparency (Cert Spotter)",
            "certificates": certificate_list
        })

    except requests.RequestException as error:

        return jsonify({
            "error":
                "Certificate lookup failed",
            "details": str(error)
        }), 502

    except Exception as error:

        return jsonify({
            "error":
                "Unexpected certificate error",
            "details": str(error)
        }), 500


# =========================
# HTTP CHECKER
# =========================

@app.get("/api/http-check")
def http_check():

    domain = clean_domain(
        request.args.get("domain", "")
    )

    if not domain:
        return jsonify({
            "error": "Domain is required"
        }), 400

    url = "https://" + domain

    headers = {
        "User-Agent":
            "VGUSubdomain-Finder/1.0"
    }

    try:

        start_time = time.perf_counter()

        response = requests.get(
            url,
            headers=headers,
            timeout=15,
            allow_redirects=True
        )

        elapsed = (
            time.perf_counter() - start_time
        )

        return jsonify({
            "domain": domain,
            "requested_url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "status": "OK"
                if response.ok
                else "HTTP Error",
            "response_time_ms": round(
                elapsed * 1000,
                2
            ),
            "server": response.headers.get(
                "Server",
                ""
            ),
            "content_type":
                response.headers.get(
                    "Content-Type",
                    ""
                ),
            "source": "HTTP response"
        })

    except requests.RequestException as error:

        return jsonify({
            "error": "HTTP check failed",
            "details": str(error)
        }), 502

# =========================
# IP / HOST LOOKUP
# =========================

@app.get("/api/ip")
def ip_lookup():

    domain = clean_domain(
        request.args.get("domain", "")
    )

    if not domain:
        return jsonify({
            "error": "Domain is required"
        }), 400

    try:

        import socket

        addresses = socket.getaddrinfo(
            domain,
            443,
            type=socket.SOCK_STREAM
        )

        ips = sorted({
            address[4][0]
            for address in addresses
        })

        return jsonify({
            "domain": domain,
            "ips": ips,
            "count": len(ips),
            "source": "DNS / Host Resolution"
        })

    except socket.gaierror:

        return jsonify({
            "error": "Unable to resolve host"
        }), 502

    except Exception as error:

        return jsonify({
            "error": "Host lookup failed",
            "details": str(error)
        }), 500
# =========================
# WHOIS / RDAP LOOKUP
# =========================

@app.get("/api/whois")
def whois_lookup():

    domain = clean_domain(
        request.args.get("domain", "")
    )

    if not domain:
        return jsonify({
            "error": "Domain is required"
        }), 400

    try:

        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={
                "Accept": "application/rdap+json",
                "User-Agent":
                    "VGUSubdomain-Finder/1.0"
            },
            timeout=20
        )

        if response.status_code == 404:
            return jsonify({
                "error": "Domain registration information not found"
            }), 404

        response.raise_for_status()

        data = response.json()

        events = {}

        for event in data.get("events", []):
            event_action = event.get("eventAction")
            event_date = event.get("eventDate")

            if event_action and event_date:
                events[event_action] = event_date

        nameservers = []

        for nameserver in data.get(
            "nameservers",
            []
        ):
            name = nameserver.get(
                "ldhName"
            )

            if name:
                nameservers.append(name)

        return jsonify({
            "domain": data.get(
                "ldhName",
                domain
            ),
            "status": data.get(
                "status",
                []
            ),
            "registered": events.get(
                "registration"
            ),
            "last_changed": events.get(
                "last changed"
            ),
            "expiration": events.get(
                "expiration"
            ),
            "nameservers": nameservers,
            "source": "RDAP"
        })

    except requests.RequestException as error:

        return jsonify({
            "error": "WHOIS/RDAP lookup failed",
            "details": str(error)
        }), 502

    except Exception as error:

        return jsonify({
            "error": "Unexpected WHOIS error",
            "details": str(error)
        }), 500
# =========================
# URL / DOMAIN PARSER
# =========================

@app.get("/api/parser")
def parse_url():

    from urllib.parse import urlparse

    value = request.args.get("url", "").strip()

    if not value:
        return jsonify({
            "error": "URL is required"
        }), 400

    if not re.match(
        r"^https?://",
        value,
        re.IGNORECASE
    ):
        value = "https://" + value

    try:

        parsed = urlparse(value)

        hostname = parsed.hostname or ""

        port = parsed.port

        if not port:
            if parsed.scheme == "https":
                port = 443
            elif parsed.scheme == "http":
                port = 80

        return jsonify({
            "original_url": value,
            "protocol": parsed.scheme,
            "hostname": hostname,
            "port": port,
            "path": parsed.path or "/",
            "query": parsed.query,
            "fragment": parsed.fragment,
            "username": parsed.username or "",
            "source": "URL Parser"
        })

    except ValueError:

        return jsonify({
            "error": "Invalid URL"
        }), 400
# =========================
# TECHNOLOGY DETECTION
# =========================

@app.get("/api/tech")
def technology_detection():

    domain = clean_domain(
        request.args.get("domain", "")
    )

    if not domain:
        return jsonify({
            "error": "Domain is required"
        }), 400

    url = "https://" + domain

    headers = {
        "User-Agent":
            "VGUSubdomain-Finder/1.0"
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=15,
            allow_redirects=True
        )

        detected = []

        server = response.headers.get(
            "Server", ""
        )

        powered_by = response.headers.get(
            "X-Powered-By", ""
        )

        if server:
            detected.append({
                "technology": "Web Server",
                "value": server
            })

        if powered_by:
            detected.append({
                "technology": "X-Powered-By",
                "value": powered_by
            })

        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy"
        ]

        for header in security_headers:

            value = response.headers.get(header)

            if value:
                detected.append({
                    "technology": "Security Header",
                    "value": header
                })

        return jsonify({
            "domain": domain,
            "final_url": response.url,
            "status_code": response.status_code,
            "technologies": detected,
            "source": "HTTP response headers"
        })

    except requests.RequestException as error:

        return jsonify({
            "error": "Technology detection failed",
            "details": str(error)
        }), 502
# =========================
# HEALTH CHECK
# =========================

@app.get("/api/health")
def health():

    return jsonify({
        "status": "ok",
        "project": "VGUSubdomain Finder"
    })


# =========================
# START SERVER
# =========================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
    )
