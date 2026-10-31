"""Bundled static data.

Credential and path lists are well-known public defaults used by honeypot
research tools (Cowrie, Mirai sinkholes, SecLists). They are DATA, never
executed. GeoIP map uses only RFC 5737 documentation ranges (TEST-NET), so no
real IP is ever referenced.
"""

# ATT&CK matrix version referenced by the technique tags below.
ATTACK_VERSION = "v20"

# Mirai-style telnet credential pairs (public, well-known defaults).
MIRAI_TELNET_CREDS = [
    ("root", "xc3511"),
    ("root", "vizxv"),
    ("root", "admin"),
    ("admin", "admin"),
    ("root", "888888"),
    ("root", "54321"),
    ("support", "support"),
    ("root", "root"),
    ("admin", "password"),
    ("root", "12345"),
    ("user", "user"),
    ("admin", "1234"),
    ("root", "pass"),
    ("admin", ""),
    ("guest", "guest"),
]

# Common SSH brute-force user/pass pairs (public defaults).
SSH_BRUTE_CREDS = [
    ("root", "root"),
    ("root", "toor"),
    ("admin", "admin"),
    ("ubuntu", "ubuntu"),
    ("pi", "raspberry"),
    ("oracle", "oracle"),
    ("postgres", "postgres"),
    ("git", "git"),
    ("test", "test"),
    ("deploy", "deploy"),
    ("user", "1234"),
    ("ftp", "ftp"),
]

# Web scanner paths (SecLists common-dirs / known probe targets).
WEB_PATHS = [
    "/",
    "/admin",
    "/admin/login.php",
    "/wp-login.php",
    "/wp-admin/",
    "/.env",
    "/.git/config",
    "/phpmyadmin/",
    "/phpMyAdmin/index.php",
    "/config.php",
    "/server-status",
    "/.aws/credentials",
    "/actuator/health",
    "/api/v1/",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/shell.php",
    "/cgi-bin/",
    "/manager/html",
    "/robots.txt",
    "/favicon.ico",
]

# Paths that indicate an exploit / sensitive-target probe (not just crawling).
SENSITIVE_PATHS = (
    "wp-login.php",
    "wp-admin",
    ".env",
    ".git",
    "phpmyadmin",
    "config.php",
    ".aws",
    "eval-stdin.php",
    "shell.php",
    "manager/html",
    "actuator",
)

# User agents seen from scanners / tools.
SCANNER_UAS = [
    "zgrab/0.x",
    "masscan/1.3",
    "Mozilla/5.0 (Nuclei - Open-source project)",
    "curl/7.81.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
]

# UA substring -> scanner label.
UA_SIGNATURES = {
    "zgrab": "zgrab",
    "masscan": "masscan",
    "nuclei": "nuclei",
    "curl": "curl",
    "python-requests": "python-requests",
    "go-http-client": "go-http-client",
}

# Fake GeoIP: RFC 5737 /24 documentation prefixes only. Clearly simulated.
GEOIP = {
    "192.0.2.0/24": {
        "country": "United States", "city": "Ashburn",
        "asn": 13335, "org": "TEST-NET-1 (simulated)",
    },
    "198.51.100.0/24": {
        "country": "Germany", "city": "Frankfurt",
        "asn": 24940, "org": "TEST-NET-2 (simulated)",
    },
    "203.0.113.0/24": {
        "country": "Singapore", "city": "Singapore",
        "asn": 4837, "org": "TEST-NET-3 (simulated)",
    },
}

# The three documentation /24 blocks the replayer draws attacker IPs from.
TESTNET_PREFIXES = ["192.0.2", "198.51.100", "203.0.113"]
