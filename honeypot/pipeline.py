"""Pipeline: enrich honeypot logs, aggregate alerts, export for SOC tooling.

Steps: load JSON-lines -> enrich (fake GeoIP, scanner classification, ATT&CK
tagging) -> aggregate into alerts -> export Elastic/Wazuh-friendly NDJSON, an
IP block-list, and a Sigma-like rule file.
"""
from __future__ import annotations

import argparse
import json
import os
import uuid
from collections import defaultdict
from datetime import date

from . import data

# Alert thresholds (events from one source IP).
BRUTE_THRESHOLD = 5      # ssh/telnet connections -> brute force
CRED_THRESHOLD = 10      # distinct credentials -> credential stuffing


def load_events(path: str) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def geo_lookup(ip: str) -> dict:
    prefix = ".".join(ip.split(".")[:3]) + ".0/24"
    return data.GEOIP.get(
        prefix, {"country": "Unknown", "city": "Unknown",
                 "asn": 0, "org": "unknown"})


def classify_scanner(ua: str) -> str:
    low = (ua or "").lower()
    for sig, label in data.UA_SIGNATURES.items():
        if sig in low:
            return label
    return "generic" if ua else "none"


def tag_attack(ev: dict) -> list[str]:
    """ATT&CK technique IDs for an event (matrix version in data.ATTACK_VERSION)."""
    svc = ev.get("service")
    tags: list[str] = []
    if svc == "telnet":
        tags.append("T1110.001")                    # brute force: guessing
    elif svc == "ssh":
        tags.append("T1110.001")
    elif svc == "http":
        path = (ev.get("path") or "").lower()
        if any(s in path for s in data.SENSITIVE_PATHS):
            tags.append("T1190")                    # exploit public-facing app
        if classify_scanner(ev.get("user_agent", "")) != "generic":
            tags.append("T1595.002")                # active scanning: vuln scan
        if not tags:
            tags.append("T1595.002")
    elif svc == "tcp":
        tags.append("T1595.001")                    # scanning: IP block
    return tags


def enrich(ev: dict) -> dict:
    ip = ev.get("src_ip", "")
    ev["geo"] = geo_lookup(ip)
    if ev.get("service") == "http":
        ev["scanner"] = classify_scanner(ev.get("user_agent", ""))
    ev["attack_techniques"] = tag_attack(ev)
    return ev


def _hits(events):
    """Index interaction events (ignore rate_limited/error/meta rows)."""
    return [e for e in events if e.get("service") and "event" not in e]


def build_alerts(events, known_ips=None) -> list[dict]:
    """Aggregate enriched events into alerts. known_ips = baseline for watchlist."""
    known_ips = set(known_ips or [])
    hits = _hits(events)

    by_ip_service = defaultdict(int)
    creds_by_ip = defaultdict(set)
    sensitive_by_ip = defaultdict(list)
    seen_ips = []

    for e in hits:
        ip = e.get("src_ip", "")
        if ip not in seen_ips:
            seen_ips.append(ip)
        svc = e["service"]
        by_ip_service[(ip, svc)] += 1
        if svc == "telnet":
            creds_by_ip[ip].add((e.get("username", ""), e.get("password", "")))
        if svc == "http":
            path = (e.get("path") or "").lower()
            if any(s in path for s in data.SENSITIVE_PATHS):
                sensitive_by_ip[ip].append(e.get("path"))

    alerts: list[dict] = []

    for (ip, svc), count in sorted(by_ip_service.items()):
        if svc in ("ssh", "telnet") and count >= BRUTE_THRESHOLD:
            alerts.append({
                "type": "brute_force", "severity": "high", "src_ip": ip,
                "service": svc, "count": count,
                "geo": geo_lookup(ip)["country"],
                "technique": "T1110.001",
                "summary": f"{count} {svc} login attempts from {ip}",
            })

    for ip, creds in sorted(creds_by_ip.items()):
        if len(creds) >= CRED_THRESHOLD:
            alerts.append({
                "type": "credential_stuffing", "severity": "high",
                "src_ip": ip, "distinct_credentials": len(creds),
                "geo": geo_lookup(ip)["country"], "technique": "T1110.004",
                "summary": f"{len(creds)} distinct credentials from {ip}",
            })

    for ip, paths in sorted(sensitive_by_ip.items()):
        alerts.append({
            "type": "web_exploit_probe", "severity": "medium", "src_ip": ip,
            "hits": len(paths), "paths": sorted(set(paths))[:10],
            "geo": geo_lookup(ip)["country"], "technique": "T1190",
            "summary": f"{len(paths)} sensitive-path probes from {ip}",
        })

    new_ips = [ip for ip in seen_ips if ip not in known_ips]
    if new_ips:
        alerts.append({
            "type": "new_attacker_watchlist", "severity": "low",
            "count": len(new_ips), "src_ips": new_ips, "technique": "T1595.001",
            "summary": f"{len(new_ips)} new attacker IP(s) this run",
        })

    return alerts


def _ecs_doc(ev: dict) -> dict:
    """Map an enriched event to an ECS-ish doc (Elastic / Wazuh friendly)."""
    geo = ev.get("geo", {})
    return {
        "@timestamp": ev.get("ts"),
        "event": {"kind": "event", "module": "mini-honeypot",
                  "category": ["intrusion_detection"],
                  "action": ev.get("service")},
        "source": {"ip": ev.get("src_ip"), "port": ev.get("src_port"),
                   "geo": {"country_name": geo.get("country"),
                           "city_name": geo.get("city")},
                   "as": {"number": geo.get("asn"),
                          "organization": {"name": geo.get("org")}}},
        "destination": {"port": ev.get("dst_port")},
        "user_agent": {"original": ev.get("user_agent")},
        "url": {"path": ev.get("path")},
        "honeypot": {"username": ev.get("username"),
                     "password": ev.get("password"),
                     "client_version": ev.get("client_version"),
                     "scanner": ev.get("scanner")},
        "threat": {"technique": {"id": ev.get("attack_techniques")}},
    }


_SIGMA_NS = uuid.UUID("6f1c2a3e-9b4d-4c8e-8f0a-1d2e3f4a5b6c")

# type -> (title, technique, tactic, level, description)
_SIGMA_TMPL = {
    "brute_force": ("Honeypot Brute Force", "T1110.001", "credential_access",
                    "high", "many login attempts from one source"),
    "credential_stuffing": ("Honeypot Credential Stuffing", "T1110.004",
                            "credential_access", "high",
                            "many distinct credentials from one source"),
    "web_exploit_probe": ("Honeypot Web Exploit Probe", "T1190",
                          "initial_access", "medium",
                          "requests to sensitive web paths"),
    "new_attacker_watchlist": ("Honeypot New Attacker IP", "T1595.001",
                               "reconnaissance", "low",
                               "source IP not seen before"),
}


def _sigma_rules(alerts) -> str:
    """Sigma-style YAML, hand-written (no yaml dependency).

    These are ALERT-level rules: the selection matches records in alerts.json
    (field `type`), not raw events. IDs are uuid5 so output is stable.
    """
    types = {a["type"] for a in alerts}
    today = date.today().isoformat()
    out = ["# Sigma-style rules generated by mini-honeypot",
           "# Scope: alert-level -- selection matches alerts.json records.",
           f"# ATT&CK {data.ATTACK_VERSION}", ""]
    for t in sorted(types):
        title, tech, tactic, level, desc = _SIGMA_TMPL[t]
        out += [
            f"title: {title}",
            f"id: {uuid.uuid5(_SIGMA_NS, t)}",
            "status: experimental",
            f"description: {desc}",
            "author: mini-honeypot",
            f"date: {today}",
            "logsource:",
            "  product: mini-honeypot",
            "  service: alerts",
            "detection:",
            "  selection:",
            f"    type: {t}",
            "  condition: selection",
            f"level: {level}",
            "tags:",
            f"  - attack.{tactic}",
            f"  - attack.{tech.lower()}",
            "---",
        ]
    return "\n".join(out) + "\n"


def export(events, alerts, outdir: str) -> dict:
    os.makedirs(outdir, exist_ok=True)
    paths = {
        "events": os.path.join(outdir, "events.ndjson"),
        "alerts": os.path.join(outdir, "alerts.json"),
        "blocklist": os.path.join(outdir, "blocklist.txt"),
        "sigma": os.path.join(outdir, "rules.sigma.yml"),
    }
    with open(paths["events"], "w", encoding="utf-8") as fh:
        for ev in _hits(events):
            fh.write(json.dumps(_ecs_doc(ev), ensure_ascii=False) + "\n")
    with open(paths["alerts"], "w", encoding="utf-8") as fh:
        json.dump(alerts, fh, indent=2, ensure_ascii=False)
    block = sorted({a["src_ip"] for a in alerts if a.get("src_ip")})
    with open(paths["blocklist"], "w", encoding="utf-8") as fh:
        fh.write("# mini-honeypot block-list (simulated IPs)\n")
        fh.write("\n".join(block) + ("\n" if block else ""))
    with open(paths["sigma"], "w", encoding="utf-8") as fh:
        fh.write(_sigma_rules(alerts))
    return paths


def process(log_path: str, outdir: str, known_ips=None):
    events = [enrich(e) for e in load_events(log_path)]
    alerts = build_alerts(events, known_ips)
    paths = export(events, alerts, outdir)
    return events, alerts, paths


def run(argv=None):
    ap = argparse.ArgumentParser(description="Enrich logs and build alerts.")
    ap.add_argument("--log", default="honeypot.log")
    ap.add_argument("--out", default="out")
    args = ap.parse_args(argv)
    events, alerts, paths = process(args.log, args.out)
    print(f"[pipeline] events={len(_hits(events))} alerts={len(alerts)}")
    for a in alerts:
        print(f"  - {a['type']:22} {a.get('severity',''):6} "
              f"{a.get('summary','')}")
    print(f"[pipeline] wrote: {', '.join(paths.values())}")


if __name__ == "__main__":
    run()
