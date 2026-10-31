"""Tests: service logging, replayer determinism, alert thresholds, payload cap.

Each networked test starts a server on an ephemeral port, drives it with a
client, and shuts the server down in a finally block (no leaks).
"""
import asyncio
import json
import time

import pytest

from honeypot import pipeline
from honeypot.replayer import build_plan
from honeypot.server import (
    MAX_BYTES, EventLog, RateLimiter, run as server_cli, start_service,
)


# --- harness ----------------------------------------------------------------

async def _drain(reader):
    """Read until the server closes the connection (guarantees it has logged)."""
    while await reader.read(256):
        pass


async def _run(service, client, tmp_path, simulate=True, rate=None,
               trust_xff=False):
    log = EventLog(str(tmp_path / "events.log"))
    server = await start_service(
        service, "127.0.0.1", 0, log, simulate, rate or RateLimiter(),
        trust_xff)
    port = server.sockets[0].getsockname()[1]
    try:
        await asyncio.wait_for(client(port), timeout=10)
    finally:
        server.close()
        await server.wait_closed()
    with open(log.path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _first_event(service, client, tmp_path, **kw):
    events = asyncio.run(_run(service, client, tmp_path, **kw))
    assert len(events) == 1, events
    return events[0]


def _http_client(request: bytes):
    async def client(port):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(request)
        await w.drain()
        await _drain(r)
        w.close()
    return client


# --- one correct JSON event per service -------------------------------------

def test_ssh_event(tmp_path):
    async def client(port):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"X-SIM-SRC 192.0.2.5\r\n")
        await r.read(256)                       # server banner
        w.write(b"SSH-2.0-libssh2_1.9.0\r\n")
        await w.drain()
        await _drain(r)
        w.close()
    ev = _first_event("ssh", client, tmp_path)
    assert ev["service"] == "ssh"
    assert ev["src_ip"] == "192.0.2.5"
    assert "libssh2" in ev["client_version"]
    assert "ts" in ev


def test_telnet_event(tmp_path):
    async def client(port):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"X-SIM-SRC 198.51.100.7\r\n")
        await r.read(256)                       # login:
        w.write(b"root\r\n")
        await r.read(256)                       # Password:
        w.write(b"xc3511\r\n")
        await w.drain()
        await _drain(r)
        w.close()
    ev = _first_event("telnet", client, tmp_path)
    assert ev["service"] == "telnet"
    assert ev["username"] == "root"
    assert ev["password"] == "xc3511"
    assert ev["src_ip"] == "198.51.100.7"


def test_http_event(tmp_path):
    async def client(port):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"X-SIM-SRC 203.0.113.9\r\n"
                b"GET /.env HTTP/1.1\r\nHost: x\r\n"
                b"User-Agent: curl/7.81.0\r\n\r\n")
        await w.drain()
        await _drain(r)
        w.close()
    ev = _first_event("http", client, tmp_path)
    assert ev["service"] == "http"
    assert ev["path"] == "/.env"
    assert ev["method"] == "GET"
    assert ev["user_agent"] == "curl/7.81.0"
    assert ev["status"] == 404


def test_tcp_event(tmp_path):
    async def client(port):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"X-SIM-SRC 192.0.2.50\r\n")
        await r.read(256)                       # banner
        w.write(b"HELLO\r\n")
        await w.drain()
        await _drain(r)
        w.close()
    ev = _first_event("tcp", client, tmp_path)
    assert ev["service"] == "tcp"
    assert ev["data_len"] > 0


# --- simulate-mode peek hands non-tag bytes back (R7) -------------------------

def test_simulate_peek_hands_back_request_line(tmp_path):
    req = b"GET /admin HTTP/1.1\r\nHost: x\r\nUser-Agent: zgrab/0.x\r\n\r\n"
    ev = _first_event("http", _http_client(req), tmp_path)   # no X-SIM-SRC
    assert ev["path"] == "/admin"
    assert ev["method"] == "GET"
    assert ev["src_ip"] == "127.0.0.1"
    assert ev["status"] == 200


# --- X-Forwarded-For only when --trust-xff (R1) -----------------------------

_XFF_REQ = (b"X-SIM-SRC 203.0.113.9\r\nGET / HTTP/1.1\r\nHost: x\r\n"
            b"X-Forwarded-For: 198.51.100.1\r\n\r\n")


def test_xff_ignored_by_default(tmp_path):
    ev = _first_event("http", _http_client(_XFF_REQ), tmp_path)
    assert ev["src_ip"] == "203.0.113.9"


def test_xff_honored_when_trusted(tmp_path):
    ev = _first_event("http", _http_client(_XFF_REQ), tmp_path, trust_xff=True)
    assert ev["src_ip"] == "198.51.100.1"


# --- --simulate refuses non-loopback (R2) -----------------------------------

def test_simulate_is_loopback_only():
    with pytest.raises(SystemExit):
        server_cli(["--bind", "0.0.0.0", "--i-know-what-im-doing", "--simulate"])


def test_non_loopback_needs_flag():
    with pytest.raises(SystemExit):
        server_cli(["--bind", "0.0.0.0"])


# --- rate limiter (R3) -------------------------------------------------------

def test_rate_limiter_window_and_sweep():
    rl = RateLimiter(max_per_window=2, window=0.05)
    assert rl.allow("192.0.2.1") is True
    assert rl.allow("192.0.2.1") is True
    assert rl.allow("192.0.2.1") is False          # third hit in window
    assert rl.allow("192.0.2.2") is True           # other IP unaffected
    time.sleep(0.08)
    assert rl.allow("192.0.2.1") is True           # window expired
    time.sleep(0.08)
    rl.sweep()
    assert rl._hits == {}                          # stale keys removed


def test_rate_limit_logs_simulated_source(tmp_path):
    async def client(port):
        for _ in range(3):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"X-SIM-SRC 192.0.2.77\r\n")
            await r.read(256)
            w.write(b"x\r\n")
            await w.drain()
            await _drain(r)
            w.close()
    events = asyncio.run(_run("tcp", client, tmp_path,
                              rate=RateLimiter(max_per_window=2)))
    kinds = [e.get("event", "hit") for e in events]
    assert kinds == ["hit", "hit", "rate_limited"]
    assert events[2]["src_ip"] == "192.0.2.77"      # R8: simulated source


# --- payload cap ------------------------------------------------------------

def test_payload_cap(tmp_path):
    async def client(port):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"X-SIM-SRC 192.0.2.50\r\n")
        await r.read(256)
        w.write(b"A" * 20000)                   # way over the cap
        await w.drain()
        await _drain(r)
        w.close()
    ev = _first_event("tcp", client, tmp_path)
    assert ev["data_len"] <= MAX_BYTES


# --- replayer determinism ---------------------------------------------------

def test_replayer_deterministic():
    assert build_plan(1337) == build_plan(1337)
    assert build_plan(1337) != build_plan(2026)
    plan = build_plan(1337)
    assert plan, "plan must not be empty"
    assert all("src_ip" in a and "service" in a for a in plan)


# --- alert aggregation thresholds -------------------------------------------

def _telnet(ip, user, pw):
    return {"service": "telnet", "src_ip": ip, "username": user, "password": pw,
            "ts": "2026-01-01T00:00:00+00:00"}


def test_brute_force_threshold():
    below = [_telnet("192.0.2.2", "root", str(i))
             for i in range(pipeline.BRUTE_THRESHOLD - 1)]
    at = [_telnet("192.0.2.3", "root", str(i))
          for i in range(pipeline.BRUTE_THRESHOLD)]
    alerts = pipeline.build_alerts(below + at)
    bf = [a for a in alerts if a["type"] == "brute_force"]
    assert [a["src_ip"] for a in bf] == ["192.0.2.3"]
    assert bf[0]["count"] == pipeline.BRUTE_THRESHOLD


def test_credential_stuffing_threshold():
    events = [_telnet("192.0.2.4", f"u{i}", f"p{i}")
              for i in range(pipeline.CRED_THRESHOLD)]
    alerts = pipeline.build_alerts(events)
    assert any(a["type"] == "credential_stuffing"
               and a["distinct_credentials"] == pipeline.CRED_THRESHOLD
               for a in alerts)


def test_web_exploit_probe_alert():
    events = [{"service": "http", "src_ip": "203.0.113.5",
               "path": "/wp-login.php", "user_agent": "nuclei",
               "ts": "2026-01-01T00:00:00+00:00"}]
    alerts = pipeline.build_alerts(events)
    assert any(a["type"] == "web_exploit_probe" for a in alerts)


def test_new_attacker_watchlist_respects_baseline():
    events = [_telnet("192.0.2.9", "root", "x")]
    assert any(a["type"] == "new_attacker_watchlist"
               for a in pipeline.build_alerts(events, known_ips=[]))
    assert not any(a["type"] == "new_attacker_watchlist"
                   for a in pipeline.build_alerts(events, known_ips=["192.0.2.9"]))
