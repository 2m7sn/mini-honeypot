"""Low-interaction honeypot (asyncio, stdlib only).

Fake SSH / Telnet / HTTP / generic-TCP services that log every interaction as
one JSON line. It NEVER executes anything a client sends, caps every payload,
and rate-limits per source IP.

SAFETY: binds to 127.0.0.1 by default. Exposing on 0.0.0.0 needs the explicit
--i-know-what-im-doing flag; see the README warning before doing that.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
from collections import deque
from datetime import datetime, timezone

MAX_BYTES = 4096        # hard cap on any single read from a client
READ_TIMEOUT = 5.0      # seconds to wait for client data

SSH_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"

DEFAULT_PORTS = {"ssh": 2222, "telnet": 2323, "http": 8080, "tcp": 9000}

# Paths that return a fake "login" page instead of 404 (bait).
_LOGIN_PATHS = ("/admin", "/wp-login.php", "/wp-admin/", "/phpmyadmin/")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventLog:
    """Append-only JSON-lines sink. One event == one line."""

    def __init__(self, path: str):
        self.path = path

    def write(self, event: dict) -> None:
        event.setdefault("ts", now_iso())
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")


class RateLimiter:
    """Per-IP sliding window. Drops connections above max_per_window.

    Default is generous so the bundled localhost replay is not throttled; lower
    it on a real deployment. ponytail: in-memory only, resets on restart.
    """

    SWEEP_EVERY = 256   # calls between stale-key sweeps

    def __init__(self, max_per_window: int = 300, window: float = 1.0):
        self.max = max_per_window
        self.window = window
        self._hits: dict[str, deque] = {}
        self._calls = 0

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        self._calls += 1
        if self._calls % self.SWEEP_EVERY == 0:
            self.sweep(now)
        q = self._hits.get(ip)
        if q is None:
            q = deque()
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.max:
            return False
        q.append(now)
        self._hits[ip] = q          # key inserted only when a hit is stored
        return True

    def sweep(self, now: float | None = None) -> None:
        """Drop IPs with no hits inside the window so the dict stays bounded."""
        now = time.monotonic() if now is None else now
        stale = [ip for ip, q in self._hits.items()
                 if not q or now - q[-1] > self.window]
        for ip in stale:
            del self._hits[ip]


async def _read(reader: asyncio.StreamReader, n: int = MAX_BYTES) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(n), READ_TIMEOUT)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return b""


async def _readline(reader: asyncio.StreamReader) -> bytes:
    try:
        data = await asyncio.wait_for(reader.readline(), READ_TIMEOUT)
    except (asyncio.TimeoutError, ConnectionError, OSError, ValueError):
        return b""
    return data[:MAX_BYTES]


def _decode(b: bytes) -> str:
    return b.decode("latin1", "replace").strip("\r\n")


async def _read_sim_src(reader: asyncio.StreamReader, default: str) -> str:
    """Localhost-simulation shim: first line 'X-SIM-SRC <ip>' sets the source.

    Only consulted in --simulate mode. On a real deployment this is off and the
    source IP comes from the socket peer (or HTTP X-Forwarded-For).
    """
    raw = await _readline(reader)
    line = _decode(raw)
    if line.upper().startswith("X-SIM-SRC "):
        return line.split(None, 1)[1].strip() or default
    # Not a sim tag: hand the bytes back so the protocol handler sees them.
    # (asyncio's StreamReader has no unread(); prepend to its internal buffer.)
    reader._buffer[:0] = raw
    return default


# --- per-service handlers: each returns the event dict to log ---------------

async def _handle_ssh(reader, writer, src_ip, src_port, dst_port, **_) -> dict:
    writer.write(SSH_BANNER)
    await writer.drain()
    client = _decode(await _read(reader))
    return {
        "service": "ssh", "src_ip": src_ip, "src_port": src_port,
        "dst_port": dst_port, "client_version": client[:200],
    }


async def _handle_telnet(reader, writer, src_ip, src_port, dst_port, **_) -> dict:
    writer.write(b"\r\nUbuntu 18.04 LTS\r\nlogin: ")
    await writer.drain()
    user = _decode(await _readline(reader))
    writer.write(b"Password: ")
    await writer.drain()
    pw = _decode(await _readline(reader))
    writer.write(b"\r\nLogin incorrect\r\n")
    await writer.drain()
    return {
        "service": "telnet", "src_ip": src_ip, "src_port": src_port,
        "dst_port": dst_port, "username": user[:128], "password": pw[:128],
    }


def _parse_http(raw: bytes):
    text = raw.decode("latin1", "replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    parts = (lines[0].split(" ") + ["", "", ""])[:3]
    method, path, _ver = parts
    headers = {}
    for line in lines[1:]:
        k, sep, v = line.partition(":")
        if sep:
            headers[k.strip().lower()] = v.strip()
    return method, path, headers, body


async def _handle_http(reader, writer, src_ip, src_port, dst_port,
                       trust_xff=False, **_) -> dict:
    raw = await _read(reader)
    method, path, headers, body = _parse_http(raw)
    # X-Forwarded-For is attacker-controlled; only honor it behind a proxy you
    # run (--trust-xff), otherwise a client could poison the block-list.
    xff = headers.get("x-forwarded-for")
    if trust_xff and xff:
        src_ip = xff.split(",")[0].strip()
    if path in _LOGIN_PATHS:
        page = (b"<html><body><form method=post><input name=user>"
                b"<input name=pass type=password></form></body></html>")
        status = 200
        resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        resp += b"Content-Length: %d\r\n\r\n" % len(page) + page
    else:
        status = 404
        resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    writer.write(resp)
    await writer.drain()
    return {
        "service": "http", "src_ip": src_ip, "src_port": src_port,
        "dst_port": dst_port, "method": method[:16], "path": path[:512],
        "user_agent": headers.get("user-agent", "")[:256],
        "body": body[:MAX_BYTES], "status": status,
    }


async def _handle_tcp(reader, writer, src_ip, src_port, dst_port, **_) -> dict:
    writer.write(b"220 service ready\r\n")
    await writer.drain()
    data = await _read(reader)
    return {
        "service": "tcp", "src_ip": src_ip, "src_port": src_port,
        "dst_port": dst_port, "data_hex": data.hex()[: MAX_BYTES * 2],
        "data_len": len(data),
    }


_HANDLERS = {
    "ssh": _handle_ssh, "telnet": _handle_telnet,
    "http": _handle_http, "tcp": _handle_tcp,
}


def make_handler(service, log: EventLog, simulate: bool, rate: RateLimiter,
                 trust_xff: bool = False):
    fn = _HANDLERS[service]

    async def handler(reader, writer):
        peer = writer.get_extra_info("peername") or ("?", 0)
        src_ip, src_port = peer[0], peer[1]
        dst_port = (writer.get_extra_info("sockname") or ("?", 0))[1]
        try:
            if simulate:        # loopback-only; resolve the simulated source
                src_ip = await _read_sim_src(reader, src_ip)
            if not rate.allow(src_ip):
                log.write({"service": service, "event": "rate_limited",
                           "src_ip": src_ip, "dst_port": dst_port})
                return
            event = await fn(reader, writer, src_ip, src_port, dst_port,
                             trust_xff=trust_xff)
            log.write(event)
        except Exception as exc:  # never let an attacker crash the listener
            log.write({"service": service, "event": "error",
                       "src_ip": src_ip, "detail": str(exc)[:200]})
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    return handler


async def start_service(service, host, port, log, simulate, rate,
                        trust_xff=False):
    """Start one service; returns the asyncio.Server (port 0 -> ephemeral)."""
    handler = make_handler(service, log, simulate, rate, trust_xff)
    return await asyncio.start_server(handler, host, port, limit=MAX_BYTES)


async def start_all(host, ports, log, simulate, rate, trust_xff=False):
    servers = {}
    for service, port in ports.items():
        servers[service] = await start_service(
            service, host, port, log, simulate, rate, trust_xff)
    return servers


async def _serve_forever(host, ports, log, simulate, rate, trust_xff):
    servers = await start_all(host, ports, log, simulate, rate, trust_xff)
    for svc, srv in servers.items():
        addr = srv.sockets[0].getsockname()
        print(f"[honeypot] {svc:6} listening on {addr[0]}:{addr[1]}")
    async with asyncio.TaskGroup() as tg:
        for srv in servers.values():
            tg.create_task(srv.serve_forever())


def run(argv=None):
    ap = argparse.ArgumentParser(description="Low-interaction honeypot.")
    ap.add_argument("--bind", default="127.0.0.1",
                    help="bind address (default 127.0.0.1)")
    ap.add_argument("--log", default="honeypot.log",
                    help="JSON-lines output file")
    ap.add_argument("--simulate", action="store_true",
                    help="trust X-SIM-SRC first line (localhost replay only)")
    ap.add_argument("--rate", type=int, default=300,
                    help="max connections per second per IP")
    ap.add_argument("--trust-xff", action="store_true",
                    help="honor X-Forwarded-For (only behind a proxy you control)")
    ap.add_argument("--i-know-what-im-doing", action="store_true",
                    help="required to bind a non-loopback address")
    args = ap.parse_args(argv)

    loopback = args.bind in ("127.0.0.1", "::1", "localhost")
    if not loopback and not args.i_know_what_im_doing:
        ap.error("refusing to bind non-loopback without --i-know-what-im-doing "
                 "(run only on an isolated VPS; see README)")
    if args.simulate and not loopback:
        ap.error("--simulate is loopback-only")

    log = EventLog(args.log)
    rate = RateLimiter(max_per_window=args.rate)
    try:
        asyncio.run(_serve_forever(
            args.bind, DEFAULT_PORTS, log, args.simulate, rate, args.trust_xff))
    except KeyboardInterrupt:
        print("\n[honeypot] stopped")


if __name__ == "__main__":
    run()
