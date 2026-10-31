"""Attack replayer: seeded, reproducible, localhost-only.

Replays realistic internet background noise against the local honeypot:
Mirai-style telnet credential lists, SSH brute force, web scanners, and a
"low and slow" attacker. The plan is fully determined by the seed, so two runs
with the same seed produce the same sequence of actions.

This only connects to the honeypot you point it at. It sends no exploits -- it
drives the honeypot's fake prompts with credential/path data so the pipeline
has something to classify.
"""
from __future__ import annotations

import argparse
import asyncio
import random

from . import data
from .server import DEFAULT_PORTS, _read, _readline


def _ip(rnd, prefix):
    return f"{prefix}.{rnd.randint(2, 254)}"


def build_plan(seed: int = 1337) -> list[dict]:
    """Return the deterministic list of actions for a seed.

    Network-free and pure -> used directly by the determinism test.
    """
    rnd = random.Random(seed)
    plan: list[dict] = []

    # Telnet: 3 Mirai bots, each cycling the full credential list.
    telnet_bots = [_ip(rnd, data.TESTNET_PREFIXES[0]) for _ in range(3)]
    for bot in telnet_bots:
        for user, pw in data.MIRAI_TELNET_CREDS:
            plan.append({"service": "telnet", "src_ip": bot,
                         "user": user, "password": pw})

    # SSH: 2 brute-force hosts, each opening many sessions.
    ssh_hosts = [_ip(rnd, data.TESTNET_PREFIXES[1]) for _ in range(2)]
    for host in ssh_hosts:
        for user, pw in data.SSH_BRUTE_CREDS:
            plan.append({"service": "ssh", "src_ip": host,
                         "client_version": "SSH-2.0-libssh2_1.9.0",
                         "user": user, "password": pw})

    # Web: 2 scanners sweeping the path list with a random scanner UA each.
    scanners = [_ip(rnd, data.TESTNET_PREFIXES[2]) for _ in range(2)]
    for scanner in scanners:
        ua = rnd.choice(data.SCANNER_UAS)
        for path in data.WEB_PATHS:
            plan.append({"service": "http", "src_ip": scanner,
                         "method": "GET", "path": path, "ua": ua})

    # Low and slow: 1 host, a handful of spaced requests to a login page.
    slow = _ip(rnd, data.TESTNET_PREFIXES[0])
    for _ in range(5):
        plan.append({"service": "http", "src_ip": slow, "method": "POST",
                     "path": "/wp-login.php", "ua": "curl/7.81.0",
                     "slow": True})

    return plan


async def _do_telnet(host, port, act):
    r, w = await asyncio.open_connection(host, port)
    w.write(f"X-SIM-SRC {act['src_ip']}\r\n".encode())
    await w.drain()
    await _readline(r)                      # login:
    w.write((act["user"] + "\r\n").encode())
    await w.drain()
    await _read(r)                          # Password:
    w.write((act["password"] + "\r\n").encode())
    await w.drain()
    await _read(r)
    w.close()
    await w.wait_closed()


async def _do_ssh(host, port, act):
    r, w = await asyncio.open_connection(host, port)
    w.write(f"X-SIM-SRC {act['src_ip']}\r\n".encode())
    await w.drain()
    await _read(r)                          # server banner
    w.write((act["client_version"] + "\r\n").encode())
    await w.drain()
    w.close()
    await w.wait_closed()


async def _do_http(host, port, act):
    r, w = await asyncio.open_connection(host, port)
    req = (f"X-SIM-SRC {act['src_ip']}\r\n"
           f"{act['method']} {act['path']} HTTP/1.1\r\n"
           f"Host: honeypot.local\r\n"
           f"User-Agent: {act['ua']}\r\n\r\n")
    w.write(req.encode())
    await w.drain()
    await _read(r)
    w.close()
    await w.wait_closed()


_EXEC = {"telnet": _do_telnet, "ssh": _do_ssh, "http": _do_http}


async def execute(plan, host="127.0.0.1", ports=None):
    """Run a plan against a honeypot in --simulate mode. Returns per-service counts."""
    ports = ports or DEFAULT_PORTS
    counts: dict[str, int] = {}
    for act in plan:
        svc = act["service"]
        try:
            await _EXEC[svc](host, ports[svc], act)
            counts[svc] = counts.get(svc, 0) + 1
            if act.get("slow"):
                await asyncio.sleep(0.05)   # token "low and slow" pacing
        except (ConnectionError, OSError):
            pass
    return counts


def run(argv=None):
    ap = argparse.ArgumentParser(description="Seeded localhost attack replayer.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args(argv)
    if args.host not in ("127.0.0.1", "::1", "localhost"):
        ap.error("replayer is localhost-only")
    plan = build_plan(args.seed)
    counts = asyncio.run(execute(plan, args.host))
    print(f"[replayer] seed={args.seed} actions={len(plan)} sent={counts}")


if __name__ == "__main__":
    run()
