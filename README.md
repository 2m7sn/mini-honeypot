# Mini Honeypot + Attack Replayer

A low-interaction honeypot and the pipeline that turns its hits into SOC-ready
alerts. Pure Python 3.13, standard library only (pytest for tests).

## Why a honeypot in a SOC

A honeypot is a service with no legitimate users. Any traffic that reaches it
is, by definition, unsolicited — scanning, brute force, or probing. That makes
it a very low-noise source of detections: there are no false positives from
real users, so every hit is signal. In a SOC a honeypot is used to:

- see which credentials, paths, and tools are hitting your range right now,
- feed fresh attacker IPs into block-lists and watchlists,
- generate labelled data to tune and test detection rules (Sigma, Wazuh,
  Elastic) without touching production logs.

This project is low-interaction: it fakes just enough of each service to
capture what the client sends, and **never executes anything**.

## Safety

- Binds to `127.0.0.1` by default. Binding a non-loopback address requires the
  explicit `--i-know-what-im-doing` flag.
- **Only expose this on an isolated VPS you own** — a throwaway host with no
  other services and nothing else on its network. Never on a work machine, a
  home LAN, or anything with access to real systems.
- It never runs attacker input. Every read is size-capped (4 KB) and there is a
  per-IP rate limit.
- `X-Forwarded-For` is ignored unless you pass `--trust-xff`. **Enable it only
  behind a proxy you control** — otherwise any client can forge the source IP
  and poison your block-list.
- `--simulate` (trust the replayer's `X-SIM-SRC` line) is loopback-only; the
  server refuses to start with it on any other bind address.
- The replayer is localhost-only and sends no real exploits; it drives the
  honeypot's fake prompts with public credential/path lists so the pipeline has
  something to classify.

## Threat model / what this is NOT

This is a **sensor**, not a defence. It assumes an attacker who scans and
brute-forces internet-facing services with automated tools; it exists to
observe and record that, nothing more. It is **not** a firewall, an IDS for
your real hosts, or a deception platform that can hold an attacker's
attention. It does not detect anything aimed at other machines, cannot see
encrypted SSH credentials, and offers no protection to the host it runs on —
which is exactly why it must only run on an isolated box. The simulated data
in this repo demonstrates the pipeline; it says nothing about real-world
attack volume until the honeypot is deployed for real.

## Quickstart

```bash
pip install -e ".[dev]"

# 1. start the honeypot (simulate mode trusts the replayer's X-SIM-SRC line)
honeypot --simulate --log honeypot.log

# 2. in another shell, replay internet background noise (seeded, reproducible)
honeypot-replay --seed 1337

# 3. stop the honeypot (Ctrl+C), then build alerts + report
honeypot-pipeline --log honeypot.log --out out
honeypot-report  --log honeypot.log --out out --html report.html
```

Outputs:

- `out/events.ndjson` — ECS-style docs for Elastic / Wazuh ingest
- `out/alerts.json` — aggregated alerts
- `out/blocklist.txt` — unique attacker IPs
- `out/rules.sigma.yml` — Sigma-like detection rules
- `report.html` — daily digest (open in a browser)

Default ports: SSH `2222`, Telnet `2323`, HTTP `8080`, generic TCP `9000`.

## Real numbers (simulated traffic, seed 1337)

From one localhost replay against the honeypot. **This is simulated traffic** —
all source IPs are RFC 5737 documentation ranges (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`), so no real host is involved.

| Metric | Value |
|---|---|
| Interactions logged | 114 |
| Distinct attacker IPs | 8 |
| Telnet credential attempts | 45 |
| SSH login attempts | 24 |
| Web requests | 45 |
| Alerts raised | 12 |

Alerts: 5 brute force (3 telnet, 2 SSH), 3 credential stuffing, 3 web exploit
probe, 1 new-attacker watchlist (8 IPs). Numbers are reproducible: same seed,
same output.

ATT&CK v20 techniques tagged:

| ID | Name | Where |
|---|---|---|
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | telnet/SSH events, brute-force alert |
| [T1110.004](https://attack.mitre.org/techniques/T1110/004/) | Brute Force: Credential Stuffing | credential-stuffing alert |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | sensitive-path HTTP events, web-probe alert |
| [T1595.001](https://attack.mitre.org/techniques/T1595/001/) | Active Scanning: Scanning IP Blocks | generic TCP events, new-attacker watchlist |
| [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Active Scanning: Vulnerability Scanning | HTTP events with scanner user agents |

## Sample output

Ten lines of `out/events.ndjson` (ECS-style; `event.category` is a list,
`source.as.number` is an int). Ports are ephemeral from the test run.

```json
{"@timestamp":"2026-10-30T19:49:19.757951+00:00","event":{"kind":"event","module":"mini-honeypot","category":["intrusion_detection"],"action":"telnet"},"source":{"ip":"192.0.2.160","port":50973,"geo":{"country_name":"United States","city_name":"Ashburn"},"as":{"number":13335,"organization":{"name":"TEST-NET-1 (simulated)"}}},"destination":{"port":50970},"user_agent":{"original":null},"url":{"path":null},"honeypot":{"username":"root","password":"xc3511","client_version":null,"scanner":null},"threat":{"technique":{"id":["T1110.001"]}}}
{"@timestamp":"2026-10-30T19:49:19.759183+00:00","event":{"kind":"event","module":"mini-honeypot","category":["intrusion_detection"],"action":"telnet"},"source":{"ip":"192.0.2.160","port":50974,"geo":{"country_name":"United States","city_name":"Ashburn"},"as":{"number":13335,"organization":{"name":"TEST-NET-1 (simulated)"}}},"destination":{"port":50970},"user_agent":{"original":null},"url":{"path":null},"honeypot":{"username":"root","password":"vizxv","client_version":null,"scanner":null},"threat":{"technique":{"id":["T1110.001"]}}}
{"@timestamp":"2026-10-30T19:49:19.760319+00:00","event":{"kind":"event","module":"mini-honeypot","category":["intrusion_detection"],"action":"telnet"},"source":{"ip":"192.0.2.160","port":50975,"geo":{"country_name":"United States","city_name":"Ashburn"},"as":{"number":13335,"organization":{"name":"TEST-NET-1 (simulated)"}}},"destination":{"port":50970},"user_agent":{"original":null},"url":{"path":null},"honeypot":{"username":"root","password":"admin","client_version":null,"scanner":null},"threat":{"technique":{"id":["T1110.001"]}}}
{"@timestamp":"2026-10-30T19:49:19.761084+00:00","event":{"kind":"event","module":"mini-honeypot","category":["intrusion_detection"],"action":"telnet"},"source":{"ip":"192.0.2.160","port":50976,"geo":{"country_name":"United States","city_name":"Ashburn"},"as":{"number":13335,"organization":{"name":"TEST-NET-1 (simulated)"}}},"destination":{"port":50970},"user_agent":{"original":null},"url":{"path":null},"honeypot":{"username":"admin","password":"admin","client_version":null,"scanner":null},"threat":{"technique":{"id":["T1110.001"]}}}
{"@timestamp":"2026-10-30T19:49:19.794227+00:00","event":{"kind":"event","module":"mini-honeypot","category":["intrusion_detection"],"action":"ssh"},"source":{"ip":"198.51.100.183","port":51020,"geo":{"country_name":"Germany","city_name":"Frankfurt"},"as":{"number":24940,"organization":{"name":"TEST-NET-2 (simulated)"}}},"destination":{"port":50969},"user_agent":{"original":null},"url":{"path":null},"honeypot":{"username":null,"password":null,"client_version":"SSH-2.0-libssh2_1.9.0","scanner":null},"threat":{"technique":{"id":["T1110.001"]}}}
{"@timestamp":"2026-10-30T19:49:19.794993+00:00","event":{"kind":"event","module":"mini-honeypot","category":["intrusion_detection"],"action":"ssh"},"source":{"ip":"198.51.100.183","port":51021,"geo":{"country_name":"Germany","city_name":"Frankfurt"},"as":{"number":24940,"organization":{"name":"TEST-NET-2 (simulated)"}}},"destination":{"port":50969},"user_agent":{"original":null},"url":{"path":null},"honeypot":{"username":null,"password":null,"client_version":"SSH-2.0-libssh2_1.9.0","scanner":null},"threat":{"technique":{"id":["T1110.001"]}}}
{"@timestamp":"2026-10-30T19:49:19.795763+00:00","event":{"kind":"event","module":"mini-honeypot","category":["intrusion_detection"],"action":"ssh"},"source":{"ip":"198.51.100.183","port":51023,"geo":{"country_name":"Germany","city_name":"Frankfurt"},"as":{"number":24940,"organization":{"name":"TEST-NET-2 (simulated)"}}},"destination":{"port":50969},"user_agent":{"original":null},"url":{"path":null},"honeypot":{"username":null,"password":null,"client_version":"SSH-2.0-libssh2_1.9.0","scanner":null},"threat":{"technique":{"id":["T1110.001"]}}}
{"@timestamp":"2026-10-30T19:49:19.810770+00:00","event":{"kind":"event","module":"mini-honeypot","category":["intrusion_detection"],"action":"http"},"source":{"ip":"203.0.113.148","port":51046,"geo":{"country_name":"Singapore","city_name":"Singapore"},"as":{"number":4837,"organization":{"name":"TEST-NET-3 (simulated)"}}},"destination":{"port":50971},"user_agent":{"original":"Go-http-client/1.1"},"url":{"path":"/"},"honeypot":{"username":null,"password":null,"client_version":null,"scanner":"go-http-client"},"threat":{"technique":{"id":["T1595.002"]}}}
{"@timestamp":"2026-10-30T19:49:19.811529+00:00","event":{"kind":"event","module":"mini-honeypot","category":["intrusion_detection"],"action":"http"},"source":{"ip":"203.0.113.148","port":51047,"geo":{"country_name":"Singapore","city_name":"Singapore"},"as":{"number":4837,"organization":{"name":"TEST-NET-3 (simulated)"}}},"destination":{"port":50971},"user_agent":{"original":"Go-http-client/1.1"},"url":{"path":"/admin"},"honeypot":{"username":null,"password":null,"client_version":null,"scanner":"go-http-client"},"threat":{"technique":{"id":["T1595.002"]}}}
{"@timestamp":"2026-10-30T19:49:19.812251+00:00","event":{"kind":"event","module":"mini-honeypot","category":["intrusion_detection"],"action":"http"},"source":{"ip":"203.0.113.148","port":51048,"geo":{"country_name":"Singapore","city_name":"Singapore"},"as":{"number":4837,"organization":{"name":"TEST-NET-3 (simulated)"}}},"destination":{"port":50971},"user_agent":{"original":"Go-http-client/1.1"},"url":{"path":"/admin/login.php"},"honeypot":{"username":null,"password":null,"client_version":null,"scanner":"go-http-client"},"threat":{"technique":{"id":["T1595.002"]}}}
```

One entry from `out/alerts.json`:

```json
{
  "type": "brute_force",
  "severity": "high",
  "src_ip": "192.0.2.138",
  "service": "telnet",
  "count": 15,
  "geo": "United States",
  "technique": "T1110.001",
  "summary": "15 telnet login attempts from 192.0.2.138"
}
```

The Sigma rules in `out/rules.sigma.yml` are **alert-level**: their
`selection` matches the `type` field of `alerts.json` records, not raw events.
Each rule has a stable uuid5 `id`, `status: experimental`, a date, and both
tactic and technique tags.

## Services captured

| Service | Captured |
|---|---|
| SSH | banner exchange + client version (no crypto, so no credentials) |
| Telnet | username + password |
| HTTP | method, path, User-Agent, body; fake admin/wp-login pages as bait |
| TCP | generic banner-grab + payload length (exercised by the test suite) |

## Limits

- Low-interaction: no real shell, no SSH crypto, so SSH captures the client
  version and connection metadata, not offered credentials.
- GeoIP is a small bundled fake map over RFC 5737 blocks — illustrative, not
  real geolocation.
- Rate limiting and state are in-memory; they reset when the process restarts.
- The replayer is a traffic generator for the pipeline, not a pentest tool.

## Roadmap

- Deploy on a cheap isolated VPS to collect **real** background-noise data and
  compare it with these simulated numbers.
- Swap the fake GeoIP map for a real MaxMind GeoLite2 lookup.
- Compare coverage and log schema against [Cowrie](https://github.com/cowrie/cowrie),
  a mature medium-interaction SSH/Telnet honeypot, and document where this
  minimal build is enough and where Cowrie earns its weight.
- Ship the Sigma rules into a local Wazuh/Elastic stack and validate detections.

## Tests

```bash
pytest -q
```

Covers: each service logs a correct JSON event (server started on an ephemeral
port and torn down per test), the replayer plan is deterministic, alert
thresholds hold, the payload cap holds, `X-Forwarded-For` is ignored unless
`--trust-xff`, `--simulate` refuses non-loopback binds, and the rate limiter
blocks at `max_per_window` and sweeps stale IPs.

## License

MIT — Abdulmohsen Alharbi. Defensive / educational use only.
