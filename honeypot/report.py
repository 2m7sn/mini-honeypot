"""HTML daily-digest report.

Plain, dense, engineer-made: tables and one inline-SVG timeline. No tiles,
no gradients, no pills, no emoji. Dark #262626 background, accent #a68af9 used
sparingly. Readable down to 375px.
"""
from __future__ import annotations

import argparse
import html
from collections import Counter
from datetime import datetime

from . import pipeline

_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  background: #262626; color: #d6d6d6; margin: 0;
  font: 13px/1.5 ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
.wrap { max-width: 880px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { font-size: 16px; font-weight: 600; margin: 0 0 2px; color: #f0f0f0; }
h2 {
  font-size: 13px; font-weight: 600; margin: 32px 0 8px; color: #f0f0f0;
  border-bottom: 1px solid #a68af9; padding-bottom: 4px;
}
.meta { color: #8a8a8a; font-size: 12px; margin: 0 0 4px; }
p { margin: 8px 0; color: #c2c2c2; }
a { color: #a68af9; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; margin: 4px 0; font-size: 12px; }
th, td {
  border: 1px solid #3a3a3a; padding: 4px 8px; text-align: left;
  white-space: nowrap; vertical-align: top;
}
th { color: #9a9a9a; font-weight: 600; background: #2c2c2c; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
.sev-high { color: #e0806f; }
.sev-medium { color: #d6b36a; }
.sev-low { color: #8a8a8a; }
.empty { color: #8a8a8a; font-style: italic; }
svg { display: block; width: 100%; height: auto; margin-top: 8px; }
"""


def _esc(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _table(headers, rows, numeric_cols=()):
    if not rows:
        return '<p class="empty">none</p>'
    out = ['<div class="scroll"><table><thead><tr>']
    out += [f"<th>{_esc(h)}</th>" for h in headers]
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>")
        for i, cell in enumerate(row):
            cls = ' class="num"' if i in numeric_cols else ""
            out.append(f"<td{cls}>{_esc(cell)}</td>")
        out.append("</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def _timeline_svg(hits, bins=20, width=400, height=80):
    """Events bucketed into `bins` equal slices of the run's own time span.

    Axis labels live in HTML below the SVG (not inside it) so they stay
    readable when the SVG scales down to a 375px viewport.
    """
    times = []
    for e in hits:
        try:
            times.append(datetime.fromisoformat(e["ts"]).timestamp())
        except (KeyError, ValueError):
            pass
    if len(times) < 2:
        return '<p class="empty">not enough timestamps for a timeline</p>'
    lo, hi = min(times), max(times)
    span = hi - lo
    counts = [0] * bins
    for t in times:
        idx = min(bins - 1, int((t - lo) / span * bins)) if span else 0
        counts[idx] += 1
    peak = max(counts) or 1
    bw = width / bins
    bars = []
    for i, c in enumerate(counts):
        bh = (c / peak) * (height - 4)
        bars.append(f'<rect x="{i * bw:.1f}" y="{height - bh:.1f}" '
                    f'width="{bw - 1:.1f}" height="{bh:.1f}" fill="#a68af9"/>')
    bin_ms = span / bins * 1000
    return (
        f'<svg viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="events over time">' + "".join(bars) + "</svg>"
        f'<p class="meta">{len(times)} events over {span:.2f}s, '
        f'{bins} bins of {bin_ms:.0f}ms, peak {peak} per bin. '
        f'left = run start, right = run end.</p>'
    )


def build_html(events, alerts) -> str:
    hits = pipeline._hits(events)
    telnet = [e for e in hits if e["service"] == "telnet"]
    http = [e for e in hits if e["service"] == "http"]

    ip_counts = Counter(e.get("src_ip", "") for e in hits).most_common(10)
    ip_rows = [(ip, n, pipeline.geo_lookup(ip)["country"]) for ip, n in ip_counts]

    cred_counts = Counter(
        f'{e.get("username","")}:{e.get("password","")}' for e in telnet
    ).most_common(10)

    path_counts = Counter(e.get("path", "") for e in http).most_common(10)

    alert_rows = [(a["type"], a.get("severity", ""), a.get("src_ip", "-"),
                   a.get("summary", "")) for a in alerts]

    date = datetime.now().strftime("%Y-%m-%d %H:%M")
    parts = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        '<meta name=viewport content="width=device-width, initial-scale=1">',
        "<title>Honeypot daily digest</title>",
        f"<style>{_CSS}</style></head><body><div class=wrap>",
        "<h1>Honeypot daily digest</h1>",
        f'<p class="meta">generated {date} &middot; source: mini-honeypot '
        "&middot; <strong>simulated traffic (localhost replay)</strong></p>",
        f"<p>{len(hits)} interactions, {len(alerts)} alerts. "
        f"{len(telnet)} telnet credential attempts, {len(http)} web requests. "
        "All source IPs are RFC 5737 documentation ranges.</p>",

        "<h2>Alerts</h2>",
        _sev_table(alert_rows),

        "<h2>Events over time</h2>",
        _timeline_svg(hits),

        "<h2>Top attacker IPs</h2>",
        _table(["IP", "events", "geo (simulated)"], ip_rows, numeric_cols={1}),

        "<h2>Top credentials tried (telnet)</h2>",
        _table(["user:pass", "count"],
               [(c, n) for c, n in cred_counts], numeric_cols={1}),

        "<h2>Top paths requested (http)</h2>",
        _table(["path", "count"],
               [(p, n) for p, n in path_counts], numeric_cols={1}),

        "</div></body></html>",
    ]
    return "".join(parts)


def _sev_table(alert_rows):
    """Alerts table with severity coloring (kept separate for the sev class)."""
    if not alert_rows:
        return '<p class="empty">no alerts</p>'
    out = ['<div class="scroll"><table><thead><tr>'
           "<th>type</th><th>severity</th><th>src IP</th><th>summary</th>"
           "</tr></thead><tbody>"]
    for t, sev, ip, summary in alert_rows:
        out.append(
            f"<tr><td>{_esc(t)}</td>"
            f'<td class="sev-{_esc(sev)}">{_esc(sev)}</td>'
            f"<td>{_esc(ip)}</td><td>{_esc(summary)}</td></tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def write_report(log_path, outdir, html_path):
    events, alerts, _ = pipeline.process(log_path, outdir)
    html_text = build_html(events, alerts)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_text)
    return html_path, len(pipeline._hits(events)), len(alerts)


def run(argv=None):
    ap = argparse.ArgumentParser(description="Build the HTML daily digest.")
    ap.add_argument("--log", default="honeypot.log")
    ap.add_argument("--out", default="out")
    ap.add_argument("--html", default="report.html")
    args = ap.parse_args(argv)
    path, n_events, n_alerts = write_report(args.log, args.out, args.html)
    print(f"[report] {path}: {n_events} events, {n_alerts} alerts")


if __name__ == "__main__":
    run()
