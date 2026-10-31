"""Mini Honeypot + Attack Replayer.

Low-interaction honeypot (stdlib asyncio) that logs every interaction as JSON
lines, a seeded replayer that generates realistic internet background noise
against localhost, and a pipeline that turns the hits into SOC-ready alerts.

Defensive / educational use only. See README.md for the safety warning.
"""

__version__ = "0.1.0"
