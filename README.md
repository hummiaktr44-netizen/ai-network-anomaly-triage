# AI-Powered Network Anomaly Triage Tool

A Python tool that detects network anomalies using rule-based detection, with optional LLM-powered triage for severity scoring and plain-language explanations.

## Why this project

Rule-based network intrusion detection generates a lot of alerts, but every alert still needs a human to interpret it and decide what matters. This tool automates the first-pass triage step: it flags suspicious traffic patterns using independent detection rules, and can optionally hand each flagged incident to an LLM for a severity score and explanation — the way a junior analyst would summarize a finding for review.

## How it works

1. **Ingest** — reads network traffic events from a CSV log (timestamp, source/destination IP, port, protocol, packet size, flags).
2. **Detect** — four independent rule-based detectors flag:
   - **Port scans** — a single source IP contacting an unusually high number of distinct destination ports in a short window.
   - **Repeated authentication failures** — a source IP with multiple failed login attempts, indicating a possible brute-force attempt.
   - **Oversized packets** — packets larger than a defined threshold, which can indicate data exfiltration.
   - **Unusual destination ports** — connections to non-standard, non-whitelisted ports.
3. **Triage** — each flagged incident can optionally be sent to an LLM (Claude, via the Anthropic API) for a severity score (1-10), explanation, and recommended action. If no API key is configured, the tool still reports full rule-based detection results.
4. **Report** — prints all flagged incidents with their detection reason and detail.

## Example output

![triage tool output](Screenshot%202026-09-11%20012136.png)

Running against a sample traffic log, the tool correctly flagged a port scan (7 distinct ports from one source), a brute-force pattern (4 failed logins), an oversized packet (9800 bytes), and a connection to port 4444 — a port commonly associated with reverse shells.

## Tech stack

Python, `csv` and `dataclasses` for data handling, `requests` for optional Anthropic API integration.

## Run it yourself

```bash
python triage.py
```

Runs on the included `sample_traffic.csv` by default. To enable AI-generated severity scoring and explanations, set an `ANTHROPIC_API_KEY` environment variable before running.

## What I learned

This project reinforced how a small set of independent, well-chosen detection rules (unusual port counts, repeated failures, packet size, non-standard ports) can catch a meaningful range of suspicious network behavior without needing machine learning, and how an LLM layer can be added on top to turn raw detections into analyst-ready explanations.

## Possible extensions

- Add a time-window parameter so detection rules apply to rolling time periods instead of the whole log
- Support live packet capture (via `scapy`) instead of only static CSV logs
- Persist flagged incidents to a database for historical tracking
