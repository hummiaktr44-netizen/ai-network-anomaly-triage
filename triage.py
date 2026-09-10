import csv
import os
from collections import defaultdict, Counter
from dataclasses import dataclass, field

import requests

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = "claude-sonnet-4-6"

PORT_SCAN_THRESHOLD = 5
FAILED_AUTH_THRESHOLD = 3
LARGE_PACKET_BYTES = 8000
RARE_PORT_WHITELIST = {80, 443, 53, 22, 123, 25, 110, 143}


@dataclass
class TrafficEvent:
    timestamp: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    size_bytes: int
    flag: str = ""


@dataclass
class FlaggedIncident:
    reason: str
    src_ip: str
    detail: str
    events: list = field(default_factory=list)


def load_traffic(path):
    events = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(
                TrafficEvent(
                    timestamp=row["timestamp"],
                    src_ip=row["src_ip"],
                    dst_ip=row["dst_ip"],
                    dst_port=int(row["dst_port"]),
                    protocol=row["protocol"],
                    size_bytes=int(row["size_bytes"]),
                    flag=row.get("flag", ""),
                )
            )
    return events


def detect_anomalies(events):
    incidents = []

    ports_by_src = defaultdict(set)
    events_by_src = defaultdict(list)
    for e in events:
        ports_by_src[e.src_ip].add(e.dst_port)
        events_by_src[e.src_ip].append(e)

    for src, ports in ports_by_src.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            incidents.append(
                FlaggedIncident(
                    reason="possible_port_scan",
                    src_ip=src,
                    detail=f"{src} contacted {len(ports)} distinct destination ports",
                    events=events_by_src[src][:10],
                )
            )

    auth_fail_count = Counter(e.src_ip for e in events if e.flag == "AUTH_FAIL")
    for src, count in auth_fail_count.items():
        if count >= FAILED_AUTH_THRESHOLD:
            incidents.append(
                FlaggedIncident(
                    reason="repeated_auth_failure",
                    src_ip=src,
                    detail=f"{src} had {count} failed authentication attempts",
                    events=[e for e in events if e.src_ip == src and e.flag == "AUTH_FAIL"][:10],
                )
            )

    for e in events:
        if e.size_bytes >= LARGE_PACKET_BYTES:
            incidents.append(
                FlaggedIncident(
                    reason="oversized_packet",
                    src_ip=e.src_ip,
                    detail=f"{e.size_bytes} byte packet to {e.dst_ip}:{e.dst_port}",
                    events=[e],
                )
            )

    for e in events:
        if e.dst_port not in RARE_PORT_WHITELIST and e.dst_port > 1024:
            incidents.append(
                FlaggedIncident(
                    reason="unusual_destination_port",
                    src_ip=e.src_ip,
                    detail=f"connection to non-standard port {e.dst_port} on {e.dst_ip}",
                    events=[e],
                )
            )

    return incidents


def build_prompt(incident):
    sample_events = "\n".join(
        f"  - {e.timestamp} {e.src_ip} -> {e.dst_ip}:{e.dst_port} "
        f"({e.protocol}, {e.size_bytes} bytes, flag={e.flag or 'none'})"
        for e in incident.events
    )
    return f"""You are a network security analyst assistant. Review this flagged event
and respond ONLY with valid JSON, no other text, in this exact shape:

{{
  "severity": <integer 1-10>,
  "explanation": "<2-3 sentence explanation>",
  "recommended_action": "<one short recommended next step>"
}}

Flag type: {incident.reason}
Source IP: {incident.src_ip}
Summary: {incident.detail}

Sample events:
{sample_events}
"""


def triage_with_llm(incident):
    if not ANTHROPIC_API_KEY:
        return {
            "severity": "N/A",
            "explanation": "ANTHROPIC_API_KEY not set - showing rule-based detection only.",
            "recommended_action": "Set ANTHROPIC_API_KEY to enable AI-generated explanations.",
        }

    import json
    prompt = build_prompt(incident)
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": 300,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=30,
        )
        resp.raise_for_status()
        text = resp.json()["content"][0]["text"]
        text = text.strip().strip("`").replace("json", "", 1).strip()
        return json.loads(text)
    except Exception as exc:
        return {
            "severity": "N/A",
            "explanation": f"LLM triage unavailable: {exc}",
            "recommended_action": "Review manually.",
        }


def print_report(incident, verdict):
    print("=" * 70)
    print(f"[{incident.reason.upper()}]  src={incident.src_ip}  severity={verdict.get('severity')}")
    print(f"  Detail:      {incident.detail}")
    print(f"  Explanation: {verdict.get('explanation')}")
    print(f"  Action:      {verdict.get('recommended_action')}")


def main():
    csv_path = os.path.join(os.path.dirname(__file__), "sample_traffic.csv")
    events = load_traffic(csv_path)
    print(f"Loaded {len(events)} traffic events.")

    incidents = detect_anomalies(events)
    print(f"Flagged {len(incidents)} potential incidents.\n")

    if not incidents:
        print("No anomalies detected.")
        return

    for incident in incidents:
        verdict = triage_with_llm(incident)
        print_report(incident, verdict)

    print("=" * 70)
    print(f"\nTriage complete: {len(incidents)} incidents reviewed.")


if __name__ == "__main__":
    main()