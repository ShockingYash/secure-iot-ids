#!/usr/bin/env python3
"""Secure IoT IDS event bridge.

Reads Contiki/Cooja IDS logs, converts real IDS messages into structured events,
and POSTs them to the existing Express backend at /api/events.

Examples:
  python3 secure_iot_event_bridge.py --file ../flood_ids_log.txt --once --dry-run
  python3 secure_iot_event_bridge.py --file ../flood_ids_log.txt --once
  python3 secure_iot_event_bridge.py --file ../flood_ids_log.txt --follow
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_BACKEND = "http://localhost:5000/api/events"

# Raw Cooja timestamps normally look like MM:SS.mmm; the parser also accepts
# HH:MM:SS.mmm so it remains useful if the logger is configured differently.
TS_RE = re.compile(
    r"^(?P<a>\d+):(?P<b>\d{2})(?::(?P<c>\d{2}))?\.(?P<ms>\d{3})\b"
)

FLOOD_ALERT_RE = re.compile(
    r"IDS ALERT: FLOODING DETECTED source=(\S+) rate=([0-9.]+) packets/sec"
)
SINK_ALERT_RE = re.compile(
    r"IDS ALERT: SINKHOLE DETECTED node=(\S+) advertised_rank=(\d+) threshold=(\d+)"
)
SINK_BLOCK_RE = re.compile(r"IDS ACTION: BLOCK sent to sinkhole (\S+)")

@dataclass
class AttackState:
    attack_type: str
    node: int | None = None
    address: str | None = None
    onset_ms: float | None = None
    detection_ms: float | None = None
    block_sent_ms: float | None = None
    mitigation_ms: float | None = None
    active: bool = False


@dataclass
class BridgeState:
    attacks: dict[str, AttackState] = field(default_factory=dict)
    last_offset: int = 0
    last_inode: int | None = None


def parse_timestamp(line: str) -> float | None:
    """Return timestamp in milliseconds from a raw log line."""
    m = TS_RE.match(line.strip())
    if not m:
        return None
    a = int(m.group("a"))
    b = int(m.group("b"))
    c = m.group("c")
    ms = int(m.group("ms"))
    if c is None:
        # MM:SS.mmm
        return (a * 60 + b) * 1000 + ms
    # HH:MM:SS.mmm
    return (a * 3600 + b * 60 + int(c)) * 1000 + ms


def parse_node_from_id(line: str) -> int | None:
    m = re.search(r"\bID:(\d+)\b", line)
    return int(m.group(1)) if m else None


def post_event(url: str, event: dict, dry_run: bool) -> None:
    payload = json.dumps(event).encode("utf-8")
    if dry_run:
        print("DRY-RUN EVENT:", json.dumps(event, separators=(",", ":")))
        return
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read().decode("utf-8", errors="replace")
            print(f"POST {response.status}: {body}")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not POST event to {url}: {exc}") from exc


def emit(
    *,
    backend: str,
    dry_run: bool,
    attack_type: str,
    node: int | None,
    status: str,
    message: str,
    detection_ms: float | None = None,
    mitigation_ms: float | None = None,
    event_time_ms: float | None = None,
    address: str | None = None,
) -> None:
    event = {
        "attackType": attack_type,
        "node": node,
        "status": status,
        "message": message,
    }
    if detection_ms is not None:
        event["detectionTimeMs"] = round(detection_ms, 3)
    if mitigation_ms is not None:
        event["mitigationTimeMs"] = round(mitigation_ms, 3)
    if event_time_ms is not None:
        event["eventTimeMs"] = round(event_time_ms, 3)
    if address:
        event["address"] = address
    post_event(backend, event, dry_run)


def process_line(line: str, state: BridgeState, backend: str, dry_run: bool) -> None:
    ts = parse_timestamp(line)
    if ts is None:
        return

    # ---------------- Flooding ----------------
    if "FLOOD TX" in line:
        if "flood" not in state.attacks or not state.attacks["flood"].active:
            state.attacks["flood"] = AttackState(
                attack_type="Flooding", node=parse_node_from_id(line), onset_ms=ts, active=True
            )
        return

    m = FLOOD_ALERT_RE.search(line)
    if m:
        address, rate = m.groups()
        attack = state.attacks.setdefault("flood", AttackState("Flooding"))
        attack.address = address
        attack.detection_ms = ts
        if attack.onset_ms is None:
            attack.onset_ms = ts
        detection = ts - attack.onset_ms
        # The actual attacker is node 5 in the validated experiment, but the
        # parser does not invent a node number from the IP address.
        emit(
            backend=backend,
            dry_run=dry_run,
            attack_type="Flooding",
            node=attack.node,
            status="DETECTED",
            message=f"Flooding attack detected from {address} at {rate} packets/sec",
            detection_ms=detection,
            event_time_ms=ts,
            address=address,
        )
        return

    if "IDS ACTION: source blacklisted and BLOCK sent" in line:
        attack = state.attacks.setdefault("flood", AttackState("Flooding"))
        attack.block_sent_ms = ts
        emit(
            backend=backend,
            dry_run=dry_run,
            attack_type="Flooding",
            node=attack.node,
            status="BLOCK_SENT",
            message="IDS blacklisted the source and sent BLOCK",
            detection_ms=(ts - attack.onset_ms) if attack.onset_ms is not None else None,
            event_time_ms=ts,
            address=attack.address,
        )
        return

    if "MITIGATION: BLOCK received from IDS" in line and ("FloodAttack" in line or "flooding" in line.lower()):
        attack = state.attacks.setdefault("flood", AttackState("Flooding"))
        attack.mitigation_ms = ts
        mitigation = (
            ts - attack.detection_ms if attack.detection_ms is not None else None
        )
        emit(
            backend=backend,
            dry_run=dry_run,
            attack_type="Flooding",
            node=parse_node_from_id(line) or attack.node,
            status="MITIGATED",
            message="BLOCK received by flooding attacker",
            detection_ms=(attack.detection_ms - attack.onset_ms)
            if attack.detection_ms is not None and attack.onset_ms is not None
            else None,
            mitigation_ms=mitigation,
            event_time_ms=ts,
            address=attack.address,
        )
        return

    if "MITIGATION: attacker stopped" in line:
        attack = state.attacks.setdefault("flood", AttackState("Flooding"))
        attack.active = False
        emit(
            backend=backend,
            dry_run=dry_run,
            attack_type="Flooding",
            node=parse_node_from_id(line) or attack.node,
            status="STOPPED",
            message="Flooding attacker stopped",
            event_time_ms=ts,
            address=attack.address,
        )
        return

    # ---------------- Sinkhole ----------------

    # The attacker may emit its first malicious DIO before the
    # explicit SINKHOLE ATTACK ACTIVE message is captured.
    # Use this as a fallback onset marker and capture the attacker
    # node from the Cooja mote ID. This does NOT invent a node number.
    if "SINKHOLE DIO SENT with fake attractive rank" in line:
        attack = state.attacks.setdefault("sinkhole", AttackState("Sinkhole"))

        node_id = parse_node_from_id(line)
        if node_id is not None:
            attack.node = node_id

        if attack.onset_ms is None:
            attack.onset_ms = ts

        attack.active = True
        return

    if "SINKHOLE ATTACK ACTIVE" in line:
        attack = state.attacks.setdefault("sinkhole", AttackState("Sinkhole"))
        attack.node = parse_node_from_id(line) or attack.node
        attack.onset_ms = ts
        attack.active = True
        emit(
            backend=backend,
            dry_run=dry_run,
            attack_type="Sinkhole",
            node=attack.node,
            status="ATTACK_ACTIVE",
            message="Sinkhole attack became active",
            event_time_ms=ts,
        )
        return

    m = SINK_ALERT_RE.search(line)
    if m:
        address, rank, threshold = m.groups()
        attack = state.attacks.setdefault("sinkhole", AttackState("Sinkhole"))
        attack.address = address
        attack.detection_ms = ts
        if attack.onset_ms is None:
            attack.onset_ms = ts
        detection = ts - attack.onset_ms
        emit(
            backend=backend,
            dry_run=dry_run,
            attack_type="Sinkhole",
            node=attack.node,
            status="DETECTED",
            message=(
                f"Sinkhole detected at {address}; advertised rank={rank}, "
                f"threshold={threshold}"
            ),
            detection_ms=detection,
            event_time_ms=ts,
            address=address,
        )
        return

    m = SINK_BLOCK_RE.search(line)
    if m:
        address = m.group(1)
        attack = state.attacks.setdefault("sinkhole", AttackState("Sinkhole"))
        attack.address = address
        attack.block_sent_ms = ts
        emit(
            backend=backend,
            dry_run=dry_run,
            attack_type="Sinkhole",
            node=attack.node,
            status="BLOCK_SENT",
            message=f"BLOCK sent to sinkhole {address}",
            detection_ms=(attack.detection_ms - attack.onset_ms)
            if attack.detection_ms is not None and attack.onset_ms is not None
            else None,
            event_time_ms=ts,
            address=address,
        )
        return

    if "IDS ACTION: sinkhole node isolated" in line:
        attack = state.attacks.setdefault("sinkhole", AttackState("Sinkhole"))
        emit(
            backend=backend,
            dry_run=dry_run,
            attack_type="Sinkhole",
            node=attack.node,
            status="ISOLATED",
            message="Sinkhole node isolated by IDS",
            event_time_ms=ts,
            address=attack.address,
        )
        return

    if "IDS ACTION: RPL global repair triggered" in line:
        attack = state.attacks.setdefault("sinkhole", AttackState("Sinkhole"))
        emit(
            backend=backend,
            dry_run=dry_run,
            attack_type="Sinkhole",
            node=attack.node,
            status="RPL_REPAIR",
            message="RPL global repair triggered",
            event_time_ms=ts,
            address=attack.address,
        )
        return

    if "MITIGATION: BLOCK received from IDS" in line and ("Sinkhole" in line or "IDS-Sinkhole" in line):
        attack = state.attacks.setdefault("sinkhole", AttackState("Sinkhole"))
        attack.mitigation_ms = ts
        mitigation = ts - attack.detection_ms if attack.detection_ms is not None else None
        emit(
            backend=backend,
            dry_run=dry_run,
            attack_type="Sinkhole",
            node=parse_node_from_id(line) or attack.node,
            status="MITIGATED",
            message="BLOCK received by sinkhole attacker",
            detection_ms=(attack.detection_ms - attack.onset_ms)
            if attack.detection_ms is not None and attack.onset_ms is not None
            else None,
            mitigation_ms=mitigation,
            event_time_ms=ts,
            address=attack.address,
        )
        return

    if "MITIGATION: sinkhole poisoned and leaving DAG" in line:
        attack = state.attacks.setdefault("sinkhole", AttackState("Sinkhole"))
        emit(
            backend=backend,
            dry_run=dry_run,
            attack_type="Sinkhole",
            node=parse_node_from_id(line) or attack.node,
            status="POISONED",
            message="Sinkhole poisoned and leaving DAG",
            event_time_ms=ts,
            address=attack.address,
        )
        return

    if "SINKHOLE ATTACK STOPPED" in line:
        attack = state.attacks.setdefault("sinkhole", AttackState("Sinkhole"))
        attack.active = False
        emit(
            backend=backend,
            dry_run=dry_run,
            attack_type="Sinkhole",
            node=parse_node_from_id(line) or attack.node,
            status="STOPPED",
            message="Sinkhole attack stopped",
            event_time_ms=ts,
            address=attack.address,
        )


def load_state(path: Path) -> BridgeState:
    if not path.exists():
        return BridgeState()
    try:
        data = json.loads(path.read_text())
        return BridgeState(last_offset=int(data.get("last_offset", 0)), last_inode=data.get("last_inode"))
    except Exception:
        return BridgeState()


def save_state(path: Path, state: BridgeState) -> None:
    path.write_text(json.dumps({"last_offset": state.last_offset, "last_inode": state.last_inode}, indent=2))


def process_file(path: Path, state: BridgeState, backend: str, dry_run: bool, from_start: bool) -> None:
    stat = path.stat()
    inode = getattr(stat, "st_ino", None)
    if from_start or state.last_inode != inode or state.last_offset > stat.st_size:
        state.last_offset = 0
        state.last_inode = inode

    with path.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(state.last_offset)
        while True:
            line = f.readline()
            if not line:
                break
            process_line(line.rstrip("\n"), state, backend, dry_run)
        state.last_offset = f.tell()
        state.last_inode = inode


def main() -> int:
    parser = argparse.ArgumentParser(description="Bridge Contiki/Cooja IDS log events to the Secure IoT backend")
    parser.add_argument("--file", required=True, help="Contiki/Cooja log file")
    parser.add_argument("--backend", default=DEFAULT_BACKEND, help=f"Event endpoint (default: {DEFAULT_BACKEND})")
    parser.add_argument("--once", action="store_true", help="Process current file contents and exit")
    parser.add_argument("--follow", action="store_true", help="Follow a growing log file")
    parser.add_argument("--dry-run", action="store_true", help="Parse and print events without POSTing")
    parser.add_argument("--from-start", action="store_true", help="Ignore saved offset and process from beginning")
    parser.add_argument("--state", default=None, help="State file; default is <log>.bridge-state.json")
    args = parser.parse_args()

    if not args.once and not args.follow:
        parser.error("choose --once or --follow")

    log_path = Path(args.file).expanduser().resolve()
    if not log_path.is_file():
        print(f"ERROR: log file not found: {log_path}", file=sys.stderr)
        return 2

    state_path = Path(args.state).expanduser() if args.state else Path(str(log_path) + ".bridge-state.json")
    state = load_state(state_path)

    if args.from_start:
        state.last_offset = 0
        state.last_inode = None

    while True:
        process_file(log_path, state, args.backend, args.dry_run, args.from_start)
        save_state(state_path, state)
        if not args.follow:
            break
        args.from_start = False
        time.sleep(0.25)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
