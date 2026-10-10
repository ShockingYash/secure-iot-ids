import re
import csv
import os

LOG_FILES = {
    "Normal": "normal_log.txt",
    "Flooding (No IDS)": "flood_no_ids_log.txt",
    "Flooding + IDS": "flood_ids_log.txt",
    "Sinkhole (No IDS)": "sinkhole_no_ids_log.txt",
    "Sinkhole + IDS": "sinkhole_fast_ids_final_log.txt",
}

ROUTING_LOG = "sinkhole_routing_diag_log.txt"


def time_to_seconds(t):
    m, s = t.split(":")
    return int(m) * 60 + float(s)


def parse_log(filename):
    events = []

    # Accept INFO, WARN, ERROR, etc.
    pattern = re.compile(
        r"^(\d+:\d+\.\d+)\s+ID:(\d+)\s+\[([^\]]+)\]\s+(.*)$"
    )

    with open(filename, "r", errors="ignore") as f:
        for line in f:
            match = pattern.match(line.rstrip())

            if not match:
                continue

            timestamp = match.group(1)
            mote = int(match.group(2))
            level_component = match.group(3).strip()
            message = match.group(4).strip()

            if ":" in level_component:
                level, component = level_component.split(":", 1)
                level = level.strip()
                component = component.strip()
            else:
                level = ""
                component = level_component

            events.append({
                "time": time_to_seconds(timestamp),
                "timestamp": timestamp,
                "mote": mote,
                "level": level,
                "component": component,
                "message": message,
            })

    return events


def response_latencies(events):
    values = []

    pattern = re.compile(r"latency_ms=(\d+)")

    for e in events:
        if "RESPONSE" in e["message"]:
            match = pattern.search(e["message"])
            if match:
                values.append(float(match.group(1)))

    return values


def analyze_normal_flood(filename):
    events = parse_log(filename)

    normal_tx = []
    normal_metrics = []
    flood_tx = []
    ids_alerts = []
    ids_drops = []
    block_received = []
    attacker_stopped = []

    for e in events:
        msg = e["message"]

        if msg.startswith("NORMAL TX"):
            normal_tx.append(e)

        elif msg.startswith("NORMAL METRIC"):
            normal_metrics.append(e)

        elif msg.startswith("FLOOD TX"):
            flood_tx.append(e)

        elif "IDS ALERT: FLOODING DETECTED" in msg:
            ids_alerts.append(e)

        elif msg.startswith("IDS DROP"):
            ids_drops.append(e)

        elif "MITIGATION: BLOCK received" in msg:
            block_received.append(e)

        elif "MITIGATION: attacker stopped" in msg:
            attacker_stopped.append(e)

    tx_count = len(normal_tx)

    rx_count = 0
    missed_count = 0

    for e in normal_metrics:
        m = re.search(
            r"tx=(\d+)\s+rx=(\d+)\s+missed=(\d+)",
            e["message"]
        )

        if m:
            rx_count = max(rx_count, int(m.group(2)))
            missed_count = max(missed_count, int(m.group(3)))

    responses = [
        e for e in events
        if "RESPONSE" in e["message"]
    ]

    if responses:
        rx_count = max(rx_count, len(responses))

    pdr = (rx_count / tx_count * 100) if tx_count else 0

    latencies = response_latencies(events)
    avg_latency = sum(latencies) / len(latencies) if latencies else None

    flood_count = len(flood_tx)

    if len(flood_tx) >= 2:
        start = flood_tx[0]["time"]
        end = flood_tx[-1]["time"]
        duration = end - start

        flood_rate = (
            (flood_count - 1) / duration
            if duration > 0 else 0
        )
    else:
        flood_rate = 0

    max_rate = 0
    flood_times = [e["time"] for e in flood_tx]

    for start in flood_times:
        count = sum(
            1 for t in flood_times
            if start <= t < start + 1
        )
        max_rate = max(max_rate, count)

    detection_time = None

    if flood_tx and ids_alerts:
        detection_time = (
            ids_alerts[0]["time"] - flood_tx[0]["time"]
        ) * 1000

    mitigation_time = None

    if ids_alerts and block_received:
        mitigation_time = (
            block_received[0]["time"] - ids_alerts[0]["time"]
        ) * 1000

    return {
        "scenario": None,
        "attack_type": "Flooding",
        "tx": tx_count,
        "rx": rx_count,
        "pdr_percent": pdr,
        "avg_latency_ms": avg_latency or 0,
        "flood_packets": flood_count,
        "flood_rate": flood_rate,
        "max_flood_rate": max_rate,
        "sinkhole_dio_packets": 0,
        "attack_duration_s": 0,
        "ids_alerts": len(ids_alerts),
        "ids_drops": len(ids_drops),
        "detection_time_ms": detection_time,
        "block_time_ms": (
            mitigation_time
            if mitigation_time is not None else 0
        ),
        "attacker_stop_time_ms": 0,
        "mitigation_time_ms": mitigation_time,
        "sinkhole_parent_observations": 0,
        "sinkhole_parent_nodes": 0,
    }


def analyze_sinkhole(filename):
    events = parse_log(filename)

    normal_tx = [
        e for e in events
        if e["message"].startswith("NORMAL TX")
    ]

    normal_metrics = [
        e for e in events
        if e["message"].startswith("NORMAL METRIC")
    ]

    dio = [
        e for e in events
        if "SINKHOLE DIO SENT" in e["message"]
    ]

    attack_active = [
        e for e in events
        if "SINKHOLE ATTACK ACTIVE" in e["message"]
    ]

    alerts = [
        e for e in events
        if "IDS ALERT: SINKHOLE DETECTED" in e["message"]
    ]

    block_sent = [
        e for e in events
        if "IDS ACTION: BLOCK sent" in e["message"]
    ]

    block_received = [
        e for e in events
        if "MITIGATION: BLOCK received" in e["message"]
    ]

    stopped = [
        e for e in events
        if "SINKHOLE ATTACK STOPPED" in e["message"]
    ]

    tx_count = len(normal_tx)

    rx_count = 0
    missed_count = 0

    for e in normal_metrics:
        m = re.search(
            r"tx=(\d+)\s+rx=(\d+)\s+missed=(\d+)",
            e["message"]
        )

        if m:
            rx_count = max(rx_count, int(m.group(2)))
            missed_count = max(missed_count, int(m.group(3)))

    responses = [
        e for e in events
        if "RESPONSE" in e["message"]
    ]

    if responses:
        rx_count = max(rx_count, len(responses))

    pdr = (rx_count / tx_count * 100) if tx_count else 0

    latencies = response_latencies(events)
    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    detection_time = None
    block_delay = None
    stop_delay = None
    attack_duration = 0

    if attack_active:
        attack_start = attack_active[0]["time"]

        if alerts:
            detection_time = (
                alerts[0]["time"] - attack_start
            ) * 1000

        if stopped:
            attack_duration = (
                stopped[-1]["time"] - attack_start
            )
        elif dio:
            attack_duration = (
                dio[-1]["time"] - attack_start
            )

        if alerts and block_received:
            block_delay = (
                block_received[0]["time"]
                - alerts[0]["time"]
            ) * 1000

        if alerts and stopped:
            stop_delay = (
                stopped[0]["time"]
                - alerts[0]["time"]
            ) * 1000

    return {
        "scenario": None,
        "attack_type": "Sinkhole",
        "tx": tx_count,
        "rx": rx_count,
        "pdr_percent": pdr,
        "avg_latency_ms": avg_latency,
        "flood_packets": 0,
        "flood_rate": 0,
        "max_flood_rate": 0,
        "sinkhole_dio_packets": len(dio),
        "attack_duration_s": attack_duration,
        "ids_alerts": len(alerts),
        "ids_drops": 0,
        "detection_time_ms": detection_time,
        "block_time_ms": block_delay,
        "attacker_stop_time_ms": stop_delay,
        "mitigation_time_ms": block_delay,
        "sinkhole_parent_observations": 0,
        "sinkhole_parent_nodes": 0,
    }


def analyze_routing_log(filename):
    if not os.path.exists(filename):
        return {
            "parent_observations": 0,
            "parent_nodes": 0,
            "first_parent_time": None,
            "last_parent_time": None,
            "parent_duration_s": 0,
            "rank": None,
        }

    events = parse_log(filename)

    sinkhole_ip = "fe80::205:5:5:5"

    matches = [
        e for e in events
        if f"RPL PARENT: {sinkhole_ip}" in e["message"]
    ]

    nodes = sorted(set(e["mote"] for e in matches))

    ranks = []

    for e in matches:
        m = re.search(r"rank=(\d+)", e["message"])
        if m:
            ranks.append(int(m.group(1)))

    first_time = matches[0]["time"] if matches else None
    last_time = matches[-1]["time"] if matches else None

    duration = (
        last_time - first_time
        if first_time is not None and last_time is not None
        else 0
    )

    return {
        "parent_observations": len(matches),
        "parent_nodes": len(nodes),
        "first_parent_time": first_time,
        "last_parent_time": last_time,
        "parent_duration_s": duration,
        "rank": ranks[0] if ranks else None,
    }


def print_flood_result(filename, result):
    print()
    print("=" * 65)
    print(filename)
    print("=" * 65)

    print("Normal TX           :", result["tx"])
    print("Normal RX           :", result["rx"])
    print("PDR (%)             :", f'{result["pdr_percent"]:.2f}')
    print("Average latency     :", f'{result["avg_latency_ms"]:.2f}', "ms")
    print("Flood packets       :", result["flood_packets"])
    print("Average flood rate  :", f'{result["flood_rate"]:.2f}', "packets/sec")
    print("Maximum flood rate  :", result["max_flood_rate"], "packets/sec")
    print("IDS alerts          :", result["ids_alerts"])
    print("IDS drops           :", result["ids_drops"])

    if result["detection_time_ms"] is not None:
        print("Detection time      :", f'{result["detection_time_ms"]:.2f}', "ms")
    else:
        print("Detection time      : N/A")

    if result["mitigation_time_ms"] is not None:
        print("Mitigation time     :", f'{result["mitigation_time_ms"]:.2f}', "ms")
    else:
        print("Mitigation time     : N/A")


def print_sinkhole_result(filename, result):
    print()
    print("=" * 65)
    print(filename)
    print("=" * 65)

    print("Normal TX           :", result["tx"])
    print("Normal RX           :", result["rx"])
    print("PDR (%)             :", f'{result["pdr_percent"]:.2f}')
    print("Average latency     :", f'{result["avg_latency_ms"]:.2f}', "ms")
    print("Sinkhole DIO packets:", result["sinkhole_dio_packets"])
    print("Attack duration     :", f'{result["attack_duration_s"]:.3f}', "sec")
    print("IDS alerts          :", result["ids_alerts"])

    if result["detection_time_ms"] is not None:
        print("Detection time      :", f'{result["detection_time_ms"]:.2f}', "ms")
    else:
        print("Detection time      : N/A")

    if result["block_time_ms"] is not None:
        print("Alert -> BLOCK recv :", f'{result["block_time_ms"]:.2f}', "ms")
    else:
        print("Alert -> BLOCK recv : N/A")

    if result["attacker_stop_time_ms"]:
        print(
            "Alert -> attack stop:",
            f'{result["attacker_stop_time_ms"]:.2f}',
            "ms"
        )
    else:
        print("Alert -> attack stop: N/A")


def main():
    results = []

    for scenario, filename in LOG_FILES.items():

        if not os.path.exists(filename):
            print("WARNING:", filename, "not found")
            continue

        if "Sinkhole" in scenario:
            result = analyze_sinkhole(filename)
            print_sinkhole_result(filename, result)
        else:
            result = analyze_normal_flood(filename)
            print_flood_result(filename, result)

        result["scenario"] = scenario
        results.append(result)

    routing = analyze_routing_log(ROUTING_LOG)

    for result in results:
        if result["attack_type"] == "Sinkhole":
            result["sinkhole_parent_observations"] = routing[
                "parent_observations"
            ]
            result["sinkhole_parent_nodes"] = routing[
                "parent_nodes"
            ]

    with open("results_summary.csv", "w", newline="") as f:
        fieldnames = [
            "scenario",
            "attack_type",
            "tx",
            "rx",
            "pdr_percent",
            "avg_latency_ms",
            "flood_packets",
            "flood_rate",
            "max_flood_rate",
            "sinkhole_dio_packets",
            "attack_duration_s",
            "ids_alerts",
            "ids_drops",
            "detection_time_ms",
            "block_time_ms",
            "attacker_stop_time_ms",
            "mitigation_time_ms",
            "sinkhole_parent_observations",
            "sinkhole_parent_nodes",
        ]

        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print()
    print("=" * 65)
    print("SINKHOLE ROUTING DIAGNOSTIC")
    print("=" * 65)
    print("Preferred-parent observations:", routing["parent_observations"])
    print("Normal nodes attracted       :", routing["parent_nodes"])

    if routing["first_parent_time"] is not None:
        print(
            "First sinkhole-parent time   :",
            f'{routing["first_parent_time"]:.3f}',
            "s"
        )
        print(
            "Last sinkhole-parent time    :",
            f'{routing["last_parent_time"]:.3f}',
            "s"
        )
        print(
            "Parent persistence           :",
            f'{routing["parent_duration_s"]:.3f}',
            "s"
        )
        print(
            "Advertised sinkhole rank    :",
            routing["rank"]
        )

    print()
    print("CSV saved to:", os.path.abspath("results_summary.csv"))

    # --------------------------------------------------
    # GRAPHS
    # --------------------------------------------------

    try:
        import matplotlib.pyplot as plt

        names = [r["scenario"] for r in results]
        pdr = [r["pdr_percent"] for r in results]

        # PDR
        plt.figure(figsize=(10, 5))
        plt.bar(names, pdr)
        plt.ylabel("Packet Delivery Ratio (%)")
        plt.title("Packet Delivery Ratio Comparison")
        plt.ylim(0, 100)
        plt.xticks(rotation=20, ha="right")
        plt.tight_layout()
        plt.savefig("pdr_comparison.png", dpi=200)
        plt.close()

        # Flood packets
        flood_results = [
            r for r in results
            if r["attack_type"] == "Flooding"
        ]

        if flood_results:
            flood_names = [r["scenario"] for r in flood_results]
            flood_values = [r["flood_packets"] for r in flood_results]

            plt.figure(figsize=(8, 5))
            plt.bar(flood_names, flood_values)
            plt.ylabel("Flood Packets")
            plt.title("Flooding Traffic Comparison")
            plt.xticks(rotation=15, ha="right")
            plt.tight_layout()
            plt.savefig("flood_packets_comparison.png", dpi=200)
            plt.close()

        # Sinkhole DIO count
        sink_results = [
            r for r in results
            if r["attack_type"] == "Sinkhole"
        ]

        if sink_results:
            sink_names = [r["scenario"] for r in sink_results]
            sink_dios = [r["sinkhole_dio_packets"] for r in sink_results]

            plt.figure(figsize=(8, 5))
            plt.bar(sink_names, sink_dios)
            plt.ylabel("Malicious DIO Advertisements")
            plt.title("Sinkhole Attack Activity Comparison")
            plt.xticks(rotation=15, ha="right")
            plt.tight_layout()
            plt.savefig("sinkhole_dio_comparison.png", dpi=200)
            plt.close()

        # Flooding IDS response
        flood_ids = [
            r for r in results
            if r["scenario"] == "Flooding + IDS"
        ]

        if flood_ids:
            r = flood_ids[0]

            labels = ["Detection", "Mitigation"]
            values = [
                r["detection_time_ms"] or 0,
                r["mitigation_time_ms"] or 0
            ]

            plt.figure(figsize=(8, 5))
            plt.bar(labels, values)
            plt.ylabel("Time (ms)")
            plt.title("Flooding IDS Detection and Mitigation")
            plt.tight_layout()
            plt.savefig("ids_response_time.png", dpi=200)
            plt.close()

        # Sinkhole IDS response
        sink_ids = [
            r for r in results
            if r["scenario"] == "Sinkhole + IDS"
        ]

        if sink_ids:
            r = sink_ids[0]

            labels = [
                "Detection",
                "Alert → BLOCK",
                "Alert → Stop"
            ]

            values = [
                r["detection_time_ms"] or 0,
                r["block_time_ms"] or 0,
                r["attacker_stop_time_ms"] or 0
            ]

            plt.figure(figsize=(8, 5))
            plt.bar(labels, values)
            plt.ylabel("Time (ms)")
            plt.title("Sinkhole IDS Detection and Mitigation")
            plt.tight_layout()
            plt.savefig("sinkhole_response_time.png", dpi=200)
            plt.close()

        print("Graphs generated successfully.")

    except ImportError:
        print("matplotlib is not installed; graphs skipped.")


if __name__ == "__main__":
    main()
