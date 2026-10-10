import re
import csv
import os

LOG_FILES = {
    "Normal": "normal_log.txt",
    "Flooding (No IDS)": "flood_no_ids_log.txt",
    "Flooding + IDS": "flood_ids_log.txt",
}


def time_to_seconds(t):
    """
    Convert Cooja time:
    MM:SS.mmm
    into seconds.
    """
    m, s = t.split(":")
    return int(m) * 60 + float(s)


def parse_log(filename):
    events = []

    pattern = re.compile(
        r"^(\d+:\d+\.\d+)\s+ID:(\d+)\s+\[INFO:\s*([^\]]+)\]\s+(.*)$"
    )

    with open(filename, "r", errors="ignore") as f:
        for line in f:
            match = pattern.match(line.rstrip())

            if not match:
                continue

            timestamp = match.group(1)
            mote = int(match.group(2))
            component = match.group(3).strip()
            message = match.group(4).strip()

            events.append({
                "time": time_to_seconds(timestamp),
                "timestamp": timestamp,
                "mote": mote,
                "component": component,
                "message": message
            })

    return events


def analyze(filename):
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

    # --------------------------------------------------
    # NORMAL TRAFFIC
    # --------------------------------------------------

    tx_count = len(normal_tx)

    rx_count = 0
    missed_count = 0
    latency_values = []

    for e in normal_metrics:
        m = re.search(
            r"tx=(\d+)\s+rx=(\d+)\s+missed=(\d+)",
            e["message"]
        )

        if m:
            rx_count = max(rx_count, int(m.group(2)))
            missed_count = max(missed_count, int(m.group(3)))

    # Search for individual RESPONSE lines if present.
    response_lines = [
        e for e in events
        if "RESPONSE" in e["message"]
    ]

    if response_lines:
        rx_count = max(rx_count, len(response_lines))

    if tx_count > 0:
        pdr = (rx_count / tx_count) * 100
    else:
        pdr = 0

    # --------------------------------------------------
    # FLOOD TRAFFIC
    # --------------------------------------------------

    flood_count = len(flood_tx)

    if len(flood_tx) >= 2:
        start = flood_tx[0]["time"]
        end = flood_tx[-1]["time"]

        duration = end - start

        if duration > 0:
            flood_rate = (flood_count - 1) / duration
        else:
            flood_rate = 0
    else:
        flood_rate = 0

    # Maximum number of flood packets inside any 1-second window.
    max_rate = 0

    flood_times = [e["time"] for e in flood_tx]

    for start in flood_times:
        count = sum(
            1 for t in flood_times
            if start <= t < start + 1
        )

        max_rate = max(max_rate, count)

    # --------------------------------------------------
    # IDS DETECTION
    # --------------------------------------------------

    detection_time = None

    if flood_tx and ids_alerts:
        first_flood = flood_tx[0]["time"]
        alert_time = ids_alerts[0]["time"]

        detection_time = (alert_time - first_flood) * 1000

    # --------------------------------------------------
    # MITIGATION
    # --------------------------------------------------

    mitigation_time = None

    if ids_alerts and block_received:
        mitigation_time = (
            block_received[0]["time"]
            - ids_alerts[0]["time"]
        ) * 1000

    # --------------------------------------------------
    # OUTPUT
    # --------------------------------------------------

    print()
    print("=" * 65)
    print(filename)
    print("=" * 65)

    print("Parsed events       :", len(events))
    print("Normal TX           :", tx_count)
    print("Normal RX           :", rx_count)
    print("Normal missed       :", missed_count)
    print("PDR (%)             :", f"{pdr:.2f}")

    print("Flood packets       :", flood_count)
    print("Average flood rate  :", f"{flood_rate:.2f}", "packets/sec")
    print("Maximum flood rate  :", max_rate, "packets/sec")

    print("IDS alerts          :", len(ids_alerts))
    print("IDS drops           :", len(ids_drops))

    if detection_time is not None:
        print("Detection time      :", f"{detection_time:.2f}", "ms")
    else:
        print("Detection time      : N/A")

    print("BLOCK received      :", len(block_received))
    print("Attacker stopped    :", len(attacker_stopped))

    if mitigation_time is not None:
        print("Mitigation time     :", f"{mitigation_time:.2f}", "ms")
    else:
        print("Mitigation time     : N/A")

    return {
        "scenario": None,
        "tx": tx_count,
        "rx": rx_count,
        "pdr_percent": pdr,
        "avg_latency_ms": 0,
        "flood_packets": flood_count,
        "flood_rate": flood_rate,
        "detection_time": detection_time,
        "mitigation_time": mitigation_time,
        "ids_drops": len(ids_drops),
    }


def main():

    results = []

    for scenario, filename in LOG_FILES.items():

        if not os.path.exists(filename):
            print("WARNING:", filename, "not found")
            continue

        result = analyze(filename)
        result["scenario"] = scenario
        results.append(result)

    # --------------------------------------------------
    # SAVE CSV
    # --------------------------------------------------

    with open("results_summary.csv", "w", newline="") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=[
                "scenario",
                "tx",
                "rx",
                "pdr_percent",
                "avg_latency_ms",
                "flood_packets",
                "flood_rate",
                "detection_time",
                "mitigation_time",
                "ids_drops"
            ]
        )

        writer.writeheader()
        writer.writerows(results)

    print()
    print("CSV saved to:", os.path.abspath("results_summary.csv"))

    # --------------------------------------------------
    # GRAPHS
    # --------------------------------------------------

    try:
        import matplotlib.pyplot as plt

        names = [r["scenario"] for r in results]
        pdr = [r["pdr_percent"] for r in results]
        flood = [r["flood_packets"] for r in results]

        # PDR
        plt.figure(figsize=(8, 5))
        plt.bar(names, pdr)
        plt.ylabel("Packet Delivery Ratio (%)")
        plt.title("Packet Delivery Ratio Comparison")
        plt.ylim(0, 100)
        plt.tight_layout()
        plt.savefig("pdr_comparison.png", dpi=200)
        plt.close()

        # Flood packets
        plt.figure(figsize=(8, 5))
        plt.bar(names, flood)
        plt.ylabel("Flood Packets")
        plt.title("Flooding Traffic Comparison")
        plt.tight_layout()
        plt.savefig("flood_packets_comparison.png", dpi=200)
        plt.close()

        # IDS response
        ids = [
            r for r in results
            if r["scenario"] == "Flooding + IDS"
        ]

        if ids:

            r = ids[0]

            labels = ["Detection", "Mitigation"]
            values = [
                r["detection_time"] or 0,
                r["mitigation_time"] or 0
            ]

            plt.figure(figsize=(8, 5))
            plt.bar(labels, values)
            plt.ylabel("Time (ms)")
            plt.title("IDS Detection and Mitigation Response")
            plt.tight_layout()
            plt.savefig("ids_response_time.png", dpi=200)
            plt.close()

        print("Graphs generated:")
        print("  pdr_comparison.png")
        print("  flood_packets_comparison.png")
        print("  ids_response_time.png")

    except ImportError:
        print("matplotlib is not installed; graphs skipped.")


if __name__ == "__main__":
    main()
