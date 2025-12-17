import os
import re
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from glob import glob
from scapy.all import rdpcap, TCP, UDP
import pyshark
import tqdm 

# =========================================
# DIRECTORY CONFIG
# =========================================

BASE_DIR = "./"
CSV_DIR = os.path.join(BASE_DIR, "csvs")
PCAP_DIR = os.path.join(BASE_DIR, "pcaps")
QLOG_DIR = os.path.join(BASE_DIR, "qlogs")
OUT_DIR = os.path.join(BASE_DIR, "plots")

os.makedirs(OUT_DIR, exist_ok=True)

BANDWIDTH_MAP = {
    "10mbps": 10e6,
    "50mbps": 50e6,
    "100mbps": 100e6
}

# =========================================
# FILENAME PARSER
# =========================================

def parse_pcap_filename(fname):
    base = os.path.basename(fname).replace(".pcap", "")
    parts = base.split("-")
    return parts[0], parts[1], parts[2], parts[3]

# =========================================
# TCP HTTP THROUGHPUT
# =========================================
from scapy.all import rdpcap, TCP, IP, Raw

def get_http_flow(pcap_file):
    packets = rdpcap(pcap_file)

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw].load)

                # ✅ Loose match (handles fragmentation)
                if b"GET" in payload or b"HTTP/1." in payload:
                    ip = pkt[IP]
                    tcp = pkt[TCP]

                    flow = (
                        ip.src,
                        ip.dst,
                        tcp.sport,
                        tcp.dport
                    )

                    print("✅ HTTP flow detected:", flow)
                    return flow

            except Exception as e:
                pass

    print("❌ No HTTP flow detected by Scapy")
    return None

def extract_flow_packets(pcap_file, flow):
    packets = rdpcap(pcap_file)
    flow_pkts = []

    c_ip, s_ip, c_port, s_port = flow

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            ip = pkt[IP]
            tcp = pkt[TCP]

            # ✅ Match BOTH directions
            if (
                (ip.src == c_ip and ip.dst == s_ip ) or
                (ip.src == s_ip and ip.dst == c_ip )
            ):
                flow_pkts.append(pkt)

    print("✅ Total packets in TCP flow:", len(flow_pkts))
    return flow_pkts

from scapy.all import TCP, Raw

def compute_tcp_throughput(flow_pkts):
    data_pkts = []
    all_pkts = []

    for pkt in flow_pkts:
        if pkt.haslayer(TCP):
            all_pkts.append(pkt)

            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                if len(payload) > 0:   # exclude pure ACKs for goodput
                    data_pkts.append(pkt)

    if len(all_pkts) < 2:
        print("⚠️ Not enough TCP packets in flow.")
        return 0, 0

    times = [float(pkt.time) for pkt in all_pkts]
    duration = max(times) - min(times)

    print("✅ TCP flow duration (s):", duration)
    print("Max time:", max(times))
    print("Min time:", min(times))

    if duration <= 0:
        return 0, 0

    # ✅ Throughput = FULL packet sizes (link-level)
    tcp_total_bytes = sum(len(pkt) for pkt in all_pkts)
    print("✅ TCP total bytes (all packets):", tcp_total_bytes)
    tcp_throughput = (tcp_total_bytes * 8.0) / duration / 1e6  # Mbps

    # ✅ Goodput = PAYLOAD ONLY
    tcp_payload_bytes = sum(len(bytes(pkt[Raw].load)) for pkt in data_pkts)
    tcp_goodput = (tcp_payload_bytes * 8.0) / duration / 1e6  # Mbps

    return tcp_throughput, tcp_goodput



# =========================================
# QUIC THROUGHPUT
# =========================================
def compute_quic_throughput(pcap_file):
    packets = rdpcap(pcap_file)

    quic_all_pkts = []
    quic_data_pkts = []

    for pkt in packets:
        if pkt.haslayer(UDP):
            quic_all_pkts.append(pkt)

            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                if len(payload) > 0:
                    quic_data_pkts.append(pkt)

    if len(quic_all_pkts) < 2:
        print("⚠️ Not enough QUIC packets found.")
        return 0, 0

    times = [float(pkt.time) for pkt in quic_all_pkts]
    duration = max(times) - min(times)

    if duration <= 0:
        return 0, 0

    # ✅ Throughput = FULL packet sizes (link-level)
    quic_total_bytes = sum(len(pkt) for pkt in quic_all_pkts)
    quic_throughput = (quic_total_bytes * 8.0) / duration / 1e6  # Mbps

    # ✅ Goodput = PAYLOAD ONLY
    quic_payload_bytes = sum(len(bytes(pkt[Raw].load)) for pkt in quic_data_pkts)
    quic_goodput = (quic_payload_bytes * 8.0) / duration / 1e6  # Mbps

    return quic_throughput, quic_goodput


# =========================================
# LOAD ALL PCAP DATA
# =========================================

DF_TPUT_PATH = os.path.join(OUT_DIR, "df_throughput_cache.csv")

if os.path.exists(DF_TPUT_PATH):
    print("✅ Loading cached throughput DataFrame...")
    df_tput = pd.read_csv(DF_TPUT_PATH)
else:
    print("⚠️ Cache not found — computing throughput from PCAPs...")

    pcap_files = glob(os.path.join(PCAP_DIR, "*.pcap"))
    throughput_data = []

    for f in tqdm.tqdm(pcap_files):
        proto, medium, cc, bw = parse_pcap_filename(f)

        if proto == "tcp":
            flow = get_http_flow(f)
            flow_pkts = extract_flow_packets(f, flow)
            tput, gput = compute_tcp_throughput(flow_pkts)

            print(f"✅ [{f}] TCP Flow Throughput: {tput:.3f} Mbps")

        else:
            tput, gput = compute_quic_throughput(f)
            print(f"✅ [{f}] QUIC Throughput: {tput:.3f} Mbps")

        throughput_data.append({
            "protocol": proto.upper(),
            "medium": medium,
            "cc": cc.upper(),
            "bandwidth": bw,
            "throughput": tput,
            "goodput": gput
        })


    df_tput = pd.DataFrame(throughput_data)

    # ✅ Save for future runs
    df_tput.to_csv(DF_TPUT_PATH, index=False)
    print(f"✅ Throughput DataFrame cached at: {DF_TPUT_PATH}")




# =========================================
# ✅ ✅ ✅ FIG 1 — THROUGHPUT vs BANDWIDTH (FIXED)
# =========================================

BW_ORDER = ["10mbps", "50mbps", "100mbps"]

for medium in ["wired", "cellular"]:
    df_sub = df_tput[df_tput["medium"] == medium]

    plt.figure()

    for key in df_sub.groupby(["protocol", "cc"]).groups:
        proto, cc = key
        print("✅ Plotting:", proto, cc, "on", medium)
        temp = df_sub[(df_sub["protocol"] == proto) & (df_sub["cc"] == cc)]

        y = []
        for bw in BW_ORDER:
            vals = temp[temp["bandwidth"] == bw]["throughput"]
            y.append(vals.mean() if len(vals) > 0 else 0)

        plt.plot(BW_ORDER, y, marker='o', label=f"{proto}-{cc}")

    plt.ylabel("Throughput (Mbps)")
    plt.xlabel("Bandwidth")
    plt.title(f"Throughput vs Bandwidth ({medium})")
    plt.legend()
    plt.grid(True)
    plt.savefig(f"{OUT_DIR}/fig1_throughput_{medium}.png")
    plt.close()


# =========================================
# FIG 2 — GOODPUT vs THROUGHPUT
# =========================================

df_bar = (
    df_tput
    .groupby(["protocol", "cc"])[["throughput", "goodput"]]
    .mean()
    .reset_index()
)

# Create combined label like: QUIC-bbr, TCP-cubic, etc.
df_bar["label"] = df_bar["protocol"] + "-" + df_bar["cc"]

df_bar.set_index("label")[["throughput", "goodput"]].plot(kind="bar")

plt.ylabel("Mbps")
plt.title("Throughput vs Goodput (Protocol + CC)")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig2_goodput_vs_throughput.png")
plt.close()

# =========================================
# QUEUE DELAY FROM CSV
# =========================================

csv_files = glob(os.path.join(CSV_DIR, "*.csv"))
queue_results = []

csv_files = glob(os.path.join(CSV_DIR, "*.csv"))
queue_results = []

for f in csv_files:
    base = os.path.basename(f)

    # match: tcp-wired-bbr-10mbps-queue.csv
    m = re.match(r"(tcp|quic)-(wired|cellular)-(bbr|cubic)-(10|50|100)mbps", base)
    if not m:
        print(f"⚠️ Skipping CSV with unexpected name: {base}")
        continue

    proto, medium, cc, bw = m.groups()
    bw_key = f"{bw}mbps"
    bw_val = BANDWIDTH_MAP[bw_key]

    df = pd.read_csv(f)

    df["bytes"] = df["QDisc-Backlog-Bytes"].str.replace("p", "").astype(float)
    df["delay_ms"] = (df["bytes"] * 1500 / bw_val) * 1000

    queue_results.append({
        "file": base,
        "protocol": proto.upper(),
        "medium": medium,
        "cc": cc.upper(),
        "bandwidth": bw_key,
        "mean_delay": df["delay_ms"].mean(),
        "p95_delay": df["delay_ms"].quantile(0.95)
    })

df_q = pd.DataFrame(queue_results)

# =========================================
# FIG 3 — QUEUE BACKLOG vs TIME
# =========================================

BW_ORDER = ["10mbps", "50mbps", "100mbps"]
# Plot: mean queue delay vs bandwidth, split by TCP / QUIC / CC / medium

plt.figure()

for medium in ["wired", "cellular"]:
    sub = df_q[df_q["medium"] == medium]

    for (proto, cc), group in sub.groupby(["protocol", "cc"]):
        ys = []
        for bw in BW_ORDER:
            vals = group[group["bandwidth"] == bw]["mean_delay"]
            ys.append(vals.mean() if len(vals) > 0 else 0)

        plt.plot(
            BW_ORDER,
            ys,
            marker="o",
            label=f"{proto}-{cc}-{medium}"
        )

plt.ylabel("Mean Queue Delay (ms)")
plt.xlabel("Bandwidth")
plt.title("Mean Queue Delay vs Bandwidth ")
plt.legend()
plt.grid(True)
plt.tight_layout()

plt.savefig(f"{OUT_DIR}/fig3_queue_delay_vs_bw_merged.png")
plt.close()
# Per-bandwidth bar chart: TCP vs QUIC + CC + medium

# Create a combined label for grouping
df_q["group"] = (
    df_q["protocol"] + "-" +
    df_q["cc"] + "-" +
    df_q["medium"]
)

# Pivot so each bandwidth becomes a bar in the same group
pivot = df_q.pivot_table(
    index="group",
    columns="bandwidth",
    values="mean_delay",
    aggfunc="mean"
).reindex(columns=BW_ORDER)

# Plot grouped bar chart
plt.figure(figsize=(12, 6))
pivot.plot(kind="bar", width=0.8)

plt.ylabel("Mean Queue Delay (ms)")
plt.xlabel("Protocol - CC - Medium")
plt.title("Queue Delay Comparison")
plt.xticks(rotation=45, ha="right")
plt.legend(title="Bandwidth")
plt.grid(axis="y", linestyle="--", alpha=0.4)
plt.tight_layout()

plt.savefig(f"{OUT_DIR}/fig3_queue_delay_merged_all_bw.png")
plt.close()

if len(csv_files) == 0:
    print("⚠️ No CSV files found — skipping queue time plot.")
else:
    example = pd.read_csv(csv_files[0])
    plt.plot(example["QDisc-Backlog-Bytes"])
    plt.title("Queue Backlog vs Time")
    plt.ylabel("Bytes")
    plt.xlabel("Sample Index")
    plt.savefig(f"{OUT_DIR}/fig3_queue_time.png")
    plt.close()
# =========================================
# FIG 4 — MEAN QUEUE DELAY vs BANDWIDTH
# =========================================

df_q.groupby("bandwidth")["mean_delay"].mean().plot(kind="bar")
plt.ylabel("Mean Queue Delay (ms)")
plt.title("Mean Queue Delay vs Bandwidth")
plt.savefig(f"{OUT_DIR}/fig4_queue_delay_vs_bw.png")
plt.close()

# =========================================
# QUIC FCT FROM QLOG
# =========================================
def extract_fct_from_qlog(f):
    """
    Extract FCT from ns-3 QLOG (JSON-SEQ format).
    FCT = last transport:packet_received time
          - first transport:packet_sent time
    """
    try:
        start = None
        end = None

        with open(f, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                line = line.strip()

                # Skip JSON-SEQ separators and empty lines
                if not line or line.startswith("\x1e"):
                    line = line.lstrip("\x1e").strip()
                    if not line:
                        continue

                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # ✅ Case 1: This line IS an event object
                if "name" in obj and "time" in obj:
                    name = obj["name"]
                    t = obj["time"]

                    if name == "transport:packet_sent" and start is None:
                        start = t

                    elif name == "transport:packet_received":
                        end = t

                # ✅ Case 2: This line contains a trace wrapper
                elif "trace" in obj:
                    continue

        if start is None or end is None:
            print(f"⚠️ No valid FCT in: {f}")
            return None

        fct = end - start

        # ✅ Your times are already in seconds (no μs scaling needed)
        return fct

    except Exception as e:
        print(f"⚠️ QLOG FCT parse failed: {f} ({e})")
        return None




qlog_files = glob(os.path.join(QLOG_DIR, "*.qlog"))
fcts = []

for f in qlog_files:
    val = extract_fct_from_qlog(f)
    if val is not None:
        fcts.append(val)

# =========================================
# FIG 5 — FCT CDF
# =========================================

fcts_sorted = np.sort(fcts)
cdf = np.arange(len(fcts_sorted)) / len(fcts_sorted)

plt.plot(fcts_sorted, cdf)
plt.xlabel("FCT (s)")
plt.ylabel("CDF")
plt.title("QUIC Flow Completion Time")
plt.savefig(f"{OUT_DIR}/fig5_fct_cdf.png")
plt.close()

fct_records = []

qlog_files = glob(os.path.join(QLOG_DIR, "*.qlog"))

for f in qlog_files:
    base = os.path.basename(f)

    # ✅ Parse scenario from filename:
    # quic-cellular-bbr-100mbps.qlog
    m = re.match(r"quic-(wired|cellular)-(bbr|cubic)-(10|50|100)mbps", base)
    if not m:
        print(f"⚠️ Skipping QLOG with unexpected name: {base}")
        continue

    medium, cc, bw = m.groups()
    bw = f"{bw}mbps"

    fct = extract_fct_from_qlog(f)


    fct_records.append({
        "medium": medium,
        "cc": cc.upper(),
        "bandwidth": bw,
        "fct": fct
    })

df_fct = pd.DataFrame(fct_records)
print(df_fct)

BW_ORDER = ["10mbps", "50mbps", "100mbps"]

# Create combined group label: MEDIUM-CC
df_fct["group"] = df_fct["medium"].str.upper() + "-" + df_fct["cc"]

# Pivot so bandwidth becomes bar groups
pivot = df_fct.pivot_table(
    index="group",
    columns="bandwidth",
    values="fct",
    aggfunc="mean"
).reindex(columns=BW_ORDER)

# Plot grouped bar chart
plt.figure(figsize=(12, 6))
pivot.plot(kind="bar", width=0.8)

plt.ylabel("Flow Completion Time (ms)")
plt.xlabel("Medium - Congestion Control")
plt.title("QUIC Mean Flow Completion Time vs Bandwidth (Wired + Cellular)")
plt.xticks(rotation=0)
plt.legend(title="Bandwidth")
plt.grid(axis="y", linestyle="--", alpha=0.4)
plt.tight_layout()

plt.savefig(f"{OUT_DIR}/fig5_mean_fct_bar_merged.png")
plt.close()



# =========================================
# FIG 6 — MEAN FCT vs BANDWIDTH
# =========================================

fct_by_bw = {}
for f in qlog_files:
    m = re.search(r"(10|50|100)mbps", f)
    if not m:
        continue
    bw = m.group(0)
    val = extract_fct_from_qlog(f)
    if val:
        fct_by_bw.setdefault(bw, []).append(val)

keys = sorted(fct_by_bw.keys())
means = [np.mean(fct_by_bw[k]) for k in keys]

plt.bar(keys, means)
plt.ylabel("Mean FCT (s)")
plt.title("Mean FCT vs Bandwidth (QUIC)")
plt.savefig(f"{OUT_DIR}/fig6_mean_fct_vs_bw.png")
plt.close()

# =========================================
# FIG 7 — WIRED vs CELLULAR LOSS
# =========================================


# Group by protocol, CC, and medium
loss_cc = (
    df_tput
    .groupby(["protocol", "cc", "medium"])["throughput"]
    .mean()
    .reset_index()
)

# Pivot so wired/cellular are columns
loss_cc = loss_cc.pivot_table(
    index=["protocol", "cc"],
    columns="medium",
    values="throughput"
).reset_index()

# ✅ Compute percentage loss per (protocol, CC)
loss_cc["loss_pct"] = (
    (loss_cc["wired"] - loss_cc["cellular"]) / loss_cc["wired"] * 100
)

# ✅ Create clean labels like: QUIC-BBR, TCP-CUBIC
labels = [
    f"{p}-{c}" for p, c in zip(loss_cc["protocol"], loss_cc["cc"])
]

# ✅ Plot
plt.figure(figsize=(8, 5))
plt.bar(labels, loss_cc["loss_pct"])
plt.ylabel("Throughput Loss (%)")
plt.title("Wired → Cellular Throughput Degradation (Per CC)")
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/fig7_cellular_loss_per_cc.png")
plt.close()



# per bw 
# =========================================
# ✅ FIG 7 — WIRED → CELLULAR LOSS PER BANDWIDTH & CC
# =========================================

# BW_ORDER = ["10mbps", "50mbps", "100mbps"]

# # Mean throughput per (protocol, cc, medium, bandwidth)
# loss_bw = (
#     df_tput
#     .groupby(["protocol", "cc", "medium", "bandwidth"])["throughput"]
#     .mean()
#     .reset_index()
# )

# # Pivot wired vs cellular
# loss_bw = loss_bw.pivot_table(
#     index=["protocol", "cc", "bandwidth"],
#     columns="medium",
#     values="throughput"
# ).reset_index()

# # ✅ Compute loss per bandwidth
# loss_bw["loss_pct"] = (
#     (loss_bw["wired"] - loss_bw["cellular"]) / loss_bw["wired"] * 100
# )

# # ✅ Plot bandwidth-separated bars
# plt.figure(figsize=(10, 5))

# x_labels = []
# y_vals = []

# for bw in BW_ORDER:
#     sub = loss_bw[loss_bw["bandwidth"] == bw]

#     for _, row in sub.iterrows():
#         label = f"{row['protocol']}-{row['cc']}-{bw}"
#         x_labels.append(label)
#         y_vals.append(row["loss_pct"])

# plt.bar(x_labels, y_vals)
# plt.xticks(rotation=45, ha="right")
# plt.ylabel("Throughput Loss (%)")
# plt.title("Wired → Cellular Throughput Degradation (Per Bandwidth & CC)")
# plt.grid(axis="y", linestyle="--", alpha=0.6)
# plt.tight_layout()
# plt.savefig(f"{OUT_DIR}/fig7_cellular_loss_per_bw_and_cc.png")
# plt.close()


# =========================================
# FIG 8 — CUBIC vs BBR
# =========================================

df_tput.groupby(["protocol", "cc"])["throughput"].mean().unstack().plot(kind="bar")
plt.ylabel("Mean Throughput (Mbps)")
plt.title("CUBIC vs BBR")
plt.savefig(f"{OUT_DIR}/fig8_cc_comparison.png")
plt.close()

# =========================================
# ✅ ✅ ✅ TCP RTT (ACK-CORRECT, HTTP ONLY)
# =========================================

def extract_tcp_http_rtt(pcap_file):
    cap = pyshark.FileCapture(
        pcap_file,
        display_filter="tcp",
        keep_packets=True
    )

    # ✅ Force full file load
    cap.load_packets()

    print("✅ PyShark loaded:", pcap_file)
    print("✅ Total packets in capture:", len(cap))

    http_methods = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"OPTI", b"PATC")

    sent_times = {}
    rtts = []

    for pkt in tqdm.tqdm(cap):
        try:
            ts = float(pkt.sniff_timestamp)
            seq = int(pkt.tcp.seq)
            ack = int(pkt.tcp.ack)
            payload_len = int(pkt.tcp.len)

            payload = b""

            # ✅ Proper PyShark payload extraction
            if payload_len > 0 and hasattr(pkt.tcp, "payload"):
                payload = bytes.fromhex(pkt.tcp.payload.replace(":", ""))

            # ✅ Detect HTTP request/response
            if (
                (len(payload) >= 4 and payload[:4] in http_methods)
                or b"HTTP" in payload
            ):
                sent_times[seq + payload_len] = ts

            # ✅ RTT via ACK
            if ack in sent_times:
                rtt = ts - sent_times.pop(ack)
                if 0 < rtt < 5:
                    rtts.append(rtt)

        except Exception:
            pass

    cap.close()
    return rtts


from scapy.all import rdpcap, TCP, IP, Raw

def extract_tcp_http_rtt(pcap_file):
    packets = rdpcap(pcap_file)

    print("✅ Scapy loaded:", pcap_file)
    print("✅ Total packets in capture:", len(packets))

    http_methods = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"OPTI", b"PATC")

    sent_times = {}
    rtts = []


    for pkt in packets:
        try:
            if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                continue

            ts = float(pkt.time)
            seq = int(pkt[TCP].seq)
            ack = int(pkt[TCP].ack)

            # ✅ RAW PAYLOAD EXTRACTION
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load
            else:
                payload = b""

            payload_len = len(payload)

            # ✅ HTTP detection
            if (
                payload_len > 0 and
                (
                    (len(payload) >= 4 and payload[:4] in http_methods)
                    or b"HTTP" in payload
                )
            ):
                sent_times[seq + payload_len] = ts

            # ✅ RTT via ACK
            if ack in sent_times:
                rtt = ts - sent_times.pop(ack)
                if 0 < rtt < 5:
                    rtts.append(rtt)

        except Exception:
            pass

    return rtts


# =========================================
# ✅ ✅ ✅ QUIC RTT FROM QLOG (SAFE UNITS)
# =========================================

def extract_quic_rtt_from_qlog(qlog_file):
    rtts = []

    try:
        with open(qlog_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()

                if not line or line.startswith("\x1e"):
                    line = line.lstrip("\x1e").strip()
                    if not line:
                        continue

                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if "name" in obj and obj["name"] == "recovery:metrics_updated":
                    data = obj.get("data", {})
                    if "smoothed_rtt" in data:
                        rtts.append(float(data["smoothed_rtt"]))  # already ms

    except:
        pass

    return rtts



# =========================================
# ✅ ✅ ✅ COLLECT ALL RTT DATA
# =========================================
# To generate df for rtt
# rtt_records = []
# pcap_files = glob(os.path.join(PCAP_DIR, "*.pcap"))

# tcp_pcaps = [f for f in pcap_files if os.path.basename(f).startswith("tcp")]

# for f in tqdm.tqdm(tcp_pcaps):
#     proto, medium, cc, bw = parse_pcap_filename(f)
#     print("✅ Processing TCP RTT for:", f)
#     rtts = extract_tcp_http_rtt(f)

#     for r in rtts:
#         rtt_records.append({
#             "protocol": "TCP",
#             "medium": medium,
#             "cc": cc.upper(),
#             "bandwidth": bw,
#             "rtt": r * 1000
#         })


# q_log_files = glob(os.path.join(QLOG_DIR, "*.qlog"))

# qlog_files = [f for f in q_log_files if os.path.basename(f).startswith("quic")]
# for f in qlog_files:
#     m = re.search(r"(10|50|100)mbps", f)
#     if not m:
#         continue
#     bw = m.group(0)
#     medium = "cellular" if "cellular" in f else "wired"
#     cc = "BBR" if "bbr" in f else "CUBIC"

#     rtts = extract_quic_rtt_from_qlog(f)

#     for r in rtts:
#         rtt_records.append({
#             "protocol": "QUIC",
#             "medium": medium,
#             "cc": cc,
#             "bandwidth": bw,
#             "rtt": r
#         })

rtt_outfile = os.path.join(OUT_DIR, "tcp_http_rtt.csv")

if os.path.exists(rtt_outfile):
    print("✅ Loading cached RTT data from:", rtt_outfile)
    df_rtt = pd.read_csv(rtt_outfile)
else:
    print("✅ No cache found — using freshly computed RTTs")
    df_rtt = pd.DataFrame(rtt_records)

    os.makedirs(OUT_DIR, exist_ok=True)
    df_rtt.to_csv(rtt_outfile, index=False)

    print(f"✅ TCP RTTs saved to: {rtt_outfile}")
    print("✅ Total RTT samples saved:", len(df_rtt))
# FIG 9 — MEAN RTT vs BANDWIDTH
# =========================================

# if not df_rtt.empty:
#     df_rtt.groupby(["protocol", "bandwidth"])["rtt"].mean().unstack().T.plot(kind="bar")
#     plt.ylabel("Mean RTT (ms)")
#     plt.title("Mean RTT vs Bandwidth (TCP vs QUIC)")
#     plt.savefig(f"{OUT_DIR}/fig9_mean_rtt_vs_bw.png")
#     plt.close()

BW_ORDER = ["10mbps", "50mbps", "100mbps"]
CLIP_LIMIT = 300  # ms

for medium in ["wired", "cellular"]:

    df_sub = df_rtt[df_rtt["medium"] == medium]

    if df_sub.empty:
        print(f"⚠️ No RTT data for {medium} — skipping plot.")
        continue

    # ✅ Pivot into required shape
    pivot = df_sub.pivot_table(
        index=["protocol", "cc"],
        columns="bandwidth",
        values="rtt",
        aggfunc="mean"
    )

    # ✅ Enforce bandwidth order
    pivot = pivot.reindex(columns=BW_ORDER)

    # ✅ Build labels
    x_labels = [f"{p}-{c}" for p, c in pivot.index]

    # ✅ Convert to numeric matrix
    data = pivot.values
    y_max = np.nanmax(data)

    use_clip = y_max > CLIP_LIMIT
    plot_data = np.clip(data, 0, CLIP_LIMIT) if use_clip else data

    # ================================
    # ✅ BAR PLOT
    # ================================

    x = np.arange(len(x_labels))
    width = 0.25

    plt.figure(figsize=(12, 6))

    for i, bw in enumerate(BW_ORDER):
        plt.bar(
            x + i * width,
            plot_data[:, i],
            width=width,
            label=bw
        )

    # ✅ Annotate clipped bars (outliers)
    if use_clip:
        for i in range(plot_data.shape[0]):
            for j in range(plot_data.shape[1]):
                if data[i, j] > CLIP_LIMIT:
                    plt.text(
                        x[i] + j * width,
                        CLIP_LIMIT * 0.95,
                        f"{int(data[i, j])} ms",
                        ha="center",
                        va="bottom",
                        fontsize=8,
                        rotation=90
                    )

    # ✅ Formatting
    plt.xticks(x + width, x_labels, rotation=45)
    plt.ylabel("Mean RTT (ms)")
    plt.xlabel("Protocol / Congestion Control")
    plt.title(f"Mean RTT vs Bandwidth ({medium.upper()})")
    plt.legend(title="Bandwidth")
    plt.grid(True, axis="y", linestyle="--", alpha=0.5)

    if use_clip:
        plt.ylim(0, CLIP_LIMIT)
        plt.text(
            0.5, 0.92,
            f"⚠️ Values clipped above {CLIP_LIMIT} ms (real values annotated)",
            transform=plt.gca().transAxes,
            ha="center",
            fontsize=10
        )

    plt.tight_layout()
    plt.savefig(f"{OUT_DIR}/fig9_mean_rtt_vs_bw_protocol_cc_{medium}.png")
    plt.close()

    print(f"✅ RTT plot saved for {medium}")

print("✅✅✅ ALL 10 FIGURES GENERATED SUCCESSFULLY IN ./plots/")
