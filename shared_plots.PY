import pandas as pd
import matplotlib.pyplot as plt

# Load CSV
df = pd.read_csv("cellular-cubic-cubic-50mbps.csv")

# ✅ Convert Bits/s → Mbps
x = df["Interval start"]
tcp = df["TCP"] / 1e6
quic = df["QUIC"] / 1e6

# Create plot
plt.figure()
plt.plot(x, tcp, marker='o', label="TCP")
plt.plot(x, quic, marker='o', label="QUIC")

# Axis labels and title
plt.xlabel("Interval")
plt.ylabel("Throughput (Mbps)")   # ✅ FIXED UNIT
plt.title("TCP (CUBIC) vs QUIC (CUBIC) Throughput Over Time (50 Mbps)")
plt.legend()
plt.grid(True)

# ✅ Disable scientific notation on Y-axis
plt.ticklabel_format(axis='y', style='plain')

# ✅ SAVE ONLY (no display)
plt.savefig("cellular-cubic-cubic-50mbps.png", dpi=300, bbox_inches="tight")
plt.close()

print("✅ Plot saved as cellular-cubic-cubic-50mbps.png in Mbps")