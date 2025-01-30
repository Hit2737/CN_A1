from scapy.all import *
import matplotlib.pyplot as plt
from collections import defaultdict

# Load pcap file
packets = rdpcap("0.pcap")  # Replace X.pcap with your file

# Open a file to write the output
with open("part1_output.txt", "w") as f:
    # Question 1: Basic Metrics & Histogram
    total_packets = len(packets)
    total_bytes = sum(len(p) for p in packets)
    sizes = [len(p) for p in packets]
    min_size = min(sizes)
    max_size = max(sizes)
    avg_size = total_bytes / total_packets if total_packets > 0 else 0

    # Write metrics to file
    f.write(f"Q1: Total Data = {total_bytes} B, Packets = {total_packets}\n")
    f.write(f"Min/Max/Avg Size = {min_size}/{max_size}/{avg_size:.2f}\n")

    # Plot histogram
    plt.hist(sizes, bins=50, edgecolor="black")
    plt.xlabel("Packet Size (Bytes)")
    plt.ylabel("Frequency")
    plt.title("Packet Size Distribution")
    plt.savefig("packet_size_histogram.png")
    plt.close()

    # Question 2: Unique Source-Destination Pairs
    unique_pairs = set()
    for p in packets:
        if IP in p and (TCP in p or UDP in p):
            src_ip = p[IP].src
            dst_ip = p[IP].dst
            sport = p[TCP].sport if TCP in p else p[UDP].sport
            dport = p[TCP].dport if TCP in p else p[UDP].dport
            unique_pairs.add((src_ip, sport, dst_ip, dport))

    f.write(f"Q2: Unique Pairs = {len(unique_pairs)}\n")

    # Question 3: Flow Analysis
    source_flows = defaultdict(int)
    dest_flows = defaultdict(int)
    flow_data = defaultdict(int)

    for p in packets:
        if IP in p and (TCP in p or UDP in p):
            src = p[IP].src
            dst = p[IP].dst
            sport = p[TCP].sport if TCP in p else p[UDP].sport
            dport = p[TCP].dport if TCP in p else p[UDP].dport
            flow_key = (src, sport, dst, dport)

            source_flows[src] += 1
            dest_flows[dst] += 1
            flow_data[flow_key] += len(p)

    # Find top source-destination by data
    top_flow = max(flow_data.items(), key=lambda x: x[1], default=None)

    # Write flow analysis results to file
    f.write(f"Q3: Source Flows = {dict(source_flows)}\n")
    f.write(f"Q3: Destination Flows = {dict(dest_flows)}\n")
    f.write(f"Q3: Top Flow = {top_flow[0]} with {top_flow[1]} B\n")
