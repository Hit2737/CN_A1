from scapy.all import sniff, IP, TCP, UDP
import matplotlib.pyplot as plt
from collections import defaultdict
import argparse

# Global variables to store metrics
total_data = 0
total_packets = 0
packet_sizes = []
src_dst_pairs = defaultdict(int)
src_flows = defaultdict(int)
dst_flows = defaultdict(int)

# Packet handler function
def packet_handler(packet):
    global total_data, total_packets, packet_sizes, src_dst_pairs, src_flows, dst_flows
    
    if IP in packet:
        total_packets += 1
        pkt_len = len(packet)
        packet_sizes.append(pkt_len)
        total_data += pkt_len

        # Extract source and destination IPs and ports
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None)
        dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)
        
        # Update unique source-destination pairs
        if src_port and dst_port:
            src_dst_pairs[f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"] += pkt_len
        
        # Update flow counts for source and destination IPs
        src_flows[src_ip] += 1
        dst_flows[dst_ip] += 1

# Function to generate metrics and plots
def generate_metrics():
    global total_data, total_packets, packet_sizes, src_dst_pairs, src_flows, dst_flows

    # Metrics
    min_pkt_size = min(packet_sizes) if packet_sizes else 0
    max_pkt_size = max(packet_sizes) if packet_sizes else 0
    avg_pkt_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0

    print("\n--- Metrics ---")
    print(f"Total data transferred: {total_data} bytes")
    print(f"Total packets transferred: {total_packets}")
    print(f"Min packet size: {min_pkt_size} bytes")
    print(f"Max packet size: {max_pkt_size} bytes")
    print(f"Average packet size: {avg_pkt_size:.2f} bytes")

    # Plot packet size distribution
    plt.hist(packet_sizes, bins=20, edgecolor='black')
    plt.title("Packet Size Distribution")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.savefig("packet_size_distribution.png")

    # Unique source-destination pairs
    print("\n--- Unique Source-Destination Pairs ---")
    for pair, data in src_dst_pairs.items():
        print(f"{pair}: {data} bytes")

    # Source and destination flow dictionaries
    print("\n--- Flows Per IP ---")
    print("Source IP Flows:")
    for ip, flows in src_flows.items():
        print(f"{ip}: {flows} flows")
    print("Destination IP Flows:")
    for ip, flows in dst_flows.items():
        print(f"{ip}: {flows} flows")

    # Source-destination pair with the most data
    if src_dst_pairs:
        max_data_pair = max(src_dst_pairs, key=src_dst_pairs.get)
        print(f"\nSource-Destination pair with most data: {max_data_pair} ({src_dst_pairs[max_data_pair]} bytes)")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Packet sniffer")
    parser.add_argument('-t', '--timeout', type=int, help="Duration to sniff packets (in seconds)")
    parser.add_argument('-i', '--interface', type=str, help="Interface to sniff packets on")
    parser.add_argument('-f', '--file', type=str, help="Path to the .pcap file to read packets from")
    args = parser.parse_args()

    if args.file:
        print(f"Reading packets from {args.file}...")
        sniff(offline=args.file, prn=packet_handler, store=False)
    else:
        if not args.timeout or not args.interface:
            parser.error("Interface and timeout must be specified if not reading from a file.")
        print("Starting packet sniffer... Replay traffic now.")
        try:
            sniff(iface=args.interface, prn=packet_handler, store=False, timeout=args.timeout)
        except KeyboardInterrupt:
            print("\nSniffing stopped manually.")
    
    generate_metrics()

if __name__ == "__main__":
    main()