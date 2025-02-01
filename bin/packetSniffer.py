from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np
import argparse
from collections import defaultdict

# Initialize variables
packets=[]
packet_sizes = []
total_data = 0
total_packets = 0
# src_dst_pairs = set()
src_flows = defaultdict(int)
dst_flows = defaultdict(int)
src_dst_data = defaultdict(int)

def packet_handler(packet):
    global total_data, total_packets, packet_sizes, src_flows, dst_flows, src_dst_data
    # Filter out localhost and broadcast packets
    if IP in packet and (packet[IP].src == "127.0.0.1" or packet[IP].dst =="127.0.0.1"):
        return
    if IPv6 in packet and (packet[IPv6].src == "::1" or packet[IPv6].dst == "::1"):
        return
    if UDP in packet and (packet[UDP].dport == 5353 or packet[UDP].sport == 5353):
        return
    
    packet_size = len(packet)
    packet_sizes.append(packet_size)
    total_data += packet_size
    total_packets += 1
    if IP in packet:
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None

        # Update unique source-destination pairs
        src_dst_pair = (f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}")
        src_dst_data[src_dst_pair] += packet_size

        # Update source and destination flows
        src_flows[src_ip] += 1
        dst_flows[dst_ip] += 1


def start_sniffing(interface, timeout):
    print(f"Starting packet sniffing on interface {interface}...")
    sniff(iface=interface, prn=packet_handler, store=0,timeout=int(timeout))
    # sniff(offline="5.pcap", prn=packet_handler, store=0)

def analyze_results():
    if len(packet_sizes)==0:
        return
    # Metrics
    print("\n** Packet Sniffer Metrics **")
    print(f"Total Data Transferred: {total_data} bytes")
    print(f"Total Packets Transferred: {total_packets}")
    print(f"Minimum Packet Size: {min(packet_sizes)} bytes")
    print(f"Maximum Packet Size: {max(packet_sizes)} bytes")
    print(f"Average Packet Size: {np.mean(packet_sizes):.2f} bytes")


    # Unique source-destination pairs
    print(f"\nTotal unique Source-Destination Pairs: {len(src_dst_data)}")
    # top 5 source-destination pairs by data transferred
    top_pairs = sorted(src_dst_data.items(), key=lambda x: x[1], reverse=True)[:5]
    for pair, data in top_pairs:
        print(f"{pair[0]} -> {pair[1]}: {data} bytes")

    print("\nTop 5 source IPs by flow count:")
    for ip, count in sorted(src_flows.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip}: {count} flows")
    print("\nTop 5 destination IPs by flow count:")
    for ip, count in sorted(dst_flows.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip}: {count} flows")

    # Source and destination flows
    # print("Source Flows:", src_flows)
    # print("Destination Flows:", dst_flows)

    # Plot packet size distribution
    plt.hist(packet_sizes, bins=30, edgecolor="black",color='blue', alpha=0.7)
    plt.title("Packet Size Distribution from sniffing pcap file")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.grid()
    plt.savefig("pkt_size_distribution_via_sniffing_PCAPfile.png")
    # Save metrics to CSV
    # with open("packet_metrics.txt", "w") as txtfile:
    #     txtfile.write(f"Total data transferred (bytes): {total_data}\n")
    #     txtfile.write(f"Total packets transferred: {total_packets}\n")
    #     txtfile.write(f"Min packet size (bytes): {min_pkt_size}\n")
    #     txtfile.write(f"Max packet size (bytes): {max_pkt_size}\n")
    #     txtfile.write(f"Average packet size (bytes): {avg_pkt_size:.2f}\n")
    
    # # Save unique source-destination pairs and flows to JSON
    # with open("packet_flows.json", "w") as jsonfile:
    #     json.dump(src_dst_pairs, jsonfile, indent=4)
    
    # # Save flow counts to JSON (source and destination IP flows)
    # with open("ip_flows.json", "w") as jsonfile:
    #     json.dump({"src_flows": src_flows, "dst_flows": dst_flows}, jsonfile, indent=4)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--timeout", help="Timeout for sniffing")
    parser.add_argument("-i","--interface", help="Interface to sniff on",default="lo")
    parser.add_argument("-f","--file", help="Path to PCAP file",default="5.pcap")
    args = parser.parse_args()
    
    print("Packet Sniffing Program started...")
    start_sniffing(args.interface,args.timeout)
    print("Packet Sniffing Program completed.")
    print("Analyzing results...")
    analyze_results()
    print("Program completed.")