from scapy.all import sniff, IP, TCP, UDP, IPv6, Raw
import time
from collections import defaultdict
from pprint import pprint
import argparse
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import json

# Performance tracking variables
total_packets = 0
total_data = 0

port_packets = []
unique_conn_to_ims = defaultdict(int)
all_ims_packets = []
ims_dst_packets = []
super_users = 0

packet_sizes = []
src_dst_pairs = defaultdict(int)
src_flows = defaultdict(int)
dst_flows = defaultdict(int)

# mDNS (Multicast DNS) uses 224.0.0.251 (IPv4) and ff02::fb (IPv6) on UDP port 5353.
    # To filter out mDNS packets, we add checks for:

    # IPv4: packet[IP].dst == "224.0.0.251"
    # IPv6: packet[IPv6].dst == "ff02::fb"
    # UDP Port 5353: packet[UDP].dport == 5353
    
def traffic_packet(packet):
    """Filters out localhost and multicast traffic"""
    if IP in packet and (packet[IP].src == "127.0.0.1" or packet[IP].dst == "127.0.0.1"):
        return True
    if IPv6 in packet and (packet[IPv6].src == "::1" or packet[IPv6].dst == "::1"):
        return True
    if (IP in packet and packet[IP].dst == "224.0.0.251") or (IPv6 in packet and packet[IPv6].dst == "ff02::fb"):
        return True
    if UDP in packet and packet[UDP].dport == 5353:
        return True
    return False

def packet_handler(packet):
    """Handles packet sniffing for performance monitoring"""
    global total_packets, total_data

    if traffic_packet(packet):
        return

    total_packets += 1
    total_data += len(packet)
    print(packet.summary())


def question1(packet):
    global total_data, total_packets, packet_sizes, src_dst_pairs, src_flows, dst_flows
    total_packets += 1
    pkt_len = len(packet)
    packet_sizes.append(pkt_len)
    total_data += pkt_len

    if IP in packet or IPv6 in packet:
        # Extract source and destination IPs and ports
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        else:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

        src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None)
        dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)
        
        # Update unique source-destination pairs
        if src_port and dst_port:
            src_dst_pairs[f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"] += pkt_len
        
        # Update flow counts for source and destination IPs
        src_flows[src_ip] += 1
        dst_flows[dst_ip] += 1
    
    print(packet.summary())

def log_question1_metrics():
    global total_data, total_packets, packet_sizes, src_dst_pairs, src_flows, dst_flows
    
    min_pkt_size = min(packet_sizes) if packet_sizes else 0
    max_pkt_size = max(packet_sizes) if packet_sizes else 0
    avg_pkt_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0

    print("\n--- Metrics ---")
    print(f"Total data transferred: {total_data} bytes")
    print(f"Total packets transferred: {total_packets}")
    print(f"Min packet size: {min_pkt_size} bytes")
    print(f"Max packet size: {max_pkt_size} bytes")
    print(f"Average packet size: {avg_pkt_size:.2f} bytes")

    # Save packet size distribution plot using seaborn
    plt.figure(figsize=(10, 6))
    sns.histplot(packet_sizes, kde=True, bins=20, edgecolor="black", color="lightcoral")
    plt.title("Packet Size Distribution")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.savefig("packet_size_distribution.png", dpi=600)
    plt.show()

    # Describe the distribution using percentiles
    percentiles = [50, 75, 90, 95, 99]
    percentile_values = {p: np.percentile(packet_sizes, p) for p in percentiles}

    print("\n--- Packet Size Distribution Percentiles ---")
    for p, value in percentile_values.items():
        print(f"{p}th percentile: {value} bytes")

    most_packets_range = (np.percentile(packet_sizes, 25), np.percentile(packet_sizes, 75))
    print(f"\nMost packets lie between {most_packets_range[0]} and {most_packets_range[1]} bytes")

    with open("./Logs/packet_metrics.txt", "w") as txtfile:
        txtfile.write(f"Total data transferred (bytes): {total_data}\n")
        txtfile.write(f"Total packets transferred: {total_packets}\n")
        txtfile.write(f"Min packet size (bytes): {min_pkt_size}\n")
        txtfile.write(f"Max packet size (bytes): {max_pkt_size}\n")
        txtfile.write(f"Average packet size (bytes): {avg_pkt_size:.2f}\n")

    if src_dst_pairs:
        max_data_pair = max(src_dst_pairs, key=src_dst_pairs.get)
        print(f"\nSource-Destination pair with most data: {max_data_pair} ({src_dst_pairs[max_data_pair]} bytes)")
        
    sorted_src_dst_pairs = dict(sorted(src_dst_pairs.items(), key=lambda x: x[1], reverse=True))
    with open("./JSON/packet_flows.json", "w") as jsonfile:
        json.dump(sorted_src_dst_pairs, jsonfile, indent=4)
        
    sorted_src_flows = dict(sorted(src_flows.items(), key=lambda x: x[1], reverse=True))
    with open("./JSON/src_flows.json", "w") as jsonfile:
        json.dump(sorted_src_flows, jsonfile, indent=4)
    
    sorted_dst_flows = dict(sorted(dst_flows.items(), key=lambda x: x[1], reverse=True))
    with open("./JSON/dst_flows.json", "w") as jsonfile:
        json.dump(sorted_dst_flows, jsonfile, indent=4)



def question_2(packet):
    """Handles packet sniffing for IMS-related analysis"""
    global port_packets, unique_conn_to_ims, all_ims_packets, ims_dst_packets, super_users, total_packets, total_data

    if traffic_packet(packet):
        return
    
    total_packets += 1
    total_data += len(packet)

    ims_ip = "10.0.137.79"
    
    IPv = IP if IP in packet else IPv6 if IPv6 in packet else None
    if IPv:
        src_ip = packet[IPv].src
        dst_ip = packet[IPv].dst
        
        if dst_ip == ims_ip:
            ims_dst_packets.append(packet)
            all_ims_packets.append(packet)
        
        if src_ip == ims_ip:
            all_ims_packets.append(packet)
        
        protocol = TCP if TCP in packet else UDP if UDP in packet else None
        if protocol:
            src_port = packet[protocol].sport
            dst_port = packet[protocol].dport
            if dst_ip == ims_ip:
                unique_conn_to_ims[f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"] += 1
            
        if protocol and (packet[protocol].sport == 4321 or packet[protocol].dport == 4321):
            port_packets.append(packet)
        
        if Raw in packet:
            payload = packet[Raw].load.decode(errors='ignore')
            super_users += payload.lower().count("superuser")

    print(packet.summary())
    
def log_question2_metrics():
    global port_packets, unique_conn_to_ims, all_ims_packets, ims_dst_packets, super_users, total_packets, total_data
    """Logs the results from question_2 packet capture"""
    print("\n--- Question 2 Metrics ---")
    
    print("\nAll packets destined to IMS server:")
    for packet in ims_dst_packets:
        print(packet.summary())
        
    print("\nAll packets both from and to IMS server:")
    for packet in all_ims_packets:
        print(packet.summary())
        
    print("\nUnique connections to IMS server (with their connection counts):")
    pprint(unique_conn_to_ims)
    
    print("\nAll packets transferred on port 4321 (both src and dst):")
    for packet in port_packets:
        print(packet.summary())
    
    print("\n----------Summary------------")
    print(f"Q1: Unique Packets Destined to IMS server: {len(ims_dst_packets)}")
    
    print("Q2: Course registered on IMS is:")
    for ims_pkt in all_ims_packets:
        if Raw in ims_pkt:
            payload = ims_pkt[Raw].load.decode(errors='ignore')
            if 'course' in payload:
                print(payload)
                
    print(f"Q3: Total data transferred on port 4321: {sum(len(pkt) for pkt in port_packets)} bytes")
    print(f"Q4: Total number of SuperUsers: {super_users}")
    print("\n-----------------------------\n")

def compute_performance():
    """Computes and displays performance metrics"""
    print("\n--- Performance Metrics ---")
    if total_packets == 0:
        print("----------------------------")
        print("No packets captured.")
        print("----------------------------")
        return
    
    print("----------------------------")
    print(f"Total Packets Received: {total_packets}")
    print(f"Total Data: {total_data} bytes ({total_data / 1024:.2f} KB)")
    print("----------------------------")

def main():

    parser = argparse.ArgumentParser(description="Packet sniffer for performance testing")
    parser.add_argument('-t', '--timeout', type=int, help="Duration to sniff packets (in seconds)")
    parser.add_argument('-i', '--interface', type=str, help="Interface to sniff packets on")
    parser.add_argument('-q', '--question', type=int, default=0, help="Question number (default: 0)")
    parser.add_argument('-f', '--file', type=str, help="PCAP file")
    

    args = parser.parse_args()

    print(f"Starting packet capture on {args.interface} for {args.timeout or 'unlimited'} seconds for question {args.question}...")

    try:
        if args.question == 0 and not args.file:
            sniff(iface=args.interface, prn=packet_handler, store=False, timeout=args.timeout)
        elif args.question == 2 and not args.file:
            sniff(iface=args.interface, prn=question_2, store=False, timeout=args.timeout)
            log_question2_metrics()
        elif args.question == 1 and not args.file:
            sniff(iface=args.interface, prn=question1, store=False, timeout=args.timeout)
            log_question1_metrics()
        
        if args.question == 0 and args.file:
            sniff(offline=args.file, prn=packet_handler, store=False)
        elif args.question == 2 and args.file:
            sniff(offline=args.file, prn=question_2, store=False)
            log_question2_metrics()
        elif args.question == 1 and args.file:
            sniff(offline=args.file, prn=question1, store=False)
            log_question1_metrics()
        
    
    except KeyboardInterrupt:
        time.sleep(1)
        print("\nPacket capture interrupted by user.")
        if args.question == 1:
            log_question1_metrics()
        elif args.question == 2:
            log_question2_metrics()
    
    compute_performance()

if __name__ == "__main__":
    main()