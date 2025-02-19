#!/usr/bin/env python3
import socket
import struct
import time
import argparse
from collections import defaultdict
from pprint import pprint
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

IMS_IP = "10.0.137.79"

def parse_packet(packet):
    """
    Parse raw packet bytes into a dictionary with header info.
    Supports IPv4 and IPv6.
    """
    parsed = {}
    eth_length = 14
    if len(packet) < eth_length:
        return None

    # Store the raw packet length (in bytes)
    parsed["raw_length"] = len(packet)

    # Unpack Ethernet header
    eth_header = packet[:eth_length]
    eth = struct.unpack("!6s6sH", eth_header)
    eth_protocol = socket.ntohs(eth[2])
    parsed['eth_protocol'] = eth_protocol

    # IPv4
    if eth_protocol == 8:
        if len(packet) < eth_length + 20:
            return None
        ip_header = packet[eth_length:eth_length+20]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        parsed['ip_version'] = 4
        parsed['src_ip'] = socket.inet_ntoa(iph[8])
        parsed['dst_ip'] = socket.inet_ntoa(iph[9])
        protocol_num = iph[6]
        parsed['protocol_num'] = protocol_num
        header_offset = eth_length + iph_length

        # TCP
        if protocol_num == 6 and len(packet) >= header_offset + 20:
            tcp_header = packet[header_offset:header_offset+20]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            parsed['protocol'] = "TCP"
            parsed['src_port'] = tcph[0]
            parsed['dst_port'] = tcph[1]
            data_offset = (tcph[4] >> 4) * 4
            payload_offset = header_offset + data_offset
            parsed['payload'] = packet[payload_offset:]
        # UDP
        elif protocol_num == 17 and len(packet) >= header_offset + 8:
            udp_header = packet[header_offset:header_offset+8]
            udph = struct.unpack("!HHHH", udp_header)
            parsed['protocol'] = "UDP"
            parsed['src_port'] = udph[0]
            parsed['dst_port'] = udph[1]
            payload_offset = header_offset + 8
            parsed['payload'] = packet[payload_offset:]
        else:
            parsed['protocol'] = None
            parsed['payload'] = packet[header_offset:]
        return parsed

    # IPv6
    elif eth_protocol == 34525:
        if len(packet) < eth_length + 40:
            return None
        ip_header = packet[eth_length:eth_length+40]
        # Unpack IPv6 header: Version/Traffic Class/Flow Label (4 bytes), Payload Length (2),
        # Next Header (1), Hop Limit (1), Source (16), Destination (16)
        iph = struct.unpack("!IHBB16s16s", ip_header)
        parsed['ip_version'] = 6
        # Convert IPv6 addresses
        try:
            parsed['src_ip'] = socket.inet_ntop(socket.AF_INET6, iph[4])
            parsed['dst_ip'] = socket.inet_ntop(socket.AF_INET6, iph[5])
        except Exception:
            return None
        next_header = iph[2]
        parsed['protocol_num'] = next_header
        header_offset = eth_length + 40

        # TCP
        if next_header == 6 and len(packet) >= header_offset + 20:
            tcp_header = packet[header_offset:header_offset+20]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            parsed['protocol'] = "TCP"
            parsed['src_port'] = tcph[0]
            parsed['dst_port'] = tcph[1]
            data_offset = (tcph[4] >> 4) * 4
            payload_offset = header_offset + data_offset
            parsed['payload'] = packet[payload_offset:]
        # UDP
        elif next_header == 17 and len(packet) >= header_offset + 8:
            udp_header = packet[header_offset:header_offset+8]
            udph = struct.unpack("!HHHH", udp_header)
            parsed['protocol'] = "UDP"
            parsed['src_port'] = udph[0]
            parsed['dst_port'] = udph[1]
            payload_offset = header_offset + 8
            parsed['payload'] = packet[payload_offset:]
        else:
            parsed['protocol'] = None
            parsed['payload'] = packet[header_offset:]
        return parsed

    else:
        return None

def get_packet_summary(info):
    """Generate a simple summary string for the packet."""
    ip_version = info.get('ip_version', '?')
    src_ip = info.get('src_ip', '?')
    dst_ip = info.get('dst_ip', '?')
    protocol = info.get('protocol', 'Other')
    ports = ""
    if protocol in ("TCP", "UDP"):
        ports = f" (sport: {info.get('src_port', '?')}, dport: {info.get('dst_port', '?')})"
    return f"IPv{ip_version} {protocol} packet: {src_ip} -> {dst_ip}{ports}"

def traffic_packet(info):
    """Filters out localhost and multicast/mDNS traffic."""
    if not info:
        return True

    src_ip = info.get('src_ip', '')
    dst_ip = info.get('dst_ip', '')
    protocol = info.get('protocol', '')
    dst_port = info.get('dst_port', None)

    # Filter localhost addresses (IPv4 and IPv6)
    if src_ip in ("127.0.0.1", "::1") or dst_ip in ("127.0.0.1", "::1"):
        return True

    # Filter multicast addresses for mDNS
    if dst_ip == "224.0.0.251" or dst_ip.lower() == "ff02::fb":
        return True

    # Filter UDP mDNS packets (UDP port 5353)
    if protocol == "UDP" and dst_port == 5353:
        return True

    return False

def packet_handler(info):
    """Handles packet processing for performance monitoring."""
    global total_packets, total_data, packet_sizes, src_dst_pairs, src_flows, dst_flows

    if traffic_packet(info):
        return

    total_packets += 1
    pkt_len = info.get("raw_length", 0)
    packet_sizes.append(pkt_len)
    total_data += pkt_len

    src_ip = info.get('src_ip', '')
    dst_ip = info.get('dst_ip', '')
    src_port = info.get('src_port', None)
    dst_port = info.get('dst_port', None)

    if src_ip and dst_ip:
        if src_port and dst_port:
            src_dst_pairs[f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"] += pkt_len
        
        src_flows[src_ip] += 1
        dst_flows[dst_ip] += 1

    print(get_packet_summary(info))

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

def question_2(info):
    """Handles packet processing for IMS-related analysis."""
    global total_packets, total_data, port_packets
    global unique_conn_to_ims, all_ims_packets, ims_dst_packets, super_users

    if traffic_packet(info):
        return

    total_packets += 1
    total_data += info.get("raw_length", 0)
    print(get_packet_summary(info))

    src_ip = info.get('src_ip', '')
    dst_ip = info.get('dst_ip', '')
    protocol = info.get('protocol', None)
    src_port = info.get('src_port', None)
    dst_port = info.get('dst_port', None)

    # Check for IMS server involvement
    if dst_ip == IMS_IP:
        ims_dst_packets.append(info)
        all_ims_packets.append(info)
    if src_ip == IMS_IP:
        all_ims_packets.append(info)

    if protocol in ("TCP", "UDP") and src_port is not None and dst_port is not None:
        key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        unique_conn_to_ims[key] += 1

    if protocol in ("TCP", "UDP") and (src_port == 4321 or dst_port == 4321):
        port_packets.append(info)

    # Process payload for "superuser" occurrences
    payload = info.get('payload', b"")
    try:
        text = payload.decode(errors='ignore').lower()
        super_users += text.count("superuser")
    except Exception:
        pass

def log_question2_metrics():
    """Logs the results from question_2 packet capture."""
    print("\n--- Question 2 Metrics ---")

    print("\nAll packets destined to IMS server:")
    for info in ims_dst_packets:
        print(get_packet_summary(info))

    print("\nAll packets both from and to IMS server:")
    for info in all_ims_packets:
        print(get_packet_summary(info))

    print("\nUnique connections to IMS server (with their connection counts):")
    pprint(dict(unique_conn_to_ims))

    print("\nAll packets transferred on port 4321 (both src and dst):")
    for info in port_packets:
        print(get_packet_summary(info))

    print("\n----------Summary------------")
    print(f"Q1: Unique Packets Destined to IMS server: {len(ims_dst_packets)}")

    print("Q2: Course registered on IMS is:")
    for info in all_ims_packets:
        payload = info.get('payload', b"")
        try:
            text = payload.decode(errors='ignore')
            if 'course' in text:
                print(text)
        except Exception:
            continue

    print(f"Q3: Total number of packets on port 4321: {len(port_packets)}")
    print(f"Q4: Total number of SuperUsers: {super_users}")
    print("\n-----------------------------\n")

def compute_performance():
    """Computes and displays performance metrics."""
    print("\n--- Performance Metrics ---")
    if total_packets == 0:
        print("----------------------------")
        print("No packets captured.")
        print("----------------------------")
        return

    print("----------------------------")
    print(f"Total Packets Received: {total_packets}")
    print(f"Total Data: {total_data} bytes")
    print("----------------------------")

def main():
    global start_time
    parser = argparse.ArgumentParser(description="Socket-based packet sniffer for performance testing")
    parser.add_argument('-t', '--timeout', type=int, help="Duration to sniff packets (in seconds)")
    parser.add_argument('-i', '--interface', type=str, required=True, help="Interface to sniff packets on")
    parser.add_argument('-q', '--question', type=int, default=0, help="Question number (default: 0)")

    args = parser.parse_args()
    timeout = args.timeout
    question = args.question

    print(f"Starting packet capture on {args.interface} for {timeout or 'unlimited'} seconds for question {question}...")

    # Create a raw socket and bind it to the interface
    try:
        # AF_PACKET is Linux-specific
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sniffer.bind((args.interface, 0))
    except Exception as e:
        print(f"Error creating socket: {e}")
        return

    start_time = time.time()
    try:
        while True:
            # Check for timeout
            if timeout and (time.time() - start_time) > timeout:
                break

            raw_packet, addr = sniffer.recvfrom(65535)
            packet_info = parse_packet(raw_packet)
            if packet_info is None:
                continue

            if question == 0:
                packet_handler(packet_info)
            elif question == 1:
                packet_handler(packet_info)
            elif question == 2:
                question_2(packet_info)
    except KeyboardInterrupt:
        print("\nPacket capture interrupted by user.")
    finally:
        if question == 1:
            log_question1_metrics()
        elif question == 2:
            log_question2_metrics()
        sniffer.close()
        compute_performance()

if __name__ == "__main__":
    main()