import socket
import struct
import matplotlib.pyplot as plt
from collections import defaultdict
import argparse
import json
import time

# Global variables to store metrics
total_data = 0
machine2_packets = 0
total_packets = 0
packet_sizes = []
src_dst_pairs = defaultdict(int)
src_flows = defaultdict(int)
dst_flows = defaultdict(int)

def process_packet(packet_data):
    global total_data, total_packets, packet_sizes, src_dst_pairs, src_flows, dst_flows, machine2_packets

    eth_header = packet_data[:14]
    if len(eth_header) < 14:
        return

    eth_type = struct.unpack('!H', eth_header[12:14])[0]

    src_ip = None
    dst_ip = None
    protocol = None
    pkt_len = len(packet_data)  # Fallback to full packet length if IP parsing fails

    if eth_type == 0x0800:  # IPv4
        ip_header = packet_data[14:34]
        if len(ip_header) < 20:
            return

        version_ihl = ip_header[0]
        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20:
            return  # Invalid IP header length

        protocol = ip_header[9]
        src_ip = socket.inet_ntop(socket.AF_INET, ip_header[12:16])
        dst_ip = socket.inet_ntop(socket.AF_INET, ip_header[16:20])

        total_length = struct.unpack('!H', ip_header[2:4])[0]
        pkt_len = total_length

        if src_ip == "127.0.0.1" or dst_ip == "127.0.0.1":
            return

        if src_ip == "10.240.2.72":
            machine2_packets += 1

    elif eth_type == 0x86DD:  # IPv6
        ipv6_header = packet_data[14:54]
        if len(ipv6_header) < 40:
            return

        next_header = ipv6_header[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, ipv6_header[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, ipv6_header[24:40])

        payload_length = struct.unpack('!H', ipv6_header[4:6])[0]
        pkt_len = 40 + payload_length
        protocol = next_header

    else:
        return  # Non-IP packet

    # Update metrics
    total_packets += 1
    packet_sizes.append(pkt_len)
    total_data += pkt_len

    src_port = None
    dst_port = None

    if protocol in [6, 17]:  # TCP or UDP
        if eth_type == 0x0800:
            transport_start = 14 + ihl
        else:
            transport_start = 14 + 40  # IPv6 header length

        if len(packet_data) >= transport_start + 4:
            transport_header = packet_data[transport_start:transport_start+4]
            src_port, dst_port = struct.unpack('!HH', transport_header[:4])

    # Update source-destination pairs with ports
    if src_port is not None and dst_port is not None:
        pair_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        src_dst_pairs[pair_key] += pkt_len

    # Update flow counts
    if src_ip:
        src_flows[src_ip] += 1
    if dst_ip:
        dst_flows[dst_ip] += 1

    # Print packet summary
    ip_version = 'IPv4' if eth_type == 0x0800 else 'IPv6' if eth_type == 0x86DD else 'Unknown'
    proto_str = {6: 'TCP', 17: 'UDP'}.get(protocol, 'Other')
    port_str = f"{src_port} -> {dst_port}" if src_port and dst_port else ""
    print(f"{ip_version} {proto_str} {src_ip} -> {dst_ip} {port_str}")

def generate_metrics():
    global total_data, total_packets, packet_sizes, src_dst_pairs, src_flows, dst_flows, machine2_packets

    min_pkt_size = min(packet_sizes) if packet_sizes else 0
    max_pkt_size = max(packet_sizes) if packet_sizes else 0
    avg_pkt_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0

    print("\n--- Metrics ---")
    print(f"Total packets sent by Machine 2: {machine2_packets}") 
    print(f"Total data transferred: {total_data} bytes")
    print(f"Total packets transferred: {total_packets}")
    print(f"Min packet size: {min_pkt_size} bytes")
    print(f"Max packet size: {max_pkt_size} bytes")
    print(f"Average packet size: {avg_pkt_size:.2f} bytes")

    plt.hist(packet_sizes, bins=20, edgecolor='black')
    plt.title("Packet Size Distribution")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.savefig("packet_size_distribution.png")

    with open("packet_metrics.txt", "w") as txtfile:
        txtfile.write(f"Total data transferred (bytes): {total_data}\n")
        txtfile.write(f"Total packets transferred: {total_packets}\n")
        txtfile.write(f"Min packet size (bytes): {min_pkt_size}\n")
        txtfile.write(f"Max packet size (bytes): {max_pkt_size}\n")
        txtfile.write(f"Average packet size (bytes): {avg_pkt_size:.2f}\n")
    
    with open("./JSON/packet_flows.json", "w") as jsonfile:
        json.dump(src_dst_pairs, jsonfile, indent=4)
    
    with open("./JSON/ip_flows.json", "w") as jsonfile:
        json.dump({"src_flows": src_flows, "dst_flows": dst_flows}, jsonfile, indent=4)

    if src_dst_pairs:
        max_data_pair = max(src_dst_pairs, key=src_dst_pairs.get)
        print(f"\nSource-Destination pair with most data: {max_data_pair} ({src_dst_pairs[max_data_pair]} bytes)")

def main():
    parser = argparse.ArgumentParser(description="Packet sniffer using raw sockets")
    parser.add_argument('-t', '--timeout', type=int, required=True, help="Duration to sniff packets (in seconds)")
    parser.add_argument('-i', '--interface', type=str, required=True, help="Interface to sniff packets on")
    args = parser.parse_args()

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((args.interface, 0))
    except PermissionError:
        print("Permission denied. Try running with sudo.")
        return
    except Exception as e:
        print(f"Error creating socket: {e}")
        return

    print(f"Starting packet sniffer on {args.interface} for {args.timeout} seconds...")

    start_time = time.time()
    end_time = start_time + args.timeout

    try:
        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                packet_data, _ = sock.recvfrom(65535)
                process_packet(packet_data)
            except socket.timeout:
                break
    except KeyboardInterrupt:
        print("\nSniffing stopped manually.")
    finally:
        sock.close()
        generate_metrics()

if __name__ == "__main__":
    main()