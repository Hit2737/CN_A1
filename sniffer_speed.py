from scapy.all import sniff, IP, TCP, UDP, IPv6, Raw
import time
from collections import defaultdict
from pprint import pprint
import argparse

# Performance tracking variables
total_packets = 0
total_data = 0
start_time = None

port_packets = []
unique_conn_to_ims = defaultdict(int)
all_ims_packets = []
ims_dst_packets = []
super_users = 0


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
    global total_packets, total_data, start_time

    if start_time is None:
        start_time = time.time()

    if traffic_packet(packet):
        return

    total_packets += 1
    total_data += len(packet)
    print(packet.summary())

def question_2(packet):
    """Handles packet sniffing for IMS-related analysis"""
    global port_packets, unique_conn_to_ims, all_ims_packets, ims_dst_packets, super_users, start_time, total_packets, total_data

    if start_time is None:
        start_time = time.time()

    if traffic_packet(packet):
        return
    
    total_packets += 1
    total_data += len(packet)
    print(packet.summary())

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
            unique_conn_to_ims[f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"] += 1
            
        if protocol and (packet[protocol].sport == 4321 or packet[protocol].dport == 4321):
            port_packets.append(packet)
        
        if Raw in packet:
            payload = packet[Raw].load.decode(errors='ignore')
            super_users += payload.lower().count("superuser")

def log_question2_metrics():
    global port_packets, unique_conn_to_ims, all_ims_packets, ims_dst_packets, super_users, start_time, total_packets, total_data
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

def compute_performance(duration):
    """Computes and displays performance metrics"""
    print("\n--- Performance Metrics ---")
    if duration <= 0 or total_packets == 0:
        print("----------------------------")
        print("No packets captured.")
        print("----------------------------")
        return
    
    print("----------------------------")
    print(f"Total Packets Received: {total_packets}")
    print(f"Total Data: {total_data} bytes ({total_data / 1024:.2f} KB)")
    print("----------------------------")

def main():
    global start_time

    parser = argparse.ArgumentParser(description="Packet sniffer for performance testing")
    parser.add_argument('-t', '--timeout', type=int, help="Duration to sniff packets (in seconds)")
    parser.add_argument('-i', '--interface', type=str, required=True, help="Interface to sniff packets on")
    parser.add_argument('-q', '--question', type=int, default=0, help="Question number (default: 0)")

    args = parser.parse_args()

    print(f"Starting packet capture on {args.interface} for {args.timeout or 'unlimited'} seconds for question {args.question}...")

    try:
        start_time = time.time()
        if args.question == 0:
            sniff(iface=args.interface, prn=packet_handler, store=False, timeout=args.timeout)
        elif args.question == 2:
            sniff(iface=args.interface, prn=question_2, store=False, timeout=args.timeout)
            log_question2_metrics()
        
        duration = time.time() - start_time
        compute_performance(duration)
    
    except KeyboardInterrupt:
        print("\nPacket capture interrupted by user.")
    
    finally:
        # Ensure we log the metrics even if interrupted
        duration = time.time() - start_time
        compute_performance(duration)
        if args.question == 2:
            log_question2_metrics()

if __name__ == "__main__":
    main()