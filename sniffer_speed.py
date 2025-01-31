from scapy.all import sniff, IP, TCP, UDP, IPv6
import time
import argparse

# Performance tracking variables
total_packets = 0
total_data = 0
start_time = None

# Packet handler function
def packet_handler(packet):
    global total_packets, total_data, start_time

    if start_time is None:
        start_time = time.time()

    # Ignoring localhost traffic (127.0.0.1 and ::1)
    if (IP in packet and (packet[IP].src == "127.0.0.1" or packet[IP].dst == "127.0.0.1")) or (IPv6 in packet and (packet[IPv6].src == "::1" or packet[IPv6].dst == "::1")):
        return
    
    # mDNS (Multicast DNS) uses 224.0.0.251 (IPv4) and ff02::fb (IPv6) on UDP port 5353.
    # To filter out mDNS packets, we add checks for:

    # IPv4: packet[IP].dst == "224.0.0.251"
    # IPv6: packet[IPv6].dst == "ff02::fb"
    # UDP Port 5353: packet[UDP].dport == 5353
    
    if (IP in packet and packet[IP].dst == "224.0.0.251") or (IPv6 in packet and packet[IPv6].dst == "ff02::fb"):
        return

    if UDP in packet and packet[UDP].dport == 5353:
        return

    total_packets += 1
    pkt_len = len(packet)
    total_data += pkt_len
    print(packet.summary())


def compute_performance(duration):
    if duration <= 0 or total_packets == 0:
        print("\n--- Performance Metrics ---")
        print("No packets captured.")
        return

    print("\n--- Performance Metrics ---")
    print(f"Total Packets Received: {total_packets}")
    print(f"Total Data: {total_data} bytes ({total_data / 1024:.2f} KB)")


def main():
    global start_time

    parser = argparse.ArgumentParser(description="Packet sniffer for performance testing")
    parser.add_argument('-t', '--timeout', type=int, required=True, help="Duration to sniff packets (in seconds)")
    parser.add_argument('-i', '--interface', type=str, required=True, help="Interface to sniff packets on")

    args = parser.parse_args()

    print(f"Starting packet capture on {args.interface} for {args.timeout} seconds...")

    start_time = time.time()
    sniff(iface=args.interface, prn=packet_handler, store=False, timeout=args.timeout)
    duration = time.time() - start_time

    compute_performance(duration)


if __name__ == "__main__":
    main()
