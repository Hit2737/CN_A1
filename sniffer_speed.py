from scapy.all import sniff, IP, TCP, UDP, IPv6
import time
import argparse
import json

# Performance tracking variables
total_packets = 0
total_data = 0
start_time = None
pps_values = []
mbps_values = []
packet_loss_stats = {"sent": 0, "received": 0, "loss": 0, "loss_percentage": 0.0}

# Packet handler function
def packet_handler(packet):
    global total_packets, total_data, start_time

    if start_time is None:
        start_time = time.time()  # Start tracking when the first packet arrives

    total_packets += 1
    pkt_len = len(packet)
    total_data += pkt_len
    # print(packet.summary())

# Function to calculate real-time performance metrics
def compute_performance(duration):
    global total_packets, total_data

    if duration == 0:
        return

    # Packets per second (pps)
    pps = total_packets / duration
    pps_values.append(pps)

    # Megabits per second (Mbps)
    mbps = (total_data * 8) / (duration * 1e6)  # Convert bytes to megabits
    mbps_values.append(mbps)

    print(f"\n--- Performance Metrics ---")
    print(f"Total Packets Received: {total_packets}")
    print(f"Total Data: {total_data} bytes")
    print(f"Packets per second (pps): {pps:.2f}")
    print(f"Throughput (Mbps): {mbps:.2f}")

    # Save to a JSON file
    with open("performance_metrics.json", "w") as jsonfile:
        json.dump({"pps": pps_values, "mbps": mbps_values}, jsonfile, indent=4)

# Function to compare with tcpreplay stats
def compute_packet_loss(tcpreplay_sent):
    global packet_loss_stats

    received = total_packets
    loss = tcpreplay_sent - received
    loss_percentage = (loss / tcpreplay_sent) * 100 if tcpreplay_sent > 0 else 0

    packet_loss_stats.update({
        "sent": tcpreplay_sent,
        "received": received,
        "loss": loss,
        "loss_percentage": loss_percentage
    })

    print(f"\n--- Packet Loss Stats ---")
    print(f"Packets Sent (tcpreplay): {tcpreplay_sent}")
    print(f"Packets Received: {received}")
    print(f"Packet Loss: {loss} packets ({loss_percentage:.2f}%)")

    with open("packet_loss.json", "w") as jsonfile:
        json.dump(packet_loss_stats, jsonfile, indent=4)

# Main function
def main():
    parser = argparse.ArgumentParser(description="Packet sniffer for performance testing")
    parser.add_argument('-t', '--timeout', type=int, help="Duration to sniff packets (in seconds)", required=True)
    parser.add_argument('-i', '--interface', type=str, help="Interface to sniff packets on", required=True)
    # parser.add_argument('-s', '--tcpreplay_sent', type=int, help="Packets sent by tcpreplay (for loss calc)", required=True)

    args = parser.parse_args()

    print(f"Starting packet capture on {args.interface} for {args.timeout} seconds...")
    
    # Start packet sniffing
    start_time = time.time()
    sniff(iface=args.interface, prn=packet_handler, store=False, timeout=args.timeout)
    duration = time.time() - start_time

    # # Compute and display performance
    compute_performance(duration)
    # compute_packet_loss(args.tcpreplay_sent)

if __name__ == "__main__":
    main()
