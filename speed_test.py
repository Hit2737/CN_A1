from scapy.all import sniff
import argparse

captured = 0
def packet_handler(pkt):
    print(pkt.summary())
    global captured
    captured += 1

parser = argparse.ArgumentParser(description="Packet sniffer")
parser.add_argument('-t', '--timeout', type=int, help="Duration to sniff packets (in seconds)")
parser.add_argument('-i', '--interface', type=str, help="Interface to sniff packets on")

args = parser.parse_args()

if not args.interface and not args.timeout:
    print("Error: Please specify an interface using -i to sniff packets on")
    exit(1)
elif not args.timeout:
    try:
        sniff(prn=packet_handler, store=False, iface=args.interface)
    except KeyboardInterrupt:
        print("Sniffing Stopped Manually")
else:
    try:
        sniff(prn=packet_handler, store=False, iface=args.interface, timeout=args.timeout)
    except KeyboardInterrupt:
        print("Sniffing Stopped Manually")

print(f"\nCaptured {captured} packets")


