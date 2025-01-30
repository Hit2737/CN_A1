from scapy.all import sniff

captured = []
def packet_handler(pkt):
    captured.append(pkt)

sniff(prn=packet_handler, store=False, timeout=30, iface='lo')  

print(f"Captured {len(captured)} packets")
