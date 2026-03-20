from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        else:
            protocol = "Other"
        print(f"\n[+] {protocol} Packet: {ip_layer.src} -> {ip_layer.dst}")
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload_data = bytes(packet.payload)
            if payload_data:
                print(f"    Payload: {payload_data[:100]}")
print("--- CodeAlpha Basic Network Sniffer Running ---")
print("Press Ctrl+C to stop...")
sniff(prn=packet_callback, store=0)
