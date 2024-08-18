import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"Source IP : {src_ip} | Destination IP: {dst_ip} | protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = payload.decode('utf-8', 'ignore')
                print(f"TCP payload")
            except(IndexError, UnicodeDecodeError):
                print("Unable to decode TCP payload.")

        elif packet.hashlayer(scapy.UDP):
            try:
                payload = packet[scapy.Raw].load
                decoded_payload = packet[scapy.Raw].load
                print(f"UDP payload")
            except(IndexError, UnicodeDecodeError):
                print("Unable to decode UDP payload.")

def start_sniffing():
    scapy.sniff(store=False, prn=packet_callback)

start_sniffing()