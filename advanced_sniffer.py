from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest
from scapy.packet import Raw

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        
        protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, "Other")
        
        print(f"\n=== New Packet ===")
        print(f"Protocol: {protocol_name}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")

        if protocol_name == "TCP" and packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                print(f"HTTP Method: {http_layer.Method.decode()}")
                print(f"HTTP Host: {http_layer.Host.decode()}")
                print(f"HTTP Path: {http_layer.Path.decode()}")
            if packet.haslayer(Raw):
                print(f"Raw Data: {packet[Raw].load[:50]}...")  # Print first 50 bytes of payload
        elif protocol_name == "UDP" and packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
        elif protocol_name == "ICMP" and packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            print(f"ICMP Type: {icmp_layer.type}")
            print(f"ICMP Code: {icmp_layer.code}")
        
        print("-" * 60)

def main():
    print("Starting advanced network packet sniffer...")
    # Use filter to capture only IP packets optionally customize
    sniff(filter="ip", prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
