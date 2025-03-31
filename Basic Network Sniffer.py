from scapy.all import sniff

def packet_handler(packet):
    source = packet.src if hasattr(packet, 'src') else 'Unknown'
    destination = packet.dst if hasattr(packet, 'dst') else 'Unknown'
    protocol = packet.proto if hasattr(packet, 'proto') else 'Unknown'
    
    print(f"Source: {source}, Destination: {destination}, Protocol: {protocol}")

sniff(prn=packet_handler, count=10)
