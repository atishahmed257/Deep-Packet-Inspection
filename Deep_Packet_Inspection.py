# Import required modules
from scapy.all import sniff, IP, TCP, UDP, Raw

def analyze_packet(packet)

  print("\n--- Packet Captured ---")
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        
        if packet.haslayer(TCP):
            print("Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print("Protocol: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        else:
            print("Protocol: Other")

        # Check for application layer payloads
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload[:50]}...")  # Display the first 50 bytes of payload
    else:
        print("Non-IP packet detected.")

def main():
    
    print("Starting packet capture...")
    # Sniff network packets and apply the analyze_packet function
    sniff(filter="ip", prn=analyze_packet, count=10)  # Capture 10 packets with IP filter
    print("Packet capture completed.")

if __name__ == "__main__":
    main()
