from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime

print("=" * 60)
print("        CodeAlpha - Basic Network Sniffer")
print("=" * 60)

packet_count = 0

def packet_callback(packet):
    global packet_count
    packet_count += 1

    print("\n" + "=" * 60)
    print(f"Packet #{packet_count}")
    print("Time :", datetime.now().strftime("%H:%M:%S"))

    if packet.haslayer(IP):

        print("Source IP      :", packet[IP].src)
        print("Destination IP :", packet[IP].dst)

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print("Source Port    :", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print("Source Port    :", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        else:
            print("Protocol       : Other")

        print("Packet Length  :", len(packet))

print("\nSniffing Started...")
print("Press CTRL + C to Stop.\n")

sniff(prn=packet_callback, store=False, count=20)
print("\nCapture Completed Successfully!")