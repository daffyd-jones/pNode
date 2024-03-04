from scapy.all import *
from random import randint, choice

# Function to generate a random IP address
def random_ip():
    return ".".join(str(randint(0, 255)) for _ in range(4))

# Generate a list of random IP addresses
# ip_addresses = [random_ip() for _ in range(10)]
ip_addresses = ['192.168.1.2', '10.0.0.2', '192.168.1.1', '10.0.0.1']


# Define a variety of ports for different services
ports = [20, 21, 22, 23, 25, 53, 80, 110, 443, 8080]

# Create an empty list to hold the packets
packets = []

# Generate ICMP Echo Request packets
for ip in ip_addresses[:5]:
    packets.append(IP(src=choice(ip_addresses), dst=choice(ip_addresses))/ICMP(type=8, code=0))

# Generate TCP packets with various flags
tcp_flags = ['S', 'A', 'F', 'R', 'P', 'U']
for _ in range(10):
    packets.append(IP(src=choice(ip_addresses), dst=choice(ip_addresses))/
                   TCP(sport=randint(1024, 65535), dport=choice(ports), flags=choice(tcp_flags)))

# Generate UDP packets with random payload sizes
for _ in range(5):
    payload_size = randint(50, 1500)  # Random payload size between 50 and 1500 bytes
    packets.append(IP(src=choice(ip_addresses), dst=choice(ip_addresses))/
                   UDP(sport=randint(1024, 65535), dport=choice(ports))/
                   Raw(load=RandString(size=payload_size)))

# Generate DNS query and response packets
for _ in range(5):
    query_pkt = IP(src=choice(ip_addresses), dst=choice(ip_addresses))/\
                UDP(sport=randint(1024, 65535), dport=53)/\
                DNS(rd=1, qd=DNSQR(qname="example.com"))
    packets.append(query_pkt)
    response_pkt = IP(src=choice(ip_addresses), dst=query_pkt[IP].src)/\
                   UDP(sport=53, dport=query_pkt[UDP].sport)/\
                   DNS(qr=1, aa=1, rd=1, ra=1, qd=query_pkt[DNS].qd,
                       an=DNSRR(rrname="example.com", ttl=86400, rdata=random_ip()))
    packets.append(response_pkt)

# Generate a more complex HTTP GET request
http_payload = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Scapy\r\nAccept: */*\r\n\r\n"
packets.append(IP(src=choice(ip_addresses), dst=choice(ip_addresses))/
               TCP(sport=randint(1024, 65535), dport=80)/
               Raw(load=http_payload))

# mac_src = random_mac()
# mac_dst = random_mac()

mac_src = "66:77:88:99:AA:BB"
mac_dst = "00:11:22:33:44:55"

eth_packets = [Ether(src=mac_src, dst=mac_dst)/IP(dst="8.8.8.8") for _ in range(2)]

packets.extend(eth_packets)

# Modify some IP packets for specific src, dst, len, ttl, ver
packets.append(IP(src="192.168.0.1", dst="10.0.0.1", ttl=64)/TCP())
packets.append(IP(src="10.0.0.1", dst="192.168.0.1", version=4, len=100)/UDP())

# TCP and UDP packets for seq, ack, urgptr, port, sport, dport, flags
packets.append(IP()/TCP(sport=12345, dport=80, flags="S", seq=1000, ack=1001))
packets.append(IP()/UDP(sport=12345, dport=53))

# ICMP packets for type and code
packets.append(IP()/ICMP(type=8, code=0))  # Echo request
packets.append(IP()/ICMP(type=0, code=0))  # Echo reply

# DNS packets for dns_qn, dns_qr
packets.append(IP()/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com")))
packets.append(IP()/UDP(sport=53)/DNS(qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", ttl=86400, rdata="1.2.3.4")))

# Simulate HTTP packets using Raw layer for http_mthd, http_host, http_uri
http_request_packet = IP(dst="93.184.216.34")/TCP(dport=80)/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
packets.append(http_request_packet)

# Path to save the pcap file
pcap_path = "enhanced_test_pcap_file.pcap"

# Write the packets to the pcap file
wrpcap(pcap_path, packets)

print(f"Enhanced PCAP file created: {pcap_path}")
