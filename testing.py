import unittest
from unittest.mock import patch

from scapy.all import *
from scapy.all import IP, TCP, UDP, ARP, DNS, ICMP, SNMP, DHCP, BOOTP, L2TP, PPP, Raw, IPv6
from scapy.layers.l2 import Ether

from Scapy import ScapyClass as Scapy
# import Actions

packets = []

# IP addresses and ports for generating packets
ip_src = ['192.168.1.1', '10.0.0.1']
ip_dst = ['192.168.1.2', '10.0.0.2']
ports = [80, 443, 22, 53]

mac_src = "66:77:88:99:AA:BB"
mac_dst = "00:11:22:33:44:55"

eth_packets = [Ether(src=mac_src, dst=mac_dst)/IP(dst="8.8.8.8") for _ in range(2)]

packets.extend(eth_packets)

# Generate ICMP packets
for ip in ip_src:
    packets.append(IP(src=ip, dst=ip_dst[0])/ICMP())

# Generate TCP packets with different flags and ports
for port in ports:
    packets.append(IP(src=ip_src[0], dst=ip_dst[0])/TCP(sport=12345, dport=port, flags="S"))
    packets.append(IP(src=ip_src[1], dst=ip_dst[1])/TCP(sport=54321, dport=port, flags="A"))

# Generate UDP packets on different ports
for port in ports:
    packets.append(IP(src=ip_src[0], dst=ip_dst[1])/UDP(sport=12345, dport=port))
    packets.append(IP(src=ip_src[1], dst=ip_dst[0])/UDP(sport=54321, dport=port))

# Generate a DNS query packet
packets.append(IP(src=ip_src[0], dst=ip_dst[1])/UDP(sport=33333, dport=53)/DNS(rd=1, qd=DNSQR(qname="www.example.com")))

# Generate an HTTP packet (simple GET request over TCP)
payload = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
packets.append(IP(src=ip_src[0], dst=ip_dst[0])/TCP(sport=12345, dport=80)/Raw(load=payload))


class Test_scapy(unittest.TestCase):
    # @patch('pygame.init')
    def test_load_pcap(self):
        scapy = Scapy()
        resp = scapy.load_pcap("test_pcap_file.pcap")
        self.assertTrue(resp, "Tests whether a pcap loads successfully")
        pass

    def test_save_pcap(self):
        scapy = Scapy()
        scapy.packet_list = packets
        resp = scapy.save_pcap()
        self.assertTrue(resp, "Tests whether save was successful")
        pass

    def test_toggle_prot(self):
        scapy = Scapy()
        before = scapy.prot_toggle["ARP"]
        scapy.toggle_prot("ARP")
        after = scapy.prot_toggle["ARP"]
        self.assertNotEqual(before, after, "Checks if protocol boolean is toggled properly")
        pass

    def test_reset_packets(self):
        scapy = Scapy()
        scapy.packet_list = packets
        scapy.reset_packets()
        self.assertEqual(scapy.packet_list, scapy.filtered_packets)
        pass

    def test_toggle_reset(self):
        scapy = Scapy()
        scapy.packet_list = packets
        scapy.toggle_prot("TCP")
        scapy.toggle_reset()
        self.assertNotEqual(packets, scapy.filtered_packets, "Tests that list is no longer the same")
        check = True
        for t in scapy.filtered_packets:
            if not t.haslayer(TCP):
                check = False
        self.assertTrue(check, "Tests whether the packet list is now only the chosen protocol")
        pass

    def test_filter_packets(self):
        scapy = Scapy()
        scapy.filtered_packets = packets
        scapy.filter_packets("eth=---")
        check = True
        for i in scapy.filtered_packets:
            if i[Ether].src != "---" and i[Ether].dst != "---":
                check = False
        self.assertTrue(check, "Checking that list is filtered by eth")

        scapy.filtered_packets = packets
        scapy.filter_packets("src_eth=---")
        check = True
        for i in scapy.filtered_packets:
            if i[Ether].src != "---":
                check = False
        self.assertTrue(check, "Checking that list is filtered by eth.src")
        #
        # scapy.filtered_packets = packets
        # scapy.filter_packets("dst_eth=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[Ether].dst != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by eth.dst")
                #
        # scapy.filtered_packets = packets
        # scapy.filter_packets("ip=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[IP].src != "---" and i[IP].dst != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by ip")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("src_ip=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[IP].src != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by ip.src")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("dst_ip=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[IP].dst != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by ip.dst")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("len=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if len(i[IP]) != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by len")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("ttl=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[IP].ttl != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by ttl")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("ttl=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[IP].ttl != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by ttl")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("ver=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[IP].version != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by ver")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("seq=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[TCP].seq != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by seq")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("ack=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[IP].ack != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by ack")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("urgptr=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[TCP].urgptr != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by urgptr")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("icmp_type=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[ICMP].type != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by icmp_type")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("icmp_code=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[ICMP].code != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by icmp_code")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("dns_qn=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[DNS].qd.qname != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by qn")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("dns_qr=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[DNS].qr != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by qr")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("http_mthd=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[HTTP].Method != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by http_method")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("http_host=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[HTTP].Host != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by http_host")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("http_uri=---")
        # check = True
        # for i in scapy.filtered_packets:
            # if i[HTTP].Uri != "---":
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by http_uri")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("port=---")
        # check = True
        # t = "---"
        # for i in scapy.filtered_packets:
            # if i.haslayer(TCP) and (i[TCP].sport != int(t) and i[TCP].dport != int(t)) or i.haslayer(UDP) and (i[UDP].sport != int(t) and i[UDP].dport != int(t)):
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by port")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("sport=---")
        # check = True
        # t = "---"
        # for i in scapy.filtered_packets:
            # if i.haslayer(TCP) and i[TCP].sport != int(t) or i.haslayer(UDP) and i[UDP].sport != int(t):
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by src_port")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("dport=---")
        # check = True
        # t = "---"
        # for i in scapy.filtered_packets:
            # if i.haslayer(TCP) and i[TCP].dport != int(t) or i.haslayer(UDP) and i[UDP].dport != int(t):
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by dst_port")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("prot=TCP")
        # check = True
        # t = "---"
        # for i in scapy.filtered_packets:
            # if not i.haslayer(TCP):
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by prot")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("flags=---")
        # check = True
        # t = "---"
        # for i in scapy.filtered_packets:
            # if pkt.haslayer(TCP) and pkt[TCP].flags != x or pkt.haslayer(UDP) and pkt[UDP].flags != x:
                # check = False
        # self.assertTrue(check, "Checking that list is filtered by src_port")

    # def test_sniff(self):
        # scapy = Scapy()
        # resp = scapy.sniff(("wlp1s0", 20))
        # self.assertTrue(resp, "Checks whether sniff succeeded")



unittest.main()
