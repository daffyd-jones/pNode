from scapy.all import *
from scapy.all import IP, TCP, UDP, ARP, DNS, Ether
from datetime import datetime

def protocol(self, type):
    match type:
        case "ARP":
            return [pkt for pkt in self.filtered_packets if pkt.haslayer(ARP)]
        case "DNS":
            return [pkt for pkt in self.filtered_packets if pkt.haslayer(DNS)]
        case "IP":
            return [pkt for pkt in self.filtered_packets if IP in pkt]
        case "TCP":
            return [pkt for pkt in self.filtered_packets if TCP in pkt]
        case "UDP":
            return [pkt for pkt in self.filtered_packets if UDP in pkt]
        case "HTTP":
            return [pkt for pkt in self.filtered_packets if TCP in pkt and (pkt[TCP].dport == 80 or (pkt.haslayer(Raw) and "HTTP" in str(pkt[Raw].load)))]
        case "SSH":
            return [pkt for pkt in self.filtered_packets if TCP in pkt and (pkt[TCP].dport == 22 or pkt[TCP].sport == 22)]
        case "ICMP":
            return [pkt for pkt in self.filtered_packets if ICMP in pkt]
        case "IGMP":
            return [pkt for pkt in self.filtered_packets if IP in pkt and pkt[IP].proto == 2]

    pass

class ScapyClass:
    def __init__(self):
        self.packet_list = None;
        self.filtered_packets = None;
        self.op_dict = {
            "eth": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(Ether) and (pkt[Ether].src == x or pkt[Ether].dst == x)],
            "src_eth": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(Ether) and pkt[Ether].src == x],
            "dst_eth": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(Ether) and pkt[Ether].dst == x],
            "ip": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(IP) and (pkt[IP].src == x or pkt[IP].dst == x)],
            "src_ip": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(IP) and pkt[IP].src == x],
            "dst_ip": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(IP) and pkt[IP].dst == x],
            "len": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(IP) and len(pkt[IP]) == x],
            "ttl": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(IP) and pkt[IP].ttl == x],
            "ver": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(IP) and pkt[IP].version == x],
            "seq": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(TCP) and pkt[TCP].seq == int(x)],
            "ack": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(TCP) and pkt[TCP].ack == int(x)],
            "urgptr": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(TCP) and pkt[TCP].urgptr == x],
            "icmp_type": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(ICMP) and pkt[ICMP].type == x],
            "icmp_code": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(ICMP) and pkt[ICMP].code == int(x)],
            "dns_qn": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(DNS) and pkt[DNS].qd.qname == x],
            "dns_qr": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(DNS) and pkt[DNS].qr == x],
            "http_mthd": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(HTTP) and pkt[HTTP].Method == x],
            "http_host": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(HTTP) and pkt[HTTP].Host == x],
            "http_uri": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(HTTP) and pkt[HTTP].Uri == x],
            "port": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(TCP) and (pkt[TCP].sport == int(x) or pkt[TCP].dport == int(x)) or pkt.haslayer(UDP) and (pkt[UDP].sport == int(x) or pkt[UDP].dport == int(x))],
            "sport": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(TCP) and pkt[TCP].sport == int(x) or pkt.haslayer(UDP) and pkt[UDP].sport == int(x)],
            "dport": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(TCP) and pkt[TCP].dport == int(x) or pkt.haslayer(UDP) and pkt[UDP].sport == int(x)],
            "prot": lambda x: protocol(self, x),
            "flags": lambda x: [pkt for pkt in self.filtered_packets if pkt.haslayer(TCP) and pkt[TCP].flags == x or pkt.haslayer(UDP) and pkt[UDP].flags == x],
        }
        self.prot_toggle = {
            "ARP": False,
            "DNS": False,
            "IP": False,
            "TCP": False,
            "UDP": False,
            "HTTP": False,
            "SSH": False,
            "ICMP": False,
            "IGMP": False,
        }

    def load_pcap(self, path):
        try:
            self.packet_list = rdpcap(path)
            self.filtered_packets = self.packet_list
            # for packet in self.packet_list:
            # print(packet.summary())
            return True
        except FileNotFoundError as e:
            return False

    def save_pcap(self):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        file_name = f"captured_packets_{timestamp}.pcap"
        try:
            wrpcap(file_name, self.packet_list)
            return True
        except FileNotFoundError as e:
            return False


    def toggle_prot(self, prot):
        self.prot_toggle[prot] = not self.prot_toggle[prot]

    def reset_packets(self):
        self.filtered_packets = self.packet_list

    def toggle_reset(self):
        self.filtered_packets = self.packet_list
        for k, v in self.prot_toggle.items():
            if v:
                s = f"prot={k}"
                self.filter_packets(s)


    def filter_packets(self, filter_string):
        #filter packets based on string with filter requirements
        #"src_ip=x.x.x.x sport=6666 prot=TCP"

        # test = "src_ip=127.0.0.1 sport=6666 prot=TCP"
        parts = filter_string.split(" ")
        for part in parts:
            temp = part.split("=")
            if temp[0] in self.op_dict:
                try:
                    self.filtered_packets = self.op_dict[temp[0]](temp[1])
                except:
                    return False
            else:
                print("filter failed")
                return False
        return True
        # for p in self.filtered_packets:
            # print(p.summary())
        pass

    def sniff(self, args):
        try:
            print(f"iface | {args[1]} {args[2]} ")
            temp = sniff(iface=args[1], count=int(args[2]))
            self.packet_list = temp
            self.filtered_packets = temp
            print("succeeded sniffing")
            return True
        except:
            print("failed sniffing")
            return False
        # print(f"{temp}")
        # for packet in self.packet_list:
            # print(packet.summary())


    def get_filtered_packets(self):
        return self.filtered_packets;

    def get_packet_list(self):
        return self.packet_list



