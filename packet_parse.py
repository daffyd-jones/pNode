#packetparse
from scapy.all import *
from scapy.all import IP, TCP, UDP, ARP, DNS, ICMP, SNMP, DHCP, BOOTP, L2TP, PPP, Raw, IPv6
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3gr, IGMPv3mq, IGMPv3mr, IGMPv3mra


from datetime import datetime
import random

from scapy.layers.l2 import Ether


def post_list(pkt):
    to_show = []
    datetime_obj = datetime.fromtimestamp(float(pkt.time))
    ether_frame = {
        "hdr_type": "ether",
        "time": datetime_obj.strftime("%Y-%m-%d %H:%M:%S.%f"),
        "length": str(len(raw(pkt))),
        "src_mac": pkt.src,
        "dst_mac": pkt.dst
    }
    to_show.append(ether_frame)
    if pkt.haslayer(IP):
        ip = {
            "hdr_type": "ip",
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "ver": str(pkt[IP].version),
            "hed_len": str(pkt[IP].ihl),
            "tot_len": str(pkt[IP].len),
            "id": str(pkt[IP].id),
            "flag": str(pkt[IP].flags),
            "ttl": str(pkt[IP].ttl),
            "prot": str(pkt[IP].proto)
        }
        to_show.append(ip)
    if pkt.haslayer(IPv6):
        ip6 = {
            "hdr_type": "ip6",
            "src": str(pkt[IPv6].src),
            "dst": str(pkt[IPv6].dst),
            "tc": str(pkt[IPv6].tc),
            "fl": str(pkt[IPv6].fl),
            "plen": str(pkt[IPv6].plen),
            "nh": str(pkt[IPv6].nh),
            "hlim": str(pkt[IPv6].hlim),
        }
        to_show.append(ip6)
        if pkt.haslayer(IPv6ExtHdrHopByHop):
            ip6_hop = {
                "hdr_type": "ip6_hop",
                "nh": str(pkt[IPv6ExtHdrHopByHop].nh),
                "len": str(pkt[IPv6ExtHdrHopByHop].len),
                "options": pkt[IPv6ExtHdrHopByHop].options,
            }
            to_show.append(ip6_hop)
        if pkt.haslayer(IPv6ExtHdrDestOpt):
            ip6_dest_ops = {
                "hdr_type": "ip6_dest_ops",
                "nh": str(pkt[IPv6ExtHdrDestOpt].nh),
                "len": str(pkt[IPv6ExtHdrDestOpt].len),
                "options": pkt[IPv6ExtHdrDestOpt].options,
            }
            to_show.append(ip6_dest_ops)
        if pkt.haslayer(IPv6ExtHdrRouting):
            ip6_routing = {
                "hdr_type": "ip6_routing",
                "nh": str(pkt[IPv6ExtHdrRouting].nh),
                "len": str(pkt[IPv6ExtHdrRouting].len),
                "type": str(pkt[IPv6ExtHdrRouting].type),
                "segleft": str(pkt[IPv6ExtHdrRouting].segleft),
                "addr": str(pkt[IPv6ExtHdrRouting].addresses),
            }
            to_show.append(ip6_routing)
        if pkt.haslayer(IPv6ExtHdrFragment):
            ip6_fragment = {
                "hdr_type": "ip6_fragment",
                "nh": str(pkt[IPv6ExtHdrFragment].nh),
                "offset": str(pkt[IPv6ExtHdrFragment].offset),
                "m": str(pkt[IPv6ExtHdrFragment].m),
                "id": str(pkt[IPv6ExtHdrFragment].id),
            }
            to_show.append(ip6_fragment)
        if pkt.haslayer(ICMPv6EchoRequest):
            icmp6_echo_req = {
                "hdr_type": "icmp6_echo_req",
                "type": str(pkt[ICMPv6EchoRequest].type),
                "code": str(pkt[ICMPv6EchoRequest].code),
                "cksum": str(pkt[ICMPv6EchoRequest].cksum),
                "id": str(pkt[ICMPv6EchoRequest].id),
                "seq": str(pkt[ICMPv6EchoRequest].seq),
                "data": str(pkt[ICMPv6EchoRequest].data),
            }
            to_show.append(ip6_echo_req)
        if pkt.haslayer(ICMPv6EchoReply):
            icmp6_echo_rep = {
                "hdr_type": "icmp6_echo_rep",
                "type": str(pkt[ICMPv6EchoReply].type),
                "code": str(pkt[ICMPv6EchoReply].code),
                "cksum": str(pkt[ICMPv6EchoReply].cksum),
                "id": str(pkt[ICMPv6EchoReply].id),
                "seq": str(pkt[ICMPv6EchoReply].seq),
                "data": str(pkt[ICMPv6EchoReply].data),
            }
            to_show.append(ICMPv6EchoReply)
        if pkt.haslayer(ICMPv6DestUnreach):
            icmp6_dest_un = {
                "hdr_type": "icmp6_dest_un",
                "type": str(pkt[ICMPv6DestUnreach].type),
                "code": str(pkt[ICMPv6DestUnreach].code),
                "cksum": str(pkt[ICMPv6DestUnreach].cksum),
                "length": str(pkt[ICMPv6DestUnreach].length),
            }
            to_show.append(icmp6_dest_un)
        if pkt.haslayer(ICMPv6PacketTooBig):
            icmp6_too_big = {
                "hdr_type": "icmp6_too_big",
                "type": str(pkt[ICMPv6PacketTooBig].type),
                "code": str(pkt[ICMPv6PacketTooBig].code),
                "cksum": str(pkt[ICMPv6PacketTooBig].cksum),
                "mtu": str(pkt[ICMPv6PacketTooBig].mtu),
            }
            to_show.append(icmp6_too_big)
        if pkt.haslayer(ICMPv6TimeExceeded):
            icmp6_time_ex = {
                "hdr_type": "icmp6_time_ex",
                "type": str(pkt[ICMPv6TimeExceeded].type),
                "code": str(pkt[ICMPv6TimeExceeded].code),
                "cksum": str(pkt[ICMPv6TimeExceeded].cksum),
                "length": str(pkt[ICMPv6TimeExceeded].length),
            }
            to_show.append(icmp6_time_ex)
        if pkt.haslayer(ICMPv6ParamProblem):
            icmp6_param_prob = {
                "hdr_type": "icmp6_param_prob",
                "type": str(pkt[ICMPv6ParamProblem].type),
                "code": str(pkt[ICMPv6ParamProblem].code),
                "cksum": str(pkt[ICMPv6ParamProblem].cksum),
                "ptr": str(pkt[ICMPv6ParamProblem].ptr),
            }
            to_show.append(icmp6_param_prob)
        if pkt.haslayer(ICMPv6NIQueryIPv4):
            icmp6_ni_quer = {
                "hdr_type": "icmp6_ni_quer",
                "type": str(pkt[ICMPv6NIQueryIPv4].type),
                "code": str(pkt[ICMPv6NIQueryIPv4].code),
                "cksum": str(pkt[ICMPv6NIQueryIPv4].cksum),
                "qtype": str(pkt[ICMPv6NIQueryIPv4].qtype),
                "flags": str(pkt[ICMPv6NIQueryIPv4].flags),
                "data": str(pkt[ICMPv6NIQueryIPv4].data),
            }
            to_show.append(icmp6_ni_quer)
        if pkt.haslayer(ICMPv6NIReplyIPv4):
            icmp6_ni_rep = {
                "hdr_type": "icmp6_ni_rep",
                "type": str(pkt[ICMPv6NIReplyIPv4].type),
                "code": str(pkt[ICMPv6NIReplyIPv4].code),
                "cksum": str(pkt[ICMPv6NIReplyIPv4].cksum),
                "qtype": str(pkt[ICMPv6NIReplyIPv4].qtype),
                "flags": str(pkt[ICMPv6NIReplyIPv4].flags),
                "data": str(pkt[ICMPv6NIReplyIPv4].data),
            }
            to_show(icmp6_ni_rep)
        if pkt.haslayer(ICMPv6ND_RS):
            icmp6_nd_rs = {
                "hdr_type": "icmp6_nd_rs",
                "type": str(pkt[ICMPv6ND_RS].type),
                "code": str(pkt[ICMPv6ND_RS].code),
                "cksum": str(pkt[ICMPv6ND_RS].cksum),
                "res": str(pkt[ICMPv6ND_RS].res),
            }
            to_show.append(icmp6_nd_rs)
        if pkt.haslayer(ICMPv6ND_RA):
            icmp6_nd_ra = {
                "hdr_type": "icmp6_nd_ra",
                "type": str(pkt[ICMPv6ND_RA].type),
                "code": str(pkt[ICMPv6ND_RA].code),
                "cksum": str(pkt[ICMPv6ND_RA].cksum),
                "cglim": str(pkt[ICMPv6ND_RA].chlim),
                "M": str(pkt[ICMPv6ND_RA].M),
                "O": str(pkt[ICMPv6ND_RA].O),
                "H": str(pkt[ICMPv6ND_RA].H),
                "prf": str(pkt[ICMPv6ND_RA].prf),
                "P": str(pkt[ICMPv6ND_RA].P),
                "res": str(pkt[ICMPv6ND_RA].res),
                "routlt": str(pkt[ICMPv6ND_RA].routerlifetime),
                "retime": str(pkt[ICMPv6ND_RA].reachabletime),
                "rettimer": str(pkt[ICMPv6ND_RA].retranstimer),
            }
            to_show.append(icmp6_nd_ra)
        if pkt.haslayer(ICMPv6ND_NS):
            icmp6_nd_ns = {
                "hdr_type": "icmp6_nd_ns",
                "type": str(pkt[ICMPv6ND_NS].type),
                "code": str(pkt[ICMPv6ND_NS].code),
                "cksum": str(pkt[ICMPv6ND_NS].cksum),
                "res": str(pkt[ICMPv6ND_NS].res),
                "tgt": str(pkt[ICMPv6ND_NS].tgt),
            }
            to_show.append(icmp6_nd_ns)
        if pkt.haslayer(ICMPv6ND_NA):
            icmp6_nd_na = {
                "hdr_type": "icmp6_nd_na",
                "type": str(pkt[ICMPv6ND_NA].type),
                "code": str(pkt[ICMPv6ND_NA].code),
                "cksum": str(pkt[ICMPv6ND_NA].cksum),
                "R": str(pkt[ICMPv6ND_NA].R),
                "S": str(pkt[ICMPv6ND_NA].S),
                "O": str(pkt[ICMPv6ND_NA].O),
                "res": str(pkt[ICMPv6ND_NA].res),
                "tgt": str(pkt[ICMPv6ND_NA].tgt),
            }
            to_show.append(icmp6_nd_na)
        if pkt.haslayer(ICMPv6MLReport):
            icmp6_ml_rep = {
                "hdr_type": "icmp6_ml_rep",
                "type": str(pkt[ICMPv6MLReport].type),
                "code": str(pkt[ICMPv6MLReport].code),
                "chksum": str(pkt[ICMPv6MLReport].cksum),
                "mrd": str(pkt[ICMPv6MLReport].mrd),
                "mladdr": str(pkt[ICMPv6MLReport].mladdr),
            }
            to_show.append(icmp6_ml_rep)
        if pkt.haslayer(ICMPv6MLReport2):
            icmp6_ml_rep2 = {
                "hdr_type": "icmp6_ml_rep2",
                "type": str(pkt[ICMPv6MLReport2].type),
                "res": str(pkt[ICMPv6MLReport2].res),
                "chksum": str(pkt[ICMPv6MLReport2].cksum),
                "records_number": str(pkt[ICMPv6MLReport2].records_number),
                "records": pkt[ICMPv6MLReport2].records,
            }
            to_show.append(icmp6_ml_rep2)
    if pkt.haslayer(AH):
        auth = {
            "hdr_type": "auth",
            "nh": str(pkt[AH].nh),
            "playlen": str(pkt[AH].payloadlen),
            "spi": str(pkt[AH].spi),
            "seq": str(pkt[AH].seq),
            "icv": str(pkt[AH].icv),
        }
        to_show.append(auth)
    if pkt.haslayer(ESP):
        esp = {
            "hdr_type": "esp",
            "spi": str(pkt[ESP].spi),
            "seq": str(pkt[ESP].seq),
            "data": str(pkt[ESP].data),
        }
        to_show.append(esp)
    if pkt.haslayer(TCP):
        tcp = {
            "hdr_type": "tcp",
            "src_port": str(pkt[TCP].sport),
            "dst_port": str(pkt[TCP].dport),
            "seq": str(pkt[TCP].seq),
            "ack": str(pkt[TCP].ack),
            "data_off": str(pkt[TCP].dataofs),
            "res": str(pkt[TCP].reserved),
            "flags": str(pkt[TCP].flags),
            "window": str(pkt[TCP].window),
            "checksum": str(pkt[TCP].chksum),
            "urg_point": str(pkt[TCP].urgptr),
            "options": pkt[TCP].options,
        }
        to_show.append(tcp)
    if pkt.haslayer(UDP):
        udp = {
            "hdr_type": "udp",
            "src_port": str(pkt[UDP].sport),
            "dst_port": str(pkt[UDP].dport),
            "len": str(pkt[UDP].len),
            "checksum": str(pkt[UDP].chksum),
        }
        to_show.append(udp)
        if pkt.haslayer(DNS):
            dns = {
                "hdr_type": "dns",
                "tran_id": str(pkt[DNS].id),
                # "flags": pkt[DNS].flags,
                "questions": str(pkt[DNS].qdcount),
                "answers": str(pkt[DNS].ancount),
                "auth_rrs": str(pkt[DNS].nscount),
                "add_rrs": str(pkt[DNS].arcount),
                "qr": str(pkt[DNS].qr),
                "opcode": str(pkt[DNS].opcode),
                "aa": str(pkt[DNS].aa),
                "tc": str(pkt[DNS].tc),
                "rd": str(pkt[DNS].rd),
                "ra": str(pkt[DNS].ra),
                "z": str(pkt[DNS].z),
                "rcode": str(pkt[DNS].rcode),
            }
            to_show.append(dns)
    if pkt.haslayer(ICMP):
        icmp = {}
        icmp["hdr_type"] = "icmp"
        ttype = str(pkt[ICMP].type)
        code = str(pkt[ICMP].code)
        icmp["type"] = ttype
        icmp["code"] = code
        if ttype in [0, 8]:
            icmp["id"] = str(pkt[ICMP].id)
            icmp["seq"] = str(pkt[ICMP].seq)
        elif ttype == 3:
            if code == 4:
                icmp["unused"] = str(pkt[ICMP].unused)
        elif ttype == 4:
            pass
        elif ttype == 5:
            icmp["gw"] = str(pkt[ICMP].gw)
        elif ttype == 11:
            pass
        elif ttype == 12:
            icmp["ptr"] = str(pkt[ICMP].ptr)
        to_show.append(icmp)
    if IP in pkt and pkt[IP].proto == 2:
        print(pkt.show())
        igmp = {}
        igmp["hdr_type"] = "igmp"
        if pkt.haslayer(IGMP):
            print("Hey man its ok")
            igmp["ver"] = "0"
            igmp["type"] = str(pkt[IGMP].type)
            igmp["mrt"] = str(pkt[IGMP].mrcode)
            igmp["check"] = str(pkt[IGMP].chksum)
            igmp["group"] = str(pkt[IGMP].gaddr)
        elif pkt.haslayer(IGMPv3):
            igmp["ver"] = "1"
            igmp["type"] = str(pkt[IGMPv3].type)
            igmp["mrcode"] = str(pkt[IGMPv3].mrcode)
            igmp["check"] = str(pkt[IGMPv3].chksum)
        to_show.append(igmp)
    if pkt.haslayer(IGMPv3gr):
        igmp3gr = {
            "hdr_type": "igmp3_gr",
            "rtype": str(pkt[IGMPv3gr].rtype),
            "auxdlen": str(pkt[IGMPv3gr].auxdlen),
            "numsrc": str(pkt[IGMPv3gr].numsrc),
            "maddr": str(pkt[IGMPv3gr].maddr),
            "srcaddrs": pkt[IGMPv3gr].srcaddrs,
        }
        to_show.append(igmp3gr)
    if pkt.haslayer(IGMPv3mq):
        igmp3mq = {
            "hdr_type": "igmp3_mq",
            "gaddr": str(pkt[IGMPv3mq].gaddr),
            "s": str(pkt[IGMPv3mq].s),
            "qrv": str(pkt[IGMPv3mq].qrv),
            "qqic": str(pkt[IGMPv3mq].qqic),
            "numsrc": str(pkt[IGMPv3mq].numsrc),
            "srcaddrs": pkt[IGMPv3mq].srcaddrs,
        }
        to_show.append(igmp3mq)
    if pkt.haslayer(IGMPv3mra):
        igmp3mra = {
            "hdr_type": "igmp3_mra",
            "qryIntvl": str(pkt[IGMPv3mra].qryIntvl),
            "robust": str(pkt[IGMPv3mra].robust),
        }
        to_show.append(igmp3mra)
    if pkt.haslayer(IGMPv3mr):
        igmp3mr = {
            "hdr_type": "igmp3_mr",
            "numgrp": str(pkt[IGMPv3mr].numgrp),
            "records": pkt[IGMPv3mr].records,
        }
        to_show.append(igmp3mr)
    if pkt.haslayer(ARP):
        arp = {
            "hdr_type": "arp",
            "hw_type": str(pkt[ARP].hwtype),
            "prot_type": str(pkt[ARP].ptype),
            "hw_len": str(pkt[ARP].hwlen),
            "prot_len": str(pkt[ARP].plen),
            "opcode": str(pkt[ARP].op),
            "hw_src": str(pkt[ARP].hwsrc),
            "prot_src": str(pkt[ARP].psrc),
            "hw_dst": str(pkt[ARP].hwdst),
            "prot_dst": str(pkt[ARP].pdst),
        }
        to_show.append(arp)
    if pkt.haslayer(TCP):
        if str(pkt[TCP].payload) != "Raw":
            pl = {}
            pl["hdr_type"] = "payload"
            # print(f"!@@!!@ {pkt[TCP].payload}")
            try:
                pl["payload"] = str(pkt[TCP].payload.decode())
            except:
                pl["payload"] = str(pkt[TCP].payload)
            to_show.append(pl)
        pass
    elif pkt.haslayer(UDP):
        if str(pkt[UDP].payload) != "Raw":
            pl = {}
            pl["hdr_type"] = "payload"
            try:
                pl["payload"] = str(pkt[UDP].payload.decode())
            except:
                pl["payload"] = str(pkt[UDP].payload)
            to_show.append(pl)
    if pkt.haslayer(Raw):
        r = {
            "hdr_type": "raw",
            "str": pkt.getlayer(Raw).load,
        }
        to_show.append(r)
    return to_show


def post_node(elem):
    to_show = []
    pkts = elem.get_packet_list()
    mac = elem.get_mac()
    host_ip4 = None
    host_ip6 = None
    in_traffic = []
    out_traffic = []
    for p in pkts:
        # print(p.show())
        if p.haslayer(Ether):
            if p[Ether].src == mac:
                temp = str(p[Ether].dst)
                if p.haslayer(IP):
                    if host_ip4 == None:
                        host_ip4 = p[IP].src
                    temp = f"{p[IP].dst}"
                    prot = p[IP].proto
                elif p.haslayer(IPv6):
                    if host_ip6 == None:
                        host_ip6 = p[IPv6].src
                    temp = f"{p[IPv6].dst}"
                    prot = p[IPv6].nh
                if p.haslayer(TCP):
                    temp = f"{p[TCP].sport} -> {temp}"
                if p.haslayer(UDP):
                    temp = f"{p[UDP].sport} -> {temp}"
                #
                tempp = None
                if p.haslayer(IP) or p.haslayer(IPv6):
                    tempp = f"{temp} | {prot}"
                #
                if tempp and tempp not in out_traffic:
                    out_traffic.append(tempp)
                if p.haslayer(ARP):
                    if host_ip4 == None:
                        host_ip4 = p[ARP].psrc
                    temp = f"{p[ARP].psrc} -> {p[ARP].pdst} | ARP"
                    out_traffic.append(temp)
            elif p[Ether].dst == mac:
                temp = str(p[Ether].src)
                if p.haslayer(IP):
                    if host_ip4 == None:
                        host_ip4 = p[IP].dst
                    temp = f"{p[IP].src}"
                    prot = p[IP].proto
                elif p.haslayer(IPv6):
                    if host_ip6 == None:
                        host_ip6 = p[IPv6].dst
                    temp = f"{p[IPv6].src}"
                    prot = p[IPv6].nh
                if p.haslayer(TCP):
                    temp = f"{p[TCP].dport} <- {temp}"
                if p.haslayer(UDP):
                    temp = f"{p[UDP].dport} <- {temp}"
                #
                tempp = None
                if p.haslayer(IP) or p.haslayer(IPv6):
                    tempp = f"{temp} | {prot}"
                #
                if tempp and tempp not in in_traffic:
                    in_traffic.append(tempp)
                if p.haslayer(ARP):
                    if host_ip4 == None:
                        host_ip4 = p[ARP].pdst
                    temp = f"{p[ARP].pdst} <- {p[ARP].psrc} | ARP"
                    in_traffic.append(temp)
    host = {
        "hdr_type": "host",
        "host_mac": mac,
        "host_ip4": host_ip4,
        "host_ip6": host_ip6,
    }
    to_show.append(host)
    traffic = {
        "hdr_type": "traffic",
        "out_traffic": out_traffic,
        "in_traffic": in_traffic,
    }
    to_show.append(traffic)
    return to_show

def post_conn(elem):
    to_show = []
    pkts = elem.get_packet_list()
    mac_one = elem.get_mac_one()
    mac_two = elem.get_mac_two()
    traffic = []
    arp = []
    for p in pkts:
        if p.haslayer(Ether):
            if p[Ether].src == mac_one:
                temp = f"{p[Ether].src} -> {p[Ether].dst}"
                if p.haslayer(IP):
                    ips = f"{p[IP].src}:"
                    ipd = f"{p[IP].dst}:"
                    temp = f"{p[IP].src} -> {p[IP].dst}"
                    prot = p[IP].proto
                elif p.haslayer(IPv6):
                    ips = f"{p[IPv6].src}:"
                    ipd = f"{p[IPv6].dst}:"
                    temp = f"{p[IPv6].src} -> {p[IPv6].dst}"
                    prot = p[IPv6].nh
                if p.haslayer(TCP):
                    temp = f"{ips} {p[TCP].sport} -> {ipd} {p[TCP].dport} | {prot}"
                if p.haslayer(UDP):
                    temp = f"{ips} {p[UDP].sport} -> {ipd} {p[UDP].dport} | {prot}"
                if temp and temp not in traffic:
                    traffic.append(temp)
                if p.haslayer(ARP):
                    temp = f"{p[ARP].psrc} -> {p[ARP].pdst}"
                    traffic.append(temp)
            else:
                temp = f"{p[Ether].dst} <- {p[Ether].src}"
                if p.haslayer(IP):
                    ips = f"{p[IP].src}:"
                    ipd = f"{p[IP].dst}:"
                    temp = f"{p[IP].dst} <- {p[IP].src}"
                    prot = p[IP].proto
                elif p.haslayer(IPv6):
                    ips = f"{p[IPv6].src}:"
                    ipd = f"{p[IPv6].dst}:"
                    temp = f"{p[IPv6].dst} <- {p[IPv6].src}"
                    prot = p[IPv6].nh
                if p.haslayer(TCP):
                    temp = f"{ipd} {p[TCP].dport} <- {ips} {p[TCP].sport} | {prot}"
                if p.haslayer(UDP):
                    temp = f"{ipd} {p[UDP].dport} <- {ips} {p[UDP].sport} | {prot}"
                if temp and temp not in traffic:
                    traffic.append(temp)
                if p.haslayer(ARP):
                    temp = f"{p[ARP].pdst} <- {p[ARP].psrc}"
                    traffic.append(temp)
    conn = {
        "hdr_type": "conn",
        "mac_one": mac_one,
        "mac_two": mac_two,
    }
    to_show.append(conn)
    conn_traffic = {
        "hdr_type": "conn_traffic",
        "conn_traffic": traffic,
        "arp": arp,
    }
    to_show.append(conn_traffic)
    return to_show
