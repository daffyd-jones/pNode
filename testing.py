import unittest
from unittest.mock import patch
from random import randint, choice

import pygame
import numpy as np

from scapy.all import *
from scapy.all import IP, TCP, UDP, ARP, DNS, ICMP, SNMP, DHCP, BOOTP, L2TP, PPP, Raw, IPv6
from scapy.layers.l2 import Ether

from Scapy import ScapyClass as Scapy
from GUI import GUIClass as GUI
from GameLoop import GameLoop, sfilter, reset, resend, prot, play, pause, stop, beg, end, rev, fwd, prange, spdup, spddw, playmove
from Actions import Action

BLACK = (0, 0, 0)
BLUE = (207, 210, 205)
YELLOW = (229, 230, 228)
color_inactive = pygame.Color('lightskyblue3')
color_active = pygame.Color('dodgerblue2')

class Test_Scapy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scapy = Scapy()
        resp = cls.scapy.load_pcap("test.pcap")
        cls.packets = cls.scapy.packet_list

    def test_load_pcap(self):
        scapy = Scapy()
        resp = scapy.load_pcap("test.pcap")
        self.assertTrue(resp, "Tests whether a pcap loads successfully")

    def test_save_pcap(self):
        scapy = Scapy()
        scapy.packet_list = self.packets
        resp = scapy.save_pcap()
        self.assertTrue(resp, "Tests whether save was successful")

    def test_toggle_prot(self):
        scapy = Scapy()
        before = scapy.prot_toggle["ARP"]
        scapy.toggle_prot("ARP")
        after = scapy.prot_toggle["ARP"]
        self.assertNotEqual(before, after, "Checks if protocol boolean is toggled properly")

    def test_reset_packets(self):
        scapy = Scapy()
        scapy.packet_list = self.packets
        scapy.reset_packets()
        self.assertEqual(scapy.packet_list, scapy.filtered_packets)

    def test_toggle_reset(self):
        scapy = Scapy()
        scapy.packet_list = self.packets
        scapy.toggle_prot("TCP")
        scapy.toggle_reset()
        self.assertNotEqual(self.packets, scapy.filtered_packets, "Tests that list is no longer the same")
        check = True
        for t in scapy.filtered_packets:
            if not t.haslayer(TCP):
                check = False
        self.assertTrue(check, "Tests whether the packet list is now the only chosen protocol")

    def test_filter_packets_eth(self):
        packet = None
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        # while True:
        #     temp = random.choice(self.packets)
        #     if temp.haslayer(Ether):
        #         packet = temp
        #         break
        pkts = [pkt for pkt in self.packets if Ether in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"eth={packet[Ether].src}")
        check = True
        for i in scapy.filtered_packets:
            if i[Ether].src != f"{packet[Ether].src}" and i[Ether].dst != f"{packet[Ether].src}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by eth")


    def test_filter_packets_src_eth(self):
        packet = None
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        pkts = [pkt for pkt in self.packets if Ether in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"src_eth={packet[Ether].src}")
        check = True
        for i in scapy.filtered_packets:
            if i[Ether].src != f"{packet[Ether].src}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by eth.src")

    def test_filter_packets_dst_eth(self):
        packet = None
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        pkts = [pkt for pkt in self.packets if Ether in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"dst_eth={packet[Ether].dst}")
        check = True
        for i in scapy.filtered_packets:
            if i[Ether].dst != f"{packet[Ether].dst}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by eth.dst")
                #
    def test_filter_packets_ip(self):
        packet = None
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        # while True:
        #     temp = random.choice(self.packets)
        #     if temp.haslayer(IP):
        #         packet = temp
        #         break
        pkts = [pkt for pkt in self.packets if IP in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"ip={packet[IP].src}")
        check = True
        for i in scapy.filtered_packets:
            if i[IP].src != f"{packet[IP].src}" and i[IP].dst != f"{packet[IP].src}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by ip")
#
    def test_filter_packets_src_ip(self):
        packet = None
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        pkts = [pkt for pkt in self.packets if IP in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"src_ip={packet[IP].src}")
        check = True
        for i in scapy.filtered_packets:
            if i[IP].src != f"{packet[IP].src}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by ip.src")
#
    def test_filter_packets_dst_ip(self):
        packet = None
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        pkts = [pkt for pkt in self.packets if IP in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"dst_ip={packet[IP].dst}")
        check = True
        for i in scapy.filtered_packets:
            if i[IP].dst != f"{packet[IP].dst}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by ip.dst")
#
    def test_filter_packets_len(self):
        packet = None
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        pkts = [pkt for pkt in self.packets if IP in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"len={len(packet[IP])}")
        check = True
        for i in scapy.filtered_packets:
            if len(i[IP]) != f"{len(packet[IP])}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by len")
#
    def test_filter_packets_ttl(self):
        packet = None
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        packet = None
        # while True:
        #     temp = random.choice(self.packets)
        #     if temp.haslayer(IP):
        #         packet = temp
        #         break
        pkts = [pkt for pkt in self.packets if IP in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"ttl={packet[IP].ttl}")
        check = True
        for i in scapy.filtered_packets:
            if i[IP].ttl != packet[IP].ttl:
                check = False
        self.assertTrue(check, "Checking that list is filtered by ttl")
#
    def test_filter_packets_ver(self):
        packet = None
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        pkts = [pkt for pkt in self.packets if IP in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"ver={packet[IP].version}")
        check = True
        for i in scapy.filtered_packets:
            if i[IP].version != f"{packet[IP].version}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by ver")
#
    def test_filter_packets_seq(self):
        packet = None
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        # while True:
        #     temp = random.choice(self.packets)
        #     if temp.haslayer(TCP):
        #         packet = temp
        #         break
        pkts = [pkt for pkt in self.packets if TCP in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"seq={packet[TCP].seq}")
        check = True
        for i in scapy.filtered_packets:
            if i[TCP].seq != packet[TCP].seq:
                check = False
        self.assertTrue(check, "Checking that list is filtered by seq")
#
    def test_filter_packets_ack(self):
        packet = None
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        pkts = [pkt for pkt in self.packets if TCP in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"ack={packet[TCP].ack}")
        check = True
        for i in scapy.filtered_packets:
            if i[TCP].ack != packet[TCP].ack:
                check = False
        self.assertTrue(check, "Checking that list is filtered by ack")
#
    def test_filter_packets_urgptr(self):
        packet = None
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        pkts = [pkt for pkt in self.packets if TCP in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"urgptr={packet[TCP].urgptr}")
        check = True
        for i in scapy.filtered_packets:
            if i[TCP].urgptr != f"{packet[TCP].urgptr}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by urgptr")
#
        # scapy.filtered_packets = self.packets
        # # packet = None
        # # while True:
        # #     temp = random.choice(self.packets)
        # #     if temp.haslayer(ICMP):
        # #         packet = temp
        # #         break
        # # pkts = [pkt for pkt in self.packets if ICMP in pkt]
        # print(f"\nplen: {pkts}")
        # # packet = pkts[0]
        # scapy.filter_packets(f"icmp_type={packet[ICMP].type}")
        # check = True
        # for i in scapy.filtered_packets:
        #     if i[ICMP].type != f"{packet[ICMP].type}":
        #         check = False
        # self.assertTrue(check, "Checking that list is filtered by icmp_type")
# #
#         scapy.filtered_packets = self.packets
#         scapy.filter_packets(f"icmp_code={packet[ICMP].code}")
#         check = True
#         for i in scapy.filtered_packets:
#             if i[ICMP].code != f"{packet[ICMP]}":
#                 check = False
#         self.assertTrue(check, "Checking that list is filtered by icmp_code")
# #
    def test_filter_packets_dns_qn(self):
        scapy = self.scapy
        packet = None
        scapy.filtered_packets = self.packets
        pkts = [pkt for pkt in self.packets if DNS in pkt]
        while True:
            temp = random.choice(pkts)
            if temp[DNS].qd:
                packet = temp
                break
        t = scapy.filter_packets(f"dns_qn={packet[DNS].qd.qname.decode('utf-8')}")
        check = True
        for i in scapy.filtered_packets:
            if i[DNS].qd.qname != packet[DNS].qd.qname:
                check = False
        self.assertTrue(check, "Checking that list is filtered by qn")
# #
    def test_filter_packets_dns_qr(self):
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        packet = [pkt for pkt in self.packets if DNS in pkt][0]
        scapy.filter_packets(f"dns_qr={packet[DNS].qr}")
        check = True
        for i in scapy.filtered_packets:
            if i[DNS].qr != f"{packet[DNS].qr}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by qr")
# #
        # scapy.filtered_packets = self.packets
        # # while True:
        # #     temp = random.choice(self.packets)
        # #     if temp.haslayer(HTTP):
        # #         packet = temp
        # #         break
        # packet = [pkt for pkt in self.packets if HTTP in pkt][0]
        #
        # scapy.filter_packets(f"http_mthd={packet[HTTP].Method}")
        # check = True
        # for i in scapy.filtered_packets:
        #     if i[HTTP].Method != f"{packet[HTTP].Method}":
        #         check = False
        # self.assertTrue(check, "Checking that list is filtered by http_method")
# #
#         scapy.filtered_packets = self.packets
#         scapy.filter_packets(f"http_host={packet[HTTP].Host}")
#         check = True
#         for i in scapy.filtered_packets:
#             if i[HTTP].Host != f"{packet[HTTP].Host}":
#                 check = False
#         self.assertTrue(check, "Checking that list is filtered by http_host")
# #
#         scapy.filtered_packets = self.packets
#         scapy.filter_packets(f"http_uri={packet[HTTP].Uri}")
#         check = True
#         for i in scapy.filtered_packets:
#             if i[HTTP].Uri != f"{packet[HTTP].Uri}":
#                 check = False
#         self.assertTrue(check, "Checking that list is filtered by http_uri")
# #
    def test_filter_packets_port(self):
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        pkts = [pkt for pkt in self.packets if TCP in pkt]
        packet = pkts[2]
        # while True:
        #     temp = random.choice(self.packets)
        #     if temp.haslayer(TCP):
        #         packet = temp
        #         break
        scapy.filter_packets(f"port={packet[TCP].sport}")
        check = True
        t = f"{packet[TCP].sport}"
        for i in scapy.filtered_packets:
            if i.haslayer(TCP) and (i[TCP].sport != int(t) and i[TCP].dport != int(t)) or i.haslayer(UDP) and (i[UDP].sport != int(t) and i[UDP].dport != int(t)):
                check = False
        self.assertTrue(check, "Checking that list is filtered by port")
# #
    def test_filter_packets_sport(self):
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        pkts = [pkt for pkt in self.packets if TCP in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"sport={packet[TCP].sport}")
        check = True
        t = f"{packet[TCP].sport}"
        for i in scapy.filtered_packets:
            if i.haslayer(TCP) and i[TCP].sport != int(t) or i.haslayer(UDP) and i[UDP].sport != int(t):
                check = False
        self.assertTrue(check, "Checking that list is filtered by src_port")
# #
    def test_filter_packets_dport(self):
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        pkts = [pkt for pkt in self.packets if TCP in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"dport={packet[TCP].dport}")
        check = True
        t = f"{packet[TCP].dport}"
        for i in scapy.filtered_packets:
            if i.haslayer(TCP) and i[TCP].dport != int(t) or i.haslayer(UDP) and i[UDP].dport != int(t):
                check = False
        self.assertTrue(check, "Checking that list is filtered by dst_port")
# #
    def test_filter_packets_prot(self):
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        scapy.filter_packets("prot=TCP")
        check = True
        for i in scapy.filtered_packets:
            if not i.haslayer(TCP):
                check = False
        self.assertTrue(check, "Checking that list is filtered by prot")
# #
    def test_filter_packets_flags(self):
        scapy = self.scapy
        scapy.filtered_packets = self.packets
        pkts = [pkt for pkt in self.packets if TCP in pkt]
        packet = pkts[2]
        scapy.filter_packets(f"flags={packet[TCP].flags}")
        check = True
        t = f"{packet[TCP].flags}"
        for i in scapy.filtered_packets:
            if packet.haslayer(TCP) and packet[TCP].flags != t or packet.haslayer(UDP) and packet[UDP].flags != t:
                check = False
        self.assertTrue(check, "Checking that list is filtered by src_port")

    def test_sniff(self):
        scapy = Scapy()
        resp = scapy.sniff(("sniff", "wlp1s0", 20))
        self.assertTrue(resp, "Checks whether sniff succeeded")

class Test_Scapy_Failure(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scapy = Scapy()
        resp = cls.scapy.load_pcap("test.pcap")
        cls.packets = cls.scapy.packet_list

    def test_load_pcap_fail(self):
        scapy = Scapy()
        resp = scapy.load_pcap("tesdt.pcap")
        self.assertFalse(resp, "Tests whether a pcap loads successfully")

    # def test_save_pcap(self):
    #     scapy = Scapy()
    #     scapy.packet_list = self.packets
    #     resp = scapy.save_pcap()
    #     self.assertTrue(resp, "Tests whether save was successful")

    def test_filter_packets_fail_wrong_input_parameter(self):
        scapy = Scapy()
        # print(f"dddd {self.packets}")
        scapy.filtered_packets = self.packets
        packet = None
        while True:
            temp = random.choice(self.packets)
            if temp.haslayer(Ether):
                packet = temp
                break
        t = scapy.filter_packets(f"ethf={packet[Ether].src}")
        self.assertFalse(t, "filter packets returns False upon receiving a parameter 'eth=' that is invalid")

    # def test_sniff(self):
    #     scapy = Scapy()
    #     resp = scapy.sniff(("wlp1s0", 20))
    #     self.assertTrue(resp, "Checks whether sniff succeeded")



#-------

class Test_GameLoop(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scapy = Scapy()
        resp = cls.scapy.load_pcap("test.pcap")
        cls.packets = cls.scapy.packet_list

    def test_sfilter(self):
        gl = GameLoop()
        gl.Scapy.packet_list = self.packets
        gl.Scapy.reset_packets()
        packet = None
        while True:
            temp = random.choice(self.packets)
            if temp.haslayer(TCP):
                packet = temp
                break
        sfilter(gl, ("", f"ip={packet[IP].src} sport={packet[TCP].sport}"))
        fp = gl.Scapy.filtered_packets
        check = True
        for i in fp:
            if i.haslayer(TCP):
                if i[IP].src != packet[IP].src or i[TCP].sport != packet[TCP].sport:
                    check = False
            elif i.haslayer(UDP):
                if i[IP].src != packet[IP].src or i[UDP].sport != packet[TCP].sport:
                    check = False
        self.assertTrue(check, "Checking that list is filtered filter input from GameLoop")

    def test_reset(self):
        gl = GameLoop()
        gl.Scapy.packet_list = self.packets
        gl.Scapy.reset_packets()
        packet = None
        while True:
            temp = random.choice(self.packets)
            if temp.haslayer(TCP):
                packet = temp
                break
        sfilter(gl, ("", f"src_ip={packet[IP].src}"))
        check = True
        fp = gl.Scapy.filtered_packets
        for i in fp:
            if i[IP].src != packet[IP].src:
                check = False
        self.assertTrue(check, "Checking that list is different from packet_list")
        reset(gl, "")
        check = False
        if gl.Scapy.packet_list == gl.Scapy.filtered_packets:
            check = True
        self.assertTrue(check, "Checking that list is reset")

    def test_resend(self):
        gl = GameLoop()
        gl.Scapy.packet_list = self.packets
        gl.Scapy.reset_packets()
        gl.play = True
        gl.step_range = 5
        resend(gl, "")
        sp = gl.GUI.screen_packets
        temp = gl.Scapy.filtered_packets[0:0+5]
        self.assertCountEqual(sp, temp, "Check to see if the resend function assigns to 'screen_packets'")

    def test_prot(self):
        gl = GameLoop()
        gl.Scapy.packet_list = self.packets
        gl.Scapy.reset_packets()
        prot(gl, ("", "T", "UDP"))
        check = True
        for i in gl.Scapy.filtered_packets:
            if not i.haslayer(UDP):
                check = False
        self.assertTrue(check)
        prot(gl, ("", "F", "UDP"))
        self.assertEqual(gl.Scapy.packet_list, gl.Scapy.filtered_packets)

    def test_play(self):
        gl = GameLoop()
        play(gl, ("", 20))
        self.assertTrue(gl.play)
        self.assertEqual(gl.step_range, 20)

    def test_pause(self):
        gl = GameLoop()
        play(gl, ("", 20))
        self.assertTrue(gl.play)
        self.assertEqual(gl.step_range, 20)
        pause(gl, (""))
        self.assertEqual(gl.play, None)

    def test_stop(self):
        gl = GameLoop()
        play(gl, ("", 20))
        gl.step_position = 20
        stop(gl, (""))
        self.assertEqual(gl.step_position, 0)
        self.assertTrue(gl.ch)
        self.assertFalse(gl.play)

    def test_beg(self):
        gl = GameLoop()
        gl.Scapy.packet_list = self.packets
        gl.Scapy.reset_packets()
        gl.step_position = 10
        gl.step_range = 10
        beg(gl, (""))
        self.assertEqual(gl.step_position, 0)
        temp = gl.GUI.screen_packets
        temp2 = gl.Scapy.filtered_packets[0: 0 + 10]
        self.assertCountEqual(temp, temp2)

    # def test_end(self):
    #     pass

    def test_rev(self):
        gl = GameLoop()
        gl.Scapy.packet_list = self.packets
        gl.Scapy.reset_packets()
        gl.step_position = 10
        gl.step_range = 10
        rev(gl, (""))
        self.assertEqual(gl.step_position, 9)
        temp = gl.GUI.screen_packets
        temp2 = gl.Scapy.filtered_packets[9: 9 + 10]
        self.assertCountEqual(temp, temp2)

    def test_fwd(self):
        gl = GameLoop()
        gl.Scapy.packet_list = self.packets
        gl.Scapy.reset_packets()
        gl.step_position = 10
        gl.step_range = 10
        fwd(gl, (""))
        self.assertEqual(gl.step_position, 11)
        temp = gl.GUI.screen_packets
        temp2 = gl.Scapy.filtered_packets[11: 11 + 10]
        self.assertCountEqual(temp, temp2)

    def test_prange(self):
        gl = GameLoop()
        gl.Scapy.packet_list = self.packets
        gl.Scapy.reset_packets()
        gl.step_position = 10
        prange(gl, ("", 30))
        self.assertEqual(gl.step_range, 30)
        temp = gl.GUI.screen_packets
        temp2 = gl.Scapy.filtered_packets[10: 10 + 30]
        self.assertCountEqual(temp, temp2)

        gl.Scapy.reset_packets()
        gl.step_position = 10
        prange(gl, ("", ""))
        self.assertEqual(gl.step_range, 6)
        temp = gl.GUI.screen_packets
        temp2 = gl.Scapy.filtered_packets[10: 10 + 6]
        self.assertCountEqual(temp, temp2)

    def test_spdup(self):
        gl = GameLoop()
        gl.step_rate = 10
        pre = gl.step_rate
        spdup(gl, "")
        self.assertEqual(pre - 1, gl.step_rate)

    def test_spddw(self):
        gl = GameLoop()
        gl.step_rate = 10
        pre = gl.step_rate
        spddw(gl, "")
        self.assertEqual(pre + 1, gl.step_rate)

    def test_playmove(self):
        gl = GameLoop()
        gl.Scapy.packet_list = self.packets
        gl.Scapy.reset_packets()
        gl.step_position = 10
        gl.step_range = 10
        gl.play = True
        playmove(gl, ("", 30))
        self.assertEqual(gl.step_position, 30)
        self.assertCountEqual(gl.GUI.screen_packets, gl.Scapy.filtered_packets[30:30 + 10])

    def test_run_action(self):
        gl = GameLoop()
        gl.Scapy.packet_list = self.packets
        gl.Scapy.reset_packets()
        t = gl.run_action((Action.FILTER, "ip=192.168.10.161"))
        self.assertTrue(t, "run_action returns True when an action is successful")
        pkts = [pkt for pkt in self.packets if pkt.haslayer(IP) and (pkt[IP].src == "192.168.10.161" or pkt[IP].dst == "192.168.10.161")]
        self.assertCountEqual(pkts, gl.Scapy.filtered_packets)

class Test_GameLoop_Failure(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scapy = Scapy()
        resp = cls.scapy.load_pcap("test.pcap")
        cls.packets = cls.scapy.packet_list

    def test_sfilter_fail_wrong_parameters(self):
        gl = GameLoop()
        gl.Scapy.packet_list = self.packets
        gl.Scapy.reset_packets()
        packet = None
        while True:
            temp = random.choice(self.packets)
            if temp.haslayer(TCP):
                packet = temp
                break
        t = sfilter(gl, ("", f"ipf={packet[IP].src} sport={packet[TCP].sport}"))
        self.assertFalse(t, "Returns False when invalid parameter 'ethf=' is given.")


class Test_GUIClass(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scapy = Scapy()
        resp = cls.scapy.load_pcap("test.pcap")
        cls.packets = cls.scapy.packet_list

    def test_set_packets(self):
        gui = GUI()
        gui.set_packets(self.packets)
        self.assertCountEqual(gui.screen_packets, self.packets)
        self.assertEqual(len(gui.list_elem), len(self.packets))
        self.assertTrue(gui.utils["new_map"])
        ethadd = set()
        for p in self.packets:
            if Ether in p:
                ethadd.add(p[Ether].src)
                ethadd.add(p[Ether].dst)
        node_eth = []
        for n in gui.node_elem.values():
            node_eth.append(n.mac)
        self.assertCountEqual(node_eth, ethadd)

    def test_set_list_packets(self):
        gui = GUI()
        gui.set_list_packets(self.packets)
        self.assertEqual(len(gui.list_elem), len(self.packets))

    def test_init_node_elem(self):
        gui = GUI()
        gui.set_packets(self.packets)
        gui._init_node_elem()
        ethadd = set()
        for p in self.packets:
            if Ether in p:
                ethadd.add(p[Ether].src)
                ethadd.add(p[Ether].dst)
        node_eth = []
        for n in gui.node_elem.values():
            node_eth.append(n.mac)
        self.assertCountEqual(node_eth, ethadd)

    def test_init_conn_elem(self):
        gui = GUI()
        gui.set_packets(self.packets)
        gui._init_conn_elem()
        ethadd = set()
        for p in self.packets:
            if Ether in p:
                ethadd.add(tuple(sorted([p[Ether].src, p[Ether].dst])))
        node_eth = []
        for n in gui.conn_elem.keys():
            node_eth.append(n)
        self.assertCountEqual(node_eth, ethadd)

    # def test_load_screen(self):
    #     gui = GUI()
    #     gui.set_packets(self.packets)

    def test_load_input_box(self):
        gui = GUI()
        gui.set_packets(self.packets)
        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(543, 182))
        pygame.event.post(t_event)
        active = gui.load_elem["input_box_active"]
        self.assertFalse(active)
        gui.load_input()
        active = gui.load_elem["input_box_active"]
        self.assertTrue(active)

        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(523, 172))
        pygame.event.post(t_event)
        gui.load_input()
        active = gui.load_elem["input_box_active"]
        self.assertFalse(active)

        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(543, 182))
        pygame.event.post(t_event)
        gui.load_input()
        active = gui.load_elem["input_box_active"]
        self.assertTrue(active)

        for char in 'hello':
            test_event = pygame.event.Event(pygame.KEYDOWN, unicode=char, key=ord(char))
            pygame.event.post(test_event)
        gui.load_input()
        self.assertEqual("hello", gui.load_elem["input_text"])

        t_event = pygame.event.Event(pygame.KEYDOWN, key=pygame.K_BACKSPACE)
        pygame.event.post(t_event)
        gui.load_input()
        self.assertEqual("hell", gui.load_elem["input_text"])

        gui.load_elem["input_text"] = ''
        for char in 'test.pcap':
            test_event = pygame.event.Event(pygame.KEYDOWN, unicode=char, key=ord(char))
            pygame.event.post(test_event)
        gui.load_input()

        t_event = pygame.event.Event(pygame.KEYDOWN, key=pygame.K_RETURN)
        pygame.event.post(t_event)
        res = gui.load_input()

        self.assertEqual("pcap", res[0])
        self.assertEqual("test.pcap", res[1])

    def test_load_amt_box(self):
        gui = GUI()
        gui.set_packets(self.packets)
        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(483, 400))
        pygame.event.post(t_event)
        active = gui.load_elem["amt_box_active"]
        self.assertFalse(active)
        gui.load_input()
        active = gui.load_elem["amt_box_active"]
        self.assertTrue(active)

        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(483, 400))
        pygame.event.post(t_event)
        gui.load_input()
        active = gui.load_elem["amt_box_active"]
        self.assertFalse(active)

        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(483, 400))
        pygame.event.post(t_event)
        gui.load_input()
        active = gui.load_elem["amt_box_active"]
        self.assertTrue(active)

        for char in '1234':
            test_event = pygame.event.Event(pygame.KEYDOWN, unicode=char, key=ord(char))
            pygame.event.post(test_event)
        gui.load_input()
        self.assertEqual("1234", gui.load_elem["amt_text"])

        t_event = pygame.event.Event(pygame.KEYDOWN, key=pygame.K_BACKSPACE)
        pygame.event.post(t_event)
        gui.load_input()
        self.assertEqual("123", gui.load_elem["amt_text"])

        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(493, 445))
        pygame.event.post(t_event)
        gui.load_screen(True)
        res = gui.load_input()
        self.assertEqual("sniff", res[0])
        self.assertEqual("lo", res[1])

        gui.load_elem["amt_text"] = "asdf"
        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(483, 455))
        pygame.event.post(t_event)
        gui.load_input()
        t = gui.load_elem["error_text"]
        tt = gui.utils["font1"].render("   Sniff amt must be #", True, BLACK)
        tarr = pygame.surfarray.pixels3d(t)
        ttarr = pygame.surfarray.pixels3d(tt)
        self.assertTrue(np.array_equal(tarr, ttarr))

    def test_check_filter_keydown(self): # extend for other fields
        gui = GUI()
        for char in 'hello':
            test_event = pygame.event.Event(pygame.KEYDOWN, unicode=char, key=ord(char))
            pygame.event.post(test_event)
        gui.filter_elem["input_box_active"] = True
        for event in pygame.event.get():
            if event.type == pygame.KEYDOWN:
                t = gui._check_filter_keydown(event, "input_box_active", Action.FILTER, "input_text", 16, "input")
        self.assertEqual("hello", gui.filter_elem["input_text"])

        t_event = pygame.event.Event(pygame.KEYDOWN, key=pygame.K_BACKSPACE)
        pygame.event.post(t_event)
        for event in pygame.event.get():
            if event.type == pygame.KEYDOWN:
                t = gui._check_filter_keydown(event, "input_box_active", Action.FILTER, "input_text", 16, "input")
        self.assertEqual("hell", gui.filter_elem["input_text"])

        t_event = pygame.event.Event(pygame.KEYDOWN, key=pygame.K_RETURN)
        pygame.event.post(t_event)
        for event in pygame.event.get():
            if event.type == pygame.KEYDOWN:
                t = gui._check_filter_keydown(event, "input_box_active", Action.FILTER, "input_text", 16, "input")
                self.assertEqual(Action.FILTER, t[0])
                self.assertEqual("hell", t[1])
                self.assertEqual("", t[2])


    def test_check_scroll(self):
        gui = GUI()
        gui.set_packets(self.packets)
        gui._post_list_ele(gui.list_elem[0])
        x, y = gui.panels["top_right"].x, gui.panels["top_right"].y
        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=5, pos=(x + 50, y + 40))
        pygame.event.post(t_event)
        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=5, pos=(x + 50, y + 40))
        pygame.event.post(t_event)
        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=5, pos=(x + 50, y + 40))
        pygame.event.post(t_event)
        pre = gui.indices["info"]
        for event in pygame.event.get():
            if event.type == pygame.MOUSEBUTTONDOWN:
                gui._check_scroll(event, "top_right", "info", gui.in_info, 1)
        scroll_down = gui.indices["info"]
        self.assertTrue(pre < scroll_down)
        # print(f"pre: {pre} down: {scroll_down}")

        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=4, pos=(x + 50, y + 40))
        pygame.event.post(t_event)

        for event in pygame.event.get():
            if event.type == pygame.MOUSEBUTTONDOWN:
                gui._check_scroll(event, "top_right", "info", gui.in_info, 1)
        scroll_up = gui.indices["info"]
        self.assertTrue(scroll_up < scroll_down)
        self.assertTrue(pre < scroll_up)
        # print(f"pre: {pre} up: {scroll_up}  down: {scroll_down}")

    def test_check_toggle(self):
        gui = GUI()
        gui.set_packets(self.packets)
        x, y = gui.panels['bottom_right'].x + 9, gui.panels['bottom_right'].y + 58,
        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(x, y))
        pygame.event.post(t_event)
        for event in pygame.event.get():
            if event.type == pygame.MOUSEBUTTONDOWN:
                t = gui._check_toggle(event, "toggle1", "toggle1_color", Action.ARP)
                if t != None:
                    self.assertEqual(Action.PROT, t[0])
                    self.assertEqual("T", t[1])
                    self.assertEqual("ARP", t[2])
        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(x, y))
        pygame.event.post(t_event)
        for event in pygame.event.get():
            if event.type == pygame.MOUSEBUTTONDOWN:
                t = gui._check_toggle(event, "toggle1", "toggle1_color", Action.ARP)
                if t != None:
                    self.assertEqual(Action.PROT, t[0])
                    self.assertEqual("F", t[1])
                    self.assertEqual("ARP", t[2])

    def test_check_active(self):
        gui = GUI()
        gui.set_packets(self.packets)
        x, y = gui.panels['bottom_right'].x + 10, gui.panels['bottom_right'].y + 10,
        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(x, y))
        pygame.event.post(t_event)
        for event in pygame.event.get():
            if event.type == pygame.MOUSEBUTTONDOWN:
                gui._check_active(event, "input_box", "input_box_active", "input_box_color")
                self.assertTrue(gui.filter_elem["input_box_active"])
                self.assertEqual(color_active, gui.filter_elem["input_box_color"])

        x, y = gui.panels['bottom_right'].x + 3, gui.panels['bottom_right'].y + 50,
        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(x, y))
        pygame.event.post(t_event)
        for event in pygame.event.get():
            if event.type == pygame.MOUSEBUTTONDOWN:
                gui._check_active(event, "input_box", "input_box_active", "input_box_color")
                self.assertFalse(gui.filter_elem["input_box_active"])
                self.assertEqual(color_inactive, gui.filter_elem["input_box_color"])

    def test_reset_node_color(self):
        gui = GUI()
        gui.set_packets(self.packets)
        k = list(gui.node_elem.keys())
        t1 = gui.node_elem[k[2]]
        gui.node_elem[k[1]].set_sprite_props("color", YELLOW)
        t1.set_sprite_props("color", YELLOW)
        gui._reset_node_color(t1)
        self.assertEqual(BLUE, gui.node_elem[k[1]].get_sprite_props()["color"])
        gui._reset_node_color("reset")
        self.assertEqual(BLUE, t1.get_sprite_props()["color"])



    def test_reset_conn_color(self):
        gui = GUI()
        gui.set_packets(self.packets)
        k = list(gui.conn_elem.keys())
        t1 = gui.conn_elem[k[2]]
        gui.conn_elem[k[1]].set_sprite_props("color", YELLOW)
        t1.set_sprite_props("color", YELLOW)
        gui._reset_conn_color(t1)
        self.assertEqual(BLUE, gui.conn_elem[k[1]].get_sprite_props()["color"])
        gui._reset_conn_color("reset")
        self.assertEqual(BLUE, t1.get_sprite_props()["color"])


    def test_check_page_buttons(self):
        gui = GUI()
        x, y = gui.info_elem["info_raw_fwd_button"].x + 5, gui.info_elem["info_raw_fwd_button"].y + 5
        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(x, y))
        pygame.event.post(t_event)
        for event in pygame.event.get():
            if event.type == pygame.MOUSEBUTTONDOWN:
                gui._check_page_buttons(event, "info_raw_fwd_button", "info_page", False)
                self.assertEqual(1, gui.indices["info_page"])

        x, y = gui.info_elem["info_raw_back_button"].x + 5, gui.info_elem["info_raw_back_button"].y + 5
        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(x, y))
        pygame.event.post(t_event)
        for event in pygame.event.get():
            if event.type == pygame.MOUSEBUTTONDOWN:
                gui._check_page_buttons(event, "info_raw_back_button", "info_page", True)
                self.assertEqual(0, gui.indices["info_page"])

    def test_check_map_ctl(self):
        gui = GUI()
        x, y = gui.panels['top_left'].x + 820, gui.panels['top_left'].y + 8,
        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(x, y))
        pygame.event.post(t_event)
        for event in pygame.event.get():
            if event.type == pygame.MOUSEBUTTONDOWN:
                t = gui._check_map_ctl(event, "rep_const_up", "rep_const", True)
                self.assertEqual(Action.RESEND, t[0])

        x, y = gui.panels['top_left'].x + 820, gui.panels['top_left'].y + 140,
        t_event = pygame.event.Event(pygame.MOUSEBUTTONDOWN, button=1, pos=(x, y))
        pygame.event.post(t_event)
        for event in pygame.event.get():
            if event.type == pygame.MOUSEBUTTONDOWN:
                t = gui._check_map_ctl(event, "rep_const_dw", "rep_const", False)
                self.assertEqual(Action.RESEND, t[0])

    def test_post_conn(self):
        gui = GUI()
        gui.set_packets(self.packets)
        t = gui.conn_elem
        k = list(t.keys())[2]
        gui._post_conn(gui.conn_elem[k])
        self.assertFalse(gui.in_info == None)

    def test_post_node(self):
        gui = GUI()
        gui.set_packets(self.packets)
        t = gui.node_elem
        k = list(t.keys())[2]
        gui._post_node(gui.node_elem[k])
        self.assertFalse(gui.in_info == None)

    def test_post_list_ele(self):
        gui = GUI()
        gui.set_packets(self.packets)
        t = gui.list_elem[5]
        gui.indices["info"] = 5
        gui._post_list_ele(t)
        self.assertEqual(0, gui.indices["info"])
        self.assertFalse(gui.in_info == None)

    def test_step_through(self):
        gui = GUI()
        # gui.set_packets(self.packets)
        p = 5
        s = 20
        gui.step_through(p, s, self.packets)
        t = self.packets[p:p + s]
        self.assertCountEqual(t, gui.screen_packets)
        self.assertEqual(p, gui.indices["play"])
        self.assertEqual(len(self.packets), gui.utils["f_len"])


unittest.main()
