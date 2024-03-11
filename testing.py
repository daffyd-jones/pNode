import unittest
from unittest.mock import patch
from random import randint, choice


from scapy.all import *
from scapy.all import IP, TCP, UDP, ARP, DNS, ICMP, SNMP, DHCP, BOOTP, L2TP, PPP, Raw, IPv6
from scapy.layers.l2 import Ether

from Scapy import ScapyClass as Scapy
from GUI import GUIClass as GUI
from GameLoop import GameLoop, sfilter, reset, resend, prot, play, pause, stop, beg, end, rev, fwd, prange, spdup, spddw, playmove
from Actions import Action


class Test_Scapy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scapy = Scapy()
        resp = cls.scapy.load_pcap("test.pcap")
        cls.packets = cls.scapy.packet_list
        # print(f"response: {resp} | pack: {cls.packets}")
        # self.assertTrue(resp, "Tests whether a pcap loads successfully")

    def test_load_pcap(self):
        scapy = Scapy()
        # resp = scapy.load_pcap("test.pcap")
        # self.packets = scapy.packet_list
        # print(f"\npack: {self.packets}")
        resp = scapy.load_pcap("test.pcap")
        self.assertTrue(resp, "Tests whether a pcap loads successfully")

    def test_save_pcap(self):
        scapy = Scapy()
        # print(f"\npack {self.packets}")
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

    def test_filter_packets(self):
        scapy = Scapy()
        # print(f"dddd {self.packets}")
        scapy.filtered_packets = self.packets
        packet = None
        while True:
            temp = random.choice(self.packets)
            if temp.haslayer(Ether):
                packet = temp
                break
        scapy.filter_packets(f"eth={packet[Ether].src}")
        check = True
        for i in scapy.filtered_packets:
            if i[Ether].src != f"{packet[Ether].src}" and i[Ether].dst != f"{packet[Ether].src}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by eth")

        scapy.filtered_packets = self.packets
        scapy.filter_packets(f"src_eth={packet[Ether].src}")
        check = True
        for i in scapy.filtered_packets:
            if i[Ether].src != f"{packet[Ether].src}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by eth.src")

        scapy.filtered_packets = self.packets
        scapy.filter_packets(f"dst_eth={packet[Ether].dst}")
        check = True
        for i in scapy.filtered_packets:
            if i[Ether].dst != f"{packet[Ether].dst}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by eth.dst")
                #
        scapy.filtered_packets = self.packets
        while True:
            temp = random.choice(self.packets)
            if temp.haslayer(IP):
                packet = temp
                break
        scapy.filter_packets(f"ip={packet[IP].src}")
        check = True
        for i in scapy.filtered_packets:
            if i[IP].src != f"{packet[IP].src}" and i[IP].dst != f"{packet[IP].src}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by ip")
#
        scapy.filtered_packets = self.packets
        scapy.filter_packets(f"src_ip={packet[IP].src}")
        check = True
        for i in scapy.filtered_packets:
            if i[IP].src != f"{packet[IP].src}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by ip.src")
#
        scapy.filtered_packets = self.packets
        scapy.filter_packets(f"dst_ip={packet[IP].dst}")
        check = True
        for i in scapy.filtered_packets:
            if i[IP].dst != f"{packet[IP].dst}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by ip.dst")
#
        scapy.filtered_packets = self.packets
        scapy.filter_packets(f"len={len(packet[IP])}")
        check = True
        for i in scapy.filtered_packets:
            if len(i[IP]) != f"{len(packet[IP])}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by len")
#
        scapy.filtered_packets = self.packets
        scapy.filter_packets(f"ttl={packet[IP].ttl}")
        check = True
        for i in scapy.filtered_packets:
            if i[IP].ttl != f"{packet[IP].ttl}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by ttl")
#
        # scapy.filtered_packets = packets
        # scapy.filter_packets("ttl=---")
        # check = True
        # for i in scapy.filtered_packets:
        #     if i[IP].ttl != "---":
        #         check = False
        # self.assertTrue(check, "Checking that list is filtered by ttl")
#
        scapy.filtered_packets = self.packets
        scapy.filter_packets(f"ver={packet[IP].version}")
        check = True
        for i in scapy.filtered_packets:
            if i[IP].version != f"{packet[IP].version}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by ver")
#
        scapy.filtered_packets = self.packets
        while True:
            temp = random.choice(self.packets)
            if temp.haslayer(TCP):
                packet = temp
                break
        scapy.filter_packets(f"seq={packet[TCP].seq}")
        check = True
        # print(f"..seq: {packet[TCP].seq}")
        for i in scapy.filtered_packets:
            # print(f"t: {packet[TCP].seq}")
            if i[TCP].seq != packet[TCP].seq:
                check = False
        self.assertTrue(check, "Checking that list is filtered by seq")
#
        scapy.filtered_packets = self.packets
        scapy.filter_packets(f"ack={packet[TCP].ack}")
        check = True
        for i in scapy.filtered_packets:
            if i[TCP].ack != packet[TCP].ack:
                check = False
        self.assertTrue(check, "Checking that list is filtered by ack")
#
        scapy.filtered_packets = self.packets
        scapy.filter_packets(f"urgptr={packet[TCP].urgptr}")
        check = True
        for i in scapy.filtered_packets:
            if i[TCP].urgptr != f"{packet[TCP].urgptr}":
                check = False
        self.assertTrue(check, "Checking that list is filtered by urgptr")
#
        # scapy.filtered_packets = self.packets
        # # while True:
        # #     temp = random.choice(self.packets)
        # #     if temp.haslayer(ICMP):
        # #         packet = temp
        # #         break
        # pkts = [pkt for pkt in self.packets if ICMP in pkt]
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
        # scapy.filtered_packets = self.packets
        # # while True:
        # #     temp = random.choice(self.packets)
        # #     if temp.haslayer(DNS):
        # #         packet = temp
        # #         break
        # pkts = [pkt for pkt in self.packets if DNS in pkt]
        # while True:
        #     temp = random.choice(pkts)
        #     if temp[DNS].qdcount > 0:
        #         packet = temp
        #         break
        # packet = pkts[4]
        # print(f"\nplen: {len(pkts)}")
        # scapy.filter_packets(f"dns_qn={packet[DNS].qd.qname}")
        # check = True
        # print(f"\npfpaklen: {len(scapy.filtered_packets)}")
        # for i in scapy.filtered_packets:
        #     if i[DNS].qd.qname != f"{packet[DNS].qd.qname}":
        #         check = False
        # self.assertTrue(check, "Checking that list is filtered by qn")
# #
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
        scapy.filtered_packets = self.packets
        while True:
            temp = random.choice(self.packets)
            if temp.haslayer(TCP):
                packet = temp
                break
        scapy.filter_packets(f"port={packet[TCP].sport}")
        check = True
        t = f"{packet[TCP].sport}"
        for i in scapy.filtered_packets:
            if i.haslayer(TCP) and (i[TCP].sport != int(t) and i[TCP].dport != int(t)) or i.haslayer(UDP) and (i[UDP].sport != int(t) and i[UDP].dport != int(t)):
                check = False
        self.assertTrue(check, "Checking that list is filtered by port")
# #
        scapy.filtered_packets = self.packets
        scapy.filter_packets(f"sport={packet[TCP].sport}")
        check = True
        t = f"{packet[TCP].sport}"
        for i in scapy.filtered_packets:
            if i.haslayer(TCP) and i[TCP].sport != int(t) or i.haslayer(UDP) and i[UDP].sport != int(t):
                check = False
        self.assertTrue(check, "Checking that list is filtered by src_port")
# #
        scapy.filtered_packets = self.packets
        scapy.filter_packets(f"dport={packet[TCP].dport}")
        check = True
        t = f"{packet[TCP].dport}"
        for i in scapy.filtered_packets:
            if i.haslayer(TCP) and i[TCP].dport != int(t) or i.haslayer(UDP) and i[UDP].dport != int(t):
                check = False
        self.assertTrue(check, "Checking that list is filtered by dst_port")
# #
        scapy.filtered_packets = self.packets
        scapy.filter_packets("prot=TCP")
        check = True
        for i in scapy.filtered_packets:
            if not i.haslayer(TCP):
                check = False
        self.assertTrue(check, "Checking that list is filtered by prot")
# #
        scapy.filtered_packets = self.packets
        scapy.filter_packets(f"flags={packet[TCP].flags}")
        check = True
        t = f"{packet[TCP].flags}"
        for i in scapy.filtered_packets:
            if packet.haslayer(TCP) and packet[TCP].flags != t or packet.haslayer(UDP) and packet[UDP].flags != t:
                check = False
        self.assertTrue(check, "Checking that list is filtered by src_port")

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
                if i[IP].src != packet[IP].src or i[UDP].sport != packet[UDP].sport:
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


class Test_GameLoop(unittest.TestCase):

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
        self.assertTrue(gui.new_map)

    def test_set_list_packets(self):
        gui = GUI()
        gui.set_list_packets(self.packets)
        self.assertEqual(len(gui.list_elem), len(self.packets))



    pass



unittest.main()
