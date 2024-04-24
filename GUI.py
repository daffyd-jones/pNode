import pygame
import sys
import time
import threading

from scapy.all import *
from scapy.all import IP, TCP, UDP, ARP, DNS, ICMP, SNMP, DHCP, BOOTP, L2TP, PPP, Raw, IPv6
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3gr, IGMPv3mq, IGMPv3mr, IGMPv3mra

from datetime import datetime
import random

from scapy.layers.l2 import Ether

from info_draw_funcs import *
from GUIObj import NObj
from GUIObj import LObj
from GUIObj import PLObj
from Actions import Action
from graph import update_positions, create_connection_rect, is_point_on_line
from packet_parse import post_list, post_node, post_conn
from init_funcs import build_filter_elem, build_load, build_list, build_info, build_map, build_help
import networkx as nx

BLACK = (0, 0, 0)
WHITE = (251, 251, 242)
GRAY = (200, 200, 200)

GREEN = (207, 210, 205)
RED = (166, 162, 162)
BLUE = (207, 210, 205)
YELLOW = (229, 230, 228)

DEFAULT_MIN = -sys.maxsize - 1
DEFAULT_MAX = sys.maxsize

SNIFFING_DONE = pygame.USEREVENT + 1

filt_parameters = [
        "eth:       x == src || dst MAC",
        "src_eth:   x == src MAC",
        "dst_eth:   x == dst MAC",
        "ip:        x == src || dst IP",
        "src_ip:    x == src IP",
        "dst_ip:    x == dst IP",
        "len:       x == IP length",
        "ttl:       x == IP time to live",
        "ver:       x == IP version",
        "port:      x == src || dst TCP || UDP",
        "sport:     x == src TCP || UDP",
        "dport:     x == dst TCP || UDP",
        "seq:       x == TCP sequence no.",
        "ack:       x == TCP acknowledgement no.",
        "urgptr:    x == TCP urgent pointer",
        "flags:     x == flags TCP || UDP",
        "icmp_type: x == ICMP type",
        "icmp_code: x == ICMP code",
        "dns_qn:    x == DNS ",
        "dns_qr:    x == src || dst",
        "http_mthd: x == http method",
        "http_host: x == http host",
        "http_uri:  x == http URI",
        "prot:      x == protocol",
]



color_inactive = pygame.Color('lightskyblue3')
color_active = pygame.Color('dodgerblue2')

protd = {
    Action.ARP: "ARP",
    Action.DNS: "DNS",
    Action.IP: "IP",
    Action.TCP: "TCP",
    Action.UDP: "UDP",
    Action.HTTP: "HTTP",
    Action.SSH: "SSH",
    Action.ICMP: "ICMP",
    Action.IGMP: "IGMP",
}

class GUIClass:
    def __init__(self):
        pygame.init()

        screen_width, screen_height = 1280, 720
        screen = pygame.display.set_mode((screen_width, screen_height))

        pygame.display.set_caption("pNode")

        img = pygame.image.load('logo.png')
        pygame.display.set_icon(img)
        font_path = "fonts/FiraCode-SemiBold.ttf"

        font1 = pygame.font.Font(font_path, 20)
        font2 = pygame.font.Font(font_path, 12)

        utils = {}
        utils["font1"] = font1
        utils["font2"] = font2
        utils["list_off"] = 0
        utils["scroll_step"] = 5
        utils["f_len"] = 0
        utils["play_drag"] = False
        utils["play_off"] = 0
        utils["play_step"] = 0
        utils["min"] = 0
        utils["max"] = DEFAULT_MAX
        utils["ascii_hex"] = False
        utils["help"] = False
        utils["new_map"] = True
        utils["map_adj"] = False
        utils["in_err"] = False

        ul_panel_size = (screen_width // 1.5, screen_height // 1.5)
        dl_panel_size = (screen_width // 1.5, screen_height // 3) # w 853 h 240
        ur_panel_size = (screen_width // 3 + 1, screen_height // 1.5) # w 426 h 480
        dr_panel_size = (screen_width // 3 + 1, screen_height // 3)

        # print(screen_width // 1.5)

        panels = {
            'top_left': pygame.Rect(0, 0, *ul_panel_size),
            'top_right': pygame.Rect(screen_width // 1.5, 0, *ur_panel_size),
            'bottom_left': pygame.Rect(0, screen_height // 1.5, *dl_panel_size),
            'bottom_right': pygame.Rect(screen_width // 1.5, screen_height // 1.5, *dr_panel_size)
        }

        self.screen = screen
        self.panels = panels
        self.utils = utils
        self.info_elem = build_info(panels)
        self.filter_elem = build_filter_elem(panels, font1, font2, color_inactive)
        self.load_elem = build_load(color_inactive, font1, font2)
        self.list_banner = build_list(panels, font2)
        self.map_ctl = build_map(panels, font2)
        self.help_win = build_help(font2)
        self.graph_pos = None
        self.screen_packets = None
        self.in_info = None
        self.node_elem = {}
        self.conn_elem = {}
        self.list_elem = []
        self.if_list = []
        self.if_panels = []
        self.screen_keys = []
        self.list_bools = {
            "time": False,
            "src": False,
            "dst": False,
            "prot": False,
            "len": False,
            "scroll_bar_drag": False,
        }
        self.indices = {
            "list": 0,
            "input": 0,
            "load": 0,
            "load_if": 0,
            "pkt_amt": 0,
            "range": 0,
            "lower": 0,
            "upper": 0,
            "info": 0,
            "info_page": 0,
            "t_in_page": 0,
            "t_out_page": 0,
            "c_t_page": 0,
            "rep_const": 1.6,
            "att_const": 0.4,
            "glob_const": 3.0,
            "play": 0,
        }

    def set_packets(self, packets):
        self.list_elem.clear()
        self.screen_packets = packets

        for packet in packets:
            # l_ele = pygame.Rect(self.panels['bottom_left'].x + 5, self.panels['bottom_right'].y + 25, 40, 24)
            l_class = PLObj()

            l_class.sprite_props["sprite"] = pygame.Rect(self.panels['bottom_left'].x + 5, -60, 803, 30)
            l_class.sprite_props["text"] = self.utils["font1"].render('', True, BLACK)

            l_class.packet = packet
            self.list_elem.append(l_class)

        self._init_node_elem()
        self._init_conn_elem()
        self.utils["new_map"] = True

    def set_list_packets(self, packets):
        self.list_elem.clear()

        for packet in packets:
            l_class = PLObj()

            l_class.sprite_props["sprite"] = pygame.Rect(self.panels['bottom_left'].x + 5, self.panels['bottom_left'].y + 30, 803, 30)
            l_class.sprite_props["text"] = self.utils["font1"].render('', True, BLACK)

            l_class.packet = packet
            self.list_elem.append(l_class)

    def _init_node_elem(self):
        pkts = self.screen_packets
        nodes = {}
        c = 1
        for pkt in pkts:
            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src
                dst_mac = pkt[Ether].dst
                if src_mac not in nodes:
                    c += 1
                    nodes[src_mac] = NObj(src_mac, pygame.Rect(c, c+3, 30, 30))
                if dst_mac not in nodes:
                    nodes[dst_mac] = NObj(dst_mac, pygame.Rect(c, c+4, 30, 30))
                nodes[src_mac].add_packet(pkt)
                nodes[src_mac].add_neighbor(dst_mac)
                nodes[dst_mac].add_packet(pkt)
                nodes[dst_mac].add_neighbor(src_mac)
        temp = {}
        for k, n in nodes.items():
            if (len(n.get_packet_list()) < self.utils["min"] or len(n.get_packet_list()) > self.utils["max"]):
                continue
            temp[k] = n
        self.node_elem = temp

    def _init_conn_elem(self):
        pkts = self.screen_packets
        nds = self.node_elem.keys()
        conns = {}
        for pkt in pkts:
            if pkt.haslayer(Ether):
                src_mac = pkt[Ether].src
                dst_mac = pkt[Ether].dst
                if src_mac == dst_mac:
                    continue
                conn_key = tuple(sorted([src_mac, dst_mac]))
                if src_mac not in nds or dst_mac not in nds:
                    continue
                if conn_key not in conns:
                    conns[conn_key] = LObj(src_mac, dst_mac, pygame.Surface((0, 0), pygame.SRCALPHA), pygame.Rect(0, 0, 30, 30))
                conns[conn_key].add_packet(pkt)
        self.conn_elem = conns

    def load_screen(self, lres):
        self.screen.fill(WHITE)
        pygame.draw.rect(self.screen, YELLOW, (40, 40, 1200, 310))
        pygame.draw.rect(self.screen, YELLOW, (40, 370, 1200, 310))
        pygame.draw.rect(self.screen, BLUE, (490, 105, 300, 150))
        pygame.draw.rect(self.screen, BLUE, (462, 385, 355, 280))
        self.screen.blit(self.load_elem["load_text"], (560, 130))

        temp = self.load_elem["load_msg"].split(" ")
        depth = 0
        for i in range(0, len(temp), 9):
            self.screen.blit(self.utils["font2"].render(" ".join(temp[i:i + 9]), True, BLACK), (850, 400+depth))
            depth += 15

        self.screen.blit(self.load_elem["logo"], (80, 340))
        self.screen.blit(self.load_elem["if_text"], (self.load_elem["amt_box"].x + 80, self.load_elem["amt_box"].y + 5))
        if lres == False:
            self.load_elem["error_text"] = self.utils["font1"].render("That is not a valid path", True, BLACK)

        if lres == True:
            self.load_elem["error_text"] = self.utils["font1"].render("There was a sniff error", True, BLACK)

        self.screen.blit(self.load_elem["error_text"], (850, 140))

        temp =  self.load_elem["input_text"]
        if len(temp) > 15:
            amt = max(15, len(temp))
            temp = temp[self.indices["load"]: self.indices["load"] + 15]
        ld_surface = self.utils["font1"].render(temp, True, BLACK)
        pygame.draw.rect(self.screen, self.load_elem["input_box_color"], self.load_elem["input_box"], 1)
        self.screen.blit(ld_surface, (self.load_elem["input_box"].x + 3, self.load_elem["input_box"].y + 3))

        temp = self.load_elem["amt_text"]
        if len(temp) > 5:
            amt = max(5, len(temp))
            temp = temp[self.indices["pkt_amt"]: self.indices["pkt_amt"] + 5]
        ld_surface = self.utils["font1"].render(temp, True, BLACK)
        pygame.draw.rect(self.screen, self.load_elem["amt_box_color"], self.load_elem["amt_box"], 1)
        self.screen.blit(ld_surface, (self.load_elem["amt_box"].x + 3, self.load_elem["amt_box"].y + 3))

        pygame.draw.rect(self.screen, self.load_elem["if_up_color"], self.load_elem["if_up"])
        self.screen.blit(self.load_elem["if_up_text"], (self.load_elem["if_up"].x + 10, self.load_elem["if_up"].y + 2))

        pygame.draw.rect(self.screen, self.load_elem["if_dw_color"], self.load_elem["if_dw"])
        self.screen.blit(self.load_elem["if_dw_text"], (self.load_elem["if_dw"].x + 10, self.load_elem["if_dw"].y + 2))

        ifs = get_if_list()
        self.if_list = ifs
        buf = 0
        for f in ifs[self.indices["load_if"]:self.indices["load_if"] + 5]:
            temp = pygame.Rect(472, 435 + buf, 300, 40)
            pygame.draw.rect(self.screen, GRAY, temp)
            ld_surface = self.utils["font1"].render(f, True, BLACK)
            self.screen.blit(ld_surface, (temp.x + 10, temp.y + 5))
            self.if_panels.append(temp)
            buf += 45
        pygame.display.flip()

    def load_input(self):
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            if event.type == SNIFFING_DONE:
                lres = event.dict['result']
                return ("dsniff", lres)
            if event.type == pygame.KEYDOWN:
                if self.load_elem["input_box_active"]:
                    if event.key == pygame.K_RETURN:
                        if self.load_elem["input_text"].endswith(".pcap"):
                            return ("pcap", self.load_elem["input_text"])
                        else:
                            self.load_elem["error_text"] = self.utils["font1"].render("That is not a valid path", True, BLACK)
                            self.load_elem["input_text"] = ""
                        pass
                    elif event.key == pygame.K_BACKSPACE:
                        self.load_elem["input_text"] = self.load_elem["input_text"][:-1]
                        if len(self.load_elem["input_text"]) > 15:
                            self.indices["load"] -= 1
                    else:
                        self.load_elem["input_text"] += event.unicode
                        if len(self.load_elem["input_text"]) > 15:
                            self.indices["load"] += 1

                if self.load_elem["amt_box_active"]:
                    if event.key == pygame.K_RETURN:
                        pass
                    elif event.key == pygame.K_BACKSPACE:
                        self.load_elem["amt_text"] = self.load_elem["amt_text"][:-1]
                        if len(self.load_elem["amt_text"]) > 5:
                            self.indices["pkt_amt"] -= 1
                    else:
                        self.load_elem["amt_text"] += event.unicode
                        if len(self.load_elem["amt_text"]) > 5:
                            self.indices["pkt_amt"] += 1
            if event.type == pygame.MOUSEBUTTONDOWN:
                if self.load_elem["input_box"].collidepoint(event.pos):
                    self.load_elem["input_box_active"] = not self.load_elem["input_box_active"]
                else:
                    self.load_elem["input_box_active"] = False
                self.load_elem["input_box_color"] = color_active if self.load_elem["input_box_active"] else color_inactive
                #
                for idx, i in enumerate(self.if_panels):
                    if i.collidepoint(event.pos):
                        if self.load_elem["amt_text"].isnumeric():
                            self.load_elem["error_text"] = self.utils["font1"].render("    Sniffing for packets", True, BLACK)
                            return ("sniff", self.if_list[idx], self.load_elem["amt_text"])
                        else:
                            self.load_elem["error_text"] = self.utils["font1"].render("   Sniff amt must be #", True, BLACK)
                            self.load_elem["input_text"] = ""
                        pass
                #
                if self.load_elem["amt_box"].collidepoint(event.pos):
                    self.load_elem["amt_box_active"] = not self.load_elem["amt_box_active"]
                    self.load_elem["amt_text"] = ''
                else:
                    self.load_elem["amt_box_active"] = False
                    self.load_elem["amt_text"] = 'pkt#'
                self.load_elem["amt_box_color"] = color_active if self.load_elem["amt_box_active"] else color_inactive
                #
                if self.load_elem["if_up"].collidepoint(event.pos):
                    if self.indices["load_if"] < len(self.if_list) - 5:
                        self.indices["load_if"] += 1
                #
                if self.load_elem["input_box"].collidepoint(event.pos):
                    if self.indices["load_if"] > 0:
                        self.indices["load_if"] -= 1

    def _check_filter_keydown(self, event, elem, action, textt, leng, idx):
        if self.filter_elem[elem]:
            if event.key == pygame.K_RETURN:
                return (action, self.filter_elem[textt], "")
            elif event.key == pygame.K_BACKSPACE:
                self.filter_elem[textt] = self.filter_elem[textt][:-1]
                if len(self.filter_elem[textt]) >= leng:
                    self.indices[idx] -= 1
            else:
                self.filter_elem[textt] += event.unicode
                if len(self.filter_elem[textt]) > leng:
                    self.indices[idx] += 1

    def _check_scroll(self, event, panel, idx, len_chk, leng):
        if self.panels[panel].collidepoint(event.pos):
            if len_chk != None:
                if event.button == 5:
                    if self.indices[idx] < len(len_chk) - leng:
                        self.indices[idx] += 1
                if event.button == 4:
                    if self.indices[idx] > 0:
                        self.indices[idx] -= 1

    def _check_toggle(self, event, tog_num, color, action):
        if self.filter_elem[tog_num].collidepoint(event.pos):
            self.indices["list"] = 0
            if self.filter_elem[color] == GRAY:
                self.filter_elem[color] = RED
                return (Action.PROT, "T", protd[action])
            else:
                self.filter_elem[color] = GRAY
                return (Action.PROT, "F", protd[action])
        else:
            pass

    def _check_active(self, event, box, active, color):
        if self.filter_elem[box].collidepoint(event.pos):
            self.filter_elem[active] = not self.filter_elem[active]
        else:
            self.filter_elem[active] = False
        self.filter_elem[color] = color_active if self.filter_elem[active] else color_inactive

    def _reset_node_color(self, elem):
        for i in self.node_elem.values():
            if elem == 'reset':
                i.set_sprite_props("color", BLUE)
                continue
            if i.get_mac() != elem.get_mac():
                i.set_sprite_props("color", BLUE)

    def _reset_conn_color(self, elem):
        for i in self.conn_elem.values():
            if elem == 'reset':
                i.set_sprite_props("color", BLUE)
                continue
            if tuple(sorted([i.get_mac_one(), i.get_mac_two()])) != tuple(sorted([elem.get_mac_one(), elem.get_mac_two()])):
                i.set_sprite_props("color", BLUE)

    def _check_page_buttons(self, event, button, idx, d):
        if d:
            if self.info_elem[button].collidepoint(event.pos):
                if self.indices[idx] > 0:
                    self.indices[idx] -= 1
        else:
            if self.info_elem[button].collidepoint(event.pos):
                self.indices[idx] += 1

    def _check_map_ctl(self, event, button, idx, d):
        if d:
            if self.map_ctl[button].collidepoint(event.pos):
                self.utils["map_adj"] = True
                self.indices[idx] = round(self.indices[idx] + .1, 1)
                return (Action.RESEND, "")
        else:
            if self.map_ctl[button].collidepoint(event.pos):
                if self.indices[idx] > 0.1:
                    self.utils["map_adj"] = True
                    self.indices[idx] = round(self.indices[idx] - .1, 1)
                    return (Action.RESEND, "")

    def input_check(self):
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            if event.type == pygame.KEYDOWN:
                temp = self._check_filter_keydown(event, "input_box_active", Action.FILTER, "input_text", 16, "input")
                if temp != None:
                    return temp
                temp = self._check_filter_keydown(event, "range_box_active", Action.RANGE, "range_text", 4, "range")
                if temp != None:
                    if temp[1].isnumeric() or temp[1] == "":
                        self.indices["list"] = 0
                        return temp
                    self.utils["in_err"] = True
                temp = self._check_filter_keydown(event, "upper_box_active", Action.MAX, "upper_text", 4, "upper")
                if temp != None:
                    if temp[1] == "":
                        self.utils["max"] = DEFAULT_MAX
                    else:
                        try:
                            self.utils["max"] = int(temp[1])
                            self.utils["new_map"] = True
                            return (Action.RESEND, "")
                        except ValueError as _:
                            self.utils["in_err"] = True
                            self.utils["max"] = DEFAULT_MAX
                    self.utils["new_map"] = True
                    return (Action.RESEND, "")
                temp = self._check_filter_keydown(event, "lower_box_active", Action.MIN, "lower_text", 4, "lower")
                if temp != None:
                    if temp[1] == "":
                        self.utils["min"] = 0
                    else:
                        try:
                            self.utils["min"] = int(temp[1])
                            self.utils["new_map"] = True
                            return (Action.RESEND, "")
                        except ValueError as _:
                            self.utils["in_err"] = True
                            self.utils["min"] = 0
                    self.utils["new_map"] = True
                    return (Action.RESEND, "")

            if event.type == pygame.MOUSEBUTTONDOWN:
                self._check_scroll(event, "top_right", "info", self.in_info, 1)
                self._check_scroll(event, "bottom_left", "list", self.list_elem, 6)

            if len(self.list_elem) > 0:
                if len(self.list_elem) > 135:
                    self.utils["scroll_step"] = (len(self.list_elem) - 6) / 135
                else:
                    self.utils["scroll_step"] =  (len(self.list_elem) - 6) / 135

            if event.type == pygame.MOUSEBUTTONDOWN and not event.button == 5 and not event.button == 4:
                if event.button == 1:
                    if self.list_banner["list_scroll"].collidepoint(event.pos):
                        self.list_bools["scroll_bar_drag"] = True
                        self.utils["list_off"] = self.list_banner["list_scroll"].y - event.pos[1]
            elif event.type == pygame.MOUSEBUTTONUP and not event.button == 5 and not event.button == 4:
                if event.button == 1:
                    self.list_bools["scroll_bar_drag"] = False
            elif event.type == pygame.MOUSEMOTION:
                if self.list_bools["scroll_bar_drag"]:
                    if self.list_banner["list_scroll"].y >= self.panels["bottom_left"].y + 55 and self.list_banner["list_scroll"].y <= self.panels["bottom_left"].y + 190:
                        temp = event.pos[1] + self.utils["list_off"]
                        if temp > self.panels["bottom_left"].y + 190:
                            temp = self.panels["bottom_left"].y + 190
                        if temp < self.panels["bottom_left"].y + 55:
                            temp = self.panels["bottom_left"].y + 55
                        self.list_banner["list_scroll"].y = temp
            if self.list_bools["scroll_bar_drag"]:
                if self.utils["scroll_step"] >= 1:#ff
                    temp = self.list_banner["list_scroll"].y - (self.panels["bottom_left"].y + 55)
                    if temp * self.utils["scroll_step"] < len(self.list_elem) - 6:
                        self.indices["list"] = int(temp * self.utils["scroll_step"])
                    if self.list_banner["list_scroll"].y == (self.panels["bottom_left"].y + 55):
                        self.indices["list"] = 0
                else:
                    temp = self.list_banner["list_scroll"].y - (self.panels["bottom_left"].y + 55)
                    scroll_s = 1
                    if self.utils["scroll_step"]:
                        scroll_s = 1 / self.utils["scroll_step"]
                    self.indices["list"] = int(temp / scroll_s)
                    if self.list_banner["list_scroll"].y == (self.panels["bottom_left"].y + 55):
                        self.indices["list"] = 0

            if len(self.list_elem) > 0:
                self.utils["play_step"] = (self.utils["f_len"] - len(self.screen_packets)) / 334
            if event.type == pygame.MOUSEBUTTONDOWN and not event.button == 5 and not event.button == 4:
                if event.button == 1:
                    if self.filter_elem["play_buf_1"].collidepoint(event.pos):
                        self.utils["play_drag"] = True
                        self.utils["play_off"] = self.filter_elem["play_buf_1"].x - event.pos[0]
                    else:
                        self.utils["play_drag"] = False
                        self.utils["play_off"] = 0
            if event.type == pygame.MOUSEMOTION:
                if self.utils["play_drag"]:
                    if self.filter_elem["play_buf_1"].x >= self.panels["bottom_right"].x + 8 and self.filter_elem["play_buf_1"].x <= self.panels["bottom_right"].x + 342:
                        temp = event.pos[0] + self.utils["play_off"]
                        if temp > self.panels["bottom_right"].x + 342:
                            temp = self.panels["bottom_right"].x + 342
                        if temp < self.panels["bottom_right"].x + 8:
                            temp = self.panels["bottom_right"].x + 8
                        self.filter_elem["play_buf_1"].x = temp
            if event.type == pygame.MOUSEBUTTONUP and not event.button == 5 and not event.button == 4:
                if event.button == 1:
                    self.utils["play_drag"] = False
            if self.utils["play_drag"]:
                if self.utils["play_step"] >= 1:
                    temp = self.filter_elem["play_buf_1"].x - (self.panels["bottom_right"].x + 8)
                    if temp * self.utils["play_step"] < self.utils["f_len"] - len(self.screen_packets):
                        return (Action.PLAYMOVE, int(temp * self.utils["play_step"]))
                else:
                    temp = self.filter_elem["play_buf_1"].x - (self.panels["bottom_right"].x + 8)
                    scroll_s = 1
                    if self.utils["play_step"]:
                        scroll_s = 1 / self.utils["play_step"]
                    return (Action.PLAYMOVE, int(temp / scroll_s))

            if event.type == pygame.MOUSEBUTTONDOWN and not event.button == 5 and not event.button == 4:
                if self.filter_elem["enter_button"].collidepoint(event.pos):
                    t = self.filter_elem["input_text"]
                    self.filter_elem["input_text"] = ''
                    self.indices["input"] = 0
                    return (Action.FILTER, t)

                if self.filter_elem["clear_button"].collidepoint(event.pos):
                    self.indices["input"] = 0
                    self.filter_elem["input_text"] = ''
                    for i in range(1, 10):
                        st = f"toggle{i}_color"
                        self.filter_elem[st] = GRAY
                    return (Action.RESET, "")

                if self.filter_elem["info_button"].collidepoint(event.pos):
                    self.in_info = None

                if self.filter_elem["help_button"].collidepoint(event.pos):
                    self.utils["help"] = not self.utils["help"]

                self._check_active(event, "input_box", "input_box_active", "input_box_color")
                self._check_active(event, "range_box", "range_box_active", "range_box_color")
                self._check_active(event, "lower_box", "lower_box_active", "lower_box_color")
                self._check_active(event, "upper_box", "upper_box_active", "upper_box_color")

                res = self._check_toggle(event, "toggle1", "toggle1_color", Action.ARP)
                if res != None: return res
                res = self._check_toggle(event, "toggle2", "toggle2_color", Action.DNS)
                if res != None: return res
                res = self._check_toggle(event, "toggle3", "toggle3_color", Action.IP)
                if res != None: return res
                res = self._check_toggle(event, "toggle4", "toggle4_color", Action.TCP)
                if res != None: return res
                res = self._check_toggle(event, "toggle5", "toggle5_color", Action.UDP)
                if res != None: return res
                res = self._check_toggle(event, "toggle6", "toggle6_color", Action.SSH)
                if res != None: return res
                res = self._check_toggle(event, "toggle7", "toggle7_color", Action.HTTP)
                if res != None: return res
                res = self._check_toggle(event, "toggle8", "toggle8_color", Action.ICMP)
                if res != None: return res
                res = self._check_toggle(event, "toggle9", "toggle9_color", Action.IGMP)
                if res != None: return res

                if self.filter_elem["play1"].collidepoint(event.pos):
                    self.filter_elem["play1_color"] = RED
                    return (Action.BEG, "")
                if self.filter_elem["play2"].collidepoint(event.pos):
                    self.filter_elem["play2_color"] = RED
                    return (Action.REV, "")

                if self.filter_elem["play3"].collidepoint(event.pos):
                    if self.filter_elem["play3_color"] == GRAY:
                        self.filter_elem["play3_color"] = RED
                        return (Action.PLAY, self.filter_elem["range_text"])
                    if self.filter_elem["play3_color"] == RED:
                        self.filter_elem["play3_color"] = GRAY
                        return (Action.PAUSE, "")

                if self.filter_elem["play4"].collidepoint(event.pos):
                    self.filter_elem["play4_color"] = RED
                    self.filter_elem["play3_color"] = GRAY
                    self.indices["play"] = 0
                    return (Action.STOP, "")
                if self.filter_elem["play5"].collidepoint(event.pos):
                    self.filter_elem["play5_color"] = RED
                    return (Action.FWD, "")
                if self.filter_elem["play6"].collidepoint(event.pos):
                    self.filter_elem["play6_color"] = RED
                    return (Action.END, len(self.screen_packets))

                if self.filter_elem["spd_up"].collidepoint(event.pos):
                    return (Action.SPDUP, "")
                if self.filter_elem["spd_dw"].collidepoint(event.pos):
                    return (Action.SPDDW, "")

                if self.list_banner["list_banner1"].collidepoint(event.pos):
                    if not self.list_bools["time"]:
                        self.list_bools["time"] = not self.list_bools["time"]
                        self.list_elem = sorted(self.list_elem, key=lambda x: x.packet.time)
                    else:
                        self.list_bools["time"] = not self.list_bools["time"]
                        self.list_elem = sorted(self.list_elem, key=lambda x: x.packet.time, reverse=True)
                if self.list_banner["list_banner2"].collidepoint(event.pos):
                    if not self.list_bools["src"]:
                        self.list_bools["src"] = not self.list_bools["src"]
                        self.list_elem = sorted(self.list_elem, key=lambda x: x.packet[IP].src if x.packet.haslayer(IP) else "255.255.255.255")
                    else:
                        self.list_bools["src"] = not self.list_bools["src"]
                        self.list_elem = sorted(self.list_elem, key=lambda x: x.packet[IP].src if x.packet.haslayer(IP) else "255.255.255.255", reverse=True)
                if self.list_banner["list_banner3"].collidepoint(event.pos):
                    if not self.list_bools["dst"]:
                        self.list_bools["dst"] = not self.list_bools["dst"]
                        self.list_elem = sorted(self.list_elem, key=lambda x: x.packet[IP].dst if x.packet.haslayer(IP) else "255.255.255.255")
                    else:
                        self.list_bools["dst"] = not self.list_bools["dst"]
                        self.list_elem = sorted(self.list_elem, key=lambda x: x.packet[IP].dst if x.packet.haslayer(IP) else "255.255.255.255", reverse=True)
                if self.list_banner["list_banner4"].collidepoint(event.pos):
                    if not self.list_bools["prot"]:
                        self.list_bools["prot"] = not self.list_bools["prot"]
                        self.list_elem = sorted(self.list_elem, key=lambda x: (
                            x.packet[IP].proto if x.packet.haslayer(IP) else (
                                x.packet[IPv6].nh if x.packet.haslayer(IPv6) else (
                                    x.packet[ARP].op if x.packet.haslayer(ARP) else 0
                                )
                            )
                        ))
                    else:
                        self.list_bools["prot"] = not self.list_bools["prot"]
                        self.list_elem = sorted(self.list_elem, key=lambda x: (
                            x.packet[IP].proto if x.packet.haslayer(IP) else (
                                x.packet[IPv6].nh if x.packet.haslayer(IPv6) else (
                                    x.packet[ARP].op if x.packet.haslayer(ARP) else 0
                                )
                            )
                        ), reverse=True)
                if self.list_banner["list_banner5"].collidepoint(event.pos):
                    if not self.list_bools["len"]:
                        self.list_bools["len"] = not self.list_bools["len"]
                        self.list_elem = sorted(self.list_elem, key=lambda x: len(raw(x.packet)))
                    else:
                        self.list_bools["len"] = not self.list_bools["len"]
                        self.list_elem = sorted(self.list_elem, key=lambda x: len(raw(x.packet)), reverse=True)

                if self.list_banner["list_banner6"].collidepoint(event.pos):
                    self.set_list_packets(self.screen_packets)
                    self._reset_conn_color("reset")
                    self._reset_node_color("reset")
                if self.list_banner["list_banner7"].collidepoint(event.pos):
                    if self.indices["list"] > 0:
                        self.indices["list"] -= 1
                if self.list_banner["list_banner8"].collidepoint(event.pos):
                    if self.indices["list"] < len(self.list_elem) - 6:
                        self.indices["list"] += 1

                if self.info_elem["info_back_button"].collidepoint(event.pos):
                    if self.indices["info_page"] > 0:
                        self.indices["info_page"] -= 1

                if self.info_elem["info_fwd_button"].collidepoint(event.pos):
                    if self.indices["info_page"] < 1:
                        self.indices["info_page"] += 1

                self._check_page_buttons(event, "info_raw_back_button", "info_page", True)
                self._check_page_buttons(event, "info_raw_fwd_button", "info_page", False)
                self._check_page_buttons(event, "info_pay_back_button", "info_page", True)
                self._check_page_buttons(event, "info_pay_fwd_button", "info_page", False)
                self._check_page_buttons(event, "traffic_in_back_button", "t_in_page", True)
                self._check_page_buttons(event, "traffic_in_fwd_button", "t_in_page", False)
                self._check_page_buttons(event, "traffic_out_back_button", "t_out_page", True)
                self._check_page_buttons(event, "traffic_out_fwd_button", "t_out_page", False)
                self._check_page_buttons(event, "conn_traffic_back_button", "c_t_page", True)
                self._check_page_buttons(event, "conn_traffic_fwd_button", "c_t_page", False)

                if self.info_elem["info_raw_ah_button"].collidepoint(event.pos):
                    self.utils["ascii_hex"] = not self.utils["ascii_hex"]

                if self.map_ctl["load_back"].collidepoint(event.pos):
                    return Action.BACK

                if self.map_ctl["save"].collidepoint(event.pos):
                    return Action.SAVE

                res = self._check_map_ctl(event, "rep_const_up", "rep_const", True)
                if res != None:
                    return res
                res = self._check_map_ctl(event, "rep_const_dw", "rep_const", False)
                if res != None:
                    return res
                res = self._check_map_ctl(event, "att_const_up", "att_const", True)
                if res != None:
                    return res
                res = self._check_map_ctl(event, "att_const_dw", "att_const", False)
                if res != None:
                    return res
                res = self._check_map_ctl(event, "glob_const_up", "glob_const", True)
                if res != None:
                    return res
                res = self._check_map_ctl(event, "glob_const_dw", "glob_const", False)
                if res != None:
                    return res

                node_toggle = True
                for elem in self.node_elem.values():
                    if elem.get_sprite_props()["sprite"].collidepoint(event.pos):
                        node_toggle = False
                        self.indices["list"] = 0
                        self.indices["info"] = 0
                        self._reset_node_color(elem)
                        self._reset_conn_color("reset")
                        self.set_list_packets(elem.get_packet_list())
                        if elem.sprite_props["color"] == YELLOW:
                            elem.sprite_props["color"] = BLUE
                        else:
                            elem.sprite_props["color"] = YELLOW
                            self._post_node(elem)

                for elem in self.conn_elem.values():
                    if node_toggle:
                        if is_point_on_line(elem.get_sprite_props()["s_sprite"], elem.get_sprite_props()["r_sprite"], event.pos):
                            self.indices["list"] = 0
                            self.indices["info"] = 0
                            self._reset_conn_color(elem)
                            self._reset_node_color("reset")
                            self.set_list_packets(elem.get_packet_list())
                            if elem.sprite_props["color"] == YELLOW:
                                elem.sprite_props["color"] = BLUE
                            else:
                                elem.sprite_props["color"] = YELLOW
                                self._post_conn(elem)

                for idx, elem in enumerate(self.list_elem):
                    if elem.sprite_props["sprite"].collidepoint(event.pos):
                        print(f"idx: {idx}")
                        self._post_list_ele(elem)
                        break

    def _post_conn(self, elem):
        self.in_info = post_conn(elem)

    def _post_node(self, elem):
        self.in_info = post_node(elem)

    def _post_list_ele(self, elem):
        self.indices["info"] = 0
        self.in_info = post_list(elem.packet)

    def _update_nodes(self):
        node_list = list(self.node_elem.keys())
        conn_list = list(self.conn_elem.keys())
        positions = {}
        pos = None
        if (self.utils["new_map"] and sorted(node_list) != sorted(self.screen_keys)) or self.utils["map_adj"]:
            self.screen_keys = node_list
            self.utils["new_map"] = False
            self.utils["map_adj"] = False
            for i in self.node_elem.values():
                positions[i.get_mac()] = (i.get_sprite_props()["sprite"].x, i.get_sprite_props()["sprite"].y)
            pos = update_positions(node_list, positions, conn_list, repulsive_const=self.indices["rep_const"], attractive_const=self.indices["att_const"], global_attractive_const=self.indices["glob_const"])

            self.graph_pos = pos
        else:
            pos = self.graph_pos
        placed = []
        cnt = 0
        for node_id, (x, y) in pos.items():
            node = self.node_elem[node_id]
            sprt_p = node.get_sprite_props()

            nx = int((x * 120)) + 400
            if nx < 40:
                nx = 40
            if nx >  750:
                nx = 750
            sprt_p["sprite"].x = nx
            ny = int((y * 100)) + 200
            if ny < 20:
                ny = 20
            if ny > 410:
                ny = 410
            sprt_p["sprite"].y = ny
            self.node_elem[node.get_mac()].set_sprite_props("sprite", sprt_p["sprite"])

        conn_list = list(self.conn_elem.values())
        conns = self.conn_elem
        for conn in conn_list:
            c_sprt_p = conn.get_sprite_props()

            n1sp = self.node_elem[conn.get_mac_one()].get_sprite_props()
            n2sp = self.node_elem[conn.get_mac_two()].get_sprite_props()

            surf, rect = create_connection_rect(conn.get_sprite_props()["color"], (n1sp["sprite"].x + 15, n1sp["sprite"].y + 15), (n2sp["sprite"].x + 15, n2sp["sprite"].y + 15), 5)
            # surf.fill(conn.get_sprite_props()["color"])
            self.conn_elem[tuple(sorted([conn.get_mac_one(), conn.get_mac_two()]))].set_sprite_props("s_sprite", surf)
            self.conn_elem[tuple(sorted([conn.get_mac_one(), conn.get_mac_two()]))].set_sprite_props("r_sprite", rect)
            self.screen.blit(surf, rect.topleft)

        for node_id, (x, y) in pos.items():
            node = self.node_elem[node_id]
            sprt_p = node.get_sprite_props()
            ipbanner = self.utils["font2"].render(str(node.get_mac()), True, BLACK)
            self.screen.blit(ipbanner, (sprt_p["sprite"].x - 15, sprt_p["sprite"].y + 40))

            pygame.draw.circle(self.screen, sprt_p["color"], (sprt_p["sprite"].x + 15, sprt_p["sprite"].y + 15), sprt_p["radius"])

    def _update_info(self, ac_bool):
        if ac_bool == False:
            pygame.draw.rect(self.screen, WHITE, self.info_elem["display_box1"])
            display_surface = self.utils["font2"].render("That is not a correct input option", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 100, self.info_elem["display_box1"].y + 250))
            return None

        if self.in_info == None:
            pygame.draw.rect(self.screen, WHITE, self.info_elem["display_box1"])

            display_surface = self.utils["font2"].render("Welcome to pNode", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 150, self.info_elem["display_box1"].y + 5))

            display_surface = self.utils["font2"].render("Node", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 5, self.info_elem["display_box1"].y + 60))

            display_surface = self.utils["font2"].render("Repulsion", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 5, self.info_elem["display_box1"].y + 75))

            display_surface = self.utils["font2"].render("Conn", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 5, self.info_elem["display_box1"].y + 215))

            display_surface = self.utils["font2"].render("Attraction", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 5, self.info_elem["display_box1"].y + 230))

            display_surface = self.utils["font2"].render("Gravity", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 5, self.info_elem["display_box1"].y + 380))

            display_surface = self.utils["font2"].render("-Seclect node map elements to view information", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 35))

            display_surface = self.utils["font2"].render("and packets related to that element.", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 50))

            display_surface = self.utils["font2"].render("-Filter parameters can be used below to filter", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 70))

            display_surface = self.utils["font2"].render("the packets that are included in the map.", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 85))

            display_surface = self.utils["font2"].render("-The play functionality can be used to step", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 105))

            display_surface = self.utils["font2"].render("through the pcap packet by packet to observe", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 120))

            display_surface = self.utils["font2"].render("the network's traffic.", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 135))

            display_surface = self.utils["font2"].render("-The 'Host packets' and 'Packets incld.' can", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 155))

            display_surface = self.utils["font2"].render("be used to limit hosts by packet amount and", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 170))

            display_surface = self.utils["font2"].render("control the amount of packets that are used", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 185))

            display_surface = self.utils["font2"].render("to create the node map.", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 200))

            display_surface = self.utils["font2"].render("Filter parameters:", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 90, self.info_elem["display_box1"].y + 225))

            display_surface = self.utils["font2"].render("ex: 'ip=xxx.xxx.xxx.xxx'", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 90, self.info_elem["display_box1"].y + 445))

            self.info_elem["info_back_button"] = pygame.Rect(self.info_elem["display_box1"].x + 300, self.info_elem["display_box1"].y + 225 , 30, 20)
            pygame.draw.rect(self.screen, GRAY, self.info_elem["info_back_button"])
            dst_surface = self.utils["font2"].render("<", True, BLACK)
            self.screen.blit(dst_surface, (self.info_elem["info_back_button"].x + 10, self.info_elem["info_back_button"].y + 2))
            #
            self.info_elem["info_fwd_button"] = pygame.Rect(self.info_elem["display_box1"].x + 335, self.info_elem["display_box1"].y + 225 , 30, 20)
            pygame.draw.rect(self.screen, GRAY, self.info_elem["info_fwd_button"])
            dst_surface = self.utils["font2"].render(">", True, BLACK)
            self.screen.blit(dst_surface, (self.info_elem["info_fwd_button"].x + 10, self.info_elem["info_fwd_button"].y + 2))

            depth = 0
            chk = 12
            for i in range(self.indices["info_page"] * chk, self.indices["info_page"] * chk + chk):
                display_surface = self.utils["font2"].render(filt_parameters[i], True, BLACK)
                self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 85, self.info_elem["display_box1"].y + 255 + depth))
                depth += 15
        else:
            depth = 0
            for hdr in self.in_info[self.indices["info"]:]:
                match hdr["hdr_type"]:
                    case "ether":
                        depth = draw_ether(self, hdr, depth)
                        pass
                    case "ip":
                        depth = draw_ip(self, hdr, depth)
                        pass
                    case "ip6":
                        depth = draw_ip6(self, hdr, depth)
                        pass
                    case "ip6_hop":
                        depth = draw_ip6_hop(self, hdr, depth)
                        pass
                    case "ip6_dest_ops":
                        depth = draw_ip6_dest_ops(self, hdr, depth)
                        pass
                    case "ip6_routing":
                        depth = draw_ip6_routing(self, hdr, depth)
                        pass
                    case "ip6_fragment":
                        depth = draw_ip6_fragment(self, hdr, depth)
                        pass
                    case "tcp":
                        depth = draw_tcp(self, hdr, depth)
                        pass
                    case "udp":
                        depth = draw_udp(self, hdr, depth)
                        pass
                    case "dns":
                        depth = draw_dns(self, hdr, depth)
                        pass
                    case "icmp":
                        depth = draw_icmp(self, hdr, depth)
                        pass
                    case "icmp6_echo_req":
                        depth = draw_icmp6_echo_req(self, hdr, depth)
                        pass
                    case "icmp6_echo_rep":
                        depth = draw_icmp6_echo_rep(self, hdr, depth)
                        pass
                    case "icmp6_dest_un":
                        depth = draw_icmp6_dest_un(self, hdr, depth)
                        pass
                    case "icmp6_too_big":
                        depth = draw_icmp6_too_big(self, hdr, depth)
                        pass
                    case "icmp6_time_ex":
                        depth = draw_icmp6_time_ex(self, hdr, depth)
                        pass
                    case "icmp6_param_prob":
                        depth = draw_icmp6_param_prob(self, hdr, depth)
                        pass
                    case "icmp6_ni_quer":
                        depth = draw_icmp6_ni_quer(self, hdr, depth)
                        pass
                    case "icmp6_ni_rep":
                        depth = draw_icmp6_ni_rep(self, hdr, depth)
                        pass
                    case "icmp6_nd_rs":
                        depth = draw_icmp6_nd_rs(self, hdr, depth)
                        pass
                    case "icmp6_nd_ra":
                        depth = draw_icmp6_nd_ra(self, hdr, depth)
                        pass
                    case "icmp6_nd_ns":
                        depth = draw_icmp6_nd_ns(self, hdr, depth)
                        pass
                    case "icmp6_nd_na":
                        depth = draw_icmp6_nd_na(self, hdr, depth)
                        pass
                    case "icmp6_ml_rep":
                        depth = draw_icmp6_ml_rep(self, hdr, depth)
                    case "icmp6_ml_rep2":
                        depth = draw_icmp6_ml_rep2(self, hdr, depth)
                    case "igmp":
                        depth = draw_igmp(self, hdr, depth)
                    case "igmp3_gr":
                        depth = draw_igmp3_gr(self, hdr, depth)
                    case "igmp3_mq":
                        depth = draw_igmp3_mq(self, hdr, depth)
                    case "igmp3_mr":
                        depth = draw_igmp3_mr(self, hdr, depth)
                    case "igmp3_mra":
                        depth = draw_igmp3_mra(self, hdr, depth)
                    case "arp":
                        depth = draw_arp(self, hdr, depth)
                    case "raw":
                        depth = draw_raw(self, hdr, depth)
                    case "payload":
                        depth = draw_payload(self, hdr, depth)
                    case "host":
                        depth = draw_host(self, hdr, depth)
                    case "traffic":
                        depth = draw_traffic(self, hdr, depth)
                    case "conn":
                        depth = draw_conn(self, hdr, depth)
                    case "conn_traffic":
                        depth = draw_conn_traffic(self, hdr, depth)

    def _update_list(self):
        # 6 packets on panel
        tempp = None
        for i in self.list_elem:
            i.sprite_props["sprite"].x = 0
            i.sprite_props["sprite"].y = - 40
        if len(self.list_elem) < 7:
            buf = 0
            for elem in self.list_elem:
                datetime_obj = datetime.fromtimestamp(float(elem.packet.time))
                df = datetime_obj.strftime('%H:%M:%S')
                fractional_seconds = f"{datetime_obj.microsecond / 1000000:.2f}"[1:]
                date = df + fractional_seconds
                elem.sprite_props["sprite"].y = self.panels['bottom_left'].y + 30 + buf
                pygame.draw.rect(self.screen, RED, elem.sprite_props["sprite"], 1)
                t = elem.packet.summary()
                self.screen.blit(self.utils["font2"].render(f"{date} | {t[:95]}", True, BLACK), (elem.sprite_props["sprite"].x + 5, elem.sprite_props["sprite"].y + 5))
                buf += 35
        else:
            buf = 0
            for elem in self.list_elem[self.indices["list"]:self.indices["list"] + 6]:
                datetime_obj = datetime.fromtimestamp(float(elem.packet.time))
                df = datetime_obj.strftime('%H:%M:%S')
                fractional_seconds = f"{datetime_obj.microsecond / 1000000:.2f}"[1:]
                date = df + fractional_seconds
                elem.sprite_props["sprite"].y = self.panels['bottom_left'].y + 30 + buf
                pygame.draw.rect(self.screen, RED, elem.sprite_props["sprite"], 1)
                t = elem.packet.summary()
                self.screen.blit(self.utils["font2"].render(f"{date} | {t[:95]}", True, BLACK), (elem.sprite_props["sprite"].x + 5, elem.sprite_props["sprite"].y + 5))
                buf += 35

    def update_screen(self, ac_bool):

        if self.utils["in_err"]:
            self.utils["in_err"] = False
            ac_bool = False

        input_txt = self.filter_elem["input_text"]
        temp = input_txt
        if len(temp) > 16:
            temp = temp[self.indices["input"]: self.indices["input"] + 16]

        txt_surface = self.utils["font1"].render(temp, True, BLACK)

        range_txt = self.filter_elem["range_text"]
        temp = range_txt
        if len(temp) > 4:
            temp = temp[self.indices["range"]: self.indices["range"] + 4]

        rng_surface = self.utils["font1"].render(temp, True, BLACK)

        greater_txt = self.filter_elem["upper_text"]

        temp = greater_txt
        if len(temp) > 4:
            temp = temp[self.indices["upper"]: self.indices["upper"] + 4]

        grt_surface = self.utils["font1"].render(temp, True, BLACK)

        lesser_txt = self.filter_elem["lower_text"]

        temp = lesser_txt
        if len(temp) > 4:
            temp = temp[self.indices["lower"]: self.indices["lower"] + 4]

        lst_surface = self.utils["font1"].render(temp, True, BLACK)


        self.screen.fill(WHITE)

        pygame.draw.rect(self.screen, RED, self.panels['top_left'])
        pygame.draw.rect(self.screen, GREEN, self.panels['top_right'])
        pygame.draw.rect(self.screen, BLUE, self.panels['bottom_left'])
        self._update_info(ac_bool)
        pygame.draw.rect(self.screen, YELLOW, self.panels['bottom_right'])

        pygame.draw.rect(self.screen, RED, self.map_ctl["load_back"])
        self.screen.blit(self.map_ctl["load_back_text"], (self.map_ctl["load_back"].x + 5, self.map_ctl["load_back"].y + 5))

        pygame.draw.rect(self.screen, RED, self.map_ctl["save"])
        self.screen.blit(self.map_ctl["save_text"], (self.map_ctl["save"].x + 5, self.map_ctl["save"].y + 5))


        pygame.draw.rect(self.screen, self.filter_elem["input_box_color"], self.filter_elem["input_box"], 1)
        self.screen.blit(txt_surface, (self.filter_elem["input_box"].x + 5, self.filter_elem["input_box"].y + 3))

        pygame.draw.rect(self.screen, GRAY, self.filter_elem["enter_button"])
        self.screen.blit(self.filter_elem["enter_button_text"], (self.filter_elem["enter_button"].x + 13, self.filter_elem["enter_button"].y - 1))

        pygame.draw.rect(self.screen, GRAY, self.filter_elem["clear_button"])
        self.screen.blit(self.filter_elem["clear_button_text"], (self.filter_elem["clear_button"].x + 14, self.filter_elem["clear_button"].y - 2))

        pygame.draw.rect(self.screen, GRAY, self.filter_elem["info_button"])
        self.screen.blit(self.filter_elem["info_button_text"], (self.filter_elem["info_button"].x + 14, self.filter_elem["info_button"].y + 5))

        pygame.draw.rect(self.screen, GRAY, self.filter_elem["help_button"])
        self.screen.blit(self.filter_elem["help_button_text"], (self.filter_elem["help_button"].x + 14, self.filter_elem["help_button"].y + 0))
        #--

        pygame.draw.rect(self.screen, self.filter_elem["toggle1_color"], self.filter_elem["toggle1"])
        self.screen.blit(self.filter_elem["toggle1_text"], (self.filter_elem["toggle1"].x + 28, self.filter_elem["toggle1"].y + 4))
        pygame.draw.rect(self.screen, self.filter_elem["toggle2_color"], self.filter_elem["toggle2"])
        self.screen.blit(self.filter_elem["toggle2_text"], (self.filter_elem["toggle2"].x + 28, self.filter_elem["toggle2"].y + 4))
        pygame.draw.rect(self.screen, self.filter_elem["toggle3_color"], self.filter_elem["toggle3"])
        self.screen.blit(self.filter_elem["toggle3_text"], (self.filter_elem["toggle3"].x + 28, self.filter_elem["toggle3"].y + 4))
        pygame.draw.rect(self.screen, self.filter_elem["toggle4_color"], self.filter_elem["toggle4"])
        self.screen.blit(self.filter_elem["toggle4_text"], (self.filter_elem["toggle4"].x + 28, self.filter_elem["toggle4"].y + 4))
        pygame.draw.rect(self.screen, self.filter_elem["toggle5_color"], self.filter_elem["toggle5"])
        self.screen.blit(self.filter_elem["toggle5_text"], (self.filter_elem["toggle5"].x + 28, self.filter_elem["toggle5"].y + 4))
        pygame.draw.rect(self.screen, self.filter_elem["toggle6_color"], self.filter_elem["toggle6"])
        self.screen.blit(self.filter_elem["toggle6_text"], (self.filter_elem["toggle6"].x + 28, self.filter_elem["toggle6"].y + 4))
        pygame.draw.rect(self.screen, self.filter_elem["toggle7_color"], self.filter_elem["toggle7"])
        self.screen.blit(self.filter_elem["toggle7_text"], (self.filter_elem["toggle7"].x + 28, self.filter_elem["toggle7"].y + 4))
        pygame.draw.rect(self.screen, self.filter_elem["toggle8_color"], self.filter_elem["toggle8"])
        self.screen.blit(self.filter_elem["toggle8_text"], (self.filter_elem["toggle8"].x + 28, self.filter_elem["toggle8"].y + 4))
        pygame.draw.rect(self.screen, self.filter_elem["toggle9_color"], self.filter_elem["toggle9"])
        self.screen.blit(self.filter_elem["toggle9_text"], (self.filter_elem["toggle9"].x + 28, self.filter_elem["toggle9"].y + 4))

        #--
        # line width = 338
        pygame.draw.rect(self.screen, self.filter_elem["play_line_color"], self.filter_elem["play_line"])



        if self.utils["f_len"] and self.indices["play"]:
            lidx = self.utils["f_len"] / self.indices["play"]
            play_x = 334 // lidx
            self.filter_elem["play_buf_1"].x = self.filter_elem["play_line"].x + play_x
        elif not self.indices["play"]:
            self.filter_elem["play_buf_1"].x = self.filter_elem["play_line"].x
        pygame.draw.rect(self.screen, self.filter_elem["play_buf_1_color"], self.filter_elem["play_buf_1"])

        pygame.draw.rect(self.screen, self.filter_elem["play1_color"], self.filter_elem["play1"])
        self.screen.blit(self.filter_elem["play1_text"], (self.filter_elem["play1"].x + 13, self.filter_elem["play1"].y + 2))


        pygame.draw.rect(self.screen, self.filter_elem["play2_color"], self.filter_elem["play2"])
        self.screen.blit(self.filter_elem["play2_text"], (self.filter_elem["play2"].x + 10, self.filter_elem["play2"].y + 3))


        pygame.draw.rect(self.screen, self.filter_elem["play3_color"], self.filter_elem["play3"])
        if self.filter_elem["play3_color"] == GRAY:
            self.screen.blit(self.filter_elem["play3_text1"], (self.filter_elem["play3"].x + 18, self.filter_elem["play3"].y + 2))
        else:
            self.screen.blit(self.filter_elem["play3_text2"], (self.filter_elem["play3"].x + 12, self.filter_elem["play3"].y + 2))

        pygame.draw.rect(self.screen, self.filter_elem["play4_color"], self.filter_elem["play4"])
        self.screen.blit(self.filter_elem["play4_text"], (self.filter_elem["play4"].x + 18, self.filter_elem["play4"].y + 2))


        pygame.draw.rect(self.screen, self.filter_elem["play5_color"], self.filter_elem["play5"])
        self.screen.blit(self.filter_elem["play5_text"], (self.filter_elem["play5"].x + 15, self.filter_elem["play5"].y + 3))


        pygame.draw.rect(self.screen, self.filter_elem["play6_color"], self.filter_elem["play6"])
        self.screen.blit(self.filter_elem["play6_text"], (self.filter_elem["play6"].x + 13, self.filter_elem["play6"].y + 2))

        pygame.draw.rect(self.screen, self.filter_elem["spd_up_color"], self.filter_elem["spd_up"])
        self.screen.blit(self.filter_elem["spd_up_text"], (self.filter_elem["spd_up"].x + 15, self.filter_elem["spd_up"].y + 0))

        pygame.draw.rect(self.screen, self.filter_elem["spd_dw_color"], self.filter_elem["spd_dw"])
        self.screen.blit(self.filter_elem["spd_dw_text"], (self.filter_elem["spd_dw"].x + 15, self.filter_elem["spd_dw"].y + 0))


        pygame.draw.rect(self.screen, self.filter_elem["range_box_color"], self.filter_elem["range_box"], 1)
        self.screen.blit(rng_surface, (self.filter_elem["range_box"].x + 5, self.filter_elem["range_box"].y + 3))
        self.screen.blit(self.filter_elem["range_banner"], (self.filter_elem["range_box"].x - 110, self.filter_elem["range_box"].y + 7))


        pygame.draw.rect(self.screen, self.filter_elem["upper_box_color"], self.filter_elem["upper_box"], 1)
        self.screen.blit(grt_surface, (self.filter_elem["upper_box"].x + 5, self.filter_elem["upper_box"].y + 3))
        self.screen.blit(self.filter_elem["upper_banner"], (self.filter_elem["upper_box"].x - 110, self.filter_elem["upper_box"].y + 7))


        pygame.draw.rect(self.screen, self.filter_elem["lower_box_color"], self.filter_elem["lower_box"], 1)
        self.screen.blit(lst_surface, (self.filter_elem["lower_box"].x + 5, self.filter_elem["lower_box"].y + 3))
        self.screen.blit(self.filter_elem["lower_banner"], (self.filter_elem["lower_box"].x - 110, self.filter_elem["lower_box"].y + 7))



        pygame.draw.rect(self.screen, GRAY, self.list_banner["list_banner1"])
        self.screen.blit(self.list_banner["list_banner1_text"], (self.list_banner["list_banner1"].x + 15, self.list_banner["list_banner1"].y + 3))

        pygame.draw.rect(self.screen, GRAY, self.list_banner["list_banner2"])
        self.screen.blit(self.list_banner["list_banner2_text"], (self.list_banner["list_banner2"].x + 15, self.list_banner["list_banner2"].y + 3))

        pygame.draw.rect(self.screen, GRAY, self.list_banner["list_banner3"])
        self.screen.blit(self.list_banner["list_banner3_text"], (self.list_banner["list_banner3"].x + 15, self.list_banner["list_banner3"].y + 3))

        pygame.draw.rect(self.screen, GRAY, self.list_banner["list_banner4"])
        self.screen.blit(self.list_banner["list_banner4_text"], (self.list_banner["list_banner4"].x + 15, self.list_banner["list_banner4"].y + 3))

        pygame.draw.rect(self.screen, GRAY, self.list_banner["list_banner5"])
        self.screen.blit(self.list_banner["list_banner5_text"], (self.list_banner["list_banner5"].x + 15, self.list_banner["list_banner5"].y + 3))

        pygame.draw.rect(self.screen, GRAY, self.list_banner["list_banner6"])
        self.screen.blit(self.list_banner["list_banner6_text"], (self.list_banner["list_banner6"].x + 10, self.list_banner["list_banner6"].y + 3))

        pygame.draw.rect(self.screen, GRAY, self.list_banner["list_banner7"])
        self.screen.blit(self.list_banner["list_banner7_text"], (self.list_banner["list_banner7"].x + 10, self.list_banner["list_banner7"].y + 3))

        pygame.draw.rect(self.screen, GRAY, self.list_banner["list_banner8"])
        self.screen.blit(self.list_banner["list_banner8_text"], (self.list_banner["list_banner8"].x + 10, self.list_banner["list_banner8"].y + 3))

        if len(self.list_elem) > 6:
            ny = (self.indices["list"] / (len(self.list_elem) - 6)) * 135
            ny = self.panels["bottom_left"].y + 55 + ny
            self.list_banner["list_scroll"].y = ny
        pygame.draw.rect(self.screen, GRAY, self.list_banner["list_scroll"])


        pygame.draw.rect(self.screen, GRAY, self.map_ctl["rep_const_up"])
        self.screen.blit(self.map_ctl["rep_const_up_text"], (self.map_ctl["rep_const_up"].x + 10, self.map_ctl["rep_const_up"].y + 3))

        pygame.draw.rect(self.screen, GRAY, self.map_ctl["rep_const_dw"])
        self.screen.blit(self.map_ctl["rep_const_dw_text"], (self.map_ctl["rep_const_dw"].x + 10, self.map_ctl["rep_const_dw"].y + 3))

        pygame.draw.rect(self.screen, GRAY, self.map_ctl["att_const_up"])
        self.screen.blit(self.map_ctl["att_const_up_text"], (self.map_ctl["att_const_up"].x + 10, self.map_ctl["att_const_up"].y + 3))

        pygame.draw.rect(self.screen, GRAY, self.map_ctl["att_const_dw"])
        self.screen.blit(self.map_ctl["att_const_dw_text"], (self.map_ctl["att_const_dw"].x + 10, self.map_ctl["att_const_dw"].y + 3))

        pygame.draw.rect(self.screen, GRAY, self.map_ctl["glob_const_up"])
        self.screen.blit(self.map_ctl["glob_const_up_text"], (self.map_ctl["glob_const_up"].x + 10, self.map_ctl["glob_const_up"].y + 3))

        pygame.draw.rect(self.screen, GRAY, self.map_ctl["glob_const_dw"])
        self.screen.blit(self.map_ctl["glob_const_dw_text"], (self.map_ctl["glob_const_dw"].x + 10, self.map_ctl["glob_const_dw"].y + 3))


        self._update_nodes()
        # self._update_info()
        self._update_list()

        if self.utils["help"]:
            pygame.draw.rect(self.screen, GRAY, self.help_win["1"])
            self.screen.blit(self.help_win["1_text_1_1"], (self.help_win["1"].x + 5, self.help_win["1"].y + 3))
            self.screen.blit(self.help_win["1_text_1_2"], (self.help_win["1"].x + 5, self.help_win["1"].y + 18))
            self.screen.blit(self.help_win["1_text_2"], (self.help_win["1"].x + 5, self.help_win["1"].y + 50))

            pygame.draw.rect(self.screen, GRAY, self.help_win["2"])
            self.screen.blit(self.help_win["2_text_1_1"], (self.help_win["2"].x + 5, self.help_win["2"].y + 3))
            self.screen.blit(self.help_win["2_text_1_2"], (self.help_win["2"].x + 5, self.help_win["2"].y + 18))
            self.screen.blit(self.help_win["2_text_1_3"], (self.help_win["2"].x + 5, self.help_win["2"].y + 33))

            pygame.draw.rect(self.screen, GRAY, self.help_win["3"])
            self.screen.blit(self.help_win["3_text_1_1"], (self.help_win["3"].x + 5, self.help_win["3"].y + 3))
            self.screen.blit(self.help_win["3_text_1_2"], (self.help_win["3"].x + 5, self.help_win["3"].y + 18))
            self.screen.blit(self.help_win["3_text_2_1"], (self.help_win["3"].x + 5, self.help_win["3"].y + 50))
            self.screen.blit(self.help_win["3_text_2_2"], (self.help_win["3"].x + 5, self.help_win["3"].y + 65))

            pygame.draw.rect(self.screen, GRAY, self.help_win["4"])
            self.screen.blit(self.help_win["4_text_1_1"], (self.help_win["4"].x + 5, self.help_win["4"].y + 3))
            self.screen.blit(self.help_win["4_text_1_2"], (self.help_win["4"].x + 5, self.help_win["4"].y + 18))
            self.screen.blit(self.help_win["4_text_1_3"], (self.help_win["4"].x + 5, self.help_win["4"].y + 33))
            self.screen.blit(self.help_win["4_text_1_4"], (self.help_win["4"].x + 5, self.help_win["4"].y + 48))

            pygame.draw.rect(self.screen, GRAY, self.help_win["5"])
            self.screen.blit(self.help_win["5_text_1_1"], (self.help_win["5"].x + 5, self.help_win["5"].y + 3))
            self.screen.blit(self.help_win["5_text_1_2"], (self.help_win["5"].x + 5, self.help_win["5"].y + 18))
            self.screen.blit(self.help_win["5_text_1_3"], (self.help_win["5"].x + 5, self.help_win["5"].y + 33))
            self.screen.blit(self.help_win["5_text_1_4"], (self.help_win["5"].x + 5, self.help_win["5"].y + 48))

            pygame.draw.rect(self.screen, GRAY, self.help_win["6"])
            self.screen.blit(self.help_win["6_text_1_1"], (self.help_win["6"].x + 5, self.help_win["6"].y + 3))
            self.screen.blit(self.help_win["6_text_1_2"], (self.help_win["6"].x + 5, self.help_win["6"].y + 18))
            self.screen.blit(self.help_win["6_text_1_3"], (self.help_win["6"].x + 5, self.help_win["6"].y + 33))

            pygame.draw.rect(self.screen, GRAY, self.help_win["7"])
            self.screen.blit(self.help_win["7_text_1_1"], (self.help_win["7"].x + 5, self.help_win["7"].y + 3))
            self.screen.blit(self.help_win["7_text_1_2"], (self.help_win["7"].x + 5, self.help_win["7"].y + 18))
            self.screen.blit(self.help_win["7_text_1_3"], (self.help_win["7"].x + 5, self.help_win["7"].y + 33))
            self.screen.blit(self.help_win["7_text_1_4"], (self.help_win["7"].x + 5, self.help_win["7"].y + 48))

            pygame.draw.rect(self.screen, GRAY, self.help_win["8"])
            self.screen.blit(self.help_win["8_text_1_1"], (self.help_win["8"].x + 5, self.help_win["8"].y + 3))
            self.screen.blit(self.help_win["8_text_1_2"], (self.help_win["8"].x + 5, self.help_win["8"].y + 18))
            self.screen.blit(self.help_win["8_text_2_1"], (self.help_win["8"].x + 5, self.help_win["8"].y + 70))
            self.screen.blit(self.help_win["8_text_2_2"], (self.help_win["8"].x + 5, self.help_win["8"].y + 85))
            self.screen.blit(self.help_win["8_text_2_3"], (self.help_win["8"].x + 5, self.help_win["8"].y + 100))

        pygame.display.flip()

        if ac_bool == False:
            time.sleep(1.0)
        else:
            time.sleep(0.05)
        # time.sleep(0.1)

        pygame.draw.rect(self.screen, GRAY, self.info_elem["info_raw_ah_button"])


        self.filter_elem["play1_color"] = GRAY
        pygame.draw.rect(self.screen, self.filter_elem["play1_color"], self.filter_elem["play1"])
        self.screen.blit(self.filter_elem["play1_text"], (self.filter_elem["play1"].x + 15, self.filter_elem["play1"].y + 3))

        self.filter_elem["play2_color"] = GRAY
        pygame.draw.rect(self.screen, self.filter_elem["play2_color"], self.filter_elem["play2"])
        self.screen.blit(self.filter_elem["play2_text"], (self.filter_elem["play2"].x + 15, self.filter_elem["play2"].y + 3))

        self.filter_elem["play4_color"] = GRAY
        pygame.draw.rect(self.screen, self.filter_elem["play4_color"], self.filter_elem["play4"])
        self.screen.blit(self.filter_elem["play4_text"], (self.filter_elem["play4"].x + 20, self.filter_elem["play4"].y + 3))

        self.filter_elem["play5_color"] = GRAY
        pygame.draw.rect(self.screen, self.filter_elem["play5_color"], self.filter_elem["play5"])
        self.screen.blit(self.filter_elem["play5_text"], (self.filter_elem["play5"].x + 15, self.filter_elem["play5"].y + 3))

        self.filter_elem["play6_color"] = GRAY
        pygame.draw.rect(self.screen, self.filter_elem["play6_color"], self.filter_elem["play6"])
        self.screen.blit(self.filter_elem["play6_text"], (self.filter_elem["play6"].x + 15, self.filter_elem["play6"].y + 3))



    def step_through(self, step_position, step_size, filtered_packets):
        pkts = filtered_packets[step_position:step_position + int(step_size)]
        self.set_packets(pkts)
        self.indices["play"] = step_position
        self.utils["f_len"] = len(filtered_packets)
