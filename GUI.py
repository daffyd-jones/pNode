import pygame
import sys
import time
import threading

from scapy.all import *
from scapy.all import IP, TCP, UDP, ARP, DNS, ICMP, SNMP, DHCP, BOOTP, L2TP, PPP, Raw, IPv6
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3


from datetime import datetime
import random

from scapy.layers.l2 import Ether

from info_draw_funcs import *
from GUIObj import NObj
from GUIObj import LObj
from GUIObj import PLObj
from Actions import Action
from test import update_positions
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

def create_connection_rect(color, node1, node2, width):
    dx = node2[0] - node1[0]
    dy = node2[1] - node1[1]
    length = math.sqrt(dx**2 + dy**2)

    # Adjust the angle calculation
    angle = math.degrees(math.atan2(dy, dx))

    rect_surface = pygame.Surface((length, width), pygame.SRCALPHA)
    rect_surface.fill(color)

    rotated_surface = pygame.transform.rotate(rect_surface, -angle)

    # Adjust the position calculation
    if dx >= 0:
        center_x = node1[0] + dx / 2
        center_y = node1[1] + dy / 2
    else:
        center_x = node2[0] - dx / 2
        center_y = node2[1] - dy / 2

    collision_rect = rotated_surface.get_rect(center=(center_x, center_y))

    return rotated_surface, collision_rect

def is_point_on_line(surface, rect, point):
    if rect.collidepoint(point):
        local_point = (point[0] - rect.x, point[1] - rect.y)
        return surface.get_at(local_point)[3] != 0
    return False






def build_filter_elem(panels, font1, font2):
    """_summary_

    Args:
        panels (_type_): _description_
        font1 (_type_): _description_
        font2 (_type_): _description_

    Returns:
        _type_: _description_
    """
    flt_ele = {};

    #-- search input box and enter button

    flt_ele["input_box"] = pygame.Rect(panels['bottom_right'].x + 8, panels['bottom_right'].y + 8, 200, 30)
    flt_ele["input_text"] = ''
    flt_ele["input_box_color"] = color_inactive
    flt_ele["input_box_active"] = False

    flt_ele["enter_button"] = pygame.Rect(panels['bottom_right'].x + 213, panels['bottom_right'].y + 11, 40, 24)
    flt_ele["enter_button_text"] = font1.render('>', True, BLACK)

    flt_ele["clear_button"] = pygame.Rect(panels['bottom_right'].x + 260, panels['bottom_right'].y + 11, 40, 24)
    flt_ele["clear_button_text"] = font1.render('x', True, BLACK)

    flt_ele["info_button"] = pygame.Rect(panels['bottom_right'].x + 307, panels['bottom_right'].y + 11, 40, 24)
    flt_ele["info_button_text"] = font1.render('^', True, BLACK)

    flt_ele["help_button"] = pygame.Rect(panels['bottom_right'].x + 354, panels['bottom_right'].y + 11, 40, 24)
    flt_ele["help_button_text"] = font1.render('?', True, BLACK)

        #--- protocol toggles

    flt_ele["toggle1"] = pygame.Rect(panels['bottom_right'].x + 8, panels['bottom_right'].y + 56, 22, 22)
    flt_ele["toggle1_text"] = font2.render('ARP', True, BLACK)
    flt_ele["toggle1_color"] = GRAY

    flt_ele["toggle2"] = pygame.Rect(panels['bottom_right'].x + 8, panels['bottom_right'].y + 96, 22, 22)
    flt_ele["toggle2_text"] = font2.render('DNS', True, BLACK)
    flt_ele["toggle2_color"] = GRAY

    flt_ele["toggle3"] = pygame.Rect(panels['bottom_right'].x + 8, panels['bottom_right'].y + 136, 22, 22)
    flt_ele["toggle3_text"] = font2.render('IP', True, BLACK)
    flt_ele["toggle3_color"] = GRAY

    flt_ele["toggle4"] = pygame.Rect(panels['bottom_right'].x + 69, panels['bottom_right'].y + 56, 22, 22)
    flt_ele["toggle4_text"] = font2.render('TCP', True, BLACK)
    flt_ele["toggle4_color"] = GRAY

    flt_ele["toggle5"] = pygame.Rect(panels['bottom_right'].x + 69, panels['bottom_right'].y + 96, 22, 22)
    flt_ele["toggle5_text"] = font2.render('UDP', True, BLACK)
    flt_ele["toggle5_color"] = GRAY

    flt_ele["toggle6"] = pygame.Rect(panels['bottom_right'].x + 69, panels['bottom_right'].y + 136, 22, 22)
    flt_ele["toggle6_text"] = font2.render('SSH', True, BLACK)
    flt_ele["toggle6_color"] = GRAY

    flt_ele["toggle7"] = pygame.Rect(panels['bottom_right'].x + 130, panels['bottom_right'].y + 56, 22, 22)
    flt_ele["toggle7_text"] = font2.render('HTTP', True, BLACK)
    flt_ele["toggle7_color"] = GRAY

    flt_ele["toggle8"] = pygame.Rect(panels['bottom_right'].x + 130, panels['bottom_right'].y + 96, 22, 22)
    flt_ele["toggle8_text"] = font2.render('ICMP', True, BLACK)
    flt_ele["toggle8_color"] = GRAY

    flt_ele["toggle9"] = pygame.Rect(panels['bottom_right'].x + 130, panels['bottom_right'].y + 136, 22, 22)
    flt_ele["toggle9_text"] = font2.render('IGMP', True, BLACK)
    flt_ele["toggle9_color"] = GRAY

        #-- debug buttons

    flt_ele["play_line"] = pygame.Rect(panels['bottom_right'].x + 8, panels['bottom_right'].y + 183, 338, 2)
    flt_ele["play_line_active"] = False
    flt_ele["play_line_color"] = GRAY

    flt_ele["play_buf_1"] = pygame.Rect(flt_ele["play_line"].x, panels['bottom_right'].y + 180, 4, 8)
    flt_ele["play_buf_1_active"] = False
    flt_ele["play_buf_1_color"] = GRAY

    # flt_ele["play_buf_2"] = pygame.Rect(panels['bottom_right'].x + 140, panels['bottom_right'].y + 180, 4, 8)
    # flt_ele["play_buf_2_active"] = False
    # flt_ele["play_buf_2_color"] = GRAY


    flt_ele["play1"] = pygame.Rect(panels['bottom_right'].x + 8, panels['bottom_right'].y + 202, 48, 30)
    flt_ele["play1_text"] = font1.render('|<', True, BLACK)
    flt_ele["play1_active"] = False
    flt_ele["play1_color"] = GRAY

    flt_ele["play2"] = pygame.Rect(panels['bottom_right'].x + 66, panels['bottom_right'].y + 202, 48, 30)
    flt_ele["play2_text"] = font1.render('<<', True, BLACK)
    flt_ele["play2_active"] = False
    flt_ele["play2_color"] = GRAY

    flt_ele["play3"] = pygame.Rect(panels['bottom_right'].x + 124, panels['bottom_right'].y + 202, 48, 30)
    flt_ele["play3_text1"] = font1.render('>', True, BLACK)
    flt_ele["play3_text2"] = font1.render('||', True, BLACK)
    flt_ele["play3_active"] = False
    flt_ele["play3_color"] = GRAY

    flt_ele["play4"] = pygame.Rect(panels['bottom_right'].x + 182, panels['bottom_right'].y + 202, 48, 30)
    flt_ele["play4_text"] = font1.render('\u23F9', True, BLACK)
    flt_ele["play4_active"] = False
    flt_ele["play4_color"] = GRAY

    flt_ele["play5"] = pygame.Rect(panels['bottom_right'].x + 240, panels['bottom_right'].y + 202, 48, 30)
    flt_ele["play5_text"] = font1.render('>>', True, BLACK)
    flt_ele["play5_active"] = False
    flt_ele["play5_color"] = GRAY

    flt_ele["play6"] = pygame.Rect(panels['bottom_right'].x + 298, panels['bottom_right'].y + 202, 48, 30)
    flt_ele["play6_text"] = font1.render('>|', True, BLACK)
    flt_ele["play6_active"] = False
    flt_ele["play6_color"] = GRAY

    flt_ele["spd_up"] = pygame.Rect(panels['bottom_right'].x + 362, panels['bottom_right'].y + 169, 42, 25)
    flt_ele["spd_up_text"] = font1.render('\u2191', True, BLACK)
    flt_ele["spd_up_active"] = False
    flt_ele["spd_up_color"] = GRAY

    flt_ele["spd_dw"] = pygame.Rect(panels['bottom_right'].x + 362, panels['bottom_right'].y + 204, 42, 25)
    flt_ele["spd_dw_text"] = font1.render('\u2193', True, BLACK)
    flt_ele["spd_dw_active"] = False
    flt_ele["spd_dw_color"] = GRAY

    flt_ele["lower_banner"] = font2.render('Host packets > ', True, BLACK)
    flt_ele["lower_box"] = pygame.Rect(panels['bottom_right'].x + 351, panels['bottom_right'].y + 44, 70, 30)
    flt_ele["lower_box_color"] = color_inactive
    flt_ele["lower_text"] = ''
    flt_ele["lower_box_active"] = False

    flt_ele["upper_banner"] = font2.render('Host packets < ', True, BLACK)
    flt_ele["upper_box"] = pygame.Rect(panels['bottom_right'].x + 351, panels['bottom_right'].y + 88, 70, 30)
    flt_ele["upper_box_color"] = color_inactive
    flt_ele["upper_text"] = ''
    flt_ele["upper_box_active"] = False

    flt_ele["range_banner"] = font2.render('Packets incld.', True, BLACK)
    flt_ele["range_box"] = pygame.Rect(panels['bottom_right'].x + 351, panels['bottom_right'].y + 132, 70, 30)
    flt_ele["range_box_color"] = color_inactive
    flt_ele["range_text"] = ''
    flt_ele["range_box_active"] = False

    return flt_ele
    pass

class GUIClass:
    def __init__(self):
        pygame.init()

        screen_width, screen_height = 1280, 720
        screen = pygame.display.set_mode((screen_width, screen_height))

        pygame.display.set_caption("pNode")

        # font1 = pygame.font.Font(None, 30)
        # font2 = pygame.font.Font(None, 20)

        font1 = pygame.font.SysFont("Consolas", 20)
        font2 = pygame.font.SysFont("Consolas", 12)
        # font2.set_bold(True)

        tings = {}
        tings["font1"] = font1
        tings["font2"] = font2


        load_ele = {}
        load_ele["load_text"] = font1.render('pcap to load:', True, BLACK)
        if_l = get_if_list()
        interfaces_str = '\n'.join(if_l)
        load_ele["if_text"] = font1.render(interfaces_str, True, BLACK)
        load_ele["input_box"] = pygame.Rect(540, 180, 200, 30)
        load_ele["input_text"] = ''
        load_ele["input_box_color"] = color_inactive
        load_ele["input_box_active"] = False
        load_ele["amt_box"] = pygame.Rect(472, 395, 70, 30)
        load_ele["amt_text"] = ''
        load_ele["amt_box_color"] = color_inactive
        load_ele["amt_box_active"] = False
        load_ele["scroll"] = 0
        load_ele["error_text"] = font1.render('', True, BLACK)
        load_ele["if_text"] = font1.render('Interfaces', True, BLACK)
        load_ele["if_temp"] = pygame.Rect(472, 435, 300, 40)
        load_ele["if_up"] = pygame.Rect(777, 435, 30, 20)
        load_ele["if_up_text"] = font2.render('\u2191', True, BLACK)
        load_ele["if_up_color"] = GRAY
        load_ele["if_dw"] = pygame.Rect(777, 635, 30, 20)
        load_ele["if_dw_text"] = font2.render('\u2193', True, BLACK)
        load_ele["if_dw_color"] = GRAY



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
        # w = 853
        list_ele = {}
        list_ele["list_banner1"] = pygame.Rect(panels['bottom_left'].x + 5, panels['bottom_left'].y + 5, 150, 20)
        list_ele["list_banner1_text"] = font2.render('time', True, BLACK)

        list_ele["list_banner2"] = pygame.Rect(panels['bottom_left'].x + 160, panels['bottom_left'].y + 5, 150, 20)
        list_ele["list_banner2_text"] = font2.render('src', True, BLACK)

        list_ele["list_banner3"] = pygame.Rect(panels['bottom_left'].x + 315, panels['bottom_left'].y + 5, 150, 20)
        list_ele["list_banner3_text"] = font2.render('dst', True, BLACK)

        list_ele["list_banner4"] = pygame.Rect(panels['bottom_left'].x + 470, panels['bottom_left'].y + 5, 150, 20)
        list_ele["list_banner4_text"] = font2.render('protocol', True, BLACK)

        list_ele["list_banner5"] = pygame.Rect(panels['bottom_left'].x + 625, panels['bottom_left'].y + 5, 183, 20)
        list_ele["list_banner5_text"] = font2.render('info', True, BLACK)

        list_ele["list_banner6"] = pygame.Rect(panels['bottom_left'].x + 813, panels['bottom_left'].y + 5, 30, 20)
        list_ele["list_banner6_text"] = font2.render('~', True, BLACK)

        list_ele["list_banner7"] = pygame.Rect(panels['bottom_left'].x + 813, panels['bottom_left'].y + 30, 30, 20)
        list_ele["list_banner7_text"] = font2.render('\u2191', True, BLACK)

        list_ele["list_banner8"] = pygame.Rect(panels['bottom_left'].x + 813, panels['bottom_left'].y + 215, 30, 20)
        list_ele["list_banner8_text"] = font2.render('\u2193', True, BLACK)

        list_ele["list_scroll"] = pygame.Rect(panels['bottom_left'].x + 813, panels['bottom_left'].y + 55, 30, 20)
        # list_ele["list_banner9_text"] = font2.render('\u2193', True, BLACK)



        #---info
        info_ele = {}
        info_ele["display_text1"] = ''
        info_ele["display_box1"] = pygame.Rect(panels['top_right'].x + 5, panels['top_right'].y + 5, 416, 470)

        info_ele["display_text2"] = ''
        info_ele["display_box2"] = pygame.Rect(panels['top_right'].x + 5, panels['top_right'].y + 160, 416, 150)

        info_ele["display_text3"] = ''
        info_ele["display_box3"] = pygame.Rect(panels['top_right'].x + 5, panels['top_right'].y + 315, 416, 150)

        info_ele["info_back_button"] = pygame.Rect(0, 0, 30, 20)
        info_ele["info_fwd_button"] = pygame.Rect(0, 0, 30, 20)

        info_ele["info_raw_back_button"] = pygame.Rect(0, 0, 30, 20)
        info_ele["info_raw_fwd_button"] = pygame.Rect(0, 0, 30, 20)

        info_ele["info_raw_ah_button"] = pygame.Rect(0, 0, 30, 20)

        info_ele["info_pay_back_button"] = pygame.Rect(0, 0, 30, 20)
        info_ele["info_pay_fwd_button"] = pygame.Rect(0, 0, 30, 20)

        info_ele["traffic_in_back_button"] = pygame.Rect(0, 0, 30, 20)
        info_ele["traffic_in_fwd_button"] = pygame.Rect(0, 0, 30, 20)

        info_ele["traffic_out_back_button"] = pygame.Rect(0, 0, 30, 20)
        info_ele["traffic_out_fwd_button"] = pygame.Rect(0, 0, 30, 20)

        info_ele["conn_traffic_back_button"] = pygame.Rect(0, 0, 30, 20)
        info_ele["conn_traffic_fwd_button"] = pygame.Rect(0, 0, 30, 20)



        map_ctl = {}

        map_ctl["load_back"] = pygame.Rect(panels['top_left'].x + 5, panels['top_left'].y + 5, 30, 30)
        map_ctl["load_back_text"] = font2.render('<', True, BLACK)

        map_ctl["save"] = pygame.Rect(panels['top_left'].x + 5, panels['top_left'].y + 40, 30, 30)
        map_ctl["save_text"] = font2.render('save', True, BLACK)


        map_ctl["rep_const_up"] = pygame.Rect(panels['top_left'].x + 818, panels['top_left'].y + 5, 30, 20)
        map_ctl["rep_const_up_text"] = font2.render('\u2191', True, BLACK)

        map_ctl["rep_const_dw"] = pygame.Rect(panels['top_left'].x + 818, panels['top_left'].y + 135, 30, 20)
        map_ctl["rep_const_dw_text"] = font2.render('\u2193', True, BLACK)

        map_ctl["att_const_up"] = pygame.Rect(panels['top_left'].x + 818, panels['top_left'].y + 160, 30, 20)
        map_ctl["att_const_up_text"] = font2.render('\u2191', True, BLACK)

        map_ctl["att_const_dw"] = pygame.Rect(panels['top_left'].x + 818, panels['top_left'].y + 290, 30, 20)
        map_ctl["att_const_dw_text"] = font2.render('\u2193', True, BLACK)

        map_ctl["glob_const_up"] = pygame.Rect(panels['top_left'].x + 818, panels['top_left'].y + 315, 30, 20)
        map_ctl["glob_const_up_text"] = font2.render('\u2191', True, BLACK)

        map_ctl["glob_const_dw"] = pygame.Rect(panels['top_left'].x + 818, panels['top_left'].y + 445, 30, 20)
        map_ctl["glob_const_dw_text"] = font2.render('\u2193', True, BLACK)

        help_win = {}

        help_win["1"] = pygame.Rect(80, 26, 230, 120)
        help_win["1_text_1_1"] = font2.render('Back button returns to load.', True, BLACK)
        help_win["1_text_1_2"] = font2.render('screen.', True, BLACK)
        help_win["1_text_2"] = font2.render('Save button saves pcap.', True, BLACK)

        help_win["2"] = pygame.Rect(100, 335, 230, 120)
        help_win["2_text_1_1"] = font2.render('When a connection or node is', True, BLACK)
        help_win["2_text_1_2"] = font2.render('selected, the related packets', True, BLACK)
        help_win["2_text_1_3"] = font2.render('are shown in the list below.', True, BLACK)

        help_win["3"] = pygame.Rect(50, 530, 230, 120)
        help_win["3_text_1_1"] = font2.render('List of packets can be sorted', True, BLACK)
        help_win["3_text_1_2"] = font2.render('by the banners above.', True, BLACK)
        help_win["3_text_2_1"] = font2.render('When a packet is selected its', True, BLACK)
        help_win["3_text_2_2"] = font2.render('info is shown upper right.', True, BLACK)

        help_win["4"] = pygame.Rect(555, 80, 240, 120)
        help_win["4_text_1_1"] = font2.render('Buttons on the right of the map', True, BLACK)
        help_win["4_text_1_2"] = font2.render('control the repulsion, attraction', True, BLACK)
        help_win["4_text_1_3"] = font2.render('and gravity of the node map from', True, BLACK)
        help_win["4_text_1_4"] = font2.render('top to bottom.', True, BLACK)

        help_win["5"] = pygame.Rect(583, 353, 230, 120)
        help_win["5_text_1_1"] = font2.render('The ~ button can be used to', True, BLACK)
        help_win["5_text_1_2"] = font2.render('switch the list between the', True, BLACK)
        help_win["5_text_1_3"] = font2.render('packets of the selected map', True, BLACK)
        help_win["5_text_1_4"] = font2.render('item and the whole map.', True, BLACK)

        help_win["6"] = pygame.Rect(620, 543, 230, 120)
        help_win["6_text_1_1"] = font2.render('Toggle buttons can be used to', True, BLACK)
        help_win["6_text_1_2"] = font2.render('quickly filter the packets by', True, BLACK)
        help_win["6_text_1_3"] = font2.render('protocol.', True, BLACK)

        help_win["7"] = pygame.Rect(868, 350, 230, 120)
        help_win["7_text_1_1"] = font2.render('Filter parameters can be used', True, BLACK)
        help_win["7_text_1_2"] = font2.render('below to filter the packets', True, BLACK)
        help_win["7_text_1_3"] = font2.render('included in the map. The X', True, BLACK)
        help_win["7_text_1_4"] = font2.render('button clears the filters.', True, BLACK)

        help_win["8"] = pygame.Rect(868, 520, 322, 130)
        help_win["8_text_1_1"] = font2.render('The Host packets <> controls can be used to', True, BLACK)
        help_win["8_text_1_2"] = font2.render('filter out hosts by packet amount.', True, BLACK)
        help_win["8_text_2_1"] = font2.render('Play controls and Packets Included can be', True, BLACK)
        help_win["8_text_2_2"] = font2.render('used to step through the pcap. The arrow', True, BLACK)
        help_win["8_text_2_3"] = font2.render('buttons in the corner control play speed.', True, BLACK)


        # help_win["header"] = font1.render('~~Help~~', True, BLACK)
        # help_win["para"] = font2.render('Below is a brief description of the purpose of the quadrants and their main functions. \
        #                         To the right is a complete list of the fields that can be used to filter packets.', True, BLACK)
        # help_win[""]



        self.screen = screen
        self.panels = panels
        self.tings = tings
        self.info_elem = info_ele
        self.filter_elem = build_filter_elem(panels, font1, font2)
        self.load_elem = load_ele
        self.list_banner = list_ele
        self.map_ctl = map_ctl
        self.help_win = help_win
        self.graph = None
        self.graph_pos = None
        self.screen_packets = None
        self.in_info = None
        self.node_elem = {}
        self.conn_elem = {}
        self.list_elem = []
        self.if_list = []
        self.if_panels = []
        self.screen_keys = []
        self.ttime = 0
        self.list_off = 0
        self.scroll_step = 5
        self.f_len = 0
        self.play_drag = False
        self.play_off = 0
        self.play_step = 0
        self.min = 0
        self.max = DEFAULT_MAX
        self.ascii_hex = False
        self.helpp = False
        self.new_map = True
        self.map_adj = False
        self.list_bools = {
            "time": False,
            "src": False,
            "dst": False,
            "prot": False,
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
            l_class.sprite_props["text"] = self.tings["font1"].render('', True, BLACK)

            l_class.packet = packet
            self.list_elem.append(l_class)

        self._init_node_elem()
        self._init_conn_elem()
        self.new_map = True


    def set_list_packets(self, packets):
        self.list_elem.clear()
        # self.screen_packets = packets

        for packet in packets:
            # l_ele = pygame.Rect(self.panels['bottom_left'].x + 5, self.panels['bottom_right'].y + 25, 40, 24)
            l_class = PLObj()

            l_class.sprite_props["sprite"] = pygame.Rect(self.panels['bottom_left'].x + 5, self.panels['bottom_left'].y + 30, 803, 30)
            l_class.sprite_props["text"] = self.tings["font1"].render('', True, BLACK)

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
            if (len(n.get_packet_list()) < self.min or len(n.get_packet_list()) > self.max):
                print(f"min {self.min} max {self.max} len: {len(n.get_packet_list())}")
                continue
            temp[k] = n

        # print(f"fuck {temp}")

        self.node_elem = temp

    def _init_conn_elem(self):
        pkts = self.screen_packets
        nds = self.node_elem.keys()
        conns = {}
        for pkt in pkts:
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst
            conn_key = tuple(sorted([src_mac, dst_mac]))
            if src_mac not in nds or dst_mac not in nds:
                continue
            if conn_key not in conns:
                conns[conn_key] = LObj(src_mac, dst_mac, pygame.Surface((0, 0), pygame.SRCALPHA), pygame.Rect(0, 0, 30, 30))

            # print(f"shit {conns}")
            conns[conn_key].add_packet(pkt)

        self.conn_elem = conns


    def load_screen(self, lres):

        self.screen.fill(WHITE)
        pygame.draw.rect(self.screen, YELLOW, (40, 40, 1200, 310))
        pygame.draw.rect(self.screen, YELLOW, (40, 370, 1200, 310))
        pygame.draw.rect(self.screen, BLUE, (490, 105, 300, 150))
        pygame.draw.rect(self.screen, BLUE, (462, 385, 355, 280))
        self.screen.blit(self.load_elem["load_text"], (560, 130))
        self.screen.blit(self.load_elem["if_text"], (self.load_elem["amt_box"].x + 80, self.load_elem["amt_box"].y + 5))
        if lres == False:
            self.load_elem["error_text"] = self.tings["font1"].render("That is not a valid path", True, BLACK)

        self.screen.blit(self.load_elem["error_text"], (230, 140))


        temp =  self.load_elem["input_text"]
        if len(temp) > 15:
            amt = max(15, len(temp))
            temp = temp[self.indices["load"]: self.indices["load"] + 15]
        ld_surface = self.tings["font1"].render(temp, True, BLACK)
        pygame.draw.rect(self.screen, self.load_elem["input_box_color"], self.load_elem["input_box"], 1)
        self.screen.blit(ld_surface, (self.load_elem["input_box"].x + 3, self.load_elem["input_box"].y + 5))

        temp = self.load_elem["amt_text"]
        if len(temp) > 5:
            amt = max(5, len(temp))
            temp = temp[self.indices["pkt_amt"]: self.indices["pkt_amt"] + 5]
        ld_surface = self.tings["font1"].render(temp, True, BLACK)
        pygame.draw.rect(self.screen, self.load_elem["amt_box_color"], self.load_elem["amt_box"], 1)
        self.screen.blit(ld_surface, (self.load_elem["amt_box"].x + 3, self.load_elem["amt_box"].y + 5))

        pygame.draw.rect(self.screen, self.load_elem["if_up_color"], self.load_elem["if_up"])
        self.screen.blit(self.load_elem["if_up_text"], (self.load_elem["if_up"].x + 10, self.load_elem["if_up"].y + 2))

        pygame.draw.rect(self.screen, self.load_elem["if_dw_color"], self.load_elem["if_dw"])
        self.screen.blit(self.load_elem["if_dw_text"], (self.load_elem["if_dw"].x + 10, self.load_elem["if_dw"].y + 2))


        ifs = get_if_list()
        self.if_list = ifs
        buf = 0
        for f in ifs[self.indices["load_if"]:self.indices["load_if"] + 5]:
            # self.load_elem["if_temp"].y + buf
            temp = pygame.Rect(472, 435 + buf, 300, 40)
            pygame.draw.rect(self.screen, GRAY, temp)
            ld_surface = self.tings["font1"].render(f, True, BLACK)
            self.screen.blit(ld_surface, (temp.x + 10, temp.y + 5))
            self.if_panels.append(temp)
            buf += 45
        pygame.display.flip()

        pass

    def load_input(self):
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            if event.type == SNIFFING_DONE:
                return ("dsniff", "")
            if event.type == pygame.KEYDOWN:
                # print("heyasdasd")
                # print(self.load_elem["input_text"])
                if self.load_elem["input_box_active"]:
                    if event.key == pygame.K_RETURN:
                        if self.load_elem["input_text"].endswith(".pcap"):
                            return ("pcap", self.load_elem["input_text"])
                        else:
                            self.load_elem["error_text"] = self.tings["font1"].render("That is not a valid path", True, BLACK)
                            self.load_elem["input_text"] = ""
                        pass
                        # self.info_elem["display_text"] = self.load_elem["input_text"]
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


                if self.load_elem["amt_box"].collidepoint(event.pos):
                    self.load_elem["amt_box_active"] = not self.load_elem["amt_box_active"]
                else:
                    self.load_elem["amt_box_active"] = False
                self.load_elem["amt_box_color"] = color_active if self.load_elem["amt_box_active"] else color_inactive

                if self.load_elem["if_up"].collidepoint(event.pos):
                    if self.indices["load_if"] < len(self.if_list) - 5:
                        self.indices["load_if"] += 1

                if self.load_elem["input_box"].collidepoint(event.pos):
                    if self.indices["load_if"] > 0:
                        self.indices["load_if"] -= 1


                for idx, i in enumerate(self.if_panels):
                    if i.collidepoint(event.pos):
                        if self.load_elem["amt_text"].isnumeric():
                            return ("sniff", self.if_list[idx], self.load_elem["amt_text"])
                        else:
                            self.load_elem["error_text"] = self.tings["font1"].render("Sniff amt must be #", True, BLACK)
                            self.load_elem["input_text"] = ""
                        pass





    def _check_filter_keydown(self, event, elem, action, textt, leng, idx):
        print(f"hey 0 {elem} {self.filter_elem[elem]}")
        if self.filter_elem[elem]:
            print("hey 1")
            if event.key == pygame.K_RETURN:
                print("hey 2")
                # self.info_elem["display_text"] = self.filter_elem["input_text"]
                return (action, self.filter_elem[textt], "")
            elif event.key == pygame.K_BACKSPACE:
                print("hey 2")
                self.filter_elem[textt] = self.filter_elem[textt][:-1]
                if len(self.filter_elem[textt]) >= leng:
                    self.indices[idx] -= 1
            else:
                print("hey 3")
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
                # self.node_elem[i.get_mac()].set_sprite_props("color", BLUE)
        pass

    def _reset_conn_color(self, elem):
        for i in self.conn_elem.values():
            # temp = i.get_sprite_props()
            # temp["color"] = BLUE
            if elem == 'reset':
                i.set_sprite_props("color", BLUE)
                continue
            if tuple(sorted([i.get_mac_one(), i.get_mac_two()])) != tuple(sorted([elem.get_mac_one(), elem.get_mac_two()])):
                i.set_sprite_props("color", BLUE)
                # self.node_elem[tuple(sorted(i.get_mac_one(), i.get_mac_two()))].set_sprite_props("color", YELLOW)
        pass


    def input_check(self):
        # self.ttime += 1
        # print(self.ttime)

        for event in pygame.event.get():
            # print(f">> list index: {self.indices['list']}")
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            if event.type == pygame.KEYDOWN:

                temp = self._check_filter_keydown(event, "input_box_active", Action.FILTER, "input_text", 16, "input")
                if temp != None:
                    return temp
                temp = self._check_filter_keydown(event, "range_box_active", Action.RANGE, "range_text", 4, "range")
                if temp != None:
                    return temp
                temp = self._check_filter_keydown(event, "upper_box_active", Action.MAX, "upper_text", 4, "upper")
                if temp != None:
                    if temp[1] == "":
                        self.max = DEFAULT_MAX
                    else:
                        self.max = int(temp[1])
                    self.new_map = True
                    return (Action.RESEND, "")
                temp = self._check_filter_keydown(event, "lower_box_active", Action.MIN, "lower_text", 4, "lower")
                if temp != None:
                    if temp[1] == "":
                        self.min = 0
                    else:
                        self.min = int(temp[1])
                    self.new_map = True
                    return (Action.RESEND, "")

            if event.type == pygame.MOUSEBUTTONDOWN:
                self._check_scroll(event, "top_right", "info", self.in_info, 1)
                self._check_scroll(event, "bottom_left", "list", self.list_elem, 6)

            if len(self.list_elem) > 0:
                if len(self.list_elem) > 135:
                    self.scroll_step = (len(self.list_elem) - 6) / 135
                else:
                    self.scroll_step =  (len(self.list_elem) - 6) / 135

            if event.type == pygame.MOUSEBUTTONDOWN and not event.button == 5 and not event.button == 4:
                if event.button == 1:
                    if self.list_banner["list_scroll"].collidepoint(event.pos):
                        self.list_bools["scroll_bar_drag"] = True
                        self.list_off = self.list_banner["list_scroll"].y - event.pos[1]
            elif event.type == pygame.MOUSEBUTTONUP and not event.button == 5 and not event.button == 4:
                if event.button == 1:
                    self.list_bools["scroll_bar_drag"] = False
            elif event.type == pygame.MOUSEMOTION:
                if self.list_bools["scroll_bar_drag"]:
                    if self.list_banner["list_scroll"].y >= self.panels["bottom_left"].y + 55 and self.list_banner["list_scroll"].y <= self.panels["bottom_left"].y + 190:
                        temp = event.pos[1] + self.list_off
                        if temp > self.panels["bottom_left"].y + 190:
                            temp = self.panels["bottom_left"].y + 190
                        if temp < self.panels["bottom_left"].y + 55:
                            temp = self.panels["bottom_left"].y + 55
                        self.list_banner["list_scroll"].y = temp
            if self.list_bools["scroll_bar_drag"]:
                if self.scroll_step >= 1:
                    temp = self.list_banner["list_scroll"].y - (self.panels["bottom_left"].y + 55)
                    if temp * self.scroll_step < len(self.list_elem) - 6:
                        self.indices["list"] = int(temp * self.scroll_step)
                    if self.list_banner["list_scroll"].y == (self.panels["bottom_left"].y + 55):
                        self.indices["list"] = 0
                else:
                    temp = self.list_banner["list_scroll"].y - (self.panels["bottom_left"].y + 55)
                    scroll_s = 1
                    if self.scroll_step:
                        scroll_s = 1 / self.scroll_step
                    self.indices["list"] = int(temp / scroll_s)
                    if self.list_banner["list_scroll"].y == (self.panels["bottom_left"].y + 55):
                        self.indices["list"] = 0

# --------

            if len(self.list_elem) > 0:
                self.play_step = (self.f_len - len(self.screen_packets)) / 334

            if event.type == pygame.MOUSEBUTTONDOWN and not event.button == 5 and not event.button == 4:
                if event.button == 1:
                    if self.filter_elem["play_buf_1"].collidepoint(event.pos):
                        self.play_drag = True
                        self.play_off = self.filter_elem["play_buf_1"].x - event.pos[0]

            if event.type == pygame.MOUSEMOTION:
                if self.play_drag:
                    if self.filter_elem["play_buf_1"].x >= self.panels["bottom_right"].x + 8 and self.filter_elem["play_buf_1"].x <= self.panels["bottom_right"].x + 342:
                        temp = event.pos[0] + self.play_off
                        if temp > self.panels["bottom_right"].x + 342:
                            temp = self.panels["bottom_right"].x + 342
                        if temp < self.panels["bottom_right"].x + 8:
                            temp = self.panels["bottom_right"].x + 8
                        self.filter_elem["play_buf_1"].x = temp
            if event.type == pygame.MOUSEBUTTONUP and not event.button == 5 and not event.button == 4:
                if event.button == 1:
                    self.play_drag = False
            if self.play_drag:
                if self.play_step >= 1:
                    temp = self.filter_elem["play_buf_1"].x - (self.panels["bottom_right"].x + 8)
                    if temp * self.play_step < self.f_len - len(self.screen_packets):
                        # self.indices["play"] = int(temp * self.play_step)
                        return (Action.PLAYMOVE, int(temp * self.play_step))
                    # if self.filter_elem["play_buf_1"].x == (self.panels["bottom_right"].x + 8):
                    #     self.indices["play"] = 0
                else:
                    temp = self.filter_elem["play_buf_1"].x - (self.panels["bottom_right"].x + 8)
                    scroll_s = 1
                    if self.play_step:
                        scroll_s = 1 / self.play_step
                    # self.indices["play"] = int(temp / scroll_s)
                    return (Action.PLAYMOVE, int(temp / scroll_s))

                    # if self.filter_elem["play_buf_1"].x == (self.panels["bottom_right"].x + 8):
                    #     self.indices["play"] = 0







            if event.type == pygame.MOUSEBUTTONDOWN and not event.button == 5 and not event.button == 4:
                if self.filter_elem["enter_button"].collidepoint(event.pos):
                    return (Action.FILTER, self.filter_elem["input_text"])

                if self.filter_elem["clear_button"].collidepoint(event.pos):
                    self.filter_elem["input_text"] = ''
                    for i in range(1, 10):
                        st = f"toggle{i}_color"
                        self.filter_elem[st] = GRAY
                    return (Action.RESET, "")

                if self.filter_elem["info_button"].collidepoint(event.pos):
                    self.in_info = None

                if self.filter_elem["help_button"].collidepoint(event.pos):
                    print("hey there!")
                    self.helpp = not self.helpp

                self._check_active(event, "input_box", "input_box_active", "input_box_color")
                # print("asdf")
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

                #-- play buttons

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
                    pass
                if self.filter_elem["spd_dw"].collidepoint(event.pos):
                    return (Action.SPDDW, "")
                    pass


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
                    self.list_elem = sorted(self.list_elem, key=lambda x: x.packet[IP].proto if x.packet.haslayer(IP) else "") # protocol needs to be filled out
                if self.list_banner["list_banner6"].collidepoint(event.pos):
                    self.set_list_packets(self.screen_packets)
                    # print(len(self.list_elem))
                    pass
                if self.list_banner["list_banner7"].collidepoint(event.pos):
                    if self.indices["list"] > 0:
                        self.indices["list"] -= 1
                if self.list_banner["list_banner8"].collidepoint(event.pos):
                    if self.indices["list"] < len(self.list_elem) - 6:
                        self.indices["list"] += 1

                if self.info_elem["info_back_button"].collidepoint(event.pos):
                    if self.indices["info_page"] > 0:
                        self.indices["info_page"] -= 1

                    pass
                if self.info_elem["info_fwd_button"].collidepoint(event.pos):
                    if self.indices["info_page"] < 1:
                        self.indices["info_page"] += 1
                    pass


                if self.info_elem["info_raw_back_button"].collidepoint(event.pos):
                    if self.indices["info_page"] > 0:
                        self.indices["info_page"] -= 1

                    pass
                if self.info_elem["info_raw_fwd_button"].collidepoint(event.pos):
                    self.indices["info_page"] += 1
                    pass

                if self.info_elem["info_raw_ah_button"].collidepoint(event.pos):
                    self.ascii_hex = not self.ascii_hex
                    pass

                if self.info_elem["info_pay_back_button"].collidepoint(event.pos):
                    if self.indices["info_page"] > 0:
                        self.indices["info_page"] -= 1

                    pass
                if self.info_elem["info_pay_fwd_button"].collidepoint(event.pos):
                    self.indices["info_page"] += 1
                    pass


                if self.info_elem["traffic_in_back_button"].collidepoint(event.pos):
                    if self.indices["t_in_page"] > 0:
                        self.indices["t_in_page"] -= 1

                    pass
                if self.info_elem["traffic_in_fwd_button"].collidepoint(event.pos):
                    self.indices["t_in_page"] += 1
                    pass


                if self.info_elem["traffic_out_back_button"].collidepoint(event.pos):
                    if self.indices["t_out_page"] > 0:
                        self.indices["t_out_page"] -= 1

                    pass
                if self.info_elem["traffic_out_fwd_button"].collidepoint(event.pos):
                    self.indices["t_out_page"] += 1
                    pass

                if self.info_elem["conn_traffic_back_button"].collidepoint(event.pos):
                    if self.indices["c_t_page"] > 0:
                        self.indices["c_t_page"] -= 1

                    pass
                if self.info_elem["conn_traffic_fwd_button"].collidepoint(event.pos):
                    self.indices["c_t_page"] += 1
                    pass

                if self.map_ctl["load_back"].collidepoint(event.pos):
                    return Action.BACK

                if self.map_ctl["save"].collidepoint(event.pos):
                    return Action.SAVE



                if self.map_ctl["rep_const_up"].collidepoint(event.pos):
                    self.new_map = True
                    self.map_adj = True
                    self.indices["rep_const"] = round(self.indices["rep_const"] + .1, 1)
                    return (Action.RESEND, "")
                    pass

                if self.map_ctl["rep_const_dw"].collidepoint(event.pos):
                    if self.indices["rep_const"] > 0.1:
                        self.new_map = True
                        self.map_adj = True
                        self.indices["rep_const"] = round(self.indices["rep_const"] - .1, 1)
                        return (Action.RESEND, "")
                    pass

                if self.map_ctl["att_const_up"].collidepoint(event.pos):
                    self.new_map = True
                    self.map_adj = True
                    self.indices["att_const"] = round(self.indices["att_const"] + .1, 1)
                    return (Action.RESEND, "")

                    pass

                if self.map_ctl["att_const_dw"].collidepoint(event.pos):
                    if self.indices["att_const"] > 0.1:
                        self.indices["att_const"] = round(self.indices["att_const"] - .1, 1)
                        self.new_map = True
                        self.map_adj = True
                        return (Action.RESEND, "")
                    pass

                if self.map_ctl["glob_const_up"].collidepoint(event.pos):
                    self.indices["glob_const"] = round(self.indices["glob_const"] + .1, 1)
                    self.new_map = True
                    self.map_adj = True
                    return (Action.RESEND, "")
                    pass

                if self.map_ctl["glob_const_dw"].collidepoint(event.pos):
                    if self.indices["glob_const"] > 0.1:
                        self.indices["glob_const"] = round(self.indices["glob_const"] - .1, 1)
                        self.new_map = True
                        self.map_adj = True
                        return (Action.RESEND, "")
                    pass

                # print(f"rep: {self.indices['rep_const']} | att: {self.indices['att_const']} | glob: {self.indices['glob_const']}")

                node_toggle = True

                for elem in self.node_elem.values():
                    if elem.get_sprite_props()["sprite"].collidepoint(event.pos):
                        node_toggle = False
                        self.indices["list"] = 0
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
                            self._reset_conn_color(elem)
                            self._reset_node_color("reset")
                            self.set_list_packets(elem.get_packet_list())
                            if elem.sprite_props["color"] == YELLOW:
                                elem.sprite_props["color"] = BLUE
                            else:
                                elem.sprite_props["color"] = YELLOW
                                self._post_conn(elem)
                            pass


                for idx, elem in enumerate(self.list_elem):
                    if elem.sprite_props["sprite"].collidepoint(event.pos):
                        print(f"idx: {idx}")
                        self._post_list_ele(elem)
                        break
                        pass


    def _post_conn(self, elem):
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
                        pass
                    if p.haslayer(UDP):
                        temp = f"{ips} {p[UDP].sport} -> {ipd} {p[UDP].dport} | {prot}"
                        pass
                    if temp and temp not in traffic:
                        traffic.append(temp)
                    if p.haslayer(ARP):
                        # hwp = f"hw: {p[ARP].hwsrc} -> {p[ARP].hwdst}"
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
                        pass
                    if p.haslayer(UDP):
                        temp = f"{ipd} {p[UDP].dport} <- {ips} {p[UDP].sport} | {prot}"
                        pass
                    if temp and temp not in traffic:
                        traffic.append(temp)
                    if p.haslayer(ARP):
                        # hwp = f"hw: {p[ARP].hwdst} <- {p[ARP].hwsrc}"
                        temp = f"{p[ARP].pdst} <- {p[ARP].psrc}"
                        # traffic.append(hwp)
                        traffic.append(temp)
                pass
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
        self.in_info = to_show
        pass

    def _post_node(self, elem):
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
                        # print("hey whats up")
                        if host_ip4 == None:
                            host_ip4 = p[IP].src
                        temp = f"{p[IP].dst}"
                        prot = p[IP].proto
                    elif p.haslayer(IPv6):
                        # print("hey whats up")
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
                        pass

                elif p[Ether].dst == mac:
                    temp = str(p[Ether].src)
                    if p.haslayer(IP):
                        # print("hey whats up")
                        if host_ip4 == None:
                            host_ip4 = p[IP].dst
                        temp = f"{p[IP].src}"
                        prot = p[IP].proto
                    elif p.haslayer(IPv6):
                        # print("hey whats up")
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
                        pass

        host = {
            "hdr_type": "host",
            "host_mac": mac,
            "host_ip4": host_ip4,
            "host_ip6": host_ip6,
        }
        # print(host)
        to_show.append(host)
        traffic = {
            "hdr_type": "traffic",
            "out_traffic": out_traffic,
            "in_traffic": in_traffic,
        }
        # print(traffic)
        to_show.append(traffic)
        self.in_info = to_show

        pass

    def _post_list_ele(self, elem):
        # self.info_elem[""] =
        to_show = []
        pkt = elem.packet
        self.indices["info"] = 0
        # print(pkt.show())
        datetime_obj = datetime.fromtimestamp(float(pkt.time))
        # df = len(raw(pkt))
        # print(f"akjshdfkj {df}")
        ether_frame = {
            "hdr_type": "ether",
            "time": datetime_obj.strftime("%Y-%m-%d %H:%M:%S.%f"),
            # "length": "str(len(raw(pkt)))",
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
            pass
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
                # print(pkt[DNS].show())
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
            # will need to be made reactive to differing types of ICMPs
            icmp = {}
            icmp["hdr_type"] = "icmp"
            ttype = str(pkt[ICMP].type)
            code = str(pkt[ICMP].code)
            icmp["type"] = type
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
            pass

        # if pkt.haslayer(ICMPv6)
        #     icmp6 = {
        #         "hdr_type": "icmp6",
        #         "type": str(pkt[ICMPv6].type),
        #         "code": str(pkt[ICMPv6].code),
        #         "check": str(pkt[ICMPv6].cksum),
        #     }
        #     to_show.append(icmp6)

        if IP in pkt and pkt[IP].proto == 2:
            print(pkt.show())
            igmp = {}
            igmp["hdr_type"] = "igmp"
            # temp = str(pkt.getlayer(Raw).load)
            # print(temp)


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

            # ch1 = temp.split("\\")
            # ttype = ch1[1].strip()
            # ttype = pkt[IP].payload.type
            # group = pkt[IP].payload.group
            # igmp["type"] = ttype
            # igmp["group"] = group
            # if ttype in ["x11", "x12", "x16", "x17"]:
            #     igmp["mrt"] = ch1[2].strip()
            #     igmp["check"] = f"{ch1[3].replace('x', '').strip()}{ch1[4].replace('x', '').strip()}"
            #     igmp["addr"] = f"{ch1[5].replace('x', '').strip()}.{ch1[5].replace('x', '').strip()}.{ch1[6].strip()}.{ch1[7].replace('x', '').strip()}"
            # else:
            #     # igmp["mrc"] =
            #     pass
            to_show.append(igmp)
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
            pass


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
            # print(r)
            to_show.append(r)
            pass
        self.in_info = to_show


    def _update_nodes(self):
        # for i in self.node_elem.values():
            # print(f"{i.get_mac()} -- {i.get_neighbors()}")
        node_list = list(self.node_elem.keys())
        conn_list = list(self.conn_elem.keys())
        # nodes = self.node_elem
        positions = {}
        pos = None
        if self.new_map and (sorted(node_list) != sorted(self.screen_keys) or self.map_adj):
            self.screen_keys = node_list
            self.new_map = False
            self.map_adj = False
            print(f"min {self.min} max {self.max}")
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
            # if (self.min != 0 or self.max != 0) and (len(node.get_packet_list()) < self.min or len(node.get_packet_list()) > self.max):
            #     continue
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

            # print(f"node: {node.get_mac()}: x: {nx}, y: {ny}")


            self.node_elem[node.get_mac()].set_sprite_props("sprite", sprt_p["sprite"])
        conn_list = list(self.conn_elem.values())
        conns = self.conn_elem
        # print("--")
        # print("--")


        for conn in conn_list:
            c_sprt_p = conn.get_sprite_props()

            n1sp = self.node_elem[conn.get_mac_one()].get_sprite_props()
            n2sp = self.node_elem[conn.get_mac_two()].get_sprite_props()

            surf, rect = create_connection_rect(conn.get_sprite_props()["color"], (n1sp["sprite"].x + 15, n1sp["sprite"].y + 15), (n2sp["sprite"].x + 15, n2sp["sprite"].y + 15), 5)
            # surf.fill(conn.get_sprite_props()["color"])
            self.conn_elem[tuple(sorted([conn.get_mac_one(), conn.get_mac_two()]))].set_sprite_props("s_sprite", surf)
            self.conn_elem[tuple(sorted([conn.get_mac_one(), conn.get_mac_two()]))].set_sprite_props("r_sprite", rect)
            self.screen.blit(surf, rect.topleft)
            pass

        for node_id, (x, y) in pos.items():
            node = self.node_elem[node_id]
            sprt_p = node.get_sprite_props()
            ipbanner = self.tings["font2"].render(str(node.get_mac()), True, BLACK)
            self.screen.blit(ipbanner, (sprt_p["sprite"].x - 15, sprt_p["sprite"].y + 40))

            pygame.draw.circle(self.screen, sprt_p["color"], (sprt_p["sprite"].x + 15, sprt_p["sprite"].y + 15), sprt_p["radius"])

        pass

    def _update_info(self, ac_bool):
        if ac_bool == False:
            print("heyyy")
            pygame.draw.rect(self.screen, WHITE, self.info_elem["display_box1"])
            display_surface = self.tings["font2"].render("That is not a correct filter option", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 100, self.info_elem["display_box1"].y + 250))

            # pygame.draw.rect(self.screen, WHITE, self.info_elem["display_box2"])
            # display_surface = self.tings["font2"].render(self.info_elem["display_text2"], True, BLACK)
            # self.screen.blit(display_surface, (self.info_elem["display_box2"].x + 5, self.info_elem["display_box2"].y + 5))
            #
            # pygame.draw.rect(self.screen, WHITE, self.info_elem["display_box3"])
            # display_surface = self.tings["font2"].render("That is not a correct filter option", True, BLACK)
            # self.screen.blit(display_surface, (self.info_elem["display_box3"].x + 100, self.info_elem["display_box3"].y + 50))
            return None


        if self.in_info == None:
            pygame.draw.rect(self.screen, WHITE, self.info_elem["display_box1"])


            display_surface = self.tings["font2"].render("Welcome to pNode", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 150, self.info_elem["display_box1"].y + 5))

            display_surface = self.tings["font2"].render("Node", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 5, self.info_elem["display_box1"].y + 60))

            display_surface = self.tings["font2"].render("Repulsion", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 5, self.info_elem["display_box1"].y + 75))

            display_surface = self.tings["font2"].render("Conn", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 5, self.info_elem["display_box1"].y + 215))

            display_surface = self.tings["font2"].render("Attraction", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 5, self.info_elem["display_box1"].y + 230))

            display_surface = self.tings["font2"].render("Gravity", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 5, self.info_elem["display_box1"].y + 380))



            display_surface = self.tings["font2"].render("-Seclect node map elements to view information", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 35))

            display_surface = self.tings["font2"].render("and packets related to that element.", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 50))

            display_surface = self.tings["font2"].render("-Filter parameters can be used below to filter", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 70))

            display_surface = self.tings["font2"].render("the packets that are included in the map.", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 85))

            display_surface = self.tings["font2"].render("-The play functionality can be used to step", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 105))

            display_surface = self.tings["font2"].render("through the pcap packet by packet to observe", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 120))

            display_surface = self.tings["font2"].render("the network's traffic.", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 135))

            display_surface = self.tings["font2"].render("-The 'Host packets' and 'Packets incld.' can", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 155))

            display_surface = self.tings["font2"].render("be used to limit hosts by packet amount and", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 170))

            display_surface = self.tings["font2"].render("control the amount of packets that are used", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 185))

            display_surface = self.tings["font2"].render("to create the node map.", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 75, self.info_elem["display_box1"].y + 200))

            display_surface = self.tings["font2"].render("Filter parameters:", True, BLACK)
            self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 90, self.info_elem["display_box1"].y + 225))

            self.info_elem["info_back_button"] = pygame.Rect(self.info_elem["display_box1"].x + 300, self.info_elem["display_box1"].y + 225 , 30, 20)
            pygame.draw.rect(self.screen, GRAY, self.info_elem["info_back_button"])
            dst_surface = self.tings["font2"].render("<", True, BLACK)
            self.screen.blit(dst_surface, (self.info_elem["info_back_button"].x + 10, self.info_elem["info_back_button"].y + 2))
            #
            self.info_elem["info_fwd_button"] = pygame.Rect(self.info_elem["display_box1"].x + 335, self.info_elem["display_box1"].y + 225 , 30, 20)
            pygame.draw.rect(self.screen, GRAY, self.info_elem["info_fwd_button"])
            dst_surface = self.tings["font2"].render(">", True, BLACK)
            self.screen.blit(dst_surface, (self.info_elem["info_fwd_button"].x + 10, self.info_elem["info_fwd_button"].y + 2))


            depth = 0

            chk = 12

            for i in range(self.indices["info_page"] * chk, self.indices["info_page"] * chk + chk):
                display_surface = self.tings["font2"].render(filt_parameters[i], True, BLACK)
                self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 85, self.info_elem["display_box1"].y + 255 + depth))
                depth += 15



            # display_surface = self.tings["font2"].render("Welcome to pNode", True, BLACK)
            # self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 100, self.info_elem["display_box1"].y + 5))
            #
            # display_surface = self.tings["font2"].render("Welcome to pNode", True, BLACK)
            # self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 100, self.info_elem["display_box1"].y + 5))
            #
            # display_surface = self.tings["font2"].render("Welcome to pNode", True, BLACK)
            # self.screen.blit(display_surface, (self.info_elem["display_box1"].x + 100, self.info_elem["display_box1"].y + 5))

            # pygame.draw.rect(self.screen, WHITE, self.info_elem["display_box2"])
            # display_surface = self.tings["font2"].render(self.info_elem["display_text2"], True, BLACK)
            # self.screen.blit(display_surface, (self.info_elem["display_box2"].x + 5, self.info_elem["display_box2"].y + 5))
            #
            #
            # pygame.draw.rect(self.screen, WHITE, self.info_elem["display_box3"])
            # display_surface = self.tings["font2"].render(self.info_elem["display_text3"], True, BLACK)
            # self.screen.blit(display_surface, (self.info_elem["display_box3"].x + 5, self.info_elem["display_box3"].y + 5))
        else:
            # is_raw
            depth = 0
            for hdr in self.in_info[self.indices["info"]:]:
                # print(f"asdfasdf {hdr}")
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
                        # will need to be built out to accoodate various types
                        depth = draw_icmp(self, hdr, depth)
                        pass
                    case "igmp":
                        depth = draw_igmp(self, hdr, depth)
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
        # print(f"-- len {len(self.list_elem)}")
        if len(self.list_elem) < 7:
            buf = 0
            for elem in self.list_elem:
                # print(elem.packet.summary())
                datetime_obj = datetime.fromtimestamp(float(elem.packet.time))
                df = datetime_obj.strftime('%H:%M:%S')
                fractional_seconds = f"{datetime_obj.microsecond / 1000000:.2f}"[1:]
                date = df + fractional_seconds
                elem.sprite_props["sprite"].y = self.panels['bottom_left'].y + 30 + buf
                pygame.draw.rect(self.screen, RED, elem.sprite_props["sprite"], 1)
                t = elem.packet.summary()
                self.screen.blit(self.tings["font2"].render(f"{date} | {t[:95]}", True, BLACK), (elem.sprite_props["sprite"].x + 5, elem.sprite_props["sprite"].y + 5))
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
                self.screen.blit(self.tings["font2"].render(f"{date} | {t[:95]}", True, BLACK), (elem.sprite_props["sprite"].x + 5, elem.sprite_props["sprite"].y + 5))
                buf += 35
        pass

    def update_screen(self, ac_bool):
        if ac_bool == False:
            print("Fuck you")
            # self.screen.blit(self.tings["font2"].render("", True, BLACK), (self.panels[""], y))

        input_txt = self.filter_elem["input_text"]
        temp = input_txt
        if len(temp) > 16:
            temp = temp[self.indices["input"]: self.indices["input"] + 16]

        txt_surface = self.tings["font1"].render(temp, True, BLACK)

        range_txt = self.filter_elem["range_text"]
        temp = range_txt
        if len(temp) > 4:
            temp = temp[self.indices["range"]: self.indices["range"] + 4]

        rng_surface = self.tings["font1"].render(temp, True, BLACK)

        greater_txt = self.filter_elem["upper_text"]

        temp = greater_txt
        if len(temp) > 4:
            temp = temp[self.indices["upper"]: self.indices["upper"] + 4]

        grt_surface = self.tings["font1"].render(temp, True, BLACK)

        lesser_txt = self.filter_elem["lower_text"]

        temp = lesser_txt
        if len(temp) > 4:
            temp = temp[self.indices["lower"]: self.indices["lower"] + 4]

        lst_surface = self.tings["font1"].render(temp, True, BLACK)


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
        self.screen.blit(txt_surface, (self.filter_elem["input_box"].x + 5, self.filter_elem["input_box"].y + 5))

        pygame.draw.rect(self.screen, GRAY, self.filter_elem["enter_button"])
        self.screen.blit(self.filter_elem["enter_button_text"], (self.filter_elem["enter_button"].x + 13, self.filter_elem["enter_button"].y - 1))

        pygame.draw.rect(self.screen, GRAY, self.filter_elem["clear_button"])
        self.screen.blit(self.filter_elem["clear_button_text"], (self.filter_elem["clear_button"].x + 14, self.filter_elem["clear_button"].y - 1))

        pygame.draw.rect(self.screen, GRAY, self.filter_elem["info_button"])
        self.screen.blit(self.filter_elem["info_button_text"], (self.filter_elem["info_button"].x + 14, self.filter_elem["info_button"].y + 5))

        pygame.draw.rect(self.screen, GRAY, self.filter_elem["help_button"])
        self.screen.blit(self.filter_elem["help_button_text"], (self.filter_elem["help_button"].x + 14, self.filter_elem["help_button"].y + 1))
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



        if self.f_len and self.indices["play"]:
            lidx = self.f_len / self.indices["play"]
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
            self.screen.blit(self.filter_elem["play3_text1"], (self.filter_elem["play3"].x + 18, self.filter_elem["play3"].y + 3))
        else:
            self.screen.blit(self.filter_elem["play3_text2"], (self.filter_elem["play3"].x + 12, self.filter_elem["play3"].y + 2))

        pygame.draw.rect(self.screen, self.filter_elem["play4_color"], self.filter_elem["play4"])
        self.screen.blit(self.filter_elem["play4_text"], (self.filter_elem["play4"].x + 18, self.filter_elem["play4"].y + 2))


        pygame.draw.rect(self.screen, self.filter_elem["play5_color"], self.filter_elem["play5"])
        self.screen.blit(self.filter_elem["play5_text"], (self.filter_elem["play5"].x + 10, self.filter_elem["play5"].y + 3))


        pygame.draw.rect(self.screen, self.filter_elem["play6_color"], self.filter_elem["play6"])
        self.screen.blit(self.filter_elem["play6_text"], (self.filter_elem["play6"].x + 13, self.filter_elem["play6"].y + 2))

        pygame.draw.rect(self.screen, self.filter_elem["spd_up_color"], self.filter_elem["spd_up"])
        self.screen.blit(self.filter_elem["spd_up_text"], (self.filter_elem["spd_up"].x + 15, self.filter_elem["spd_up"].y + 0))

        pygame.draw.rect(self.screen, self.filter_elem["spd_dw_color"], self.filter_elem["spd_dw"])
        self.screen.blit(self.filter_elem["spd_dw_text"], (self.filter_elem["spd_dw"].x + 15, self.filter_elem["spd_dw"].y + 0))


        pygame.draw.rect(self.screen, self.filter_elem["range_box_color"], self.filter_elem["range_box"], 1)
        self.screen.blit(rng_surface, (self.filter_elem["range_box"].x + 5, self.filter_elem["range_box"].y + 5))
        self.screen.blit(self.filter_elem["range_banner"], (self.filter_elem["range_box"].x - 110, self.filter_elem["range_box"].y + 7))


        pygame.draw.rect(self.screen, self.filter_elem["upper_box_color"], self.filter_elem["upper_box"], 1)
        self.screen.blit(grt_surface, (self.filter_elem["upper_box"].x + 5, self.filter_elem["upper_box"].y + 5))
        self.screen.blit(self.filter_elem["upper_banner"], (self.filter_elem["upper_box"].x - 110, self.filter_elem["upper_box"].y + 7))


        pygame.draw.rect(self.screen, self.filter_elem["lower_box_color"], self.filter_elem["lower_box"], 1)
        self.screen.blit(lst_surface, (self.filter_elem["lower_box"].x + 5, self.filter_elem["lower_box"].y + 5))
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
        # print(f"ls before: {self.list_banner['list_scroll'].y}")

        if len(self.list_elem) > 6:
            ny = (self.indices["list"] / (len(self.list_elem) - 6)) * 135
            ny = self.panels["bottom_left"].y + 55 + ny
            self.list_banner["list_scroll"].y = ny
        # print(f"ls after: {self.list_banner['list_scroll'].y}")
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

        if self.helpp:
            # print("helping")
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
            time.sleep(0.1)
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
        self.f_len = len(filtered_packets)
