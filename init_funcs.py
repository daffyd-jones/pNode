#init funcs
import pygame
from scapy.all import *
BLACK = (0, 0, 0)
GRAY = (200, 200, 200)

def build_filter_elem(panels, font1, font2, color_inactive):
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
    flt_ele["toggle7_text"] = font2.render('HTTP/S', True, BLACK)
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
    flt_ele["play4_text"] = font1.render('\u25A0', True, BLACK)
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


def build_load(color_inactive, font1, font2):
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
    load_ele["amt_text"] = 'pkt#'
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
    load_ele["logo"] = pygame.image.load('logo2.png')
    # load_ele["load_msg"] = font2.render('In order to load packets either enter a path above, or enter a number of packets and select a network interface. The program must be run with: sudo ./pnode', True, BLACK)
    load_ele["load_msg"] = 'In order to load packets either enter a path above, or enter a number of packets and select a network interface to sniff. If sniffing, the program must be run with: sudo ./pnode'
    return load_ele


def build_list(panels, font2):
    list_ele = {}
    list_ele["list_banner1"] = pygame.Rect(panels['bottom_left'].x + 5, panels['bottom_left'].y + 5, 150, 20)
    list_ele["list_banner1_text"] = font2.render('time', True, BLACK)
    #
    list_ele["list_banner2"] = pygame.Rect(panels['bottom_left'].x + 160, panels['bottom_left'].y + 5, 150, 20)
    list_ele["list_banner2_text"] = font2.render('src', True, BLACK)
    #
    list_ele["list_banner3"] = pygame.Rect(panels['bottom_left'].x + 315, panels['bottom_left'].y + 5, 150, 20)
    list_ele["list_banner3_text"] = font2.render('dst', True, BLACK)
    #
    list_ele["list_banner4"] = pygame.Rect(panels['bottom_left'].x + 470, panels['bottom_left'].y + 5, 150, 20)
    list_ele["list_banner4_text"] = font2.render('protocol', True, BLACK)
    #
    list_ele["list_banner5"] = pygame.Rect(panels['bottom_left'].x + 625, panels['bottom_left'].y + 5, 183, 20)
    list_ele["list_banner5_text"] = font2.render('length', True, BLACK)
    #
    list_ele["list_banner6"] = pygame.Rect(panels['bottom_left'].x + 813, panels['bottom_left'].y + 5, 30, 20)
    list_ele["list_banner6_text"] = font2.render('~', True, BLACK)
    #
    list_ele["list_banner7"] = pygame.Rect(panels['bottom_left'].x + 813, panels['bottom_left'].y + 30, 30, 20)
    list_ele["list_banner7_text"] = font2.render('\u2191', True, BLACK)
    #
    list_ele["list_banner8"] = pygame.Rect(panels['bottom_left'].x + 813, panels['bottom_left'].y + 215, 30, 20)
    list_ele["list_banner8_text"] = font2.render('\u2193', True, BLACK)
    #
    list_ele["list_scroll"] = pygame.Rect(panels['bottom_left'].x + 813, panels['bottom_left'].y + 55, 30, 20)
    return list_ele


def build_info(panels):
    info_ele = {}
    info_ele["display_text1"] = ''
    info_ele["display_box1"] = pygame.Rect(panels['top_right'].x + 5, panels['top_right'].y + 5, 416, 470)
    #
    info_ele["display_text2"] = ''
    info_ele["display_box2"] = pygame.Rect(panels['top_right'].x + 5, panels['top_right'].y + 160, 416, 150)
    #
    info_ele["display_text3"] = ''
    info_ele["display_box3"] = pygame.Rect(panels['top_right'].x + 5, panels['top_right'].y + 315, 416, 150)
    #
    info_ele["info_back_button"] = pygame.Rect(0, 0, 30, 20)
    info_ele["info_fwd_button"] = pygame.Rect(0, 0, 30, 20)
    #
    info_ele["info_raw_back_button"] = pygame.Rect(0, 0, 30, 20)
    info_ele["info_raw_fwd_button"] = pygame.Rect(0, 0, 30, 20)
    #
    info_ele["info_raw_ah_button"] = pygame.Rect(0, 0, 30, 20)
    #
    info_ele["info_pay_back_button"] = pygame.Rect(0, 0, 30, 20)
    info_ele["info_pay_fwd_button"] = pygame.Rect(0, 0, 30, 20)
    #
    info_ele["traffic_in_back_button"] = pygame.Rect(0, 0, 30, 20)
    info_ele["traffic_in_fwd_button"] = pygame.Rect(0, 0, 30, 20)
    #
    info_ele["traffic_out_back_button"] = pygame.Rect(0, 0, 30, 20)
    info_ele["traffic_out_fwd_button"] = pygame.Rect(0, 0, 30, 20)
    #
    info_ele["conn_traffic_back_button"] = pygame.Rect(0, 0, 30, 20)
    info_ele["conn_traffic_fwd_button"] = pygame.Rect(0, 0, 30, 20)
    return info_ele


def build_map(panels, font2):
    map_ctl = {}
    map_ctl["load_back"] = pygame.Rect(panels['top_left'].x + 5, panels['top_left'].y + 5, 30, 30)
    map_ctl["load_back_text"] = font2.render('<', True, BLACK)
    #
    map_ctl["save"] = pygame.Rect(panels['top_left'].x + 5, panels['top_left'].y + 40, 30, 30)
    map_ctl["save_text"] = font2.render('save', True, BLACK)
    #
    map_ctl["rep_const_up"] = pygame.Rect(panels['top_left'].x + 818, panels['top_left'].y + 5, 30, 20)
    map_ctl["rep_const_up_text"] = font2.render('\u2191', True, BLACK)
    #
    map_ctl["rep_const_dw"] = pygame.Rect(panels['top_left'].x + 818, panels['top_left'].y + 135, 30, 20)
    map_ctl["rep_const_dw_text"] = font2.render('\u2193', True, BLACK)
    #
    map_ctl["att_const_up"] = pygame.Rect(panels['top_left'].x + 818, panels['top_left'].y + 160, 30, 20)
    map_ctl["att_const_up_text"] = font2.render('\u2191', True, BLACK)
    #
    map_ctl["att_const_dw"] = pygame.Rect(panels['top_left'].x + 818, panels['top_left'].y + 290, 30, 20)
    map_ctl["att_const_dw_text"] = font2.render('\u2193', True, BLACK)
    #
    map_ctl["glob_const_up"] = pygame.Rect(panels['top_left'].x + 818, panels['top_left'].y + 315, 30, 20)
    map_ctl["glob_const_up_text"] = font2.render('\u2191', True, BLACK)
    #
    map_ctl["glob_const_dw"] = pygame.Rect(panels['top_left'].x + 818, panels['top_left'].y + 445, 30, 20)
    map_ctl["glob_const_dw_text"] = font2.render('\u2193', True, BLACK)
    return map_ctl


def build_help(font2):
    help_win = {}
    help_win["1"] = pygame.Rect(80, 26, 230, 120)
    help_win["1_text_1_1"] = font2.render('Back button returns to load.', True, BLACK)
    help_win["1_text_1_2"] = font2.render('screen.', True, BLACK)
    help_win["1_text_2"] = font2.render('Save button saves pcap.', True, BLACK)
    #
    help_win["2"] = pygame.Rect(100, 335, 230, 120)
    help_win["2_text_1_1"] = font2.render('When a connection or node is', True, BLACK)
    help_win["2_text_1_2"] = font2.render('selected, the related packets', True, BLACK)
    help_win["2_text_1_3"] = font2.render('are shown in the list below.', True, BLACK)
    #
    help_win["3"] = pygame.Rect(50, 530, 230, 120)
    help_win["3_text_1_1"] = font2.render('List of packets can be sorted', True, BLACK)
    help_win["3_text_1_2"] = font2.render('by the banners above.', True, BLACK)
    help_win["3_text_2_1"] = font2.render('When a packet is selected its', True, BLACK)
    help_win["3_text_2_2"] = font2.render('info is shown upper right.', True, BLACK)
    #
    help_win["4"] = pygame.Rect(555, 80, 240, 120)
    help_win["4_text_1_1"] = font2.render('Buttons on the right of the map', True, BLACK)
    help_win["4_text_1_2"] = font2.render('control the repulsion, attraction', True, BLACK)
    help_win["4_text_1_3"] = font2.render('and gravity of the node map from', True, BLACK)
    help_win["4_text_1_4"] = font2.render('top to bottom.', True, BLACK)
    #
    help_win["5"] = pygame.Rect(583, 353, 230, 120)
    help_win["5_text_1_1"] = font2.render('The ~ button can be used to', True, BLACK)
    help_win["5_text_1_2"] = font2.render('switch the list between the', True, BLACK)
    help_win["5_text_1_3"] = font2.render('packets of the selected map', True, BLACK)
    help_win["5_text_1_4"] = font2.render('item and the whole map.', True, BLACK)
    #
    help_win["6"] = pygame.Rect(620, 543, 230, 120)
    help_win["6_text_1_1"] = font2.render('Toggle buttons can be used to', True, BLACK)
    help_win["6_text_1_2"] = font2.render('quickly filter the packets by', True, BLACK)
    help_win["6_text_1_3"] = font2.render('protocol.', True, BLACK)
    #
    help_win["7"] = pygame.Rect(868, 350, 230, 120)
    help_win["7_text_1_1"] = font2.render('Filter parameters can be used', True, BLACK)
    help_win["7_text_1_2"] = font2.render('below to filter the packets', True, BLACK)
    help_win["7_text_1_3"] = font2.render('included in the map. The X', True, BLACK)
    help_win["7_text_1_4"] = font2.render('button clears the filters.', True, BLACK)
    #
    help_win["8"] = pygame.Rect(868, 520, 322, 130)
    help_win["8_text_1_1"] = font2.render('The Host packets <> controls can be used to', True, BLACK)
    help_win["8_text_1_2"] = font2.render('filter out hosts by packet amount.', True, BLACK)
    help_win["8_text_2_1"] = font2.render('Play controls and Packets Included can be', True, BLACK)
    help_win["8_text_2_2"] = font2.render('used to step through the pcap. The arrow', True, BLACK)
    help_win["8_text_2_3"] = font2.render('buttons in the corner control play speed.', True, BLACK)
    return help_win
