import pygame
WHITE = (251, 251, 242)
BLACK = (0, 0, 0)
GRAY = (200, 200, 200)


def draw_ether(slf, hdr, depth):
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, 150)
    pygame.draw.rect(slf.screen, WHITE, tile)
    depth += 155
    time_header = slf.tings["font2"].render("- Ethernet -", True, BLACK)
    slf.screen.blit(time_header, (tile.x + 5, tile.y + 5))
    time_header = slf.tings["font2"].render("Time:", True, BLACK)
    slf.screen.blit(time_header, (tile.x + 5, tile.y + 35))
    len_header = slf.tings["font2"].render("Length:", True, BLACK)
    slf.screen.blit(len_header, (tile.x + 5, tile.y + 50))
    src_header = slf.tings["font2"].render("Source MAC", True, BLACK)
    slf.screen.blit(src_header, (tile.x + 5, tile.y + 65))
    dst_header = slf.tings["font2"].render("Destination MAC:", True, BLACK)
    slf.screen.blit(dst_header, (tile.x + 5, tile.y + 80))
    #sdf
    time_surface = slf.tings["font2"].render(hdr["time"], True, BLACK)
    slf.screen.blit(time_surface, (tile.x + 150, tile.y + 35))
    length_surface = slf.tings["font2"].render(hdr["length"], True, BLACK)
    slf.screen.blit(length_surface, (tile.x + 150, tile.y + 50))
    src_surface = slf.tings["font2"].render(hdr["src_mac"], True, BLACK)
    slf.screen.blit(src_surface, (tile.x + 150, tile.y + 65))
    dst_surface = slf.tings["font2"].render(hdr["dst_mac"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 150, tile.y + 80))
    return depth
    pass

def draw_ip(slf, hdr, depth):
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, 150)
    pygame.draw.rect(slf.screen, WHITE, tile)
    #
    depth += 155
    #
    time_surface = slf.tings["font2"].render("- IP -", True, BLACK)
    slf.screen.blit(time_surface, (tile.x + 5, tile.y + 5))
    #
    time_header = slf.tings["font2"].render("Source IP:", True, BLACK)
    slf.screen.blit(time_header, (tile.x + 5, tile.y + 35))
    len_header = slf.tings["font2"].render("Destination IP:", True, BLACK)
    slf.screen.blit(len_header, (tile.x + 5, tile.y + 50))
    src_header = slf.tings["font2"].render("Version:", True, BLACK)
    slf.screen.blit(src_header, (tile.x + 5, tile.y + 65))
    dst_header = slf.tings["font2"].render("Header Length:", True, BLACK)
    slf.screen.blit(dst_header, (tile.x + 5, tile.y + 80))
    time_header = slf.tings["font2"].render("Total Length:", True, BLACK)
    slf.screen.blit(time_header, (tile.x + 5, tile.y + 95))
    len_header = slf.tings["font2"].render("ID:", True, BLACK)
    slf.screen.blit(len_header, (tile.x + 5, tile.y + 110))
    src_header = slf.tings["font2"].render("Flags:", True, BLACK)
    slf.screen.blit(src_header, (tile.x + 230, tile.y + 35))
    dst_header = slf.tings["font2"].render("Time To Live:", True, BLACK)
    slf.screen.blit(dst_header, (tile.x + 230, tile.y + 50))
    dst_header = slf.tings["font2"].render("Protocol:", True, BLACK)
    slf.screen.blit(dst_header, (tile.x + 230, tile.y + 65))
    #
    time_surface = slf.tings["font2"].render(hdr["src_ip"], True, BLACK)
    slf.screen.blit(time_surface, (tile.x + 120, tile.y + 35))
    length_surface = slf.tings["font2"].render(hdr["dst_ip"], True, BLACK)
    slf.screen.blit(length_surface, (tile.x + 120, tile.y + 50))
    src_surface = slf.tings["font2"].render(hdr["ver"], True, BLACK)
    slf.screen.blit(src_surface, (tile.x + 120, tile.y + 65))
    dst_surface = slf.tings["font2"].render(hdr["hed_len"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 80))
    time_surface = slf.tings["font2"].render(hdr["tot_len"], True, BLACK)
    slf.screen.blit(time_surface, (tile.x + 120, tile.y + 95))
    length_surface = slf.tings["font2"].render(hdr["id"], True, BLACK)
    slf.screen.blit(length_surface, (tile.x + 120, tile.y + 110))
    src_surface = slf.tings["font2"].render(hdr["flag"], True, BLACK)
    slf.screen.blit(src_surface, (tile.x + 330, tile.y + 35))
    dst_surface = slf.tings["font2"].render(hdr["ttl"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 330, tile.y + 50))
    dst_surface = slf.tings["font2"].render(hdr["prot"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 330, tile.y + 65))
    return depth
    pass

def draw_tcp(slf, hdr, depth):
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, 300)
    pygame.draw.rect(slf.screen, WHITE, tile)
    #
    depth += 305
    #
    time_surface = slf.tings["font2"].render("- TCP -", True, BLACK)
    slf.screen.blit(time_surface, (tile.x + 5, tile.y + 5))
    #
    time_surface = slf.tings["font2"].render("Source Port:", True, BLACK)
    slf.screen.blit(time_surface, (tile.x + 5, tile.y + 35))
    length_surface = slf.tings["font2"].render("Destination Port:", True, BLACK)
    slf.screen.blit(length_surface, (tile.x + 5, tile.y + 50))
    src_surface = slf.tings["font2"].render("Seq Number:", True, BLACK)
    slf.screen.blit(src_surface, (tile.x + 5, tile.y + 65))
    dst_surface = slf.tings["font2"].render("Ack Number:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 80))
    time_surface = slf.tings["font2"].render("Data Offset:", True, BLACK)
    slf.screen.blit(time_surface, (tile.x + 240, tile.y + 35))
    length_surface = slf.tings["font2"].render("Reserved:", True, BLACK)
    slf.screen.blit(length_surface, (tile.x + 240, tile.y + 50))
    src_surface = slf.tings["font2"].render("Flags:", True, BLACK)
    slf.screen.blit(src_surface, (tile.x + 240, tile.y + 65))
    dst_surface = slf.tings["font2"].render("Window:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 240, tile.y + 80))
    dst_surface = slf.tings["font2"].render("Checksum:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 240, tile.y + 95))
    dst_surface = slf.tings["font2"].render("Urgent Ponter:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 240, tile.y + 110))
    dst_surface = slf.tings["font2"].render("Options:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 95))
    #
    #
    time_surface = slf.tings["font2"].render(hdr["src_port"], True, BLACK)
    slf.screen.blit(time_surface, (tile.x + 130, tile.y + 35))
    length_surface = slf.tings["font2"].render(hdr["dst_port"], True, BLACK)
    slf.screen.blit(length_surface, (tile.x + 130, tile.y + 50))
    src_surface = slf.tings["font2"].render(hdr["seq"], True, BLACK)
    slf.screen.blit(src_surface, (tile.x + 130, tile.y + 65))
    dst_surface = slf.tings["font2"].render(hdr["ack"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 130, tile.y + 80))
    time_surface = slf.tings["font2"].render(hdr["data_off"], True, BLACK)
    slf.screen.blit(time_surface, (tile.x + 340, tile.y + 35))
    length_surface = slf.tings["font2"].render(hdr["res"], True, BLACK)
    slf.screen.blit(length_surface, (tile.x + 340, tile.y + 50))
    src_surface = slf.tings["font2"].render(hdr["flags"], True, BLACK)
    slf.screen.blit(src_surface, (tile.x + 340, tile.y + 65))
    dst_surface = slf.tings["font2"].render(hdr["window"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 340, tile.y + 80))
    dst_surface = slf.tings["font2"].render(hdr["checksum"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 340, tile.y + 95))
    dst_surface = slf.tings["font2"].render(hdr["urg_point"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 340, tile.y + 110))
    b = 0
    for a in hdr["options"]:
        # print(a)
        dst_surface = slf.tings["font2"].render(f"{a[0]}: {a[1]}", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 110 + b))
        b += 15
    #
    return depth
    pass


def draw_udp(slf, hdr, depth):
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, 150)
    pygame.draw.rect(slf.screen, WHITE, tile)
    #
    depth += 155
    #
    dst_surface = slf.tings["font2"].render("- UDP -", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 5))
    #
    dst_surface = slf.tings["font2"].render("Source Port:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 35))
    dst_surface = slf.tings["font2"].render("Destination Port:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 50))
    dst_surface = slf.tings["font2"].render("Length:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 65))
    dst_surface = slf.tings["font2"].render("Checksum:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 80))
    #
    dst_surface = slf.tings["font2"].render(hdr["src_port"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 130, tile.y + 35))
    dst_surface = slf.tings["font2"].render(hdr["dst_port"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 130, tile.y + 50))
    dst_surface = slf.tings["font2"].render(hdr["len"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 130, tile.y + 65))
    dst_surface = slf.tings["font2"].render(hdr["checksum"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 130, tile.y + 80))
    return depth
    pass

def draw_dns(slf, hdr, depth):
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, 150)
    pygame.draw.rect(slf.screen, WHITE, tile)
    #
    depth += 155
    #
    dst_surface = slf.tings["font2"].render("- DNS -", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 5))
    #
    dst_surface = slf.tings["font2"].render("Trans ID:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 35))
    dst_surface = slf.tings["font2"].render("Questions:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 50))
    dst_surface = slf.tings["font2"].render("Answers:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 65))
    dst_surface = slf.tings["font2"].render("Auth rrs:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 80))
    dst_surface = slf.tings["font2"].render("Add rrs:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 95))
    dst_surface = slf.tings["font2"].render("qr:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 110))
    dst_surface = slf.tings["font2"].render("Opcode:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 125))
    dst_surface = slf.tings["font2"].render("aa:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 230, tile.y + 35))
    dst_surface = slf.tings["font2"].render("tc:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 230, tile.y + 50))
    dst_surface = slf.tings["font2"].render("rd:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 230, tile.y + 65))
    dst_surface = slf.tings["font2"].render("ra:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 230, tile.y + 80))
    dst_surface = slf.tings["font2"].render("z:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 230, tile.y + 95))
    dst_surface = slf.tings["font2"].render("rcode:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 230, tile.y + 110))
    #
    dst_surface = slf.tings["font2"].render(hdr["tran_id"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 35))
    dst_surface = slf.tings["font2"].render(hdr["questions"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 50))
    dst_surface = slf.tings["font2"].render(hdr["answers"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 65))
    dst_surface = slf.tings["font2"].render(hdr["auth_rrs"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 80))
    dst_surface = slf.tings["font2"].render(hdr["add_rrs"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 95))
    dst_surface = slf.tings["font2"].render(hdr["qr"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 110))
    dst_surface = slf.tings["font2"].render(hdr["opcode"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 125))
    dst_surface = slf.tings["font2"].render(hdr["aa"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 320, tile.y + 35))
    dst_surface = slf.tings["font2"].render(hdr["tc"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 320, tile.y + 50))
    dst_surface = slf.tings["font2"].render(hdr["rd"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 320, tile.y + 65))
    dst_surface = slf.tings["font2"].render(hdr["ra"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 320, tile.y + 80))
    dst_surface = slf.tings["font2"].render(hdr["z"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 320, tile.y + 95))
    dst_surface = slf.tings["font2"].render(hdr["rcode"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 320, tile.y + 110))
    return depth

def draw_icmp(slf, hdr, depth):
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, 150)
    pygame.draw.rect(slf.screen, WHITE, tile)
    #
    depth += 155
    #
    dst_surface = slf.tings["font2"].render("- ICMP -", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 5))
    type = hdr["type"]
    dst_surface = slf.tings["font2"].render(hdr["type"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 30))
    dst_surface = slf.tings["font2"].render(hdr["code"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 50))
    if type in [0, 8]:
        dst_surface = slf.tings["font2"].render("ID:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 70))
        dst_surface = slf.tings["font2"].render("Sequence:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 100))
    #
        dst_surface = slf.tings["font2"].render(hdr["id"], True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 70))
        dst_surface = slf.tings["font2"].render(hdr["seq"], True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 100))
    if type == 3:
        dst_surface = slf.tings["font2"].render("Unused:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 70))
    #
        dst_surface = slf.tings["font2"].render(hdr["unused"], True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 70))
    if type == 5:
        dst_surface = slf.tings["font2"].render("gw:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 100))
        dst_surface = slf.tings["font2"].render(hdr["gw"], True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 100))
    if type == 12:
        dst_surface = slf.tings["font2"].render("Pointer:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 70))
        dst_surface = slf.tings["font2"].render(hdr["ptr"], True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 70))
    return depth

def draw_igmp(slf, hdr, depth):
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, 150)
    pygame.draw.rect(slf.screen, WHITE, tile)
    #
    depth += 155
    #
    dst_surface = slf.tings["font2"].render("- IGMP -", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 5))

    if hdr['ver'] == '0':

        dst_surface = slf.tings["font2"].render("Type:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 35))
        dst_surface = slf.tings["font2"].render("mrcode:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 50))
        dst_surface = slf.tings["font2"].render("Checksum:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 65))
        dst_surface = slf.tings["font2"].render("Group Address:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 80))
        #
        dst_surface = slf.tings["font2"].render(hdr["type"], True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 35))
        dst_surface = slf.tings["font2"].render(hdr["mrt"], True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 50))
        dst_surface = slf.tings["font2"].render(hdr["check"], True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 65))
        dst_surface = slf.tings["font2"].render(hdr["group"], True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 80))
    if hdr['ver'] == '1':

        dst_surface = slf.tings["font2"].render("Type:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 35))
        dst_surface = slf.tings["font2"].render("mrcode:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 50))
        dst_surface = slf.tings["font2"].render("Checksum:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 65))
        #
        dst_surface = slf.tings["font2"].render(hdr["type"], True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 35))
        dst_surface = slf.tings["font2"].render(hdr["mrcode"], True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 50))
        dst_surface = slf.tings["font2"].render(hdr["check"], True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 65))
    #
    # if hdr["type"] == "x22":
    #     pass
    # else:
    #     dst_surface = slf.tings["font2"].render("Type:", True, BLACK)
    #     slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 35))
    #     dst_surface = slf.tings["font2"].render("Trans:", True, BLACK)
    #     slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 50))
    #     dst_surface = slf.tings["font2"].render("Checksum:", True, BLACK)
    #     slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 65))
    #     dst_surface = slf.tings["font2"].render("Group Address:", True, BLACK)
    #     slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 80))
    #     #
    #     dst_surface = slf.tings["font2"].render(hdr["type"], True, BLACK)
    #     slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 35))
    #     dst_surface = slf.tings["font2"].render(hdr["mrt"], True, BLACK)
    #     slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 50))
    #     dst_surface = slf.tings["font2"].render(hdr["check"], True, BLACK)
    #     slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 65))
    #     dst_surface = slf.tings["font2"].render(hdr["addr"], True, BLACK)
    #     slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 80))
    return depth

def draw_arp(slf, hdr, depth):
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, 150)
    pygame.draw.rect(slf.screen, WHITE, tile)
    #
    depth += 155
    #
    dst_surface = slf.tings["font2"].render("- ARP -", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 5))
    #
    dst_surface = slf.tings["font2"].render("Hardware Type:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 35))
    dst_surface = slf.tings["font2"].render("Protocol Type:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 50))
    dst_surface = slf.tings["font2"].render("Hardware Length:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 230, tile.y + 35))
    dst_surface = slf.tings["font2"].render("Protocol Length:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 230, tile.y + 50))
    dst_surface = slf.tings["font2"].render("Opcode:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 65))
    dst_surface = slf.tings["font2"].render("Hardware Source:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 80))
    dst_surface = slf.tings["font2"].render("Protocol Source:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 95))
    dst_surface = slf.tings["font2"].render("Hardware Destination:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 110))
    dst_surface = slf.tings["font2"].render("Protocol Destination:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 125))
    #
    dst_surface = slf.tings["font2"].render(hdr["hw_type"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 160, tile.y + 35))
    dst_surface = slf.tings["font2"].render(hdr["prot_type"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 160, tile.y + 50))
    dst_surface = slf.tings["font2"].render(hdr["hw_len"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 355, tile.y + 35))
    dst_surface = slf.tings["font2"].render(hdr["prot_len"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 355, tile.y + 50))
    dst_surface = slf.tings["font2"].render(hdr["opcode"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 160, tile.y + 65))
    dst_surface = slf.tings["font2"].render(hdr["hw_src"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 160, tile.y + 80))
    dst_surface = slf.tings["font2"].render(hdr["prot_src"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 160, tile.y + 95))
    dst_surface = slf.tings["font2"].render(hdr["hw_dst"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 160, tile.y + 110))
    dst_surface = slf.tings["font2"].render(hdr["prot_dst"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 160, tile.y + 125))
    return depth

def draw_raw(slf, hdr, depth):
    rstr = hdr["str"]
    if not slf.ascii_hex:
        rstr = str(' '.join(f'{byte:02x}' for byte in hdr["str"]))
    else:
        rstr = str(hdr["str"].decode('ascii', errors='ignore')).replace('\0', '')
    lchnk = 5
    str_len = 46
    h_chk = 150
    h_num = len(rstr) // (lchnk * str_len)
    pchnk = (26 * 48)
    h_chk = 150
    temp = min(150 + (h_chk * h_num), 450)
    #
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, temp)
    pygame.draw.rect(slf.screen, WHITE, tile)
    #
    depth += 155 + (h_chk * h_num)
    #
    dst_surface = slf.tings["font2"].render("- RAW -", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 5))
    dst_surface = slf.tings["font2"].render("Load:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 35))
    # 26 len
    slf.info_elem["info_raw_ah_button"] = pygame.Rect(tile.x + 370, tile.y + 5 , 30, 20)
    pygame.draw.rect(slf.screen, GRAY, slf.info_elem["info_raw_ah_button"])
    dst_surface = slf.tings["font2"].render("a-0", True, BLACK)
    slf.screen.blit(dst_surface, (slf.info_elem["info_raw_ah_button"].x + 5, slf.info_elem["info_raw_ah_button"].y + 2))
    #
    if h_num > 2:
        pages = len(rstr) // (pchnk)
        # print(f"]|> pages {pages}")
        slf.info_elem["info_raw_back_button"] = pygame.Rect(tile.x + 300, tile.y + 5 , 30, 20)
        pygame.draw.rect(slf.screen, GRAY, slf.info_elem["info_raw_back_button"])
        dst_surface = slf.tings["font2"].render("<", True, BLACK)
        slf.screen.blit(dst_surface, (slf.info_elem["info_raw_back_button"].x + 10, slf.info_elem["info_raw_back_button"].y + 2))
        #
        slf.info_elem["info_raw_fwd_button"] = pygame.Rect(tile.x + 335, tile.y + 5 , 30, 20)
        pygame.draw.rect(slf.screen, GRAY, slf.info_elem["info_raw_fwd_button"])
        dst_surface = slf.tings["font2"].render(">", True, BLACK)
        slf.screen.blit(dst_surface, (slf.info_elem["info_raw_fwd_button"].x + 10, slf.info_elem["info_raw_fwd_button"].y + 2))
        st = rstr[slf.indices["info_page"] * pchnk:(slf.indices["info_page"] * pchnk) + pchnk]
        if not slf.ascii_hex:
            # l = []
            # r = []
            # bf = False
            # # print(st)
            # for i in range(0, len(st), 24):
            #     bf = not bf
            #     if bf:
            #         l.append(st[i: i + 24])
            #     else:
            #         r.append(st[i: i + 24])
            #     pass
            st = ''.join([st[i:i+24] + ('    ' if (i // 24) % 2 == 0 else '')
                        for i in range(0, len(st), 24)])
            buf = 0
            for i in range(0, len(st), 52):
                dst_surface = slf.tings["font2"].render(st[i: i + 52], True, BLACK)
                slf.screen.blit(dst_surface, (tile.x + 5, tile.y + str_len + buf))
                buf += 15
            # buf = 0
            # for i in range(0, len(r)):
            #     dst_surface = slf.tings["font2"].render(r[i], True, BLACK)
            #     slf.screen.blit(dst_surface, (tile.x + 205, tile.y + str_len + buf))
            #     buf += 15


        #
        else:
            buf = 0
            for i in range(0, len(st), str_len):
                dst_surface = slf.tings["font2"].render(st[i: i + str_len], True, BLACK)
                slf.screen.blit(dst_surface, (tile.x + 5, tile.y + str_len + buf))
                buf += 15
    else:
        if not slf.ascii_hex:
            l = []
            r = []
            bf = False
            # print(st)
            for i in range(0, len(rstr), 24):
                bf = not bf
                if bf:
                    l.append(rstr[i: i + 24])
                else:
                    r.append(rstr[i: i + 24])
                pass
            buf = 0
            for i in range(0, len(l)):
                dst_surface = slf.tings["font2"].render(l[i], True, BLACK)
                slf.screen.blit(dst_surface, (tile.x + 5, tile.y + str_len + buf))
                buf += 15
            buf = 0
            for i in range(0, len(r)):
                dst_surface = slf.tings["font2"].render(r[i], True, BLACK)
                slf.screen.blit(dst_surface, (tile.x + 205, tile.y + str_len + buf))
                buf += 15
            # rstr = ''.join([rstr[i:i+24] + ('    ' if (i // 24) % 2 == 0 else '')
            #             for i in range(0, len(rstr), 24)])
        else:
            buf = 0
            for i in range(0, len(rstr), str_len):
                dst_surface = slf.tings["font2"].render(rstr[i: i + str_len], True, BLACK)
                slf.screen.blit(dst_surface, (tile.x + 5, tile.y + str_len + buf))
                buf += 15
    return depth

def draw_payload(slf, hdr, depth):
    if hdr["payload"].strip() == "":
        return depth
    #
    rstr = hdr["payload"]
    lchnk = 6
    str_len = 50
    h_chk = 150
    #
    h_num = len(rstr) // (lchnk * str_len)
    pchnk = 26 * 50
    h_chk = 150
    temp = min(150 + (h_chk * h_num), 450)
    #
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, temp)
    pygame.draw.rect(slf.screen, WHITE, tile)
    #
    depth += 155 + (h_chk * h_num)
    #
    dst_surface = slf.tings["font2"].render("- Payload -", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 5))
    dst_surface = slf.tings["font2"].render("Load:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 35))
    ch_s = 50
    buf = 0
    if h_num > 2:
        pages = len(hdr['str']) // (pchnk)
        # print(f"]|> pages {pages}")
        slf.info_elem["info_pay_back_button"] = pygame.Rect(tile.x + 300, tile.y + 5 , 30, 20)
        pygame.draw.rect(slf.screen, GRAY, slf.info_elem["info_pay_back_button"])
        slf.info_elem["info_pay_fwd_button"] = pygame.Rect(tile.x + 335, tile.y + 5 , 30, 20)
        pygame.draw.rect(slf.screen, GRAY, slf.info_elem["info_pay_fwd_button"])
        st = hdr["payload"][slf.indices["info_page"] * pchnk:(slf.indices["info_page"] * pchnk) + pchnk]
        for i in range(0, len(st), str_len):
            dst_surface = slf.tings["font2"].render(st[i: i + str_len], True, BLACK)
            slf.screen.blit(dst_surface, (tile.x + 5, tile.y + str_len + buf))
            buf += 15
    else:
        for i in range(0, len(hdr["payload"]), str_len):
            dst_surface = slf.tings["font2"].render(hdr["payload"][i: i + str_len], True, BLACK)
            slf.screen.blit(dst_surface, (tile.x + 5, tile.y + str_len + buf))
            buf += 15
    return depth

def draw_host(slf, hdr, depth):
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, 150)
    pygame.draw.rect(slf.screen, WHITE, tile)
    #
    depth += 155
    #
    dst_surface = slf.tings["font2"].render("- Host -", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 5))
    #
    dst_surface = slf.tings["font2"].render("Mac Address:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 35))
    dst_surface = slf.tings["font2"].render("IPv4 Address:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 50))
    dst_surface = slf.tings["font2"].render("IPv6 Address:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 65))
    #
    dst_surface = slf.tings["font2"].render(hdr["host_mac"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 160, tile.y + 35))
    dst_surface = slf.tings["font2"].render(hdr["host_ip4"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 160, tile.y + 50))
    dst_surface = slf.tings["font2"].render(hdr["host_ip6"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 160, tile.y + 65))
    return depth

def draw_traffic(slf, hdr, depth):
    out_t = hdr["out_traffic"]
    in_t = hdr["in_traffic"]
    #
    lines = out_t + in_t
    #
    temp = 300
    if len(out_t) > 5 or len(in_t) > 5:
        temp = 450
    #
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, temp)
    pygame.draw.rect(slf.screen, WHITE, tile)
    #
    depth += temp + 5 #+ (h_chk * h_num)
    #
    dst_surface = slf.tings["font2"].render("- Traffic -", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 5))
    # dst_surface = slf.tings["font2"].render("Out:", True, BLACK)
    # slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 35))
    # dst_surface = slf.tings["font2"].render("In:", True, BLACK)
    # slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 150))
    # ch_s = 50
    # buf = 0
    h_num = 1
    if temp == 300:
        # pages = len(hdr['str']) // (pchnk)
        # # print(f"]|> pages {pages}")
        # slf.info_elem["info_pay_back_button"] = pygame.Rect(tile.x + 300, tile.y + 5 , 30, 20)
        # pygame.draw.rect(slf.screen, GRAY, slf.info_elem["info_pay_back_button"])
        # slf.info_elem["info_pay_fwd_button"] = pygame.Rect(tile.x + 335, tile.y + 5 , 30, 20)
        # pygame.draw.rect(slf.screen, GRAY, slf.info_elem["info_pay_fwd_button"])
        # st = hdr["payload"][slf.indices["info_page"] * pchnk:(slf.indices["info_page"] * pchnk) + pchnk]
        # for i in range(0, len(st), str_len):
        #     dst_surface = slf.tings["font2"].render(st[i: i + str_len], True, BLACK)
        #     slf.screen.blit(dst_surface, (tile.x + 5, tile.y + str_len + buf))
        #     buf += 15
        dst_surface = slf.tings["font2"].render("Out:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 35))
        #
        dst_surface = slf.tings["font2"].render("In:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 150))
        buf = 0
        for i in range(0, len(out_t)):
            # print(f"-> {ports[i]} --> {i}")
            dst_surface = slf.tings["font2"].render(str(out_t[i]), True, BLACK)
            slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 50 + buf))
            buf += 15
        buf = 0
        for i in range(0, len(in_t)):
            # print(f"-> {ips[i]} --> {i}")
            dst_surface = slf.tings["font2"].render(str(in_t[i]), True, BLACK)
            slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 165 + buf))
            buf += 15
        pass
    else:
        # ll lines
        dst_surface = slf.tings["font2"].render("Out:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 35))
        #
        dst_surface = slf.tings["font2"].render("In:", True, BLACK)
        slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 225))
        #
        slf.info_elem["traffic_out_back_button"] = pygame.Rect(tile.x + 300, tile.y + 35, 30, 20)
        pygame.draw.rect(slf.screen, GRAY, slf.info_elem["traffic_out_back_button"])
        slf.info_elem["traffic_out_fwd_button"] = pygame.Rect(tile.x + 335, tile.y + 35, 30, 20)
        pygame.draw.rect(slf.screen, GRAY, slf.info_elem["traffic_out_fwd_button"])
        #
        dst_surface = slf.tings["font2"].render("<", True, BLACK)
        slf.screen.blit(dst_surface, (slf.info_elem["traffic_out_back_button"].x + 10, slf.info_elem["traffic_out_back_button"].y + 2))
        dst_surface = slf.tings["font2"].render(">", True, BLACK)
        slf.screen.blit(dst_surface, (slf.info_elem["traffic_out_fwd_button"].x + 10, slf.info_elem["traffic_out_fwd_button"].y + 2))
        #
        slf.info_elem["traffic_in_back_button"] = pygame.Rect(tile.x + 300, tile.y + 225, 30, 20)
        pygame.draw.rect(slf.screen, GRAY, slf.info_elem["traffic_in_back_button"])
        slf.info_elem["traffic_in_fwd_button"] = pygame.Rect(tile.x + 335, tile.y + 225, 30, 20)
        pygame.draw.rect(slf.screen, GRAY, slf.info_elem["traffic_in_fwd_button"])
        #
        dst_surface = slf.tings["font2"].render("<", True, BLACK)
        slf.screen.blit(dst_surface, (slf.info_elem["traffic_in_back_button"].x + 10, slf.info_elem["traffic_in_back_button"].y + 2))
        dst_surface = slf.tings["font2"].render(">", True, BLACK)
        slf.screen.blit(dst_surface, (slf.info_elem["traffic_in_fwd_button"].x + 10, slf.info_elem["traffic_in_fwd_button"].y + 2))
        #
        # st = hdr["payload"][slf.indices["info_page"] * pchnk:(slf.indices["info_page"] * pchnk) + pchnk]
        #
        buf = 0
        o_chnk = out_t[slf.indices["t_out_page"] * 10: (slf.indices["t_out_page"] * 10) + 10]
        for i in range(0, len(o_chnk)):
            # print(f"-> {ports[i]} --> {i}")
            dst_surface = slf.tings["font2"].render(str(o_chnk[i]), True, BLACK)
            slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 50 + buf))
            buf += 15
        buf = 0
        i_chnk = in_t[slf.indices["t_in_page"] * 10: (slf.indices["t_in_page"] * 10) + 10]
        for i in range(0, len(i_chnk)):
            # print(f"-> {ips[i]} --> {i}")
            dst_surface = slf.tings["font2"].render(str(i_chnk[i]), True, BLACK)
            slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 240 + buf))
            buf += 15
    return depth

def draw_conn(slf, hdr, depth):
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, 150)
    pygame.draw.rect(slf.screen, WHITE, tile)
    #
    depth += 155
    #
    dst_surface = slf.tings["font2"].render("- Conn -", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 5))
    dst_surface = slf.tings["font2"].render("MAC One:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 35))
    #
    dst_surface = slf.tings["font2"].render("MAC Two:", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 50))
    #
    dst_surface = slf.tings["font2"].render(hdr["mac_one"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 160, tile.y + 35))
    #
    dst_surface = slf.tings["font2"].render(hdr["mac_two"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 160, tile.y + 50))
    #

    return depth

def draw_conn_traffic(slf, hdr, depth):
    in_t = hdr["conn_traffic"]
    temp = 300
    print(in_t)
    print(f"cont -:.> {len(in_t)}")
    if len(in_t) > 20:
        temp = 450
    #
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, temp)
    pygame.draw.rect(slf.screen, WHITE, tile)
    #
    depth += temp + 5 #+ (h_chk * h_num)
    #
    dst_surface = slf.tings["font2"].render("- Traffic -", True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 5))

    # ch_s = 50
    # buf = 0
    h_num = 1
    if temp == 300:
        #
        buf = 0
        for i in range(0, len(in_t)):
            # print(f"-> {ips[i]} --> {i}")
            dst_surface = slf.tings["font2"].render(str(in_t[i]), True, BLACK)
            slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 50 + buf))
            buf += 15
        pass
    else:
        # ll lines
        #
        slf.info_elem["conn_traffic_back_button"] = pygame.Rect(tile.x + 300, tile.y + 20, 30, 20)
        pygame.draw.rect(slf.screen, GRAY, slf.info_elem["conn_traffic_back_button"])
        slf.info_elem["conn_traffic_fwd_button"] = pygame.Rect(tile.x + 335, tile.y + 20, 30, 20)
        pygame.draw.rect(slf.screen, GRAY, slf.info_elem["conn_traffic_fwd_button"])
        #
        dst_surface = slf.tings["font2"].render("<", True, BLACK)
        slf.screen.blit(dst_surface, (slf.info_elem["conn_traffic_back_button"].x + 10, slf.info_elem["conn_traffic_back_button"].y + 2))
        dst_surface = slf.tings["font2"].render(">", True, BLACK)
        slf.screen.blit(dst_surface, (slf.info_elem["conn_traffic_fwd_button"].x + 10, slf.info_elem["conn_traffic_fwd_button"].y + 2))
        #
        buf = 0
        chk = 25
        i_chnk = in_t[slf.indices["c_t_page"] * chk: (slf.indices["c_t_page"] * chk) + chk]
        for i in range(0, len(i_chnk)):
            # print(f"-> {ips[i]} --> {i}")
            dst_surface = slf.tings["font2"].render(str(i_chnk[i]), True, BLACK)
            slf.screen.blit(dst_surface, (tile.x + 5, tile.y + 50 + buf))
            buf += 15
    return depth


def draw_ip6(slf, hdr, depth):
    tile = pygame.Rect(slf.panels['top_right'].x + 5, slf.panels['top_right'].y + 5 + depth, 416, 150)
    pygame.draw.rect(slf.screen, WHITE, tile)
    #
    depth += 155
    #
    time_surface = slf.tings["font2"].render("- IP6 -", True, BLACK)
    slf.screen.blit(time_surface, (tile.x + 5, tile.y + 5))
    #
    time_header = slf.tings["font2"].render("Source IP:", True, BLACK)
    slf.screen.blit(time_header, (tile.x + 5, tile.y + 35))
    len_header = slf.tings["font2"].render("Destination IP:", True, BLACK)
    slf.screen.blit(len_header, (tile.x + 5, tile.y + 50))
    src_header = slf.tings["font2"].render("Traffic Class:", True, BLACK)
    slf.screen.blit(src_header, (tile.x + 5, tile.y + 65))
    dst_header = slf.tings["font2"].render("Flow Label:", True, BLACK)
    slf.screen.blit(dst_header, (tile.x + 5, tile.y + 80))
    time_header = slf.tings["font2"].render("Payload Length:", True, BLACK)
    slf.screen.blit(time_header, (tile.x + 5, tile.y + 95))
    len_header = slf.tings["font2"].render("Next Header:", True, BLACK)
    slf.screen.blit(len_header, (tile.x + 5, tile.y + 110))
    src_header = slf.tings["font2"].render("Hop Limit:", True, BLACK)
    slf.screen.blit(src_header, (tile.x + 230, tile.y + 65))

    #
    time_surface = slf.tings["font2"].render(hdr["src"], True, BLACK)
    slf.screen.blit(time_surface, (tile.x + 120, tile.y + 35))
    length_surface = slf.tings["font2"].render(hdr["dst"], True, BLACK)
    slf.screen.blit(length_surface, (tile.x + 120, tile.y + 50))
    src_surface = slf.tings["font2"].render(hdr["tc"], True, BLACK)
    slf.screen.blit(src_surface, (tile.x + 120, tile.y + 65))
    dst_surface = slf.tings["font2"].render(hdr["fl"], True, BLACK)
    slf.screen.blit(dst_surface, (tile.x + 120, tile.y + 80))
    time_surface = slf.tings["font2"].render(hdr["plen"], True, BLACK)
    slf.screen.blit(time_surface, (tile.x + 120, tile.y + 95))
    length_surface = slf.tings["font2"].render(hdr["nh"], True, BLACK)
    slf.screen.blit(length_surface, (tile.x + 120, tile.y + 110))
    src_surface = slf.tings["font2"].render(hdr["hlim"], True, BLACK)
    slf.screen.blit(src_surface, (tile.x + 330, tile.y + 65))
    return depth
    pass
