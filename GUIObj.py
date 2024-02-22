from Actions import Action
from scapy.all import Ether
BLUE = (207, 210, 205)

class NObj:
    def __init__(self, mac, sp):
        self.sprite_props = {
            "sprite": sp,
            "radius": 15,
            "color": BLUE,
        }
        self.mac = mac
        self.neighbors = []
        self.packet_list = []

    def get_packet_list(self):
        return self.packet_list

    def get_sprite_props(self):
        return self.sprite_props

    def set_sprite_props(self, key, val):
        del self.sprite_props[key]
        self.sprite_props[key] = val

    def set_packet_list(self, temp):
        self.packet_list = temp

    def add_neighbor(self, temp):
        if temp not in self.neighbors:
            self.neighbors.append(temp)
        # print(f"mac: {self.mac} n: {self.neighbors}")

    def get_neighbors(self):
        return self.neighbors

    def add_packet(self, temp):
        if temp.haslayer(Ether) and (temp[Ether].src == self.mac or temp[Ether].dst == self.mac):
            self.packet_list.append(temp)

    def get_mac(self):
        return self.mac


class LObj:
    def __init__(self, mac_one, mac_two, sp1, sp2):
        self.sprite_props = {
            "s_sprite": sp1,
            "r_sprite": sp2,
            "color": BLUE,
        }
        self.mac_one = mac_one
        self.mac_two = mac_two
        self.packet_list = []

    def get_mac_one(self):
        return self.mac_one

    def get_mac_two(self):
        return self.mac_two


    def get_packet_list(self):
        return self.packet_list

    def set_packet_list(self, temp):
        self.packet_list = temp

    def add_packet(self, temp):
        if temp.haslayer(Ether):
            src_mac = temp[Ether].src
            dst_mac = temp[Ether].dst
            if (src_mac == self.mac_one and dst_mac == self.mac_two) or (src_mac == self.mac_two and dst_mac == self.mac_one):
                self.packet_list.append(temp)

    def get_sprite_props(self):
        return self.sprite_props

    def set_sprite_props(self, key, val):
        del self.sprite_props[key]
        self.sprite_props[key] = val


class PLObj:
    def __init__(self):
        self.sprite_props = {}
        self.packet = None

    def packet(self):
        return self.packet

    def sprite_props(self):
        return self.sprite_props
