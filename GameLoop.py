from enum import Enum
from GUI import GUIClass
from Scapy import ScapyClass
from Actions import Action
import pygame
import threading


SNIFFING_DONE = pygame.USEREVENT + 1

def sfilter(self, filter_string):
    return self.Scapy.filter_packets(filter_string[1])
    pass
def reset(self, _fs):
    self.Scapy.reset_packets()
    return True
    pass
def resend(self, _fs):
    if self.play != False:
        self.GUI.step_through(self.step_position, self.step_range, self.Scapy.get_filtered_packets())
    return True
    pass
def prot(self, prot):
    if prot[1] == "T":
        self.Scapy.filter_packets(f"prot={prot[2]}")
        self.Scapy.toggle_prot(prot[2])
    else:
        self.Scapy.toggle_prot(prot[2])
        self.Scapy.toggle_reset()
    return True

def play(self, res):
    self.play = True
    if res[1] == "":
        self.step_range = 6
    else:
        self.step_range = int(res[1])
    return True

def pause(self, res):
    self.play = None
    return True

def stop(self, res):
    self.step_position = 0
    self.play = False
    self.ch = True
    return True

def beg(self, res):
    self.step_position = 0
    self.GUI.step_through(self.step_position, self.step_range, self.Scapy.get_filtered_packets())
    return True

def end(self, res):
    self.step_position = res[1] - self.step_range
    self.GUI.step_through(self.step_position, self.step_range, self.Scapy.get_filtered_packets())
    return True

def rev(self, res):
    if self.step_position > 0:
        self.step_position -= 1
        self.GUI.step_through(self.step_position, self.step_range, self.Scapy.get_filtered_packets())
    return True

def fwd(self, res):
    if self.step_position < (len(self.Scapy.get_filtered_packets()) - self.step_range):
        self.step_position += 1
        self.GUI.step_through(self.step_position, self.step_range, self.Scapy.get_filtered_packets())
    return True

def prange(self, res):
    t = 6
    if res[1] != "":
        t = res[1]
    self.step_range = int(t)
    self.GUI.step_through(self.step_position, self.step_range, self.Scapy.get_filtered_packets())

    return True

def spdup(self, res):
    if self.step_rate > 1:
        self.step_rate -= 1


def spddw(self, res):
    self.step_rate += 1


def playmove(self, res):
    if self.step_position < (len(self.Scapy.get_filtered_packets()) - self.step_range) and self.play != False:
        self.step_position = int(res[1])
        self.GUI.step_through(self.step_position, self.step_range, self.Scapy.get_filtered_packets())
    return True


gui_actions = {
    Action.FILTER: sfilter,
    Action.RESET: reset,
    Action.PROT: prot,
    Action.RESEND: resend,
    Action.RANGE: prange,
    Action.PLAY: play,
    Action.PAUSE: pause,
    Action.STOP: stop,
    Action.BEG: beg,
    Action.END: end,
    Action.REV: rev,
    Action.FWD: fwd,
    Action.SPDUP: spdup,
    Action.SPDDW: spddw,
    Action.PLAYMOVE: playmove,
}

class GameLoop:
    def __init__(self):
        self.GUI = GUIClass()
        self.Scapy = ScapyClass()
        self.GUIActions = gui_actions
        self.step_position = 0
        self.step_range = 0
        self.step_rate = 10
        self.play = False
        self.ch = False
        pass

    def game_loop(self):
        self.load_pcap()
        self.ch = True
        c = 0
        run = True
        while run:
            if c == 100:
                c = -1
            c += 1
            res = self.GUI.input_check()
            ac_bool = None
            if res != None:
                if res == Action.BACK:
                    return None
                if res == Action.SAVE:
                    self.Scapy.save_pcap()
                    continue
                print(f"gonna action {res[0]}")
                ac_bool = self.run_action(res)
                if ac_bool:
                    self.ch = True
                else:
                    self.ch = False
            if self.play and c % self.step_rate == 0:
                temp = self.Scapy.get_filtered_packets()
                if self.step_position == (len(temp) - self.step_range):
                    self.play = None
                    continue
                print(f"[// step_pos: {self.step_position} | step_rate: {self.step_rate} | step_range {self.step_range} | listlen: {len(temp)}")
                self.GUI.step_through(self.step_position, self.step_range, self.Scapy.get_filtered_packets())
                self.step_position += 1
            if self.play != False:
                self.ch = False
            if self.ch:
                print("gonna change")
                self.GUI.set_packets(self.Scapy.get_filtered_packets())
                self.ch = False
            self.GUI.update_screen(ac_bool)
            pass

    def load_pcap(self):

        def sniff_in_background(sniff_args):
            try:
                lres = self.Scapy.sniff(sniff_args)
                pygame.event.post(pygame.event.Event(SNIFFING_DONE, {'result': lres}))
            except Exception as e:
                print(f"Sniffing failed: {e}")
        while True:
            res = self.GUI.load_input()
            lres = None
            if res != None:
                if res[0] == "sniff":
                    threading.Thread(target=sniff_in_background, args=(res,)).start()
                elif res[0] == "pcap":
                    lres = self.Scapy.load_pcap(res[1])
                    if lres:
                        break
                elif res[0] == "dsniff":
                    if res[1]:
                        break
                    lres = True
            self.GUI.load_screen(lres)


    def run_action(self, res):
        print(res)
        return self.GUIActions[res[0]](self, res)
        pass

    def toggle_play(self):
        self.play = not self.play
        pass
