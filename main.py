from GameLoop import GameLoop


def main():
    go = True
    while go:
        game = GameLoop()
        game.game_loop()
    # game = GameLoop()
    # game.game_loop()


main()


"""
-> 47350 --> 0
-> 47897 --> 1
-> 51262 --> 2
-> 95.168.164.7 --> 0
-> 75.153.171.116 --> 1
-> 91.189.91.48 --> 2

/home/daffyd/Desktop/skoo/proj/pNode/test.pcap
left_arrow = "\u2190"
up_arrow = "\u2191"
right_arrow = "\u2192"
down_arrow = "\u2193"

play_symbol = "\u25B6"
pause_symbol = "\u23F8"  # Alternative: "\u2016" for double vertical line
fast_forward_symbol = "\u23E9"
rewind_symbol = "\u23EA"
record_symbol = "\u25CF"
stop_symbol = "\u23F9"
eject_symbol = "\u23CF"
to_the_beginning_symbol = "\u23EE"
to_the_end_symbol = "\u23ED"
"""
