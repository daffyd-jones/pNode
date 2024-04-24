from GameLoop import GameLoop


def main():
    go = True
    while go:
        game = GameLoop()
        game.game_loop()


if __name__ == "__main__":
    main()
