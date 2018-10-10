from colorclass import Color
from colorclass import disable_all_colors, enable_all_colors, is_enabled
from time import localtime, strftime
from enum import IntEnum


class OutputHelper(object):
    def __init__(self, arguments):
        if arguments.nocolor:
            disable_all_colors()


class Level(IntEnum):
    ERROR = 0
    INFORMATION = 1
    NEWSCAN = 2
    NEWFINDING = 3
    NEWEVENT = 4

