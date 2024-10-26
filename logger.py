import os
import sys
import time

class Logger(object):
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3
    rep = {DEBUG: "D", INFO: "I", WARN: "W", ERROR: "E"}
    level = INFO
    if "256color" in os.environ.get("TERM", ""):
        GREY = "\033[90;20m"
        YELLOW_BOLD = "\033[33;1m"
        RED_BOLD = "\033[31;1m"
        RESET = "\033[0m"
    else:
        GREY = YELLOW_BOLD = RED_BOLD = RESET = ""

    @staticmethod
    def set_level(level):
        Logger.level = level

    @staticmethod
    def debug(text=""):
        if Logger.level <= Logger.DEBUG:
            sys.stderr.write(
                (Logger.GREY + "%s [%s] %s\n" + Logger.RESET)
                % (time.strftime("%Y-%m-%d %H:%M:%S"), Logger.rep[Logger.DEBUG], text)
            )

    @staticmethod
    def info(text=""):
        if Logger.level <= Logger.INFO:
            sys.stderr.write(
                ("%s [%s] %s\n")
                % (time.strftime("%Y-%m-%d %H:%M:%S"), Logger.rep[Logger.INFO], text)
            )

    @staticmethod
    def warning(text=""):
        if Logger.level <= Logger.WARN:
            sys.stderr.write(
                (Logger.YELLOW_BOLD + "%s [%s] %s\n" + Logger.RESET)
                % (time.strftime("%Y-%m-%d %H:%M:%S"), Logger.rep[Logger.WARN], text)
            )

    @staticmethod
    def error(text=""):
        if Logger.level <= Logger.ERROR:
            sys.stderr.write(
                (Logger.RED_BOLD + "%s [%s] %s\n" + Logger.RESET)
                % (time.strftime("%Y-%m-%d %H:%M:%S"), Logger.rep[Logger.ERROR], text)
            )
