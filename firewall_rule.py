import subprocess
import re
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


class FirewallRule:
    def __init__(self, table_name: str, chain_name: str):
        self.table_name = table_name
        self.chain_name = chain_name
        self.handle = None
        self.rule_specifics = None  # 用于存储规则特定部分

    def enable(self):
        """启用规则，并添加到防火墙中"""
        command = f"nft --handle --echo add rule {self.table_name} {self.chain_name} {self.rule_specifics}"
        output = self._execute_command(command)
        if output:
            handle_match = re.search(r"handle (\d+)", output)
            if handle_match:
                self.handle = handle_match.group(1)
                Logger.debug(f"已添加规则，句柄: {self.handle}")
            else:
                Logger.error(f"未能从输出中提取句柄: {output}")

    def disable(self):
        """删除规则"""
        if self.handle:
            delete_command = f"nft delete rule {self.table_name} {self.chain_name} handle {self.handle}"
            self._execute_command(delete_command)
            Logger.debug(f"已删除规则，句柄: {self.handle}")
            self.handle = None

    def _execute_command(self, command):
        """执行系统命令，捕获输出和错误"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return result.stdout.decode().strip()
        except subprocess.CalledProcessError as e:
            Logger.error(f"执行命令时出错: {command}\n错误信息: {e.stderr.decode()}")
            return None

    def __del__(self):
        """析构函数，删除规则"""
        self.disable()


class UpnpForwardRule(FirewallRule):
    def __init__(
        self, protocol: str, internal_port: int, interface="eth0", enable=False
    ):
        super().__init__("inet fw4", "upnp_forward")
        self.protocol = protocol.lower()  # 可以是 'tcp' 或 'udp'
        self.internal_port = internal_port
        self.interface = interface  # 入站接口，默认为 'eth0'

        # 设置规则特定部分
        self.rule_specifics = (
            f'iif "{self.interface}" {self.protocol} dport {self.internal_port} accept'
        )

        # 如果需要，启用规则
        if enable:
            self.enable()


class UpnpPreroutingRule(FirewallRule):
    def __init__(
        self,
        protocol: str,
        internal_ip: str,
        internal_port: int,
        relay_port: int,
        interface="eth0",
        enable=False,
    ):
        super().__init__("inet fw4", "upnp_prerouting")
        self.protocol = protocol.lower()  # 可以是 'tcp' 或 'udp'
        self.internal_ip = internal_ip
        self.internal_port = internal_port
        self.relay_port = relay_port
        self.interface = interface

        # 设置规则特定部分
        self.rule_specifics = f'iif "{self.interface}" {self.protocol} dport {self.relay_port} dnat ip to {self.internal_ip}:{self.internal_port}'

        # 如果需要，启用规则
        if enable:
            self.enable()


class InputRule(FirewallRule):
    def __init__(self, protocol: str, port: int, interface="eth0", enable=False):
        super().__init__("inet fw4", "input")
        self.protocol = protocol.lower()  # 可以是 'tcp' 或 'udp'
        self.port = port
        self.interface = interface  # 入站接口，默认为 'eth0'

        # 设置规则特定部分
        self.rule_specifics = (
            f'iif "{self.interface}" {self.protocol} dport {self.port} accept'
        )

        # 如果需要，启用规则
        if enable:
            self.enable()
