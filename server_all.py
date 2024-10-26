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

from enum import IntEnum
import struct
import socket
import time

start_time = time.time()

NAT_PMP_VERSION = 0


# 自定义异常类
class NATPMPError(Exception):
    """NAT-PMP 基础异常类"""

    pass


class UnsupportedVersionError(NATPMPError):
    """不支持的版本异常"""

    pass


class UnsupportedOpcodeError(NATPMPError):
    """不支持的操作码异常"""

    pass


class InsufficientDataError(NATPMPError):
    """数据包长度不足异常"""

    pass


class MappingError(NATPMPError):
    """与端口映射相关的错误"""

    pass


class NATPMPOpCode(IntEnum):
    """NAT-PMP 操作码基类"""

    pass


class NATPMPClientOpCode(NATPMPOpCode):
    GET_EXTERNAL_ADDRESS = 0  # 获取外部地址
    MAP_UDP = 1  # 映射UDP
    MAP_TCP = 2  # 映射TCP


class NATPMPServerOpCode(NATPMPOpCode):
    RESPONSE_EXTERNAL_ADDRESS = 128  # 响应外部地址
    RESPONSE_MAP_UDP = 129  # 响应映射UDP
    RESPONSE_MAP_TCP = 130  # 响应映射TCP


class NATPMPErrorCode(IntEnum):
    SUCCESS = 0  # 成功
    UNSUPPORTED_VERSION = 1  # 不支持的版本
    NOT_AUTHORIZED = 2  # 未授权
    NETWORK_FAILURE = 3  # 网络错误
    OUT_OF_RESOURCES = 4  # 资源不足
    UNSUPPORTED_OPCODE = 5  # 不支持的操作码


class NATPMP_Packet:
    """NAT-PMP 数据包基类"""

    def __init__(self, opcode: NATPMPOpCode, version: int = NAT_PMP_VERSION):
        self.version = version
        self.opcode = opcode

    def pack(self) -> bytes:
        """打包数据包"""
        return struct.pack("!BB", self.version, self.opcode)

    @classmethod
    def unpack(cls, data: bytes) -> "NATPMP_Packet":
        """解包数据包"""
        if len(data) < 2:  # 检查数据包长度
            raise InsufficientDataError("Not enough data to unpack NATPMP_Packet")

        version, opcode = struct.unpack("!BB", data[:2])
        if version != NAT_PMP_VERSION:
            raise UnsupportedVersionError("Unsupported version")

        if opcode == NATPMPClientOpCode.GET_EXTERNAL_ADDRESS:
            return RequestExternalAddressPacket()
        elif opcode in (NATPMPClientOpCode.MAP_UDP, NATPMPClientOpCode.MAP_TCP):
            return RequestMapPacket.unpack(data)
        elif opcode in NATPMPServerOpCode.__members__.values():
            return NATPMP_ServerPacket.unpack(data)
        else:
            raise UnsupportedOpcodeError("Unsupported opcode")


class RequestExternalAddressPacket(NATPMP_Packet):
    """获取外部地址请求数据包"""

    def __init__(self):
        super().__init__(NATPMPClientOpCode.GET_EXTERNAL_ADDRESS)


class RequestMapPacket(NATPMP_Packet):
    """端口映射请求数据包"""

    def __init__(
        self,
        opcode: NATPMPClientOpCode,
        internal_port: int,
        external_port: int,
        lifetime: int,
    ):
        super().__init__(opcode)
        self.internal_port = internal_port
        self.external_port = external_port
        self.lifetime = lifetime

    def pack(self) -> bytes:
        """打包端口映射请求数据包"""
        return super().pack() + struct.pack(
            "!HHHI", 0, self.internal_port, self.external_port, self.lifetime
        )

    @classmethod
    def unpack(cls, data: bytes) -> "RequestMapPacket":
        """解包端口映射请求数据包"""
        if len(data) < 12:  # 检查数据包长度
            raise InsufficientDataError("Not enough data to unpack RequestMapPacket")

        version, opcode, _, internal_port, external_port, lifetime = struct.unpack(
            "!BBHHHI", data
        )
        if opcode in (NATPMPClientOpCode.MAP_UDP, NATPMPClientOpCode.MAP_TCP):
            return cls(opcode, internal_port, external_port, lifetime)
        else:
            raise UnsupportedOpcodeError("Not a map request packet")


class NATPMP_ServerPacket(NATPMP_Packet):
    """NAT-PMP 服务器响应数据包"""

    def __init__(
        self,
        opcode: NATPMPServerOpCode,
        error: NATPMPErrorCode,
        version: int = NAT_PMP_VERSION,
        epoch_time: int = 0,
    ):
        if opcode not in NATPMPServerOpCode.__members__.values() and opcode != 0:
            raise UnsupportedOpcodeError("Unsupported server opcode")
        super().__init__(opcode, version)
        self.error = error
        self.epoch_time = (
            int(time.time() - start_time) if epoch_time == 0 else epoch_time
        )

    def pack(self) -> bytes:
        """打包服务器响应数据包"""
        return super().pack() + struct.pack("!HI", self.error, self.epoch_time)

    @classmethod
    def unpack(cls, data: bytes) -> "NATPMP_ServerPacket":
        """解包服务器响应数据包"""
        if len(data) < 8:  # 检查数据包长度
            raise InsufficientDataError("Not enough data to unpack NATPMP_ServerPacket")

        version, opcode, error, seconds_since_epoch = struct.unpack("!BBHI", data[:8])
        if opcode == NATPMPServerOpCode.RESPONSE_EXTERNAL_ADDRESS:
            return ResponseExternalAddressPacket.unpack(data)
        elif opcode in (
            NATPMPServerOpCode.RESPONSE_MAP_UDP,
            NATPMPServerOpCode.RESPONSE_MAP_TCP,
        ):
            return ResponseMapPacket.unpack(data)
        else:
            raise UnsupportedOpcodeError("Not a server response packet")


class ResponseExternalAddressPacket(NATPMP_ServerPacket):
    """获取外部地址响应数据包"""

    def __init__(
        self,
        error: NATPMPErrorCode,
        external_ip: str,
        version: int = NAT_PMP_VERSION,
        epoch_time: int = 0,
    ):
        super().__init__(
            NATPMPServerOpCode.RESPONSE_EXTERNAL_ADDRESS, error, version, epoch_time
        )
        self.external_ip = external_ip

    def pack(self) -> bytes:
        """打包外部地址响应数据包"""
        return super().pack() + struct.pack("!4s", socket.inet_aton(self.external_ip))

    @classmethod
    def unpack(cls, data: bytes) -> "ResponseExternalAddressPacket":
        """解包外部地址响应数据包"""
        if len(data) < 12:  # 检查数据包长度
            raise InsufficientDataError(
                "Not enough data to unpack ResponseExternalAddressPacket"
            )

        version, opcode, error, seconds_since_epoch, external_ip_bytes = struct.unpack(
            "!BBHI4s", data
        )
        external_ip = socket.inet_ntoa(external_ip_bytes)
        return cls(error, external_ip, version, seconds_since_epoch)


class ResponseMapPacket(NATPMP_ServerPacket):
    """端口映射响应数据包"""

    def __init__(
        self,
        opcode: NATPMPServerOpCode,
        error: NATPMPErrorCode,
        internal_port: int,
        external_port: int,
        lifetime: int,
        version: int = NAT_PMP_VERSION,
        epoch_time: int = 0,
    ):
        super().__init__(opcode, error, version, epoch_time)
        self.internal_port = internal_port
        self.external_port = external_port
        self.lifetime = lifetime

    def pack(self) -> bytes:
        """打包端口映射响应数据包"""
        return super().pack() + struct.pack(
            "!HHI", self.internal_port, self.external_port, self.lifetime
        )

    @classmethod
    def unpack(cls, data: bytes) -> "ResponseMapPacket":
        """解包端口映射响应数据包"""
        if len(data) < 12:  # 检查数据包长度
            raise InsufficientDataError("Not enough data to unpack ResponseMapPacket")

        (
            version,
            opcode,
            error,
            seconds_since_epoch,
            internal_port,
            external_port,
            lifetime,
        ) = struct.unpack("!BBHIHHI", data)
        return cls(
            opcode,
            error,
            internal_port,
            external_port,
            lifetime,
            version,
            seconds_since_epoch,
        )


import subprocess
import re

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

#!/usr/bin/env python3

'''
Natter - https://github.com/MikeWang000000/Natter
Copyright (C) 2023  MikeWang000000

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import os
import re
import sys
import time
import errno
import atexit
import codecs
import random
import socket
import struct
import threading

__version__ = "2.1.1"





class NatterExit(object):
    atexit.register(lambda : NatterExit._atexit[0]())
    _atexit = [lambda : None]

    @staticmethod
    def set_atexit(func):
        NatterExit._atexit[0] = func


class StunClient(object):
    class ServerUnavailable(Exception):
        pass

    def __init__(self, source_host="0.0.0.0", source_port=0,
                 interface=None, udp=False):
        stun_list = [
            "fwa.lifesizecloud.com",
            "global.turn.twilio.com",
            "turn.cloudflare.com",
            "stun.isp.net.au",
            "stun.nextcloud.com",
            "stun.freeswitch.org",
            "stun.voip.blackberry.com",
            "stunserver.stunprotocol.org",
            "stun.sipnet.com",
            "stun.radiojar.com",
            "stun.sonetel.com",
            "stun.telnyx.com"
        ]
        if not udp:
            stun_list = stun_list + [
                "turn.cloud-rtc.com:80"
            ]
        else:
            stun_list = [
                "stun.miwifi.com",
                "stun.chat.bilibili.com",
                "stun.hitv.com",
                "stun.cdnbye.com",
                "stun.douyucdn.cn:18000"
            ] + stun_list
        stun_srv_list = []
        for item in stun_list:
            l = item.split(":", 2) + ["3478"]
            stun_srv_list.append((l[0], int(l[1])),)

        self.stun_server_list = stun_srv_list
        self.source_host = source_host
        self.source_port = source_port
        self.interface = interface
        self.udp = udp

    def get_mapping(self):
        first = self.stun_server_list[0]
        while True:
            try:
                return self._get_mapping()
            except StunClient.ServerUnavailable as ex:
                Logger.warning("stun: STUN server %s is unavailable: %s" % (
                    addr_to_uri(self.stun_server_list[0], udp = self.udp), ex
                ))
                self.stun_server_list.append(self.stun_server_list.pop(0))
                if self.stun_server_list[0] == first:
                    Logger.error("stun: No STUN server is available right now")
                    # force sleep for 10 seconds, then try the next loop
                    time.sleep(10)

    def _get_mapping(self):
        # ref: https://www.rfc-editor.org/rfc/rfc5389
        socket_type = socket.SOCK_DGRAM if self.udp else socket.SOCK_STREAM
        stun_host, stun_port = self.stun_server_list[0]
        sock = socket.socket(socket.AF_INET, socket_type)
        socket_set_opt(
            sock,
            reuse       = True,
            bind_addr   = (self.source_host, self.source_port),
            interface   = self.interface,
            timeout     = 3
        )
        try:
            sock.connect((stun_host, stun_port))
            inner_addr = sock.getsockname()
            self.source_host, self.source_port = inner_addr
            sock.send(struct.pack(
                "!LLLLL", 0x00010000, 0x2112a442, 0x4e415452,
                random.getrandbits(32), random.getrandbits(32)
            ))
            buff = sock.recv(1500)
            ip = port = 0
            payload = buff[20:]
            while payload:
                attr_type, attr_len = struct.unpack("!HH", payload[:4])
                if attr_type in [1, 32]:
                    _, _, port, ip = struct.unpack("!BBHL", payload[4:4+attr_len])
                    if attr_type == 32:
                        port ^= 0x2112
                        ip ^= 0x2112a442
                    break
                payload = payload[4 + attr_len:]
            else:
                raise ValueError("Invalid STUN response")
            outer_addr = socket.inet_ntop(socket.AF_INET, struct.pack("!L", ip)), port
            Logger.debug("stun: Got address %s from %s, source %s" % (
                addr_to_uri(outer_addr, udp=self.udp),
                addr_to_uri((stun_host, stun_port), udp=self.udp),
                addr_to_uri(inner_addr, udp=self.udp)
            ))
            return inner_addr, outer_addr
        except (OSError, ValueError, struct.error, socket.error) as ex:
            raise StunClient.ServerUnavailable(ex)
        finally:
            sock.close()


class KeepAlive(object):
    def __init__(self, host, port, source_host, source_port, interface=None, udp=False):
        self.sock = None
        self.host = host
        self.port = port
        self.source_host = source_host
        self.source_port = source_port
        self.interface = interface
        self.udp = udp
        self.reconn = False

    def __del__(self):
        if self.sock:
            self.sock.close()

    def _connect(self):
        sock_type = socket.SOCK_DGRAM if self.udp else socket.SOCK_STREAM
        sock = socket.socket(socket.AF_INET, sock_type)
        socket_set_opt(
            sock,
            reuse       = True,
            bind_addr   = (self.source_host, self.source_port),
            interface   = self.interface,
            timeout     = 3
        )
        sock.connect((self.host, self.port))
        if not self.udp:
            Logger.debug("keep-alive: Connected to host %s" % (
                addr_to_uri((self.host, self.port), udp=self.udp)
            ))
            if self.reconn:
                Logger.info("keep-alive: connection restored")
        self.reconn = False
        self.sock = sock

    def keep_alive(self):
        if self.sock is None:
            self._connect()
        if self.udp:
            self._keep_alive_udp()
        else:
            self._keep_alive_tcp()
        Logger.debug("keep-alive: OK")

    def reset(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None
            self.reconn = True

    def _keep_alive_tcp(self):
        # send a HTTP request
        self.sock.sendall((
            "HEAD /natter-keep-alive HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: curl/8.0.0 (Natter)\r\n"
            "Accept: */*\r\n"
            "Connection: keep-alive\r\n"
            "\r\n" % self.host
        ).encode())
        buff = b""
        try:
            while True:
                buff = self.sock.recv(4096)
                if not buff:
                    raise OSError("Keep-alive server closed connection")
        except socket.timeout as ex:
            if not buff:
                raise ex
            return

    def _keep_alive_udp(self):
        # send a DNS request
        self.sock.send(
            struct.pack(
                "!HHHHHH", random.getrandbits(16), 0x0100, 0x0001, 0x0000, 0x0000, 0x0000
            ) + b"\x09keepalive\x06natter\x00" + struct.pack("!HH", 0x0001, 0x0001)
        )
        buff = b""
        try:
            while True:
                buff = self.sock.recv(1500)
                if not buff:
                    raise OSError("Keep-alive server closed connection")
        except socket.timeout as ex:
            if not buff:
                raise ex
            # fix: Keep-alive cause STUN socket timeout on Windows
            if sys.platform == "win32":
                self.reset()
            return


class NatterExitException(Exception):
    pass


class NatterRetryException(Exception):
    pass


def socket_set_opt(sock, reuse=False, bind_addr=None, interface=None, timeout=-1):
    if reuse:
        if hasattr(socket, "SO_REUSEADDR"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    if interface is not None:
        if hasattr(socket, "SO_BINDTODEVICE"):
            sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0"
            )
        else:
            raise RuntimeError("Binding to an interface is not supported on your platform.")
    if bind_addr is not None:
        sock.bind(bind_addr)
    if timeout != -1:
        sock.settimeout(timeout)
    return sock


def start_daemon_thread(target, args=()):
    th = threading.Thread(target=target, args=args)
    th.daemon = True
    th.start()
    return th


def closed_socket_ex(ex):
    if not hasattr(ex, "errno"):
        return False
    if hasattr(errno, "ECONNABORTED") and ex.errno == errno.ECONNABORTED:
        return True
    if hasattr(errno, "EBADFD") and ex.errno == errno.EBADFD:
        return True
    if hasattr(errno, "EBADF") and ex.errno == errno.EBADF:
        return True
    if hasattr(errno, "WSAEBADF") and ex.errno == errno.WSAEBADF:
        return True
    if hasattr(errno, "WSAEINTR") and ex.errno == errno.WSAEINTR:
        return True
    return False


def fix_codecs(codec_list = ["utf-8", "idna"]):
    missing_codecs = []
    for codec_name in codec_list:
        try:
            codecs.lookup(codec_name)
        except LookupError:
            missing_codecs.append(codec_name.lower())
    def search_codec(name):
        if name.lower() in missing_codecs:
            return codecs.CodecInfo(codecs.ascii_encode, codecs.ascii_decode, name="ascii")
    if missing_codecs:
        codecs.register(search_codec)


def split_url(url):
    m = re.match(
        r"^http://([^\[\]:/]+)(?:\:([0-9]+))?(/\S*)?$", url
    )
    if not m:
        raise ValueError("Unsupported URL: %s" % url)
    hostname, port_str, path = m.groups()
    port = 80
    if port_str:
        port = int(port_str)
    if not path:
        path = "/"
    return hostname, port, path


def full_url(u, refurl):
    if not u.startswith("/"):
        return u
    hostname, port, _ = split_url(refurl)
    return "http://%s:%d" % (hostname, port) + u


def addr_to_str(addr):
    return "%s:%d" % addr


def addr_to_uri(addr, udp=False):
    if udp:
        return "udp://%s:%d" % addr
    else:
        return "tcp://%s:%d" % addr


def validate_ip(s, err=True):
    try:
        socket.inet_aton(s)
        return True
    except (OSError, socket.error):
        if err:
            raise ValueError("Invalid IP address: %s" % s)
        return False


def validate_port(s, err=True):
    if str(s).isdigit() and int(s) in range(65536):
        return True
    if err:
        raise ValueError("Invalid port number: %s" % s)
    return False


def validate_addr_str(s, err=True):
    l = str(s).split(":", 1)
    if len(l) == 1:
        return True
    return validate_port(l[1], err)


def validate_positive(s, err=True):
    if str(s).isdigit() and int(s) > 0:
        return True
    if err:
        raise ValueError("Not a positive integer: %s" % s)
    return False


def validate_filepath(s, err=True):
    if os.path.isfile(s):
        return True
    if err:
        raise ValueError("File not found: %s" % s)
    return False


def ip_normalize(ipaddr):
    return socket.inet_ntoa(socket.inet_aton(ipaddr))


from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Tuple, Dict
from threading import Thread, Event, Lock
import socket
import http.client
import re
import os


global_thread_lock = Lock()


def is_valid_ip(ip):
    # 使用提供的正则表达式检查IP地址的有效性
    if not isinstance(ip, str):
        return False
    pattern = r"(?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:[1-9][0-9]\.)|(?:[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:[1-9][0-9])|(?:[0-9]))"
    return re.match(pattern, ip) is not None


def is_private_ip(ip):
    # 定义局域网 IP 的正则表达式
    private_ip_pattern = r"^(?:(?:10(?:(?:\.1[0-9][0-9])|(?:\.2[0-4][0-9])|(?:\.25[0-5])|(?:\.[1-9][0-9])|(?:\.[0-9])))|(?:172(?:\.(?:1[6-9])|(?:2[0-9])|(?:3[0-1])))|(?:192\.168))(?:(?:\.1[0-9][0-9])|(?:\.2[0-4][0-9])|(?:\.25[0-5])|(?:\.[1-9][0-9])|(?:\.[0-9])){2}$"

    # 使用 re.match 来判断 ip 是否匹配
    return re.match(private_ip_pattern, ip) is not None


def update_upnpd_config(file_path="/etc/config/upnpd"):
    # 检查文件是否存在
    if not os.path.exists(file_path):
        return

    # 读取文件内容
    with open(file_path, "r") as file:
        content = file.read()

    # 使用 replace 方法更新选项
    content = content.replace("option enabled '1'", "option enabled '0'")
    content = content.replace("option enable_upnp '1'", "option enable_upnp '0'")
    content = content.replace("option enable_natpmp '1'", "option enable_natpmp '0'")
    content = content.replace("option use_stun '1'", "option use_stun '0'")
    content = content.replace(
        "option force_forwarding '1'", "option force_forwarding '0'"
    )

    # 写回修改后的内容
    with open(file_path, "w") as file:
        file.write(content)
    
    os.system("/etc/init.d/miniupnpd restart")

    Logger.debug(f"文件已更新: {file_path}")


# 定义缓存变量
cache = {"ip": None, "timestamp": 0}


def get_ip():
    timeout = 0.5
    cache_duration = 600  # 缓存有效期为 x 秒

    # 检查缓存是否有效
    current_time = time.time()
    if is_valid_ip(cache["ip"]) and current_time - cache["timestamp"] < cache_duration:
        return (200, cache["ip"])

    # 创建 HTTP 连接，设置超时时间
    conn = http.client.HTTPConnection("api.ipify.cn", timeout=timeout)

    try:
        # 发送 GET 请求
        conn.request("GET", "/")

        # 获取响应
        response = conn.getresponse()

        # 读取并解码响应内容
        data = response.read().decode("utf-8")

        # 检查响应状态码
        if response.status == 200:
            if is_valid_ip(data):
                # 更新缓存
                cache["ip"] = data
                cache["timestamp"] = current_time
                return (response.status, data)  # 返回状态码和有效的 IP 地址
            else:
                return (400, "返回的内容不是有效的 IP 地址")  # 状态码设置为 400
        else:
            return (response.status, f"请求失败，状态码: {response.status}")

    except http.client.HTTPException as e:
        return (500, f"HTTP 请求失败: {e}")  # 处理HTTP异常
    except Exception as e:
        return (500, f"发生错误: {e}")  # 处理其他异常

    finally:
        # 关闭连接
        conn.close()


def new_socket_reuse(family, type):
    sock = socket.socket(family, type)
    if hasattr(socket, "SO_REUSEADDR"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    return sock


def get_free_port(proto_type: str = "TCP") -> int:
    # 创建一个新的套接字
    sock = new_socket_reuse(
        socket.AF_INET, socket.SOCK_STREAM if proto_type == "TCP" else socket.SOCK_DGRAM
    )
    sock.bind(("", 0))  # 绑定到任何地址的一个随机端口
    ret = sock.getsockname()[1]  # 获取绑定的端口
    sock.close()  # 关闭套接字
    return ret


def keepalive_loop(
    stun: StunClient,
    keep_alive: KeepAlive,
    udp_mode,
    outer_addr,
    stopEvent: Event,
    interval=15,
):
    need_recheck = False
    cnt = 0
    while True and not stopEvent.is_set():
        # force recheck every 20th loop
        cnt = (cnt + 1) % 20
        if cnt == 0:
            need_recheck = True
        if need_recheck:
            Logger.debug("Start recheck")
            need_recheck = False
            # then check through STUN
            _, outer_addr_curr = stun.get_mapping()
            if outer_addr_curr != outer_addr:
                Logger.warning(f"STUN映射改变：{outer_addr} -> {outer_addr_curr}")
                return
        # end of recheck
        ts = time.time()
        try:
            keep_alive.keep_alive()
        except (OSError, socket.error) as ex:
            if udp_mode:
                Logger.debug("keep-alive: UDP response not received: %s" % ex)
            else:
                Logger.error("keep-alive: connection broken: %s" % ex)
            keep_alive.reset()
            need_recheck = True
        sleep_sec = interval - (time.time() - ts)
        while sleep_sec > 0 and not stopEvent.is_set():
            time.sleep(1)
            sleep_sec -= 1


class KeepAliveThread:
    """用于在对象销毁时自动停止线程"""

    def __init__(
        self,
        stun: StunClient,
        keep_alive: KeepAlive,
        udp_mode,
        outer_addr,
        interval=15,
        auto_start=True,
    ):
        self.outer_addr = outer_addr
        self.stopEvent = Event()
        self.thread = Thread(
            target=keepalive_loop,
            args=(stun, keep_alive, udp_mode, outer_addr, self.stopEvent, interval),
        )
        if auto_start:
            self.start()

    def start(self):
        Logger.warning(f"{self.outer_addr} 的 keep-alive 线程已启动")
        self.thread.start()

    def stop(self):
        Logger.warning(f"{self.outer_addr} 的 keep-alive 线程正在停止...")
        self.stopEvent.set()
        self.thread.join()

    def is_alive(self):
        return self.thread.is_alive()

    def __del__(self):
        self.stop()


# 定义映射会话
@dataclass
class MappingSession:
    protocol: str  # 协议（"UDP" 或 "TCP"）
    internal_ip: str  # 内网 IP 地址
    internal_port: int  # 内网端口
    relay_port: int  # 中继端口
    remote_port: int  # 远程端口
    expire_time: datetime  # 过期时间

    stun_keepalive: KeepAliveThread  # STUN 保活线程
    relay_port_rule: Any  # 中继端口入站规则
    upnp_forward_rule: Any  # UPnP 转发规则
    upnp_prerouting_rule: Any  # UPnP 预路由规则


class MappingSessionPool:
    """映射会话池"""

    def __init__(self):
        self.sessions: Dict[Tuple[str, str, int], MappingSession] = {}

    def add_session(self, session: MappingSession):
        """添加映射会话"""
        self.sessions[
            (session.protocol, session.internal_ip, session.internal_port)
        ] = session

    def get_session(
        self, protocol: str, internal_ip: str, internal_port: int
    ) -> MappingSession:
        """获取映射会话"""
        return self.sessions.get((protocol, internal_ip, internal_port))

    def remove_session(self, protocol: str, internal_ip: str, internal_port: int):
        """删除映射会话"""
        del self.sessions[(protocol, internal_ip, internal_port)]

    def clear(self):
        """清空映射会话"""
        self.sessions.clear()

    def clean_expired_sessions(self):
        """清理过期的映射会话"""
        now = datetime.now()
        keys_to_delete = [
            key
            for key, session in self.sessions.items()
            if session.expire_time < now or not session.stun_keepalive.is_alive()
        ]

        for key in keys_to_delete:
            Logger.warning(f"清理过期的映射会话: {key}")
            del self.sessions[key]

    def __del__(self):
        self.clear()


class NATPMPServer:
    """NAT-PMP 服务器"""

    def __init__(self, host: str = "0.0.0.0", port: int = 5351):
        self.host = host
        self.port = port
        self.pool = MappingSessionPool()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 绑定到指定地址和端口
        self.sock.bind((self.host, self.port))
        self.run_flag = Event()
        self.current_public_ip = ""
        # 子线程
        self.clean_thread = Thread(target=self.clean_sessions)
        self.broadcast_thread = Thread(target=self.broadcast)

    def handle_request(self, data: bytes, addr: Tuple[str, int]) -> NATPMP_ServerPacket:
        """处理请求，返回响应"""
        # 尝试解包
        try:
            packet = NATPMP_Packet.unpack(data)
            if isinstance(packet, RequestExternalAddressPacket):
                status, external_ip = get_ip()
                if status == 200:
                    Logger.info(f"为 {addr} 返回外部 IP 地址: {external_ip}")
                    return ResponseExternalAddressPacket(
                        NATPMPErrorCode.SUCCESS, external_ip
                    )
                else:
                    Logger.error(f"获取外部 IP 地址失败: {external_ip}")
                    return NATPMP_ServerPacket(
                        NATPMPServerOpCode.RESPONSE_EXTERNAL_ADDRESS,
                        NATPMPErrorCode.NETWORK_FAILURE,
                    )
            elif isinstance(packet, RequestMapPacket):
                return self.handle_map_request(packet, addr)
            else:
                raise UnsupportedOpcodeError()
        except UnsupportedVersionError:
            Logger.warning(f"接收到来自 {addr} 的请求：不支持的 NAT-PMP 版本")
            return NATPMP_ServerPacket(0, NATPMPErrorCode.UNSUPPORTED_VERSION)
        except UnsupportedOpcodeError:
            Logger.warning(f"接收到来自 {addr} 的请求：不支持的操作码")
            return NATPMP_ServerPacket(0, NATPMPErrorCode.UNSUPPORTED_OPCODE)

    def handle_map_request(
        self, packet: RequestMapPacket, addr: Tuple[str, int]
    ) -> NATPMP_ServerPacket:
        """处理映射请求"""
        protocol = "UDP" if packet.opcode == NATPMPClientOpCode.MAP_UDP else "TCP"
        Logger.info(
            f"接收到来自 {addr} 的映射请求: {protocol} {packet.internal_port} -> {packet.external_port}, lifetime: {packet.lifetime}"
        )
        response_opcode = (
            NATPMPServerOpCode.RESPONSE_MAP_UDP
            if protocol == "UDP"
            else NATPMPServerOpCode.RESPONSE_MAP_TCP
        )
        udp_mode = protocol == "UDP"
        # 检查端口是否已经映射，如果是，直接更新过期时间
        session = self.pool.get_session(protocol, addr[0], packet.internal_port)
        if session:
            session.expire_time = datetime.now() + timedelta(seconds=packet.lifetime)
            return ResponseMapPacket(
                response_opcode,
                NATPMPErrorCode.SUCCESS,
                session.internal_port,
                session.remote_port,
                packet.lifetime,
            )
        # 获取中继端口
        relay_port = get_free_port(protocol)
        # 设置入站规则
        relay_port_rule = InputRule(protocol, relay_port, enable=True)
        # 设置 UPnP 转发规则
        upnp_forward_rule = UpnpForwardRule(protocol, packet.internal_port, enable=True)
        # 设置 UPnP 预路由规则
        upnp_prerouting_rule = UpnpPreroutingRule(
            protocol, addr[0], packet.internal_port, relay_port, enable=True
        )
        # 准备STUN
        bind_interface = "eth0"
        bind_ip = "0.0.0.0"
        bind_port = relay_port

        if udp_mode:
            keepalive_host = "119.29.29.29"
            keepalive_port = 53
        else:
            keepalive_host = "www.baidu.com"
            keepalive_port = 80
        # 开始STUN
        stun = StunClient(bind_ip, bind_port, udp=udp_mode, interface=bind_interface)
        Logger.info(f"开始STUN: {bind_ip}:{bind_port}")
        natter_addr, outer_addr = stun.get_mapping()
        Logger.info(f"STUN完成: {natter_addr} -> {outer_addr}")
        bind_ip, bind_port = natter_addr
        keep_alive = KeepAlive(
            keepalive_host,
            keepalive_port,
            bind_ip,
            bind_port,
            udp=udp_mode,
            interface=bind_interface,
        )
        # STUN完成，创建STUN保活子线程
        stun_keepalive = KeepAliveThread(stun, keep_alive, udp_mode, outer_addr)
        # 添加映射会话
        self.pool.add_session(
            MappingSession(
                protocol,
                addr[0],
                packet.internal_port,
                relay_port,
                outer_addr[1],
                datetime.now() + timedelta(seconds=packet.lifetime),
                stun_keepalive,
                relay_port_rule,
                upnp_forward_rule,
                upnp_prerouting_rule,
            )
        )
        Logger.warning(
            f"创建映射: {protocol} {addr[0]}:{packet.internal_port} -> [{relay_port}] -> {outer_addr[0]}:{outer_addr[1]}, 过期时间: {packet.lifetime}秒"
        )
        # 返回响应
        return ResponseMapPacket(
            response_opcode,
            NATPMPErrorCode.SUCCESS,
            packet.internal_port,
            outer_addr[1],
            packet.lifetime,
        )

    def broadcast(self):
        """定期广播"""
        while self.run_flag.is_set():
            status, new_public_ip = get_ip()
            if status == 200 and new_public_ip != self.current_public_ip:
                # 向224.0.0.1:5350广播新的公网IP地址
                self.sock.sendto(
                    ResponseExternalAddressPacket(
                        NATPMPErrorCode.SUCCESS, new_public_ip
                    ).pack(),
                    ("224.0.0.1", 5350),
                )
                self.current_public_ip = new_public_ip
                Logger.warning(f"广播新的公网IP地址: {new_public_ip}")
            sleep_time = 100
            while sleep_time > 0 and self.run_flag.is_set():
                time.sleep(2)
                sleep_time -= 2
        Logger.info("广播线程已停止")

    # 先创建一个定期清理过期映射会话的线程
    def clean_sessions(self):
        while self.run_flag.is_set():
            Logger.debug("开始定期清理过期映射会话，正在获取全局锁")
            global_thread_lock.acquire()
            Logger.debug("获取全局锁成功，开始清理过期映射会话")
            self.pool.clean_expired_sessions()
            global_thread_lock.release()
            Logger.debug("定期清理过期映射会话完成")
            time.sleep(2)
        Logger.info("定期清理线程已停止")

    def run(self):
        self.run_flag.set()
        self.clean_thread.start()
        self.broadcast_thread.start()
        Logger.info(f"NAT-PMP 服务器已启动，监听地址: {self.host}:{self.port}")

        while self.run_flag.is_set():
            # 接收请求
            data, addr = self.sock.recvfrom(1024)

            Logger.debug(f"接收到来自 {addr} 的请求")

            # 检查ip地址是否为私有地址，公网地址将被忽略
            if not is_private_ip(addr[0]):
                Logger.warning(f"来自 {addr} 的请求不是私有地址，已被忽略")
                continue

            # 处理请求
            Logger.debug(f"准备处理来自 {addr} 的请求，正在获取全局锁")
            global_thread_lock.acquire()
            Logger.debug(f"获取全局锁成功，开始处理请求")
            response = self.handle_request(data, addr)
            Logger.debug(f"请求处理完成，释放全局锁")
            global_thread_lock.release()

            # 发送响应
            self.sock.sendto(response.pack(), addr)
        Logger.info("NAT-PMP 服务器已停止")

    def stop(self):
        if self.run_flag.is_set():
            self.run_flag.clear()
            # 给本机发送一个请求外部ip的请求，以便唤醒阻塞在recvfrom的线程
            soc = new_socket_reuse(socket.AF_INET, socket.SOCK_DGRAM)
            soc.sendto(RequestExternalAddressPacket().pack(), ("127.0.0.1", self.port))
            soc.close()
            Logger.warning("正在停止 NAT-PMP 服务器...")
            self.clean_thread.join()
            self.broadcast_thread.join()
            self.sock.close()
            Logger.warning("清理与广播线程已结束")
            self.pool.clear()
            Logger.warning(
                "会话池已清空，接下来进入会话的析构函数，将析构stun保活线程并删除规则"
            )

    def __del__(self):
        self.stop()


from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import urllib.parse


# Initialize the NAT-PMP server
server = NATPMPServer()


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.handle_index()
        elif self.path == "/mappings":
            self.handle_list_mappings()
        else:
            self.send_error(404, "File Not Found")

    def do_POST(self):
        if self.path == "/mappings":
            self.handle_add_mapping()
        else:
            self.send_error(404, "File Not Found")

    def do_DELETE(self):
        if "/mappings/" in self.path:
            self.handle_delete_mapping()
        else:
            self.send_error(404, "File Not Found")

    def handle_index(self):
        """Handle the root path to provide API overview, current mappings, and forms for add/delete."""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        # Overview and mapping table
        api_overview = """
<html>
<body>
<h1>NAT-PMP Web Interface</h1>
<h2>API Endpoints</h2>
<ul>
    <li><strong>GET /mappings</strong>: List all mapping sessions</li>
    <li><strong>POST /mappings</strong>: Add a new mapping session (JSON body required)</li>
    <li><strong>DELETE /mappings/&lt;protocol&gt;/&lt;internal_ip&gt;/&lt;internal_port&gt;</strong>: Delete a mapping session</li>
</ul>
<h2>Current Mappings</h2>
<pre>{mapping_table}</pre>

<h2>Add Mapping</h2>
<form method="post" action="/mappings" onsubmit="return addMapping(event)">
    Protocol: <input type="text" name="protocol" value="TCP"><br>
    Internal IP: <input type="text" name="internal_ip"><br>
    Internal Port: <input type="number" name="internal_port"><br>
    Lifetime (seconds): <input type="number" name="lifetime" value="3600"><br>
    <input type="submit" value="Add Mapping">
</form>

<h2>Delete Mapping</h2>
<form method="post" onsubmit="return deleteMapping(event)">
    Protocol: <input type="text" name="protocol" value="TCP"><br>
    Internal IP: <input type="text" name="internal_ip"><br>
    Internal Port: <input type="number" name="internal_port"><br>
    <input type="submit" value="Delete Mapping">
</form>

<script>
    function addMapping(event) {{
        event.preventDefault();
        const form = event.target;
        const data = {{
            protocol: form.protocol.value,
            internal_ip: form.internal_ip.value,
            internal_port: form.internal_port.value,
            lifetime: form.lifetime.value
        }};
        fetch('/mappings', {{
            method: 'POST',
            headers: {{
                'Content-Type': 'application/json'
            }},
            body: JSON.stringify(data)
        }}).then(response => response.json())
        .then(data => {{
            alert('Mapping Added: ' + JSON.stringify(data));
            window.location.reload();
        }}).catch((error) => {{
            alert('Error: ' + error);
        }});
    }}

    function deleteMapping(event) {{
        event.preventDefault();
        const form = event.target;
        const protocol = form.protocol.value;
        const internal_ip = form.internal_ip.value;
        const internal_port = form.internal_port.value;

        fetch(`/mappings/${{protocol}}/${{internal_ip}}/${{internal_port}}`, {{
            method: 'DELETE'
        }}).then(response => response.json())
        .then(data => {{
            alert('Mapping Deleted: ' + JSON.stringify(data));
            window.location.reload();
        }}).catch((error) => {{
            alert('Error: ' + error);
        }});
    }}
</script>

</body>
</html>
        """
        public_ip = get_ip()[1]
        mapping_table = ""
        for key, session in server.pool.sessions.items():
            mapping_table += (
                f"{session.protocol} {session.internal_ip}:{session.internal_port} -> "
                f"[{session.relay_port}] -> {public_ip}:{session.remote_port}, "
                f"Expire_at: {session.expire_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            )

        self.wfile.write(
            api_overview.format(mapping_table=mapping_table).encode("utf-8")
        )

    def handle_list_mappings(self):
        """List all mapping sessions."""
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()

        public_ip = get_ip()[1]
        sessions = []
        for key, session in server.pool.sessions.items():
            sessions.append(
                {
                    "protocol": session.protocol,
                    "internal_ip": session.internal_ip,
                    "internal_port": session.internal_port,
                    "relay_port": session.relay_port,
                    "public_ip": public_ip,
                    "remote_port": session.remote_port,
                    "expire_time": session.expire_time.isoformat(),
                }
            )
        self.wfile.write(json.dumps(sessions).encode("utf-8"))

    def handle_add_mapping(self):
        """Add a new mapping session."""
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode("utf-8"))

        protocol = data.get("protocol")
        internal_ip = data.get("internal_ip")
        internal_port = data.get("internal_port")
        lifetime = data.get("lifetime", 3600)  # Default to 1 hour if not provided

        if protocol not in ["TCP", "UDP"]:
            self.send_error(400, "Unsupported protocol")
            return

        if not internal_ip or not internal_port:
            self.send_error(400, "Missing internal_ip or internal_port")
            return

        protocol = (
            NATPMPClientOpCode.MAP_UDP
            if protocol == "UDP"
            else NATPMPClientOpCode.MAP_TCP
        )
        public_ip = get_ip()[1]
        internal_port = int(internal_port)
        lifetime = int(lifetime)
        packet = RequestMapPacket(protocol, internal_port, 0, lifetime)
        addr = (internal_ip, 0)  # Mock address since this is manual
        response_packet: ResponseMapPacket = server.handle_map_request(packet, addr)

        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(
            json.dumps(
                {
                    "status": "success",
                    "internal_ip": internal_ip,
                    "internal_port": internal_port,
                    "public_ip": public_ip,
                    "external_port": response_packet.external_port,
                    "lifetime": lifetime,
                }
            ).encode("utf-8")
        )

    def handle_delete_mapping(self):
        """Delete a mapping session."""
        parsed_path = urllib.parse.urlparse(self.path)
        path_parts = parsed_path.path.split("/")

        if len(path_parts) != 5:
            self.send_error(400, "Invalid path format")
            return

        _, _, protocol, internal_ip, internal_port = path_parts

        try:
            internal_port = int(internal_port)
            server.pool.remove_session(protocol, internal_ip, internal_port)
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success"}).encode("utf-8"))
        except KeyError:
            self.send_error(404, "Mapping not found")
        except ValueError:
            self.send_error(400, "Invalid internal port")


import signal


def run_server():
    httpd = HTTPServer(("0.0.0.0", 9699), SimpleHTTPRequestHandler)
    print("Starting web server on http://0.0.0.0:9699")
    httpd.serve_forever()


def signal_handler(sig, frame):
    Logger.warning("接收到信号 %s，正在停止服务器..." % sig)
    # 在这里添加清理代码
    server.stop()
    exit(0)


if __name__ == "__main__":
    update_upnpd_config()
    # 捕获 SIGINT 和 SIGTERM 信号
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    try:
        # Start the NAT-PMP server in a separate thread
        natpmp_thread = Thread(target=server.run)
        natpmp_thread.start()

        # Start the web server in a separate thread
        web_server_thread = Thread(target=run_server)
        web_server_thread.start()

        # Wait for both threads to complete
        web_server_thread.join()
    except KeyboardInterrupt:
        Logger.warning("主程序接收到中断信号，正在退出....")
        pass
    finally:
        server.stop()
        Logger.info("NAT-PMP 服务器与 Web 服务器已停止")
