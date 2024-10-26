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


from logger import Logger


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

