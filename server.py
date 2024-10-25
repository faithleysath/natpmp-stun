from natpmp_sdk import *
from firewall_rule import *
from natter_slim import StunClient, KeepAlive
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Tuple, Dict
from threading import Thread, Event
import socket
import sys
import http.client
import re
import os


class Logger(object):
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3
    rep = {DEBUG: "D", INFO: "I", WARN: "W", ERROR: "E"}
    level = DEBUG
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


def is_valid_ip(ip):
    # 使用提供的正则表达式检查IP地址的有效性
    pattern = r"(?:(?:1[0-9][0-9]\.)|(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:[1-9][0-9]\.)|(?:[0-9]\.)){3}(?:(?:1[0-9][0-9])|(?:2[0-4][0-9])|(?:25[0-5])|(?:[1-9][0-9])|(?:[0-9]))"
    return re.match(pattern, ip) is not None


def is_private_ip(ip):
    # 定义局域网 IP 的正则表达式
    private_ip_pattern = r"^(?:(?:10(?:(?:\.1[0-9][0-9])|(?:\.2[0-4][0-9])|(?:\.25[0-5])|(?:\.[1-9][0-9])|(?:\.[0-9])))|(?:172(?:\.(?:1[6-9])|(?:2[0-9])|(?:3[0-1])))|(?:192\.168))(?:(?:\.1[0-9][0-9])|(?:\.2[0-4][0-9])|(?:\.25[0-5])|(?:\.[1-9][0-9])|(?:\.[0-9])){2}$"

    # 使用 re.match 来判断 ip 是否匹配
    return re.match(private_ip_pattern, ip) is not None


def get_ip(timeout=0.5):
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
        if sleep_sec > 0:
            time.sleep(sleep_sec)


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
        self.lease_fie = "/var/run/miniupnpd.leases"  # miniupnpd 租约文件，每一行是“<协议>:<外部端口>:<内部地址>:<内部端口>:<过期时间>:<描述>”

    def add_session(self, session: MappingSession):
        """添加映射会话"""
        self.sessions[
            (session.protocol, session.internal_ip, session.internal_port)
        ] = session
        # 更新租约文件
        self.update_lease_file()

    def get_session(
        self, protocol: str, internal_ip: str, internal_port: int
    ) -> MappingSession:
        """获取映射会话"""
        return self.sessions.get((protocol, internal_ip, internal_port))

    def remove_session(self, protocol: str, internal_ip: str, internal_port: int):
        """删除映射会话"""
        del self.sessions[(protocol, internal_ip, internal_port)]
        self.update_lease_file()

    def clear(self):
        """清空映射会话"""
        self.sessions.clear()

    def update_lease_file(self):
        """更新租约文件"""
        with open(self.lease_fie, "w") as f:
            for key, session in self.sessions.items():
                f.write(
                    f"{session.protocol}:{session.remote_port}:{session.internal_ip}:{session.internal_port}:{int(session.expire_time.timestamp())}:STUN中继端口：{session.relay_port}\n"
                )
        # 执行/etc/init.d/miniupnpd restart
        os.system("/etc/init.d/miniupnpd restart")

    def get_keys_from_lease_file(self):
        """从租约文件中获取键"""
        keys = []
        with open(self.lease_fie, "r") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 6:
                    keys.append(
                        (parts[0], parts[2], int(parts[3]))
                    )  # (protocol, internal_ip, internal_port)
        return keys

    def clean_expired_sessions(self):
        """清理过期的映射会话，同时更新租约文件"""
        # 从租约文件中获取键
        lease_keys = self.get_keys_from_lease_file()
        now = datetime.now()
        keys_to_delete = [
            key
            for key, session in self.sessions.items()
            if session.expire_time < now or not session.stun_keepalive.is_alive() or key not in lease_keys
        ]

        for key in keys_to_delete:
            Logger.warning(f"清理过期的映射会话: {key}")
            del self.sessions[key]

        # 更新租约文件
        self.update_lease_file()

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
            Logger.warning(f"接收到来自 {addr} 的不支持的 NAT-PMP 版本请求")
            return NATPMP_ServerPacket(0, NATPMPErrorCode.UNSUPPORTED_VERSION)
        except UnsupportedOpcodeError:
            Logger.warning(f"接收到来自 {addr} 的不支持的 NAT-PMP 操作请求")
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
            time.sleep(10)
        Logger.info("广播线程已停止")

    # 先创建一个定期清理过期映射会话的线程
    def clean_sessions(self):
        while self.run_flag.is_set():
            self.pool.clean_expired_sessions()
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
            response = self.handle_request(data, addr)

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

        packet = RequestMapPacket(protocol, internal_port, 0, lifetime)
        addr = (internal_ip, 0)  # Mock address since this is manual
        response_packet = server.handle_map_request(packet, addr)

        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response_packet.to_dict()).encode("utf-8"))

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


def run_server():
    httpd = HTTPServer(("0.0.0.0", 8080), SimpleHTTPRequestHandler)
    print("Starting web server on http://0.0.0.0:8080")
    httpd.serve_forever()


import signal
import time


def signal_handler(sig, frame):
    Logger.warning("接收到信号 %s，正在停止服务器..." % sig)
    # 在这里添加清理代码
    server.stop()


if __name__ == "__main__":
    # 捕获 SIGINT 和 SIGTERM 信号
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    try:
        # Start the NAT-PMP server in a separate thread
        natpmp_thread = Thread(target=server.run)
        natpmp_thread.start()

        # Start the web server
        run_server()
    except KeyboardInterrupt:
        Logger.warning("主程序接收到中断信号，正在退出....")
        pass
    finally:
        server.stop()
        Logger.info("NAT-PMP 服务器与 Web 服务器已停止")
