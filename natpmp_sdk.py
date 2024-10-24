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
