import socket
from natpmp_sdk import *

# 客户端配置
SERVER_IP = '127.0.0.1'  # 服务端的 IP（本地测试）
SERVER_PORT = 5351       # NAT-PMP 默认端口

def send_request(packet: NATPMP_Packet) -> bytes:
    """发送请求并接收响应"""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        client_socket.sendto(packet.pack(), (SERVER_IP, SERVER_PORT))  # 发送请求
        response_data, _ = client_socket.recvfrom(1024)  # 等待响应
        return response_data

def main():
    """主函数，发送 NAT-PMP 请求"""
    try:
        # 创建获取外部地址请求
        request_packet = RequestExternalAddressPacket()
        print("发送 RequestExternalAddressPacket 请求...")
        response_data = send_request(request_packet)
        
        # 解包响应
        response_packet = NATPMP_Packet.unpack(response_data)
        if isinstance(response_packet, ResponseExternalAddressPacket):
            print(f"外部 IP 地址: {response_packet.external_ip}")
        else:
            print("收到意外的响应")

        # 创建端口映射请求
        internal_port = 12345
        external_port = 54321
        lifetime = 3600
        map_request_packet = RequestMapPacket(NATPMPClientOpCode.MAP_UDP, internal_port, external_port, lifetime)
        print("发送 RequestMapPacket 请求...")
        response_data = send_request(map_request_packet)
        
        # 解包端口映射响应
        response_packet = NATPMP_Packet.unpack(response_data)
        if isinstance(response_packet, ResponseMapPacket):
            print(f"成功将内部端口 {response_packet.internal_port} 映射到外部端口 {response_packet.external_port}，生命周期 {response_packet.lifetime} 秒")
        else:
            print("收到意外的映射响应")

    except NATPMPError as e:
        print(f"NAT-PMP 错误: {e}")

if __name__ == "__main__":
    main()
