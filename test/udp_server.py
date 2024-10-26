import socket

def udp_server(host='0.0.0.0', port=12345):
    # 创建UDP套接字
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    print(f"UDP服务器正在运行，监听地址 {host}:{port}")

    while True:
        # 接收数据
        data, addr = server_socket.recvfrom(1024)  # 缓冲区大小为1024字节
        print(f"接收到来自 {addr} 的消息: {data.decode()}")
        
        # 回应客户端
        response = f"服务器已收到: {data.decode()}"
        server_socket.sendto(response.encode(), addr)

if __name__ == "__main__":
    udp_server()
