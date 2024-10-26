import socket

def udp_client(message, host='127.0.0.1', port=12345):
    # 创建UDP套接字
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # 发送数据
        client_socket.sendto(message.encode(), (host, port))
        print(f"发送到 {host}:{port} 的消息: {message}")
        
        # 接收服务端的回应
        response, _ = client_socket.recvfrom(1024)
        print(f"来自服务器的回应: {response.decode()}")
        
    finally:
        client_socket.close()

if __name__ == "__main__":
    msg = input("请输入要发送的消息: ")
    udp_client(msg)
