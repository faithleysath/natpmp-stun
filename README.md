# natpmp-stun 项目

## 引用声明
本项目采用了[Natter](https://github.com/MikeWang000000/Natter)的代码，感谢原作者的贡献。

## 简介

`natpmp-stun` 是一个基于 NAT-PMP 协议的端口映射和 STUN (Session Traversal Utilities for NAT) 功能的实现项目。它提供了一种在 NAT 网络中自动配置端口转发的方式，并且支持通过 STUN 协议检测和公布外部 IP 地址。

该项目的实现还包括一个简单的 Web 界面，用于管理和查看当前的端口映射状态。

## 主要功能

1. **NAT-PMP 服务器实现**：
   - 处理 NAT-PMP 客户端（如qbbittorrent、transmission）的请求。
   - 支持获取外部 IP 地址和端口映射功能。
   - 自动处理请求中的不支持版本和操作码。

2. **STUN 支持**：
   - 使用 STUN 协议获取外部 IP 地址和端口。
   - 支持通过 STUN 协议定期检查外部 IP 变化，并广播更新。

3. **端口映射管理**：
   - 通过 NAT-PMP 协议实现对 UDP 和 TCP 端口的映射。
   - 支持通过 UPnP 规则配置防火墙规则。
   - 提供会话池管理，支持过期会话自动清理。

4. **HTTP Web 界面**：
   - 提供查看当前映射会话的列表。
   - 支持通过 Web 界面添加和删除端口映射。
   - 提供简单的 API 供外部系统集成。

5. **日志记录**：
   - 根据日志级别输出详细的调试、信息、警告和错误日志。
   - 支持不同颜色显示不同级别的日志（仅在支持 256 色终端下）。

## 安装与运行

### 环境要求

- Python 3.6 及以上
- `nftables` 需要在系统中可用（用于防火墙规则配置）

### 安装步骤

1. 克隆项目代码：
   ```bash
   git clone https://github.com/你的用户名/natpmp-stun.git
   cd natpmp-stun
   ```

2. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```

3. 运行项目：
   ```bash
   python main.py
   ```

项目启动后，NAT-PMP 服务器将会在默认的 5351 端口上监听，Web 界面默认在 `http://0.0.0.0:9699` 启动。

## 使用说明

- **Web 界面**：
  - 打开浏览器访问 `http://<你的服务器IP>:9699` 查看和管理映射。
  - 在“添加映射”和“删除映射”表单中，输入相应信息进行操作。

- **API 使用**：
  - `GET /mappings`：获取当前所有映射会话。
  - `POST /mappings`：创建新的映射会话（需要提供 JSON 格式的协议、内网 IP 和端口等信息）。
  - `DELETE /mappings/{protocol}/{internal_ip}/{internal_port}`：删除指定的映射会话。

## 注意事项

- 确保运行该程序的服务器网络配置允许 NAT-PMP 和 STUN 相关的流量。
- 使用 Web 界面或 API 前，请确保防火墙规则允许相应的 HTTP 访问。

## 作者测试环境

测试环境：openwrt
分支: 23.05.5
内核: 6.6.56
安装依赖：python3-base python3-pip python3 luci-app-upnp

eth0为wan口，eth1为br-lan

如有任何报错，请创建issues

## Q&A
- **Q：是否支持UPnP？**
  - A：不支持，未来也不打算支持。

- **Q：为什么不支持UPnP？**
  - A：因为STUN获取到的外部端口是随机的，UPnP必须遵循客户端请求的端口，相反，NAT-PMP和PCP可以拒绝客户端建议的端口。

- **Q：为什么不支持PCP？**
  - A：精力有限，且目前大部分应用都兼容NAT-PMP，未来可能会支持。

- **Q：为什么不支持IPv6？**
  - A：因为我不会，未来可能会支持。且ipv6大多都是公网ip，不需要端口映射。

- **Q：relay port的范围？**
  - A：目前是向系统申请一个可用的端口，是随机的。如需要固定在一个范围内，请自行修改`get_free_port`函数。未来可能会支持设定。

- **Q：为什么不支持自定义relay port？**
  - A：因为我懒，未来可能会支持。

- **Q：你还会继续更新吗？**
  - A：看情况，如果没人用就不更了。所以你的每一个Star都是对我的鼓励。

- **Q：如果你打算继续更新，你会加入什么功能？**
  - A：首先是写一键脚本，一行命令就能安装，并且完善此教程文档，然后是支持iptables防火墙，最后是支持PCP。

- **Q：如果你不打算继续更新，我可以fork吗？**
  - A：可以，但请保留原作者信息。

- **Q：我有其他问题，可以联系你吗？**
  - A：可以，但请先看看issues有没有类似的问题。如果没有，请创建一个新的issues。

## 许可证

该项目基于 GPLv3 许可证发布，详细信息请参考项目中的 LICENSE 文件。

## 使用截图

![运行日志](/doc/img/log.png)
![web界面](/doc/img/web-interface.png)
