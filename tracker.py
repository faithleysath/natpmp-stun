from fastapi import FastAPI, Request, Query
from fastapi.responses import PlainTextResponse
import uvicorn
import os
from rich.console import Console
from rich.table import Table
import logging

app = FastAPI()

# Disable INFO level logging for uvicorn
logging.getLogger("uvicorn").setLevel(logging.WARNING)

@app.get("/", response_class=PlainTextResponse)
async def read_root(
    request: Request,
    info_hash: str = Query(None),
    peer_id: str = Query(None),
    port: int = Query(None),
    uploaded: int = Query(None),
    downloaded: int = Query(None),
    left: int = Query(None),
    corrupt: int = Query(None),
    key: str = Query(None),
    event: str = Query(None),
    numwant: int = Query(None),
    compact: int = Query(None),
    no_peer_id: int = Query(None),
    supportcrypto: int = Query(None),
    redundant: int = Query(None)
):
    # 获取客户端的 IP
    client_ip = request.client.host

    # 打印客户端上报的 IP 和端口
    print(f"Client IP: {client_ip}, Reported Port: {port}")

    # 使用 rich 显示表格
    console = Console()
    table = Table(title="Client Request Info")

    table.add_column("Field", justify="right", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")

    table.add_row("info_hash", info_hash)
    table.add_row("peer_id", peer_id)
    table.add_row("port", str(port))
    table.add_row("uploaded", str(uploaded))
    table.add_row("downloaded", str(downloaded))
    table.add_row("left", str(left))
    table.add_row("corrupt", str(corrupt))
    table.add_row("key", key)
    table.add_row("event", event)
    table.add_row("numwant", str(numwant))
    table.add_row("compact", str(compact))
    table.add_row("no_peer_id", str(no_peer_id))
    table.add_row("supportcrypto", str(supportcrypto))
    table.add_row("redundant", str(redundant))

    console.print(table)

    # Mock 返回数据
    response_data = "d:intervali1800e:peers0:e"  # 示例响应
    return PlainTextResponse(content=response_data)

if __name__ == "__main__":
    # 从环境变量中读取 host 和 port，默认值为 "0.0.0.0" 和 6969
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 6969))
    uvicorn.run(app, host=host, port=port)