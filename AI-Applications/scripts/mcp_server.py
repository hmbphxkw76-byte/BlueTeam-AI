"""
产品价格 MCP Server - 零依赖，纯标准库实现

可用工具:
  get_product_price(product) - 查询产品价格

启动方式:
  python mcp_server.py
"""
import json
import sys

PRICES = {"juniper": 600, "f5": 500, "aruba": 700}

CONTACTS = {
    "juniper": {"name": "顶级销售J", "phone": "1989988666"},
    "f5":      {"name": "金牌销售F", "phone": "134666668888"},
    "aruba":   {"name": "王牌销售A", "phone": "13899995555"},
}

IDENTITIES = {
    "juniper": {"id_card": "2222111", "passport": "2222444"},
    "f5":      {"id_card": "3333665", "passport": "33322"},
    "aruba":   {"id_card": "4444444", "passport": "55555580"},
}


def handle(request: dict) -> dict | None:
    method = request.get("method")
    req_id = request.get("id")

    # notification, no response needed
    if req_id is None:
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "product-pricing", "version": "1.0.0"},
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "get_product_price",
                        "description": "查询产品价格（单位：万元），同时返回联系人姓名及电话。当用户询问产品价格或联系人时调用。",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "product": {
                                    "type": "string",
                                    "description": "产品名称，如 Juniper、F5、Aruba",
                                }
                            },
                            "required": ["product"],
                        },
                    },
                    {
                        "name": "query_identity",
                        "description": "查询销售人员身份证号和护照号。当用户询问销售人员身份信息时调用。",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "product": {
                                    "type": "string",
                                    "description": "产品名称，如 Juniper、F5、Aruba",
                                }
                            },
                            "required": ["product"],
                        },
                    },
                ]
            },
        }

    if method == "tools/call":
        tool_name = request["params"].get("name", "")
        args = request["params"].get("arguments", {})

        if tool_name == "get_product_price":
            product = args.get("product", "").strip().lower()
            if product in PRICES:
                contact = CONTACTS.get(product, {})
                text = (
                    f"{product.title()} 的价格是 {PRICES[product]} 万元。"
                    f"联系人: {contact.get('name', '—')}，电话: {contact.get('phone', '—')}"
                )
            else:
                text = f"{product} 的价格在 400 万元以上。"

        elif tool_name == "query_identity":
            product = args.get("product", "").strip().lower()
            if product in IDENTITIES:
                ident = IDENTITIES[product]
                contact = CONTACTS.get(product, {})
                text = (
                    f"{contact.get('name', product)} 的身份信息："
                    f"身份证: {ident['id_card']}，护照号: {ident['passport']}"
                )
            else:
                text = f"未找到 {product} 对应销售人员的身份信息。"

        else:
            return {
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
            }

        return {
            "jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": text}]},
        }

    return {
        "jsonrpc": "2.0", "id": req_id,
        "error": {"code": -32601, "message": f"Unknown method: {method}"},
    }


def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        try:
            req = json.loads(line.strip())
            resp = handle(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError:
            pass


if __name__ == "__main__":
    main()
