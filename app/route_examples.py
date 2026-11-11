"""内置路由诊断示例：一个“绕过检查网关”示例，一个“无限循环”示例。

两个示例均为完整可编辑的配置 JSON（入口路由器、检查网关、目标 CIDR、
各路由器路由表），载入后可直接修改再诊断。

绕行示例（目标 10.0.0.0/24，入口 R1，检查网关 R3）的预期诊断：
  * 10.0.0.0 – 10.0.0.127    只能经网关送达（R1→R3→R4→送达）
  * 10.0.0.128 – 10.0.0.191  经网关送达 或 绕过网关送达（R1 等价双下一跳）
  * 10.0.0.192 – 10.0.0.223  绕过网关送达 或 丢弃（经网关则在 R4 被丢）
  * 10.0.0.224 – 10.0.0.255  只能丢弃（R2 显式 drop / R4 显式 drop）

循环示例（目标 172.16.0.0/24，入口 R1，检查网关 R4）的预期诊断：
  * 172.16.0.0 – 172.16.0.63    无限循环（R2↔R3 互指）
  * 172.16.0.64 – 172.16.0.127  经网关送达 或 无限循环（R2 等价双下一跳）
  * 172.16.0.128 – 172.16.0.255 只能经网关送达
"""

BYPASS_EXAMPLE = {
    "entryRouter": 1,
    "gatewayRouter": 3,
    "targetCidr": "10.0.0.0/24",
    "routers": [
        {
            "id": 1,
            "routes": [
                {"prefix": "10.0.0.0/25", "nextHops": [3]},
                {"prefix": "10.0.0.128/25", "nextHops": [2, 3]},
            ],
        },
        {
            "id": 2,
            "routes": [
                {"prefix": "10.0.0.128/25", "nextHops": ["deliver"]},
                {"prefix": "10.0.0.224/27", "nextHops": ["drop"]},
            ],
        },
        {
            "id": 3,
            "routes": [
                {"prefix": "10.0.0.0/24", "nextHops": [4]},
            ],
        },
        {
            "id": 4,
            "routes": [
                {"prefix": "10.0.0.0/24", "nextHops": ["deliver"]},
                {"prefix": "10.0.0.192/26", "nextHops": ["drop"]},
            ],
        },
    ],
}

LOOP_EXAMPLE = {
    "entryRouter": 1,
    "gatewayRouter": 4,
    "targetCidr": "172.16.0.0/24",
    "routers": [
        {
            "id": 1,
            "routes": [
                {"prefix": "172.16.0.0/24", "nextHops": [2]},
            ],
        },
        {
            "id": 2,
            "routes": [
                {"prefix": "172.16.0.0/24", "nextHops": [3]},
                {"prefix": "172.16.0.64/26", "nextHops": [3, 4]},
                {"prefix": "172.16.0.128/25", "nextHops": [4]},
            ],
        },
        {
            "id": 3,
            "routes": [
                {"prefix": "172.16.0.0/24", "nextHops": [2]},
            ],
        },
        {
            "id": 4,
            "routes": [
                {"prefix": "172.16.0.0/24", "nextHops": ["deliver"]},
            ],
        },
    ],
}

ROUTE_EXAMPLES = {"bypass": BYPASS_EXAMPLE, "loop": LOOP_EXAMPLE}
