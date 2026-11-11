"""
隔离网路由诊断引擎。

转发语义（与需求一一对应）：
  * 网络由若干台路由器组成（≤ 8 台），每台一张路由表（≤ 20 条，表内前缀唯一）；
  * 每条路由 = 目的 IPv4 CIDR（prefix）+ 非空下一跳列表（nextHops）；
    下一跳 ∈ {路由器编号, "deliver"（送达）, "drop"（丢弃）}；
  * 每跳按最长前缀匹配（LPM）选择路由条目；无任何条目匹配即丢弃；
  * 命中条目的下一跳列表中，每次转发可任选其一（等价多路径，结果取所有可能）；
  * 报文从指定的入口路由器进入；检查网关为其中一台路由器。

对目标 CIDR 中的每个目的 IP，其全部可能行为归结为四种可能结果的集合：
  * delivered-via-gateway  存在一条经过检查网关并最终送达的转发路径
  * delivered-bypass       存在一条不经过检查网关并最终送达的转发路径
  * dropped                存在一条以丢弃告终的路径（显式 drop 或无匹配路由）
  * loop                   存在一条无限循环的路径（从入口可达的环）

精确性保证（不逐 IP 枚举、不抽样）：
  把所有路由前缀的边界（与目标 CIDR 求交后）作为切点，将目标网段切分为
  若干基本区间。在任一基本区间内部，每台路由器 LPM 命中的条目恒定，因此
  逐跳转发图恒定、四种可能结果的集合恒定。随后把相邻且结果集合相同的
  基本区间贪心合并，得到目标网段的完整、互不重叠划分；每个区间内的
  每个目的 IP 的可能结果集合完全相同。

  每个区间的每种结果都附一个该区间内的具体目的 IP 与一条真实可行的
  转发路径作为见证：送达/丢弃路径以终态动作结尾；循环路径标出重复段
  （cycleStart 起回到同一台路由器，无限重复）。
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Any, Optional

from .engine import ValidationFailure

MAX_ROUTERS = 8
MAX_ROUTES_PER_ROUTER = 20
DELIVER = "deliver"
DROP = "drop"
TERMINAL_HOPS = (DELIVER, DROP)

OUTCOME_VIA = "delivered-via-gateway"
OUTCOME_BYPASS = "delivered-bypass"
OUTCOME_DROP = "dropped"
OUTCOME_LOOP = "loop"
OUTCOME_ORDER = (OUTCOME_VIA, OUTCOME_BYPASS, OUTCOME_DROP, OUTCOME_LOOP)

_MISSING = object()


# --------------------------------------------------------------------------- #
# 数据模型
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RouteEntry:
    prefix: IPv4Network
    next_hops: tuple  # 元素为 int（路由器编号）或 "deliver" / "drop"


@dataclass(frozen=True)
class RouterConfig:
    router_id: int
    routes: tuple  # tuple[RouteEntry, ...]


@dataclass(frozen=True)
class DiagConfig:
    entry: int
    gateway: int
    target: IPv4Network
    routers: tuple  # tuple[RouterConfig, ...]


# --------------------------------------------------------------------------- #
# 输入校验
# --------------------------------------------------------------------------- #
def _err(message: str, *, field: Optional[str] = None,
         router_id: Optional[int] = None, route_index: Optional[int] = None,
         line: Optional[int] = None, col: Optional[int] = None
         ) -> dict[str, Any]:
    e: dict[str, Any] = {"message": message}
    if router_id is not None:
        e["routerId"] = router_id
    if route_index is not None:
        e["routeIndex"] = route_index  # 1-based，与管理员阅读顺序一致
    if field is not None:
        e["field"] = field
    if line is not None:
        e["line"] = line
    if col is not None:
        e["col"] = col
    return e


def _tname(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "布尔值"
    if isinstance(value, (int, float)):
        return "数字"
    if isinstance(value, str):
        return "字符串"
    if isinstance(value, list):
        return "数组"
    if isinstance(value, dict):
        return "对象"
    return type(value).__name__


def _parse_router_id(value: Any, field: str, errors: list[dict[str, Any]],
                     *, router_id: Optional[int] = None) -> Optional[int]:
    loc = {"field": field, "router_id": router_id}
    if value is _MISSING:
        errors.append(_err(f"缺少字段 {field}（整数路由器编号）", **loc))
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        errors.append(_err(f"{field} 必须是整数路由器编号，当前为 {value!r}", **loc))
        return None
    if value < 1:
        errors.append(_err(f"路由器编号必须是 ≥ 1 的整数，当前为 {value}", **loc))
        return None
    return value


def _parse_cidr(value: Any, field: str, errors: list[dict[str, Any]], *,
                router_id: Optional[int] = None,
                route_index: Optional[int] = None) -> Optional[IPv4Network]:
    """严格 IPv4 CIDR：必须是字符串、必须带前缀、必须是网络地址（主机位为 0）。"""
    loc = {"field": field, "router_id": router_id, "route_index": route_index}
    if value is _MISSING:
        errors.append(_err(f"缺少字段 {field}（IPv4 CIDR）", **loc))
        return None
    if not isinstance(value, str):
        errors.append(_err(f"{field} 必须是字符串形式的 IPv4 CIDR，"
                           f"例如 10.0.0.0/24，当前是{_tname(value)}", **loc))
        return None
    text = value.strip()
    if ":" in text:
        errors.append(_err(f"{field} 仅支持 IPv4，不支持 IPv6：{value!r}", **loc))
        return None
    if "/" not in text:
        errors.append(_err(f"{field} 缺少前缀长度，CIDR 应形如 10.0.0.0/24；"
                           "单个主机请写 a.b.c.d/32，全网请写 0.0.0.0/0", **loc))
        return None
    try:
        network = IPv4Network(text, strict=True)
    except ValueError:
        errors.append(_err(f"{field} 不是合法的 IPv4 CIDR：{value!r}；"
                           "请使用网络地址（主机位为 0），如 192.168.1.0/24", **loc))
        return None
    return network


def _parse_next_hops(value: Any, router_id: Optional[int], route_index: int,
                     declared_ids: set[int], errors: list[dict[str, Any]]
                     ) -> Optional[tuple]:
    loc = {"router_id": router_id, "route_index": route_index}
    if value is _MISSING:
        errors.append(_err("缺少字段 nextHops（非空下一跳列表）",
                           field="nextHops", **loc))
        return None
    if not isinstance(value, list):
        errors.append(_err(f"nextHops 必须是数组，当前是{_tname(value)}",
                           field="nextHops", **loc))
        return None
    if not value:
        errors.append(_err("nextHops 不能为空：每条路由至少需要一个下一跳",
                           field="nextHops", **loc))
        return None
    hops: list[Any] = []
    seen: set[Any] = set()
    ok = True
    for pos, hop in enumerate(value, start=1):
        if isinstance(hop, bool) or not isinstance(hop, (int, str)):
            errors.append(_err(f"第 {pos} 个下一跳必须是路由器编号（整数）或 "
                               f"\"deliver\"/\"drop\"，当前为 {hop!r}",
                               field="nextHops", **loc))
            ok = False
            continue
        if isinstance(hop, int):
            if hop < 1:
                errors.append(_err(f"第 {pos} 个下一跳的路由器编号必须 ≥ 1，"
                                   f"当前为 {hop}", field="nextHops", **loc))
                ok = False
                continue
            if declared_ids and hop not in declared_ids:
                errors.append(_err(f"第 {pos} 个下一跳引用了未定义的路由器编号 "
                                   f"{hop}（routers 中不存在该 id）",
                                   field="nextHops", **loc))
                ok = False
                continue
        elif hop not in TERMINAL_HOPS:
            errors.append(_err(f"第 {pos} 个下一跳的字符串只能是 "
                               f"\"deliver\"（送达）或 \"drop\"（丢弃），"
                               f"当前为 {hop!r}", field="nextHops", **loc))
            ok = False
            continue
        if hop not in seen:  # 重复下一跳去重（保持首次出现顺序）
            seen.add(hop)
            hops.append(hop)
    if not ok:
        return None
    return tuple(hops)


def _parse_route(obj: Any, router_id: Optional[int], route_index: int,
                 seen_prefixes: dict[IPv4Network, int], declared_ids: set[int],
                 errors: list[dict[str, Any]]) -> Optional[RouteEntry]:
    loc = {"router_id": router_id, "route_index": route_index}
    if not isinstance(obj, dict):
        errors.append(_err(f"第 {route_index} 条路由必须是 JSON 对象，"
                           f"当前是{_tname(obj)}", **loc))
        return None
    allowed = {"prefix", "nextHops"}
    for name in sorted(set(obj) - allowed):
        errors.append(_err(f"路由存在不支持的字段 {name!r}，"
                           f"允许的字段为：{sorted(allowed)}",
                           field=name, **loc))

    prefix = _parse_cidr(obj.get("prefix", _MISSING), "prefix", errors, **loc)
    if prefix is not None:
        if prefix in seen_prefixes:
            errors.append(_err(f"前缀 {prefix} 与本表第 "
                               f"{seen_prefixes[prefix]} 条路由重复，"
                               "同一路由表内前缀必须唯一",
                               field="prefix", **loc))
            prefix = None
        else:
            seen_prefixes[prefix] = route_index

    next_hops = _parse_next_hops(obj.get("nextHops", _MISSING), router_id,
                                 route_index, declared_ids, errors)
    if prefix is None or next_hops is None:
        return None
    return RouteEntry(prefix=prefix, next_hops=next_hops)


def _parse_router(obj: Any, position: int, declared_ids: set[int],
                  seen_ids: dict[int, int], errors: list[dict[str, Any]]
                  ) -> Optional[RouterConfig]:
    if not isinstance(obj, dict):
        errors.append(_err(f"第 {position} 个路由器必须是 JSON 对象，"
                           f"当前是{_tname(obj)}", field="routers"))
        return None
    allowed = {"id", "routes"}
    for name in sorted(set(obj) - allowed):
        errors.append(_err(f"路由器存在不支持的字段 {name!r}，"
                           f"允许的字段为：{sorted(allowed)}", field=name))

    router_id = _parse_router_id(obj.get("id", _MISSING), "id", errors)
    if router_id is not None:
        if router_id in seen_ids:
            errors.append(_err(f"路由器编号 {router_id} 与第 "
                               f"{seen_ids[router_id]} 个路由器重复，"
                               "路由器编号必须唯一", field="id"))
            router_id = None
        else:
            seen_ids[router_id] = position

    routes: tuple = ()
    routes_value = obj.get("routes", _MISSING)
    if routes_value is _MISSING:
        errors.append(_err("缺少字段 routes（该路由器的路由条目数组）",
                           field="routes", router_id=router_id))
    elif not isinstance(routes_value, list):
        errors.append(_err(f"routes 必须是数组，当前是{_tname(routes_value)}",
                           field="routes", router_id=router_id))
    else:
        if len(routes_value) > MAX_ROUTES_PER_ROUTER:
            errors.append(_err(f"路由条目数量为 {len(routes_value)} 条，"
                               f"超过每台路由器的上限 {MAX_ROUTES_PER_ROUTER} 条",
                               field="routes", router_id=router_id))
        seen_prefixes: dict[IPv4Network, int] = {}
        parsed = []
        for route_index, route_obj in enumerate(
                routes_value[:MAX_ROUTES_PER_ROUTER], start=1):
            entry = _parse_route(route_obj, router_id, route_index,
                                 seen_prefixes, declared_ids, errors)
            if entry is not None:
                parsed.append(entry)
        routes = tuple(parsed)

    if router_id is None:
        return None
    return RouterConfig(router_id=router_id, routes=routes)


def _parse_routers(value: Any, errors: list[dict[str, Any]]
                   ) -> tuple[list[RouterConfig], set[int]]:
    """解析路由器数组；返回（合法路由器列表，全部合法 id 集合）。"""
    declared_ids: set[int] = set()
    if value is _MISSING:
        errors.append(_err("缺少字段 routers（路由器数组）", field="routers"))
        return [], declared_ids
    if not isinstance(value, list):
        errors.append(_err(f"routers 必须是数组，当前是{_tname(value)}",
                           field="routers"))
        return [], declared_ids
    if not value:
        errors.append(_err("routers 至少需要 1 台路由器", field="routers"))
        return [], declared_ids
    if len(value) > MAX_ROUTERS:
        errors.append(_err(f"路由器数量为 {len(value)} 台，"
                           f"超过上限 {MAX_ROUTERS} 台", field="routers"))

    # 第一遍：收集全部语法合法的 id，供下一跳/入口/网关的引用完整性检查
    for obj in value:
        if isinstance(obj, dict):
            rid = obj.get("id", _MISSING)
            if isinstance(rid, int) and not isinstance(rid, bool) and rid >= 1:
                declared_ids.add(rid)

    routers: list[RouterConfig] = []
    seen_ids: dict[int, int] = {}
    for position, obj in enumerate(value[:MAX_ROUTERS], start=1):
        router = _parse_router(obj, position, declared_ids, seen_ids, errors)
        if router is not None:
            routers.append(router)
    return routers, declared_ids


def parse_config(text: str) -> DiagConfig:
    """解析并校验整份路由诊断配置，失败时抛 ValidationFailure（含全部错误）。"""
    errors: list[dict[str, Any]] = []
    if not isinstance(text, str) or not text.strip():
        raise ValidationFailure(
            [_err("内容为空，请粘贴路由诊断配置 JSON")])
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationFailure([_err(f"JSON 语法错误：{exc.msg}",
                                      line=exc.lineno, col=exc.colno)]) from exc
    if not isinstance(data, dict):
        raise ValidationFailure(
            [_err(f"顶层必须是 JSON 对象（{{ ... }}），当前是{_tname(data)}")])

    allowed = {"entryRouter", "gatewayRouter", "targetCidr", "routers"}
    for name in sorted(set(data) - allowed):
        errors.append(_err(f"存在不支持的顶层字段 {name!r}，"
                           f"允许的字段为：{sorted(allowed)}", field=name))

    entry = _parse_router_id(data.get("entryRouter", _MISSING),
                             "entryRouter", errors)
    gateway = _parse_router_id(data.get("gatewayRouter", _MISSING),
                               "gatewayRouter", errors)
    target = _parse_cidr(data.get("targetCidr", _MISSING), "targetCidr", errors)
    routers, declared_ids = _parse_routers(data.get("routers", _MISSING), errors)

    if entry is not None and declared_ids and entry not in declared_ids:
        errors.append(_err(f"入口路由器 {entry} 不在 routers 定义的路由器编号中",
                           field="entryRouter"))
    if gateway is not None and declared_ids and gateway not in declared_ids:
        errors.append(_err(f"检查网关 {gateway} 不在 routers 定义的路由器编号中",
                           field="gatewayRouter"))

    if errors:
        raise ValidationFailure(errors)
    return DiagConfig(entry=entry, gateway=gateway, target=target,
                      routers=tuple(routers))


# --------------------------------------------------------------------------- #
# 逐跳转发图（在某个基本区间内恒定）
# --------------------------------------------------------------------------- #
def _lpm_entry(router: RouterConfig, ip: int) -> Optional[RouteEntry]:
    """最长前缀匹配：返回命中条目；无匹配返回 None（语义为丢弃）。"""
    best: Optional[RouteEntry] = None
    for entry in router.routes:
        if int(entry.prefix.network_address) <= ip \
                <= int(entry.prefix.broadcast_address):
            if best is None or entry.prefix.prefixlen > best.prefix.prefixlen:
                best = entry
    return best


class _ForwardingGraph:
    """某一基本区间内（对区间内任意目的 IP 相同）的逐跳转发图。"""

    def __init__(self, config: DiagConfig, ip: int):
        self.matched: dict[int, Optional[RouteEntry]] = {}
        self.succ: dict[int, set[int]] = {}
        self.can_deliver: set[int] = set()
        self.can_drop: set[int] = set()
        self.drop_no_match: set[int] = set()
        for router in config.routers:
            rid = router.router_id
            entry = _lpm_entry(router, ip)
            self.matched[rid] = entry
            self.succ[rid] = set()
            if entry is None:
                self.can_drop.add(rid)
                self.drop_no_match.add(rid)
            else:
                for hop in entry.next_hops:
                    if hop == DELIVER:
                        self.can_deliver.add(rid)
                    elif hop == DROP:
                        self.can_drop.add(rid)
                    else:
                        self.succ[rid].add(hop)

    def prefix_str(self, router_id: int) -> Optional[str]:
        entry = self.matched[router_id]
        return str(entry.prefix) if entry is not None else None


def _bfs_all(start: int, succ: dict[int, set[int]]) -> set[int]:
    seen = {start}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for nxt in sorted(succ[node]):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def _bfs_path(start: int, succ: dict[int, set[int]],
              goal, banned: frozenset = frozenset()) -> Optional[list[int]]:
    """从 start 到首个满足 goal(node) 节点的最短路由器路径；不可达返回 None。"""
    if start in banned:
        return None
    parent: dict[int, Optional[int]] = {start: None}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        if goal(node):
            path = []
            cursor: Optional[int] = node
            while cursor is not None:
                path.append(cursor)
                cursor = parent[cursor]
            return path[::-1]
        for nxt in sorted(succ[node]):
            if nxt not in parent and nxt not in banned:
                parent[nxt] = node
                queue.append(nxt)
    return None


def _find_cycle(start: int, succ: dict[int, set[int]]
                ) -> Optional[tuple[list[int], int, int]]:
    """
    从 start 可达的环：返回 (栈路径, 环起点在栈中的下标, 回边目标)。
    栈路径最后一跳指向回边目标（= 栈路径[环起点]），构成无限重复段。
    """
    stack: list[int] = []
    on_stack: set[int] = set()
    visited: set[int] = set()

    def dfs(node: int) -> Optional[tuple[list[int], int, int]]:
        visited.add(node)
        stack.append(node)
        on_stack.add(node)
        for nxt in sorted(succ[node]):
            if nxt not in visited:
                found = dfs(nxt)
                if found is not None:
                    return found
            elif nxt in on_stack:
                return list(stack), stack.index(nxt), nxt
        stack.pop()
        on_stack.discard(node)
        return None

    return dfs(start)


# --------------------------------------------------------------------------- #
# 区间分析
# --------------------------------------------------------------------------- #
def _hops_for_path(graph: _ForwardingGraph, path: list[int],
                   terminal: Any) -> list[dict[str, Any]]:
    """把路由器路径 + 终态动作序列化为逐跳记录。"""
    hops = []
    for i, rid in enumerate(path):
        next_hop = path[i + 1] if i + 1 < len(path) else terminal
        hop: dict[str, Any] = {"router": rid,
                               "matchedPrefix": graph.prefix_str(rid),
                               "nextHop": next_hop}
        if next_hop == DROP:
            hop["dropReason"] = ("no-matching-route"
                                 if rid in graph.drop_no_match
                                 else "explicit-drop-route")
        hops.append(hop)
    return hops


def _analyze_interval(config: DiagConfig, lo: int, hi: int
                      ) -> tuple[list[str], list[dict[str, Any]]]:
    """计算一个基本区间的可能结果集合与见证（区间内任意 IP 结果相同）。"""
    graph = _ForwardingGraph(config, lo)
    entry, gateway = config.entry, config.gateway
    witness_ip = str(IPv4Address(lo))

    reachable = _bfs_all(entry, graph.succ)
    found: dict[str, dict[str, Any]] = {}

    # 经网关送达：入口可达网关，且网关可达某个 deliver
    if gateway in reachable:
        tail = _bfs_path(gateway, graph.succ,
                         lambda node: node in graph.can_deliver)
        if tail is not None:
            head = _bfs_path(entry, graph.succ,
                             lambda node: node == gateway) or [gateway]
            full = head + tail[1:]
            found[OUTCOME_VIA] = {
                "outcome": OUTCOME_VIA, "ip": witness_ip,
                "hops": _hops_for_path(graph, full, DELIVER),
                "cycleStart": None, "passesGateway": True,
            }

    # 绕过网关送达：在剔除网关的图上可达 deliver
    bypass = _bfs_path(entry, graph.succ,
                       lambda node: node in graph.can_deliver,
                       banned=frozenset({gateway}))
    if bypass is not None:
        found[OUTCOME_BYPASS] = {
            "outcome": OUTCOME_BYPASS, "ip": witness_ip,
            "hops": _hops_for_path(graph, bypass, DELIVER),
            "cycleStart": None, "passesGateway": False,
        }

    # 丢弃：可达某个 drop（显式 drop 下一跳，或无匹配路由）
    drop_path = _bfs_path(entry, graph.succ,
                          lambda node: node in graph.can_drop)
    if drop_path is not None:
        hops = _hops_for_path(graph, drop_path, DROP)
        found[OUTCOME_DROP] = {
            "outcome": OUTCOME_DROP, "ip": witness_ip,
            "hops": hops,
            "cycleStart": None,
            "passesGateway": any(h["router"] == gateway for h in hops),
        }

    # 无限循环：从入口可达的环
    cycle = _find_cycle(entry, graph.succ)
    if cycle is not None:
        stack, cycle_start, back_target = cycle
        hops = _hops_for_path(graph, stack, back_target)
        found[OUTCOME_LOOP] = {
            "outcome": OUTCOME_LOOP, "ip": witness_ip,
            "hops": hops,
            "cycleStart": cycle_start,
            "passesGateway": any(h["router"] == gateway for h in hops),
        }

    outcomes = [o for o in OUTCOME_ORDER if o in found]
    return outcomes, [found[o] for o in outcomes]


# --------------------------------------------------------------------------- #
# 结果序列化
# --------------------------------------------------------------------------- #
def _ip_str(value: int) -> str:
    return str(IPv4Address(value))


def _aligned_cidr(lo: int, hi: int) -> Optional[str]:
    """若整数闭区间恰好是一个 CIDR 网络，返回其字符串表示；否则 None。"""
    size = hi - lo + 1
    if size <= 0 or (size & (size - 1)) != 0:
        return None
    if lo % size != 0:
        return None
    prefix = 32 - size.bit_length() + 1
    return f"{_ip_str(lo)}/{prefix}"


def _interval_json(lo: int, hi: int) -> dict[str, Any]:
    return {
        "start": _ip_str(lo),
        "end": _ip_str(hi),
        "cidr": _aligned_cidr(lo, hi),
        "addressCount": str(hi - lo + 1),
    }


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def diagnose(config: DiagConfig) -> dict[str, Any]:
    """
    把目标网段完整划分为互不重叠的闭区间，给出每个区间的全部可能结果
    （含见证路径）。不逐 IP 枚举：按全部路由前缀边界符号化切分。
    """
    target_lo = int(config.target.network_address)
    target_hi = int(config.target.broadcast_address)

    # 1) 全部路由前缀边界（与目标求交）作为切点
    points = {target_lo, target_hi + 1}
    for router in config.routers:
        for entry in router.routes:
            lo = max(int(entry.prefix.network_address), target_lo)
            hi = min(int(entry.prefix.broadcast_address), target_hi)
            if lo <= hi:
                points.add(lo)
                points.add(hi + 1)
    ordered = sorted(points)

    # 2) 逐基本区间分析（区间内转发图恒定）
    blocks: list[dict[str, Any]] = []
    for i in range(len(ordered) - 1):
        lo, hi = ordered[i], ordered[i + 1] - 1
        outcomes, witnesses = _analyze_interval(config, lo, hi)
        blocks.append({"lo": lo, "hi": hi,
                       "outcomes": outcomes, "witnesses": witnesses})

    # 3) 合并相邻且结果集合相同的基本区间（结果集合在合并段内仍处处一致）
    merged: list[dict[str, Any]] = []
    for block in blocks:
        if merged and merged[-1]["outcomes"] == block["outcomes"]:
            merged[-1]["hi"] = block["hi"]
        else:
            merged.append(block)

    intervals = [{
        "index": index,
        "range": _interval_json(block["lo"], block["hi"]),
        "outcomes": block["outcomes"],
        "witnesses": block["witnesses"],
    } for index, block in enumerate(merged, start=1)]

    # 4) 汇总：直接回答“受保护网段是否会绕过检查网关”
    stats = {o: {"intervals": 0, "addresses": 0} for o in OUTCOME_ORDER}
    for block in merged:
        size = block["hi"] - block["lo"] + 1
        for outcome in block["outcomes"]:
            stats[outcome]["intervals"] += 1
            stats[outcome]["addresses"] += size

    bypass_found = stats[OUTCOME_BYPASS]["intervals"] > 0
    loop_found = stats[OUTCOME_LOOP]["intervals"] > 0
    any_deliver = stats[OUTCOME_VIA]["intervals"] > 0 or bypass_found
    if bypass_found:
        verdict = "bypass-possible"        # 存在绕过检查网关送达的路径
    elif not any_deliver:
        verdict = "no-deliver-path"        # 不存在任何送达路径
    else:
        verdict = "all-delivered-via-gateway"  # 所有可能送达的路径均经网关

    return {
        "summary": {
            "entryRouter": config.entry,
            "gatewayRouter": config.gateway,
            "targetCidr": str(config.target),
            "routerCount": len(config.routers),
            "routeCount": sum(len(r.routes) for r in config.routers),
            "targetAddressCount": str(target_hi - target_lo + 1),
            "intervalCount": len(intervals),
            "outcomeStats": {
                o: {"intervals": stats[o]["intervals"],
                    "addresses": str(stats[o]["addresses"])}
                for o in OUTCOME_ORDER
            },
            "bypassFound": bypass_found,
            "loopFound": loop_found,
            "verdict": verdict,
        },
        "intervals": intervals,
    }


def diagnose_text(text: str) -> dict[str, Any]:
    """供 API 调用的入口：先整体校验（任一非法即拒绝），再诊断。"""
    return diagnose(parse_config(text))
