"""路由诊断引擎测试：校验、LPM/等价下一跳语义、划分性质、见证合法性、
以及用逐 IP 暴力枚举（仅测试侧）对符号化结果做精确性核对。"""

import json
import random
from ipaddress import IPv4Address, IPv4Network

import pytest

from app.route_engine import (
    MAX_ROUTERS,
    MAX_ROUTES_PER_ROUTER,
    DiagConfig,
    RouteEntry,
    RouterConfig,
    ValidationFailure,
    diagnose,
    diagnose_text,
    parse_config,
)


# --------------------------------------------------------------------------- #
# 工具
# --------------------------------------------------------------------------- #
def make_config(entry, gateway, target, routers):
    """routers: {router_id: [(prefix, [nextHops...]), ...]}"""
    return DiagConfig(
        entry=entry,
        gateway=gateway,
        target=IPv4Network(target),
        routers=tuple(
            RouterConfig(router_id=rid, routes=tuple(
                RouteEntry(prefix=IPv4Network(p), next_hops=tuple(hops))
                for p, hops in routes))
            for rid, routes in routers.items()),
    )


def config_json(entry, gateway, target, routers):
    """与 make_config 同构，但生成 JSON 文本（走完整校验路径）。"""
    return json.dumps({
        "entryRouter": entry,
        "gatewayRouter": gateway,
        "targetCidr": target,
        "routers": [
            {"id": rid,
             "routes": [{"prefix": p, "nextHops": hops} for p, hops in routes]}
            for rid, routes in routers.items()
        ],
    })


def ip_int(s):
    return int(IPv4Address(s))


def interval_bounds(result):
    return [(ip_int(iv["range"]["start"]), ip_int(iv["range"]["end"]))
            for iv in result["intervals"]]


def lpm(routes, ip):
    """测试侧独立 LPM：返回 (prefix, nextHops) 或 None。"""
    best = None
    for prefix, hops in routes:
        net = IPv4Network(prefix)
        if int(net.network_address) <= ip <= int(net.broadcast_address):
            if best is None or net.prefixlen > best[0].prefixlen:
                best = (net, hops)
    return best


def ref_outcomes_for_ip(routers, entry, gateway, ip):
    """参考实现：对单个目的 IP 直接构图求四种可能结果（供逐 IP 核对）。"""
    succ = {rid: set() for rid in routers}
    can_deliver, can_drop = set(), set()
    for rid, routes in routers.items():
        hit = lpm(routes, ip)
        if hit is None:
            can_drop.add(rid)
        else:
            for hop in hit[1]:
                if hop == "deliver":
                    can_deliver.add(rid)
                elif hop == "drop":
                    can_drop.add(rid)
                else:
                    succ[rid].add(hop)

    def reach(start, banned=None):
        if banned is not None and start == banned:
            return set()  # 起点即被禁节点（如入口=网关时不可能绕过网关）
        seen = {start}
        stack = [start]
        while stack:
            node = stack.pop()
            for nxt in succ[node]:
                if nxt not in seen and nxt != banned:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen

    out = set()
    reachable = reach(entry)
    if any(node in can_drop for node in reachable):
        out.add("dropped")
    if gateway in reachable and any(node in can_deliver
                                    for node in reach(gateway)):
        out.add("delivered-via-gateway")
    if any(node in can_deliver for node in reach(entry, banned=gateway)):
        out.add("delivered-bypass")

    color = {}

    def has_cycle(node):
        color[node] = 1
        for nxt in succ[node]:
            state = color.get(nxt, 0)
            if state == 1:
                return True
            if state == 0 and has_cycle(nxt):
                return True
        color[node] = 2
        return False

    if has_cycle(entry):
        out.add("loop")
    return out


def check_partition(result, target):
    """区间互不重叠、升序、无缝衔接且并集恰为目标网段。"""
    bounds = interval_bounds(result)
    net = IPv4Network(target)
    assert bounds, "划分不能为空"
    assert bounds[0][0] == int(net.network_address)
    assert bounds[-1][1] == int(net.broadcast_address)
    for i, (lo, hi) in enumerate(bounds):
        assert lo <= hi
        if i:
            assert lo == bounds[i - 1][1] + 1, "区间必须无缝衔接"


def check_witnesses(config, result):
    """每个区间：见证集合与结果集合一一对应；每条见证路径逐步合法。"""
    routers = {r.router_id: [(str(e.prefix), list(e.next_hops))
                             for e in r.routes] for r in config.routers}
    for iv in result["intervals"]:
        lo = ip_int(iv["range"]["start"])
        hi = ip_int(iv["range"]["end"])
        assert [w["outcome"] for w in iv["witnesses"]] == iv["outcomes"]
        for w in iv["witnesses"]:
            ip = ip_int(w["ip"])
            assert lo <= ip <= hi, "见证 IP 必须落在区间内"
            hops = w["hops"]
            assert hops and hops[0]["router"] == config.entry
            for i, hop in enumerate(hops):
                rid = hop["router"]
                hit = lpm(routers[rid], ip)
                expect_prefix = str(hit[0]) if hit else None
                assert hop["matchedPrefix"] == expect_prefix, \
                    "逐跳匹配前缀必须与 LPM 一致"
                nh = hop["nextHop"]
                if i + 1 < len(hops):
                    assert nh == hops[i + 1]["router"]
                    assert hit is not None and nh in hit[1]
                elif w["outcome"] == "loop":
                    cs = w["cycleStart"]
                    assert cs is not None and 0 <= cs < len(hops)
                    # 重复段：最后一跳回到 cycleStart 处的路由器
                    assert nh == hops[cs]["router"]
                    assert hit is not None and nh in hit[1]
                elif nh == "deliver":
                    assert hit is not None and "deliver" in hit[1]
                else:
                    assert nh == "drop"
                    if hit is None:
                        assert hop["dropReason"] == "no-matching-route"
                    else:
                        assert "drop" in hit[1]
                        assert hop["dropReason"] == "explicit-drop-route"
            on_path = {h["router"] for h in hops}
            if w["outcome"] == "delivered-via-gateway":
                assert config.gateway in on_path
                assert w["passesGateway"] is True
            if w["outcome"] == "delivered-bypass":
                assert config.gateway not in on_path
                assert w["passesGateway"] is False
            if w["outcome"] != "loop":
                assert w["cycleStart"] is None


# --------------------------------------------------------------------------- #
# 输入校验
# --------------------------------------------------------------------------- #
def test_empty_input_rejected():
    with pytest.raises(ValidationFailure) as ei:
        parse_config("   ")
    assert "空" in ei.value.errors[0]["message"]


def test_json_syntax_error_has_line_and_col():
    with pytest.raises(ValidationFailure) as ei:
        parse_config('{"entryRouter": 1,\n"gatewayRouter": }')
    err = ei.value.errors[0]
    assert err["line"] == 2 and err["col"] is not None
    assert "JSON" in err["message"]


def test_top_level_must_be_object():
    with pytest.raises(ValidationFailure) as ei:
        parse_config('[{"id": 1}]')
    assert "对象" in ei.value.errors[0]["message"]


def test_unknown_and_missing_top_level_fields():
    with pytest.raises(ValidationFailure) as ei:
        parse_config('{"entryRouter": 1, "gatewayRouter": 1,'
                     ' "targetCidr": "10.0.0.0/24", "routers": [],'
                     ' "extra": 1}')
    fields = {e.get("field") for e in ei.value.errors}
    assert "extra" in fields  # 未知字段被定位
    assert any("至少需要" in e["message"] for e in ei.value.errors)


def test_missing_required_fields_all_reported():
    with pytest.raises(ValidationFailure) as ei:
        parse_config('{}')
    fields = {e.get("field") for e in ei.value.errors}
    assert {"entryRouter", "gatewayRouter", "targetCidr", "routers"} <= fields


def test_router_id_type_validation():
    base = {"entryRouter": 1, "gatewayRouter": 1,
            "targetCidr": "10.0.0.0/24", "routers": [{"id": 1, "routes": []}]}
    for bad in ('"1"', "1.5", "true", "null", "0", "-2"):
        data = json.loads(json.dumps(base))
        data["entryRouter"] = json.loads(bad)
        with pytest.raises(ValidationFailure):
            parse_config(json.dumps(data))


def test_too_many_routers_and_routes():
    routers = [{"id": i, "routes": []} for i in range(1, MAX_ROUTERS + 2)]
    with pytest.raises(ValidationFailure) as ei:
        parse_config(json.dumps({"entryRouter": 1, "gatewayRouter": 1,
                                 "targetCidr": "10.0.0.0/24",
                                 "routers": routers}))
    assert str(MAX_ROUTERS) in ei.value.errors[0]["message"]

    routes = [{"prefix": f"10.0.{i}.0/24", "nextHops": ["drop"]}
              for i in range(MAX_ROUTES_PER_ROUTER + 1)]
    with pytest.raises(ValidationFailure) as ei2:
        parse_config(json.dumps({"entryRouter": 1, "gatewayRouter": 1,
                                 "targetCidr": "0.0.0.0/0",
                                 "routers": [{"id": 1, "routes": routes}]}))
    assert str(MAX_ROUTES_PER_ROUTER) in json.dumps(ei2.value.errors)


def test_duplicate_router_id_located():
    text = json.dumps({
        "entryRouter": 1, "gatewayRouter": 1, "targetCidr": "10.0.0.0/24",
        "routers": [{"id": 1, "routes": []}, {"id": 1, "routes": []}]})
    with pytest.raises(ValidationFailure) as ei:
        parse_config(text)
    assert any(e.get("field") == "id" and "重复" in e["message"]
               for e in ei.value.errors)


def test_duplicate_prefix_within_table_located():
    text = config_json(1, 1, "10.0.0.0/24",
                       {1: [("10.0.0.0/24", ["drop"]),
                            ("10.0.0.0/24", ["deliver"])]})
    with pytest.raises(ValidationFailure) as ei:
        parse_config(text)
    err = ei.value.errors[0]
    assert err["routerId"] == 1 and err["routeIndex"] == 2
    assert err["field"] == "prefix" and "唯一" in err["message"]


def test_same_prefix_in_different_tables_ok():
    cfg = parse_config(config_json(
        1, 2, "10.0.0.0/24",
        {1: [("10.0.0.0/24", [2])], 2: [("10.0.0.0/24", ["deliver"])]}))
    assert len(cfg.routers) == 2


def test_bad_prefix_variants():
    for bad in ('"10.0.0.1/24"', '"10.0.0.0"', '"::1/128"', '"abc"',
                '"10.0.0.0/33"', "123", "null"):
        text = ('{"entryRouter": 1, "gatewayRouter": 1,'
                ' "targetCidr": "10.0.0.0/24", "routers": [{"id": 1,'
                f' "routes": [{{"prefix": {bad}, "nextHops": ["drop"]}}]}}]}}')
        with pytest.raises(ValidationFailure) as ei:
            parse_config(text)
        assert ei.value.errors[0]["routeIndex"] == 1


def test_bad_target_cidr():
    for bad in ('"10.0.0.1/24"', '"10.0.0.0"', '"::1/128"', "42"):
        text = ('{"entryRouter": 1, "gatewayRouter": 1,'
                f' "targetCidr": {bad},'
                ' "routers": [{"id": 1, "routes": []}]}')
        with pytest.raises(ValidationFailure) as ei:
            parse_config(text)
        assert ei.value.errors[0]["field"] == "targetCidr"


def test_nexthops_validation():
    def cfg_with(hops):
        return json.dumps({
            "entryRouter": 1, "gatewayRouter": 1, "targetCidr": "10.0.0.0/24",
            "routers": [{"id": 1, "routes": [
                {"prefix": "10.0.0.0/24", "nextHops": hops}]}]})

    for bad in ("[]", '"deliver"', '[null]', '[true]', '[1.5]', '[0]',
                '["DELIVER"]', '["deliver "]', '[9]', '["drop", 9]'):
        with pytest.raises(ValidationFailure) as ei:
            parse_config(cfg_with(json.loads(bad)))
        assert any(e.get("field") == "nextHops" for e in ei.value.errors), bad

    # 缺 nextHops 字段
    with pytest.raises(ValidationFailure):
        parse_config('{"entryRouter": 1, "gatewayRouter": 1,'
                     ' "targetCidr": "10.0.0.0/24", "routers": [{"id": 1,'
                     ' "routes": [{"prefix": "10.0.0.0/24"}]}]}')


def test_undefined_entry_gateway_and_nexthop_reference():
    text = json.dumps({
        "entryRouter": 7, "gatewayRouter": 8, "targetCidr": "10.0.0.0/24",
        "routers": [{"id": 1, "routes": [
            {"prefix": "10.0.0.0/24", "nextHops": [2]}]}]})
    with pytest.raises(ValidationFailure) as ei:
        parse_config(text)
    fields = {e.get("field") for e in ei.value.errors}
    assert {"entryRouter", "gatewayRouter", "nextHops"} <= fields


def test_unknown_fields_in_router_and_route():
    text = json.dumps({
        "entryRouter": 1, "gatewayRouter": 1, "targetCidr": "10.0.0.0/24",
        "routers": [{"id": 1, "name": "core", "routes": [
            {"prefix": "10.0.0.0/24", "nextHops": ["drop"], "metric": 5}]}]})
    with pytest.raises(ValidationFailure) as ei:
        parse_config(text)
    fields = {e.get("field") for e in ei.value.errors}
    assert {"name", "metric"} <= fields


def test_multiple_errors_collected_together():
    text = json.dumps({
        "entryRouter": "x", "gatewayRouter": 99, "targetCidr": "bad",
        "routers": [{"id": 1, "routes": [
            {"prefix": "10.0.0.1/24", "nextHops": []},
            {"prefix": "10.0.0.0/24"}]}]})
    with pytest.raises(ValidationFailure) as ei:
        parse_config(text)
    assert len(ei.value.errors) >= 5


def test_duplicate_nexthops_deduplicated():
    cfg = parse_config(config_json(1, 1, "10.0.0.0/24",
                                   {1: [("10.0.0.0/24",
                                         ["drop", "drop", "deliver"])]}))
    assert cfg.routers[0].routes[0].next_hops == ("drop", "deliver")


# --------------------------------------------------------------------------- #
# 语义：LPM、无匹配丢弃、等价下一跳、经/绕网关、循环
# --------------------------------------------------------------------------- #
def test_lpm_longest_prefix_wins():
    cfg = make_config(1, 1, "10.0.0.0/24",
                      {1: [("10.0.0.0/24", ["deliver"]),
                           ("10.0.0.0/26", ["drop"])]})
    result = diagnose(cfg)
    bounds = interval_bounds(result)
    assert bounds == [(ip_int("10.0.0.0"), ip_int("10.0.0.63")),
                      (ip_int("10.0.0.64"), ip_int("10.0.0.255"))]
    assert result["intervals"][0]["outcomes"] == ["dropped"]
    assert result["intervals"][1]["outcomes"] == ["delivered-via-gateway"]
    # 丢弃见证：命中 /26 显式 drop
    w = result["intervals"][0]["witnesses"][0]
    assert w["hops"][0]["matchedPrefix"] == "10.0.0.0/26"
    assert w["hops"][0]["dropReason"] == "explicit-drop-route"


def test_no_matching_route_is_drop():
    cfg = make_config(1, 1, "10.0.0.0/24",
                      {1: [("10.0.0.128/25", ["deliver"])]})
    result = diagnose(cfg)
    assert result["intervals"][0]["outcomes"] == ["dropped"]
    w = result["intervals"][0]["witnesses"][0]
    assert w["hops"][0]["matchedPrefix"] is None
    assert w["hops"][0]["dropReason"] == "no-matching-route"


def test_ecmp_yields_multiple_outcomes():
    cfg = make_config(1, 3, "10.0.0.0/30",
                      {1: [("10.0.0.0/30", [2, "deliver", "drop"])],
                       2: [("10.0.0.0/30", ["deliver"])],
                       3: []})
    result = diagnose(cfg)
    # 网关 R3 不可达：只能绕过送达或丢弃
    assert result["intervals"][0]["outcomes"] == ["delivered-bypass", "dropped"]
    check_witnesses(cfg, result)


def test_entry_equals_gateway_means_no_bypass():
    cfg = make_config(1, 1, "10.0.0.0/30",
                      {1: [("10.0.0.0/30", ["deliver"])]})
    result = diagnose(cfg)
    assert result["intervals"][0]["outcomes"] == ["delivered-via-gateway"]
    assert result["summary"]["verdict"] == "all-delivered-via-gateway"


def test_self_loop_detected():
    cfg = make_config(1, 2, "10.0.0.0/30",
                      {1: [("10.0.0.0/30", [1])],
                       2: [("10.0.0.0/30", ["deliver"])]})
    result = diagnose(cfg)
    iv = result["intervals"][0]
    assert iv["outcomes"] == ["loop"]
    w = iv["witnesses"][0]
    assert w["cycleStart"] == 0
    assert len(w["hops"]) == 1 and w["hops"][0]["nextHop"] == 1


def test_two_node_loop_marks_repeated_segment():
    cfg = make_config(1, 3, "10.0.0.0/30",
                      {1: [("10.0.0.0/30", [2])],
                       2: [("10.0.0.0/30", [1])],
                       3: [("10.0.0.0/30", ["deliver"])]})
    result = diagnose(cfg)
    w = result["intervals"][0]["witnesses"][0]
    assert w["outcome"] == "loop"
    assert w["cycleStart"] == 0
    assert [h["router"] for h in w["hops"]] == [1, 2]
    assert w["hops"][-1]["nextHop"] == 1  # 回到重复段起点


def test_loop_and_deliver_coexist():
    cfg = make_config(1, 2, "10.0.0.0/30",
                      {1: [("10.0.0.0/30", [1, 2])],
                       2: [("10.0.0.0/30", ["deliver"])]})
    result = diagnose(cfg)
    assert result["intervals"][0]["outcomes"] == ["delivered-via-gateway",
                                                  "loop"]
    check_witnesses(cfg, result)


def test_via_gateway_requires_deliver_after_gateway():
    # 报文能到网关，但网关之后只能丢弃 → 不存在“经网关送达”
    cfg = make_config(1, 2, "10.0.0.0/30",
                      {1: [("10.0.0.0/30", [2, "deliver"])],
                       2: [("10.0.0.0/30", ["drop"])]})
    result = diagnose(cfg)
    assert result["intervals"][0]["outcomes"] == ["delivered-bypass",
                                                  "dropped"]


def test_witness_via_gateway_path_threads_gateway():
    cfg = make_config(1, 2, "10.0.0.0/30",
                      {1: [("10.0.0.0/30", [2])],
                       2: [("10.0.0.0/30", [3])],
                       3: [("10.0.0.0/30", ["deliver"])]})
    result = diagnose(cfg)
    w = result["intervals"][0]["witnesses"][0]
    assert [h["router"] for h in w["hops"]] == [1, 2, 3]
    assert w["hops"][-1]["nextHop"] == "deliver"
    assert w["passesGateway"] is True


# --------------------------------------------------------------------------- #
# 内置示例的已知答案
# --------------------------------------------------------------------------- #
def test_bypass_example_expected_intervals():
    from app.route_examples import BYPASS_EXAMPLE
    result = diagnose_text(json.dumps(BYPASS_EXAMPLE))
    s = result["summary"]
    assert s["verdict"] == "bypass-possible"
    assert s["bypassFound"] is True and s["loopFound"] is False
    assert s["intervalCount"] == 4

    expect = [
        ("10.0.0.0", "10.0.0.127", ["delivered-via-gateway"]),
        ("10.0.0.128", "10.0.0.191",
         ["delivered-via-gateway", "delivered-bypass"]),
        ("10.0.0.192", "10.0.0.223", ["delivered-bypass", "dropped"]),
        ("10.0.0.224", "10.0.0.255", ["dropped"]),
    ]
    for iv, (lo, hi, outcomes) in zip(result["intervals"], expect):
        assert iv["range"]["start"] == lo
        assert iv["range"]["end"] == hi
        assert iv["outcomes"] == outcomes

    st = s["outcomeStats"]
    assert st["delivered-bypass"]["addresses"] == "96"   # 64 + 32
    assert st["delivered-via-gateway"]["addresses"] == "192"
    assert st["dropped"]["addresses"] == "64"
    assert st["loop"]["addresses"] == "0"
    check_partition(result, "10.0.0.0/24")
    check_witnesses(parse_config(json.dumps(BYPASS_EXAMPLE)), result)


def test_loop_example_expected_intervals():
    from app.route_examples import LOOP_EXAMPLE
    result = diagnose_text(json.dumps(LOOP_EXAMPLE))
    s = result["summary"]
    assert s["loopFound"] is True and s["bypassFound"] is False
    assert s["intervalCount"] == 3

    expect = [
        ("172.16.0.0", "172.16.0.63", ["loop"]),
        ("172.16.0.64", "172.16.0.127", ["delivered-via-gateway", "loop"]),
        ("172.16.0.128", "172.16.0.255", ["delivered-via-gateway"]),
    ]
    for iv, (lo, hi, outcomes) in zip(result["intervals"], expect):
        assert iv["range"]["start"] == lo
        assert iv["range"]["end"] == hi
        assert iv["outcomes"] == outcomes

    # 循环见证：R1→R2→R3→R2…，重复段从 R2 开始
    w = result["intervals"][0]["witnesses"][0]
    assert [h["router"] for h in w["hops"]] == [1, 2, 3]
    assert w["cycleStart"] == 1
    assert w["hops"][-1]["nextHop"] == 2
    check_partition(result, "172.16.0.0/24")
    check_witnesses(parse_config(json.dumps(LOOP_EXAMPLE)), result)


# --------------------------------------------------------------------------- #
# 精确性：随机配置下逐 IP 暴力枚举（测试侧）核对符号化划分
# --------------------------------------------------------------------------- #
def random_config(rng, n_routers, n_routes, pools):
    routers = {}
    for rid in range(1, n_routers + 1):
        routes = []
        prefixes = rng.sample(pools, min(n_routes, len(pools)))
        for p in prefixes:
            hops = []
            for _ in range(rng.randint(1, 3)):
                roll = rng.random()
                if roll < 0.3:
                    hops.append("deliver")
                elif roll < 0.5:
                    hops.append("drop")
                else:
                    hops.append(rng.randint(1, n_routers))
            # 去重保持顺序
            hops = list(dict.fromkeys(hops))
            routes.append((p, hops))
        routers[rid] = routes
    entry = rng.randint(1, n_routers)
    gateway = rng.randint(1, n_routers)
    return make_config(entry, gateway, "10.0.0.0/28", routers)


def test_randomized_against_per_ip_bruteforce():
    rng = random.Random(20261111)
    pools = ["10.0.0.0/28", "10.0.0.0/29", "10.0.0.8/29",
             "10.0.0.0/30", "10.0.0.4/30", "10.0.0.8/30", "10.0.0.12/30",
             "10.0.0.0/32", "10.0.0.5/32", "10.0.0.15/32"]
    for trial in range(150):
        cfg = random_config(rng, rng.randint(1, 4), rng.randint(0, 5), pools)
        result = diagnose(cfg)
        check_partition(result, "10.0.0.0/28")
        check_witnesses(cfg, result)

        routers = {r.router_id: [(str(e.prefix), list(e.next_hops))
                                 for e in r.routes] for r in cfg.routers}
        # 区间内每个 IP 的暴力结果集合必须与区间标注完全一致
        for iv in result["intervals"]:
            lo = ip_int(iv["range"]["start"])
            hi = ip_int(iv["range"]["end"])
            expect = set(iv["outcomes"])
            assert expect, "结果集合不应为空"
            for ip in range(lo, hi + 1):
                actual = ref_outcomes_for_ip(routers, cfg.entry,
                                             cfg.gateway, ip)
                assert actual == expect, (trial, ip, actual, expect)


def test_whole_internet_target_symbolic():
    """目标为 0.0.0.0/0（42 亿地址）也能符号化处理，不逐 IP 枚举。"""
    cfg = make_config(1, 2, "0.0.0.0/0",
                      {1: [("0.0.0.0/0", [2])],
                       2: [("10.0.0.0/8", ["deliver"]),
                           ("0.0.0.0/0", ["drop"])]})
    result = diagnose(cfg)
    check_partition(result, "0.0.0.0/0")
    check_witnesses(cfg, result)
    assert result["summary"]["targetAddressCount"] == "4294967296"
    by_outcome = {tuple(iv["outcomes"]) for iv in result["intervals"]}
    assert by_outcome == {("delivered-via-gateway",), ("dropped",)}


def test_summary_counts_are_consistent():
    from app.route_examples import BYPASS_EXAMPLE
    result = diagnose_text(json.dumps(BYPASS_EXAMPLE))
    s = result["summary"]
    total = sum(int(iv["range"]["addressCount"]) for iv in result["intervals"])
    assert total == int(s["targetAddressCount"])
    for outcome, st in s["outcomeStats"].items():
        intervals = [iv for iv in result["intervals"]
                     if outcome in iv["outcomes"]]
        assert st["intervals"] == len(intervals)
        assert int(st["addresses"]) == sum(
            int(iv["range"]["addressCount"]) for iv in intervals)
