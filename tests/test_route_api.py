"""路由诊断 FastAPI 接口测试。"""

import json

from fastapi.testclient import TestClient

from app.main import app
from app.route_examples import BYPASS_EXAMPLE, LOOP_EXAMPLE

client = TestClient(app)


def test_route_diag_page_served_with_nav():
    resp = client.get("/route-diag")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "路由诊断" in resp.text
    # 导航可回到规则差分页
    assert 'href="/"' in resp.text


def test_index_page_links_to_route_diag():
    resp = client.get("/")
    assert resp.status_code == 200
    assert 'href="/route-diag"' in resp.text


def test_examples_endpoint_and_both_analyze_ok():
    resp = client.get("/api/route-diag/examples")
    assert resp.status_code == 200
    payload = resp.json()
    assert set(payload) == {"bypass", "loop"}
    for kind in ("bypass", "loop"):
        resp2 = client.post("/api/route-diag/analyze",
                            json={"config": json.dumps(payload[kind])})
        assert resp2.status_code == 200
        body = resp2.json()
        assert body["ok"] is True
        assert body["result"]["intervals"], kind


def test_analyze_bypass_example_flags_bypass():
    resp = client.post("/api/route-diag/analyze",
                       json={"config": json.dumps(BYPASS_EXAMPLE)})
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert result["summary"]["bypassFound"] is True
    assert result["summary"]["verdict"] == "bypass-possible"
    outcomes = {o for iv in result["intervals"] for o in iv["outcomes"]}
    assert "delivered-bypass" in outcomes


def test_analyze_loop_example_flags_loop_with_cycle_marks():
    resp = client.post("/api/route-diag/analyze",
                       json={"config": json.dumps(LOOP_EXAMPLE)})
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert result["summary"]["loopFound"] is True
    loop_witnesses = [w for iv in result["intervals"]
                      for w in iv["witnesses"] if w["outcome"] == "loop"]
    assert loop_witnesses
    for w in loop_witnesses:
        cs = w["cycleStart"]
        assert cs is not None and 0 <= cs < len(w["hops"])
        # 重复段：最后一跳回到 cycleStart 处的路由器
        assert w["hops"][-1]["nextHop"] == w["hops"][cs]["router"]


def test_analyze_validation_error_400_with_location():
    bad = json.dumps({
        "entryRouter": 1,
        "gatewayRouter": 9,
        "targetCidr": "10.0.0.1/24",
        "routers": [{"id": 1, "routes": [
            {"prefix": "10.0.0.0/24", "nextHops": []},
            {"prefix": "10.0.0.0/24", "nextHops": ["deliver", 7]},
        ]}],
    })
    resp = client.post("/api/route-diag/analyze", json={"config": bad})
    assert resp.status_code == 400
    data = resp.json()
    assert data["ok"] is False
    fields = {e.get("field") for e in data["errors"]}
    assert {"gatewayRouter", "targetCidr", "nextHops", "prefix"} <= fields
    # 路由级错误带定位信息
    route_errors = [e for e in data["errors"] if e.get("routeIndex") is not None]
    assert route_errors and all(e["routerId"] == 1 for e in route_errors)


def test_analyze_json_syntax_error_location():
    resp = client.post("/api/route-diag/analyze",
                       json={"config": '{"entryRouter": 1,\n}'})
    assert resp.status_code == 400
    err = resp.json()["errors"][0]
    assert "JSON" in err["message"]
    assert err["line"] is not None and err["col"] is not None


def test_missing_body_field_422():
    resp = client.post("/api/route-diag/analyze", json={})
    assert resp.status_code == 422


def test_existing_diff_api_still_works():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    resp = client.get("/api/example")
    assert resp.status_code == 200
