"""FastAPI 入口：规则差分 + 路由诊断两个工具的页面与 JSON API。"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .engine import ValidationFailure, analyze
from .example_data import EXAMPLE_PAYLOAD
from .route_engine import diagnose_text
from .route_examples import ROUTE_EXAMPLES

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="网络安全分析台",
    description="防火墙规则变更精确差分 + 隔离网路由诊断（绕过检查网关 / 无限循环检测）。",
    version="1.1.0",
)


class DiffRequest(BaseModel):
    old: str = Field(..., description="旧规则集 JSON 文本（数组，最多 20 条）")
    new: str = Field(..., description="新规则集 JSON 文本（数组，最多 20 条）")


class RouteDiagRequest(BaseModel):
    config: str = Field(..., description="路由诊断配置 JSON 文本"
                                         "（入口/网关/目标网段/各路由器路由表）")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/route-diag", include_in_schema=False)
def route_diag() -> FileResponse:
    return FileResponse(STATIC_DIR / "route-diag.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/api/example")
def get_example() -> JSONResponse:
    """提供可一键载入的重叠规则示例。"""
    return JSONResponse(EXAMPLE_PAYLOAD)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/analyze")
def post_analyze(req: DiffRequest) -> JSONResponse:
    try:
        result = analyze(req.old, req.new)
    except ValidationFailure as exc:
        # 输入无效：返回带位置的结构化错误，前端据此清除旧结果
        return JSONResponse(status_code=400,
                            content={"ok": False, "errors": exc.errors})
    return JSONResponse(content={"ok": True, "result": result})


@app.get("/api/route-diag/examples")
def get_route_examples() -> JSONResponse:
    """提供可一键载入的绕行 / 循环示例（bypass 与 loop 两份完整配置）。"""
    return JSONResponse(ROUTE_EXAMPLES)


@app.post("/api/route-diag/analyze")
def post_route_analyze(req: RouteDiagRequest) -> JSONResponse:
    try:
        result = diagnose_text(req.config)
    except ValidationFailure as exc:
        # 输入无效：返回带位置的结构化错误，前端据此清除旧结果
        return JSONResponse(status_code=400,
                            content={"ok": False, "errors": exc.errors})
    return JSONResponse(content={"ok": True, "result": result})


@app.exception_handler(Exception)
def unhandled(_request, exc: Exception) -> JSONResponse:  # pragma: no cover
    return JSONResponse(status_code=500,
                        content={"ok": False, "errors": [
                            {"message": f"服务器内部错误："
                                        f"{type(exc).__name__}: {exc}"}]})
