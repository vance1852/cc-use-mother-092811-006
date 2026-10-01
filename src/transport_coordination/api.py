"""提供不依赖第三方框架的 HTTP/JSON 边界。"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .errors import DomainError, ValidationError
from .risk_service import RiskService
from .service import DomainService
from .storage import Database


def _view(value):
    """把数据对象转换为 JSON 结构。"""

    if hasattr(value, "__dict__"):
        return {key: _view(item) for key, item in value.__dict__.items()}
    if isinstance(value, (list, tuple)):
        return [_view(item) for item in value]
    if isinstance(value, dict):
        return {key: _view(item) for key, item in value.items()}
    return value


def risk_route(service: RiskService, method: str, path: str, body: dict[str, Any],
               actor_id: str) -> tuple[int, dict[str, Any]] | None:
    """分派重点路桥风险处置接口；不匹配时返回 None。"""

    parsed = urlparse(path)
    segments = [segment for segment in parsed.path.split("/") if segment]
    query = parse_qs(parsed.query)

    def q(name: str, default: str | None = None) -> str | None:
        return query.get(name, [default])[0]

    if method == "POST" and parsed.path == "/facilities":
        receipt = service.register_facility(actor_id=actor_id, **body)
        return 200 if receipt.replayed else 201, receipt.__dict__
    if method == "POST" and parsed.path == "/facility-links":
        receipt = service.link_facilities(actor_id=actor_id, **body)
        return 200 if receipt.replayed else 201, receipt.__dict__
    if method == "POST" and parsed.path == "/sensors":
        receipt = service.register_sensor(actor_id=actor_id, **body)
        return 200 if receipt.replayed else 201, receipt.__dict__
    if method == "POST" and parsed.path == "/calibrations":
        receipt = service.record_calibration(actor_id=actor_id, **body)
        return 200 if receipt.replayed else 201, receipt.__dict__
    if method == "POST" and parsed.path == "/rule-versions":
        receipt = service.publish_rules(actor_id=actor_id, **body)
        return 200 if receipt.replayed else 201, receipt.__dict__
    if method == "POST" and parsed.path == "/rule-versions/activate":
        receipt = service.activate_rules(actor_id=actor_id, **body)
        return 200 if receipt.replayed else 201, receipt.__dict__
    if method == "POST" and parsed.path == "/plan-versions":
        receipt = service.publish_plan(actor_id=actor_id, **body)
        return 200 if receipt.replayed else 201, receipt.__dict__
    if method == "POST" and parsed.path == "/observations":
        return 201, service.ingest_observation(actor_id=actor_id, **body)
    if method == "GET" and parsed.path == "/facilities":
        return 200, {"items": [item.__dict__ for item in service.list_facilities(q("site_id"))]}
    if len(segments) == 3 and segments[0] == "facilities" and method == "GET":
        if segments[2] == "sensors":
            return 200, {"items": [item.__dict__ for item in service.list_sensors(segments[1])]}
        if segments[2] == "observations":
            return 200, {"items": [item.__dict__ for item in service.list_observations(segments[1])]}
    if method == "GET" and parsed.path == "/incidents":
        if q("status", "open") != "open":
            return 200, {"items": []}
        return 200, {"items": [_view(item) for item in service.list_open_incidents(q("site_id"))]}
    if len(segments) == 2 and segments[0] == "incidents" and method == "GET":
        return 200, _view(service.get_incident(segments[1]))
    if len(segments) == 3 and segments[0] == "incidents" and method == "GET":
        if segments[2] == "timeline":
            return 200, service.timeline(segments[1])
    if len(segments) == 3 and segments[0] == "incidents" and method == "POST":
        if segments[2] == "dispositions":
            receipt = service.advance_disposition(actor_id=actor_id, incident_id=segments[1], **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if segments[2] == "confirmations":
            receipt = service.add_technical_confirmation(
                actor_id=actor_id, incident_id=segments[1], **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if segments[2] == "close":
            receipt = service.close_incident(actor_id=actor_id, incident_id=segments[1], **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
    if len(segments) == 3 and segments[0] == "dispositions" and segments[2] == "basis" \
            and method == "GET":
        return 200, service.decision_basis(segments[1])
    if method == "GET" and parsed.path == "/reviews":
        return 200, {"items": service.review_queue()}
    return None


def route(service: DomainService, method: str, path: str, body: dict[str, Any] | None,
          headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    """把一个 HTTP 语义请求分派到领域服务。"""

    headers = headers or {}
    body = body or {}
    parsed = urlparse(path)
    actor_id = headers.get("X-Actor-Id", "")
    try:
        if method == "GET" and parsed.path == "/health":
            valid, count = service.verify_audit()
            return 200, {"status": "ok", "audit_valid": valid, "audit_events": count}
        if method == "POST" and parsed.path == "/organizations":
            receipt = service.register_organization(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/actors":
            receipt = service.register_actor(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/sites":
            receipt = service.register_site(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "POST" and parsed.path == "/domain-records":
            receipt = service.record_domain_data(actor_id=actor_id, **body)
            return 200 if receipt.replayed else 201, receipt.__dict__
        if method == "GET" and parsed.path == "/domain-records":
            query = parse_qs(parsed.query)
            site_id = query.get("site_id", [""])[0]
            if not site_id:
                raise ValidationError("site_id 不能为空")
            category = query.get("category", [None])[0]
            return 200, {"items": [item.__dict__ for item in service.list_domain_data(site_id, category)]}
        if method == "GET" and parsed.path == "/audit-events":
            query = parse_qs(parsed.query)
            after = int(query.get("after_sequence", ["0"])[0])
            return 200, {"items": service.audit_events(after)}
        if isinstance(service, RiskService):
            risk_result = risk_route(service, method, path, body, actor_id)
            if risk_result is not None:
                return risk_result
        return 404, {"error": "route_not_found", "message": "接口不存在"}
    except DomainError as exc:
        return exc.status, {"error": exc.code, "message": str(exc)}
    except (TypeError, ValueError) as exc:
        return 400, {"error": "invalid_request", "message": str(exc)}


class Handler(BaseHTTPRequestHandler):
    """把标准库 HTTP 请求转换为路由调用。"""

    service: DomainService

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._write(400, {"error": "invalid_json", "message": "请求体必须是 UTF-8 JSON"})
            return
        status, payload = route(self.service, self.command, self.path, body,
                                {"X-Actor-Id": self.headers.get("X-Actor-Id", "")})
        self._write(status, payload)

    def _write(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> int:
    """启动本地 HTTP 服务。"""

    parser = argparse.ArgumentParser(description="启动重点路桥风险处置协同服务")
    parser.add_argument("--database", default="service.sqlite3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    database = Database(args.database)
    Handler.service = RiskService(database)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
