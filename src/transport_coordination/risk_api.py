"""重点路桥风险处置服务的 HTTP 路由。"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse

from .errors import DomainError, ValidationError


def risk_route(service, method: str, path: str, body: dict[str, Any],
               headers: dict[str, str]) -> tuple[int, dict[str, Any]] | None:
    """处理 /risk 前缀请求；不匹配时返回 None 交给基础路由。"""

    parsed = urlparse(path)
    segments = [segment for segment in parsed.path.split("/") if segment]
    query = parse_qs(parsed.query)
    actor_id = headers.get("X-Actor-Id", "")

    def call(method_name: str, **kwargs):
        return getattr(service, method_name)(actor_id=actor_id, **kwargs)

    def receipt_payload(receipt):
        return {**receipt.__dict__, **(receipt.response or {})}

    try:
        if method == "POST" and parsed.path == "/risk/facilities":
            receipt = call("register_facility", **body)
            return 200 if receipt.replayed else 201, receipt_payload(receipt)
        if method == "POST" and parsed.path == "/risk/facility-links":
            receipt = call("register_facility_link", **body)
            return 200 if receipt.replayed else 201, receipt_payload(receipt)
        if method == "POST" and parsed.path == "/risk/sensors":
            receipt = call("register_sensor", **body)
            return 200 if receipt.replayed else 201, receipt_payload(receipt)
        if method == "POST" and parsed.path == "/risk/calibrations":
            receipt = call("record_calibration", **body)
            return 200 if receipt.replayed else 201, receipt_payload(receipt)
        if method == "POST" and parsed.path == "/risk/rule-versions":
            receipt = call("register_rule_version", **body)
            return 200 if receipt.replayed else 201, receipt_payload(receipt)
        if method == "POST" and parsed.path == "/risk/rule-versions/activate":
            receipt = call("activate_rule_version", **body)
            return 200 if receipt.replayed else 201, receipt_payload(receipt)
        if method == "POST" and parsed.path == "/risk/plan-versions":
            receipt = call("register_plan_version", **body)
            return 200 if receipt.replayed else 201, receipt_payload(receipt)
        if method == "POST" and parsed.path == "/risk/plan-versions/activate":
            receipt = call("activate_plan_version", **body)
            return 200 if receipt.replayed else 201, receipt_payload(receipt)
        if method == "POST" and parsed.path == "/risk/observations":
            receipt = call("ingest_observation", **body)
            return 200 if receipt.replayed else 201, receipt_payload(receipt)

        # /risk/events/...
        if len(segments) >= 3 and segments[0] == "risk" and segments[1] == "events":
            event_id = segments[2]
            if method == "GET" and len(segments) == 3:
                return 200, service.get_event(event_id)
            if method == "GET" and len(segments) == 4 and segments[3] == "timeline":
                return 200, service.event_timeline(event_id)
            if method == "POST" and len(segments) == 4 and segments[3] == "decisions":
                receipt = call("decide", event_id=event_id, **body)
                return 200 if receipt.replayed else 201, receipt_payload(receipt)
            if method == "POST" and len(segments) == 4 and segments[3] == "attempts":
                return 200, call("attempt", event_id=event_id, **body)
            if method == "POST" and len(segments) == 4 and segments[3] == "confirmations":
                receipt = call("add_technical_confirmation", event_id=event_id, **body)
                return 200 if receipt.replayed else 201, receipt_payload(receipt)
            if method == "POST" and len(segments) == 4 and segments[3] == "calibration-reviews":
                receipt = call("review_event_after_calibration", event_id=event_id, **body)
                return 200 if receipt.replayed else 201, receipt_payload(receipt)

        if method == "GET" and parsed.path == "/risk/events":
            episode_id = query.get("episode_id", [None])[0]
            open_only = query.get("open_only", ["false"])[0] == "true"
            review_required = query.get("review_required", ["false"])[0] == "true"
            if review_required:
                return 200, {"items": service.list_reviews_required()}
            return 200, {"items": service.list_events(episode_id=episode_id, open_only=open_only)}

        if method == "GET" and len(segments) == 4 and segments[0] == "risk" \
                and segments[1] == "facilities" and segments[3] == "impact":
            return 200, service.impact_area(segments[2])
        return None
    except DomainError as exc:
        return exc.status, {"error": exc.code, "message": str(exc)}
    except (TypeError, ValueError) as exc:
        return 400, {"error": "invalid_request", "message": str(exc)}
