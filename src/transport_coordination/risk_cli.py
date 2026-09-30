"""重点路桥风险处置服务命令行。

示例：

  # 重放一场灾害从首个信号到恢复通行的完整时间线
  python3 -m transport_coordination.risk_cli --database demo.sqlite3 \\
      timeline --event-id <event_id>

  # 查看校准失效后需要重新审查的未结事件
  python3 -m transport_coordination.risk_cli --database demo.sqlite3 reviews

登记、观测、处置、确认等写操作通过 JSON 文件或 --data 提交，例如：

  python3 -m transport_coordination.risk_cli --database demo.sqlite3 \\
      --actor op-duty call ingest_observation --data obs.json
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .errors import DomainError
from .risk_service import RiskService
from .storage import Database


def _load_data(args: argparse.Namespace) -> dict[str, Any]:
    if getattr(args, "data", None):
        with open(args.data, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    else:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
    if not isinstance(payload, dict):
        raise ValueError("请求体必须是 JSON 对象")
    return payload


def _print(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="重点路桥风险处置服务命令行")
    parser.add_argument("--database", default="risk_service.sqlite3", help="SQLite 数据库路径")
    parser.add_argument("--actor", default=None, help="操作者 actor_id，写入调用时注入")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("events", help="列出风险事件")
    p_timeline = sub.add_parser("timeline", help="重放单个事件的完整时间线")
    p_timeline.add_argument("--event-id", required=True)
    sub.add_parser("reviews", help="列出校准失效后需要重新审查的未结事件")
    p_event = sub.add_parser("event", help="查看单个事件（含置信度与影响范围）")
    p_event.add_argument("--event-id", required=True)
    p_impact = sub.add_parser("impact", help="查看设施影响范围")
    p_impact.add_argument("--facility-id", required=True)
    p_call = sub.add_parser("call", help="调用任意服务写方法")
    p_call.add_argument("method")
    p_call.add_argument("--data", help="JSON 文件路径；缺省读标准输入")
    p_replay = sub.add_parser("replay", help="从 JSON 剧本顺序重放多个调用")
    p_replay.add_argument("scenario", help="剧本 JSON 文件路径")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    database = Database(args.database)
    service = RiskService(database)
    try:
        if args.command == "events":
            _print({"items": service.list_events()})
        elif args.command == "reviews":
            _print({"items": service.list_reviews_required()})
        elif args.command == "event":
            _print(service.get_event(args.event_id))
        elif args.command == "impact":
            _print(service.impact_area(args.facility_id))
        elif args.command == "timeline":
            _print(render_timeline(service.event_timeline(args.event_id)))
        elif args.command == "call":
            payload = _load_data(args)
            if args.actor:
                payload.setdefault("actor_id", args.actor)
            method = getattr(service, args.method, None)
            if method is None:
                raise ValueError(f"未知方法 {args.method}")
            receipt = method(**payload)
            _print(receipt.__dict__ if hasattr(receipt, "__dict__") else receipt)
        elif args.command == "replay":
            _print(replay_scenario(service, args.scenario, default_actor=args.actor))
        return 0
    except (DomainError, ValueError, OSError, json.JSONDecodeError) as exc:
        _print({"error": getattr(exc, "code", "cli_error"), "message": str(exc)})
        return 1
    finally:
        database.close()


def render_timeline(timeline: dict[str, Any]) -> dict[str, Any]:
    """把结构化时间线转换为带人类解释的版本。"""

    event = timeline["event"]
    lines = [
        f"事件 {event['event_id']}（灾害批次 {event.get('episode_id')}）",
        f"主体设施：{event['primary_facility_id']} {event['facility_name']}"
        f"[风险等级={event['facility_criticality']}]，当前状态={event['state']}，"
        f"管控状态={event['control_status']}",
        f"最高严重度={event['severity']}，响应级别={event['response_level']}，"
        f"置信度={event['confidence']}，待校准复核={event['review_required']}",
        f"冻结阈值版本={event.get('rule_version_id')}，冻结预案版本={event.get('plan_version_id')}",
        "",
        "时间线：",
    ]
    for item in timeline["items"]:
        at = item["at"]
        kind = item["kind"]
        if kind == "observation":
            tag = "重复留档" if item.get("duplicate") else (
                "迟到留档" if item.get("late") else (
                    "复检证据" if item.get("is_reinspection") else "观测"))
            signal = item.get("signal")
            detail = ""
            if signal:
                threshold = signal["matched"].get("threshold")
                detail = (f" → 信号 {signal['level']}"
                          f"（阈值版本={signal.get('rule_version_id')}"
                          f"{('，命中阈值 ' + str(threshold)) if threshold is not None else ''}"
                          f"{'，校准失效污染' if signal.get('tainted') else ''}）")
            lines.append(f"  [{at}] {tag} {item['facility_id']}/{item['metric']}"
                         f" value={item.get('value')} {item.get('text','')}{detail}")
        elif kind == "decision":
            lines.append(f"  [{at}] 决策 {item['actor_id']}：{item['from_state']} → "
                         f"{item['to_state']}（动作 {item['action']}）")
            basis = item["basis"]
            lines.append(f"        依据：冻结规则 {basis.get('frozen_rule_version_id')}"
                         f"（hash {str(basis.get('frozen_rule_content_hash'))[:12]}…），"
                         f"冻结预案 {basis.get('frozen_plan_version_id')}，"
                         f"信号数 {len(basis.get('signals', []))}，"
                         f"决策时现行规则 {basis.get('active_rule_version_at_decision')}")
            if basis.get("technical_confirmations"):
                who = [f"{c['actor_id']}@{c['organization_id']}"
                       for c in basis["technical_confirmations"]]
                lines.append(f"        独立技术确认：{', '.join(who)}")
        elif kind == "technical_confirmation":
            lines.append(f"  [{at}] 技术确认 {item['actor_id']}@{item['organization_id']}"
                         f"：{item['opinion']}")
        elif kind == "calibration_review":
            lines.append(f"  [{at}] 校准复核 {item['reviewer_id']}：结论={item['conclusion']}"
                         f"（失效传感器 {item.get('failed_sensor_id')}）{item.get('note','')}")
        elif kind == "rejected_attempt":
            lines.append(f"  [{at}] 被拒绝尝试 {item['actor_id']} {item['action']}：{item['reason']}")
    return {"event": event, "explanation": lines}


def replay_scenario(service: RiskService, scenario_path: str,
                    default_actor: str | None = None) -> dict[str, Any]:
    """按剧本顺序重放调用；每步可覆盖 actor，失败立即终止。"""

    with open(scenario_path, "r", encoding="utf-8") as handle:
        scenario = json.load(handle)
    results = []
    for step in scenario.get("steps", []):
        payload = dict(step.get("payload", {}))
        if default_actor:
            payload.setdefault("actor_id", default_actor)
        method = getattr(service, step["method"])
        outcome = method(**payload)
        rendered = outcome.__dict__ if hasattr(outcome, "__dict__") else outcome
        results.append({"step": step.get("name"), "method": step["method"], "result": rendered})
    return {"scenario": scenario.get("name"), "steps": results}


if __name__ == "__main__":
    raise SystemExit(main())
