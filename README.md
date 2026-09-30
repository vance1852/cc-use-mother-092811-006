# 闭环管理重点路桥灾害预警协同服务

本项目在综合交通运输基础服务（运营机构、交通节点、操作者、参考资料、角色权限、
请求幂等、SQLite 事务与哈希串联审计）之上，提供**重点路桥风险处置服务**：

- 登记设施拓扑、传感器、人工巡检观测、校准状态、阈值规则版本与应急预案版本；
- 把同一场强降雨触发的桥梁位移、边坡含水、巡检报告等信号**归并为可追踪事件**，
  给出置信度、响应级别与影响范围；
- 升级 → 限行 → 封闭 → 抢修 → 复检 → 开放严格按角色与顺序推进，禁止跳步与倒退；
- 重复观测只留档、迟到观测不能回退已发布状态；
- 阈值规则与预案在事件首次生效决策时**冻结快照**，规则换版不静默改变既有决定；
- 校准失效会把相关未结事件列入**重新审查清单**，未经复核人凭证据闭环不得继续处置；
- 开放高风险设施需要**两名来自相互独立机构的技术确认**，且确认人与开放决策人分离。

## 目录

- `src/transport_coordination/`
  - `service.py` / `storage.py` / `audit.py` / `clock.py`：基础服务能力；
  - `risk_service.py`：风险登记、信号归并、处置状态机、校准复核与开放确认；
  - `risk_storage.py`：风险域 SQLite 表结构与状态/角色/阈值常量；
  - `risk_api.py`、`api.py`：HTTP/JSON 边界；
  - `risk_cli.py`：命令行（事件/时间线/复核清单/通用调用/剧本重放）；
  - `acceptance.py`、`risk_acceptance.py`：基础与灾害全流程离线验收。
- `tests/`：基础规则、风险服务、HTTP 路由、命令行与端到端验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
# 基础登记链
PYTHONPATH=src python3 -m transport_coordination.acceptance
# 重放一场强降雨：首个信号 → 归并 → 升级/限行/封闭 → 校准失效冻结 →
# 复核 → 抢修/复检 → 规则换版 → 双独立技术确认 → 开放 → 迟到观测另立事件
PYTHONPATH=src python3 -m transport_coordination.risk_acceptance
```

成功时输出 `status` 为 `ok` 的 JSON（含冻结规则版本、确认机构、时间线条数等），
退出码为 0，且审计哈希链校验通过。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m transport_coordination.api --database service.sqlite3 \
    --host 127.0.0.1 --port 8080
```

写入接口通过 `X-Actor-Id` 标识操作者，所有请求支持 `request_id` 幂等重放。
风险域主要接口：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/risk/facilities` | 登记设施（bridge/slope/tunnel/road/culvert，high/normal） |
| POST | `/risk/facility-links` | 登记设施拓扑关系 |
| POST | `/risk/sensors` | 登记传感器与初始校准时间 |
| POST | `/risk/calibrations` | 登记校准结论（valid/failed） |
| POST | `/risk/rule-versions` | 登记阈值规则版本（可直接 activate） |
| POST | `/risk/rule-versions/activate` | 激活规则版本（旧版转 superseded） |
| POST | `/risk/plan-versions` | 登记应急预案版本（适用范围 + 响应级别/确认份数） |
| POST | `/risk/plan-versions/activate` | 激活预案版本 |
| POST | `/risk/observations` | 上报传感器读数或人工观测，即时评估并归并 |
| GET | `/risk/events` | 事件列表（`episode_id`/`open_only`/`review_required=true`） |
| GET | `/risk/events/{id}` | 事件详情（置信度、影响范围、决策依据、冻结版本） |
| GET | `/risk/events/{id}/timeline` | 完整时间线（观测/决策/确认/复核/拒绝尝试） |
| POST | `/risk/events/{id}/decisions` | 严格处置动作：escalate/restrict/close/repair/reinspect/open |
| POST | `/risk/events/{id}/attempts` | 同 decisions，非法尝试被留档而不是中断重放 |
| POST | `/risk/events/{id}/confirmations` | 技术确认（reviewer，需证据） |
| POST | `/risk/events/{id}/calibration-reviews` | 校准失效后的复核闭环（valid/invalid + 证据） |
| GET | `/risk/facilities/{id}/impact` | 设施拓扑下游影响范围 |

## 命令行

```bash
PYTHONPATH=src python3 -m transport_coordination.risk_cli --database service.sqlite3 events
PYTHONPATH=src python3 -m transport_coordination.risk_cli --database service.sqlite3 reviews
PYTHONPATH=src python3 -m transport_coordination.risk_cli --database service.sqlite3 \
    timeline --event-id <event_id>
echo '{"request_id":"esc-1","action":"escalate"}' | \
    PYTHONPATH=src python3 -m transport_coordination.risk_cli \
    --database service.sqlite3 --actor op-duty call decide
PYTHONPATH=src python3 -m transport_coordination.risk_cli --database service.sqlite3 \
    replay scenario.json
```

`timeline` 输出逐行中文解释：每条信号命中的阈值与规则版本、每项措施冻结的
规则/预案快照与内容哈希、独立技术确认人、校准复核结论以及被拒绝的违规尝试。

## 关键规则

- **归并**：相同 `episode_id` 始终归并；无批次时要求 24 小时时间窗内同一设施或
  拓扑相邻设施。已开放事件不再接收信号，迟到危险读数会另立新事件。
- **置信度**：以多来源通道、多监测指标提升，校准失效污染的信号会降权。
- **状态机**：状态索引只能增大；未完成抢修后的复检观测不能进入复检完成。
- **版本冻结**：事件在"升级"时冻结规则与预案版本及内容哈希，每个决策依据同时
  记录"冻结版本"和"决策时现行版本"，便于解释两者差异。
- **校准复核**：复核标记单调置位，校准恢复不自动清除；`invalid` 保留待复核，
  `valid` 凭证据闭环后方可继续。
- **开放确认**：高风险设施默认 2 份、普通设施 1 份（预案可覆盖份数）；高风险
  的确认人必须来自相互独立机构，开放决策人不得是确认人之一。
