# 闭环管理重点路桥灾害预警协同服务

本项目提供汛期重点路桥风险处置的服务端能力，负责设施拓扑、传感器、人工观测、
校准状态、阈值规则版本与应急预案版本的登记，把同一场强降雨触发的桥梁位移、
边坡含水和巡检报告等多源信号归并为**同一个可追踪事件**，给出置信度与沿拓扑的
影响范围，并驱动升级、限行、封闭、抢修、复检、开放的有序处置闭环。

## 核心规则

- **信号归并**：同一场所、同一拓扑连通分量、归并时间窗内（规则版本自带）命中
  阈值或巡检关键词的观测归并为一个事件；置信度按证据权重与校准状态合成。
- **校准约束**：传感器观测在评估时按其观测时刻的校准状态折算；校准失效、证书
  到期或从未校准的传感器信号不能单独支撑事件，必须有其他证据印证。
- **单向处置状态机**：`heighten 升级 → restrict 限行 → close 封闭 → repair 抢修
  → recheck 复检 → reopen 开放`，前置阶段未生效不得跨越；重复或迟到观测只能
  挂回事件补充证据，不能让处置倒退或重复生效。
- **版本冻结**：每条处置决策记录引用并冻结**决策时刻生效**的阈值规则版本与预案
  版本；规则换版不会改变任何已经发布的决定。
- **独立技术确认**：开放申请进入待确认状态。普通风险设施需要 1 个、高风险设施
  需要 2 个相互独立的外部技术确认（渠道、确认人、确认机构均不得重复，且不能是
  运营方自身）；任一确认驳回则本次开放作废，可重新申请。
- **校准失效复审**：登记校准失效或检测到证书到期后，依赖该传感器的未结事件进入
  复审队列，未解除复审不能关闭事件；完成复检（人工复核）后移出队列。

基础能力（运营机构、操作者、场所、参考资料登记，角色权限、请求幂等、SQLite
事务与哈希串联审计）由 `DomainService` 提供，`RiskService` 在同一套边界上扩展，
所有风险动作同样写入哈希审计链。

## 目录

- `src/transport_coordination/`
  - `risk_schema.py`：风险服务的 SQLite 表结构（设施/拓扑、传感器/校准、观测、
    规则与预案版本、事件、处置、技术确认、复审队列）；
  - `risk_engine.py`：阈值匹配、时态校准判定、拓扑连通分量、信号归并、置信度与
    影响范围计算（纯函数）；
  - `risk_models.py`：事件、信号、处置等只读视图；
  - `risk_service.py`：登记、归并、处置状态机、技术确认与复审的事务化服务；
  - `risk_acceptance.py`：重放一场完整汛期灾害的离线验收；
  - `api.py`：基础与风险接口的 HTTP/JSON 路由；
  - `service.py` / `storage.py` / `audit.py` / `clock.py`：基础登记服务、事务、
    哈希审计链与可替换时钟（含可推进的 `SimulatedClock`）；
- `tests/`：基础规则、风险领域规则（14 项）、HTTP 路由与两场端到端验收测试。

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

基础服务验收：

```bash
PYTHONPATH=src python3 -m transport_coordination.acceptance
```

重点路桥风险处置验收（命令行重放 2026 年 7 月一场强降雨，从首个位移信号、三源
信号归并、按权限与顺序处置、高风险设施双独立技术确认后开放，到 9 月校准证书
到期事件的复审闭环）：

```bash
PYTHONPATH=src python3 -m transport_coordination.risk_acceptance
```

成功时输出 `status` 为 `ok` 的 JSON（退出码 `0`），其中 `incident_one` 给出
事件的信号数、严重等级、置信度、影响设施和**每项措施的依据解释**（规则版本、
预案版本、命中阈值、信号数、决策时置信度），`incident_two` 给出校准证书到期后
未结事件的复审识别与解除结果。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m transport_coordination.api --database transport_coordination.sqlite3 --host 127.0.0.1 --port 8080
```

健康检查使用 `GET /health`。写入接口通过 `X-Actor-Id` 标识操作者；除观测接入外，
登记与处置类接口使用 `request_id` 实现幂等。服务重启后 SQLite 中的业务状态和审计
历史继续保留。

### 主要接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/facilities`、`/facility-links` | 登记设施与拓扑边 |
| POST | `/sensors`、`/calibrations` | 登记传感器与校准记录（含失效、有效期） |
| POST | `/rule-versions`、`/rule-versions/activate` | 发布/切换阈值规则版本（只追加、不覆盖） |
| POST | `/plan-versions` | 发布设施应急预案版本（步骤须严格有序） |
| POST | `/observations` | 接入传感器或巡检观测并驱动自动归并 |
| GET | `/facilities`、`/facilities/{id}/sensors`、`/facilities/{id}/observations` | 登记查询 |
| GET | `/incidents`、`/incidents/{id}` | 未结事件列表与事件详情（信号、影响、处置、复审） |
| POST | `/incidents/{id}/dispositions` | 推进升级/限行/封闭/抢修/复检/开放 |
| POST | `/incidents/{id}/confirmations` | 登记开放技术确认 |
| POST | `/incidents/{id}/close` | 全部设施开放且复审解除后关闭事件 |
| GET | `/incidents/{id}/timeline` | 重放从首个信号到恢复通行的时间线 |
| GET | `/dispositions/{id}/basis` | 还原某项措施冻结的规则、预案、信号与校准证据 |
| GET | `/reviews` | 校准失效/证书到期后需要重新审查的未结事件 |

> 时态语义：观测按其 `observed_at` 适用当时已发布的规则版本与当时的校准状态，
> 因此可以按真实时间线重放历史灾害；事后补发的迟到观测会挂回原事件但不影响
> 既有处置。
