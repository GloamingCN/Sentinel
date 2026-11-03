# Sentinel 被动 IDS 全周期交付方案

> 版本：v1.0  
> 日期：2026-11-03  
> 状态：方案定稿，待实施  
> 目标硬件：4 vCPU / 8 GB RAM / 300 GB SSD  
> 交付形态：单传感器、旁挂 SPAN、被动检测、WebUI 运营

---

## 执行摘要

- 方案：旁挂 SPAN → Suricata 8.0.8 → EVE JSON → Rust Sentinel → ClickHouse/SQLite → WebUI。单传感器，4C/8G/300G，目标 300 Mbps。
- 周期：单人约 12-14 周；P2 结束有可用 MVP（5-6 周），P3 结束 v1.0 RC（9-10 周），P5 完成交付。
- 第一件事：P0 用 3 天验证 300 Mbps 采集、ClickHouse 写入延迟、规则 reload、PCAP 提取；不达标先调硬件和配置，不进入 P1。
- 最大风险：SPAN 只镜像单方向或带宽不足、4C/8G 资源竞争、300G 磁盘写满。
- 待定：Sentinel 自身许可证（默认建议 Apache-2.0）、备份目标。

---

## 0. 文档说明

这份文档把当前已经确认的方案收敛成可执行的交付计划，覆盖从可行性验证到 v1.0 交付的完整周期。

文档分三部分：

1. 方案定稿：范围、架构、数据、接口、部署、安全。
2. 阶段计划：P0 到 P5 的目标、任务、交付物、验收门禁。
3. 交付清单：上线前必须完成的检查项和已知风险。

所有阶段以“能不能验收”为准，不以“代码写完了”为准。

---

## 1. 项目目标与范围

### 1.1 目标

Sentinel 是一个旁挂式网络 IDS：

- 从交换机 SPAN 或流量镜像口采集双向流量。
- 用 Suricata 做 L7 检测，输出 EVE JSON。
- Sentinel 负责规则更新、资产与 GeoIP 富化、告警关联、PCAP 取证、syslog 外发和 WebUI 运营。
- ClickHouse 存事件，SQLite 存配置、资产、triage 状态和审计。
- v1.0 支持单传感器，目标流量 300 Mbps，最低 1080p 宽屏运营。

### 1.2 范围边界

v1.0 包含：

- 交换机 SPAN / 流量镜像接入。
- Suricata 规则检测、EVE 消费、告警查询、关联、时间线。
- 四组社区规则源的每日更新与回滚。
- 威胁 PCAP 的按流保留与下载。
- 资产表、离线 GeoIP、事件类型归一化。
- syslog 告警外发。
- 本地认证、RBAC、审计。
- WebUI 驾驶舱与配置管理。

v1.0 不包含：

- 内联阻断、路由模式、透明桥接、NAT。
- 多传感器中心化管理。
- OIDC/SSO。
- 定时报表、PDF 报告。
- 全流量 PCAP 长期留存（默认只保留告警流）。
- 在线 GeoIP API。

### 1.3 假设与约束

- 现场有可用的 SPAN 镜像口，且镜像为双向。
- 采集网卡独立，管理网卡独立。
- 操作系统为 Debian 12 或 Ubuntu 24.04，systemd 管理服务。
- 单传感器，单套 ClickHouse，单机部署。
- 开发资源按 1-2 人估算；单人约 12-14 周，双人可并行到 9-11 周。
- 目标流量 300 Mbps；1 Gbps 不在本硬件配置的承诺范围内。

---

## 2. 成功标准

### 2.1 功能标准

- SPAN 采集能稳定拿到双向流量。
- ET Open 和 abuse.ch 规则能每日自动更新，失败可回滚。
- 告警能显示五元组、协议、攻击手法、目标、MITRE/CVE、关联告警和时间线。
- 告警可以确认、关闭、备注、抑制。
- 告警命中后能保留相关 PCAP，并从 WebUI 下载。
- 资产表能配置 IP/CIDR，告警能显示资产名、分组和关键级别。
- GeoIP 能离线匹配国家、ASN、组织。
- 告警能通过 syslog 外发。
- WebUI 在 1920×1080 下四块卡片一排，1366×768 下 2×2，无横向滚动。

### 2.2 性能标准

| 指标 | 目标 |
|---|---|
| 采集流量 | 300 Mbps，持续 1 小时 |
| 采集丢包 | `kernel_drops` < 0.1% |
| EVE 到 ClickHouse | P95 < 1 秒 |
| 规则 reload | < 60 秒 |
| 告警到 PCAP 可下载 | < 5 秒 |
| 告警列表查询 | 24 小时范围 P95 < 2 秒 |
| 驾驶舱首屏 | 1080p 下 < 3 秒 |
| 连续运行 | 24 小时无重启、无内存泄漏 |

### 2.3 交付标准

- 代码、构建产物、systemd 单元、配置模板、数据库迁移、OpenAPI、WebUI 静态资源齐全。
- 安装、管理员、用户、运行手册齐全。
- 备份恢复、升级回滚、故障演练通过。
- 验收报告和已知问题清单签字。

---

## 3. 总体架构

### 3.1 架构图

```
交换机 SPAN / 流量镜像
        │ 双向
        ▼
   采集网卡 dpi0（无 IP，promisc）
        │
        ▼
Suricata 8.0.8（AF_XDP，退回 AF_PACKET）
        │ EVE JSON / unix_stream
        ▼
Sentinel（Rust）
  ├─ EVE 解析与归一化
  ├─ 资产 / GeoIP / 事件类型富化
  ├─ 告警关联与时间线
  ├─ 规则管理 → rules/current → Suricata reload
  ├─ PCAP 提取 → 本地文件 + ClickHouse 元数据
  ├─ syslog 外发
  └─ REST API / SSE → WebUI
        │
        ├─ ClickHouse：事件、告警、流、协议元数据、PCAP 元数据
        └─ SQLite：配置、资产、用户、triage、抑制、审计
```

### 3.2 数据流

1. SPAN 口把双向流量送到 `dpi0`。
2. Suricata 通过 AF_XDP 采集，做协议解析和规则匹配。
3. Suricata 把 alert、flow、dns、tls、http、anomaly、stats 写到 `unix_stream`。
4. Sentinel 逐行解析 EVE，补资产、GeoIP、事件类型、规则源和规则方向。
5. 事件批量写入 ClickHouse；告警同时进入 SSE、syslog 和 PCAP 提取队列。
6. PCAP 提取器按五元组和时间窗从 ring 文件提取流量，写 per-flow 文件并落元数据。
7. WebUI 通过 REST/SSE 查询和操作。

### 3.3 组件职责

| 组件 | 职责 |
|---|---|
| Suricata | 采集、TCP 重组、协议解析、规则匹配、EVE 输出 |
| Sentinel Core | EVE 消费、归一化、富化、关联、规则、PCAP、syslog |
| ClickHouse | 事件和告警的列式存储、聚合查询 |
| SQLite | 配置、资产、用户、triage、抑制、审计、规则源元数据 |
| WebUI | 驾驶舱、告警 triage、规则/资产/设置管理 |
| GeoIP 文件 | 离线国家、ASN、组织匹配 |
| syslog | 告警外发到 SIEM/日志平台 |

---

## 4. 部署与硬件

### 4.1 硬件

| 资源 | 配置 |
|---|---|
| CPU | 4 vCPU |
| 内存 | 8 GB |
| 磁盘 | 300 GB SSD |
| 网卡 | 1 块采集网卡 + 1 块管理网卡 |
| 操作系统 | Debian 12 / Ubuntu 24.04 |

内存分配：

| 用途 | 预算 |
|---|---:|
| ClickHouse | 4.5-5 GB |
| Suricata | 约 2 GB |
| Sentinel / OS | 约 1 GB |

CPU 分配：

- Suricata AF_XDP `threads: 2`，抓包网卡 IRQ 绑到 0-1 核。
- ClickHouse 使用 2-3 核，`max_threads=2`。
- Sentinel 与系统共享剩余 CPU，靠 `CPUWeight` 调度。
- systemd 权重：Suricata 200，ClickHouse 100，Sentinel 100。

ClickHouse 资源限制：

```xml
<max_server_memory_usage>5000000000</max_server_memory_usage>
<max_memory_usage>3000000000</max_memory_usage>
<max_threads>2</max_threads>
<max_concurrent_queries>4</max_concurrent_queries>
<background_pool_size>4</background_pool_size>
<mark_cache_size>536870912</mark_cache_size>
```

systemd 给 ClickHouse 加 `MemoryMax=5G`、`CPUWeight=100`、`Nice=10`、`IOWeight=100`。Suricata 按 2 GB 预算调低 `stream.memcap` 和 `flow.memcap`。

### 4.2 网络

- 采集网卡不配 IP，开 promiscuous。
- 管理网卡单独接管理网段。
- SPAN 必须双向，保留 VLAN tag。
- 采集口带宽大于镜像流量，避免 oversubscription。
- 开 NTP，保证告警、PCAP、syslog 时间一致。

### 4.3 系统

- 关闭采集网卡的 GRO/LRO/GSO/TSO，Suricata 的 `disable-offloading` 兜底。
- `vm.swappiness=10`，保留少量 swap 作为保护。
- 文件系统建议 ext4，挂载 `noatime`。
- 防火墙只开放管理口必要端口；ClickHouse 只监听 localhost 或私网。

### 4.4 磁盘预算

| 用途 | 预算 |
|---|---:|
| 系统 + 服务 | 15 GB |
| ClickHouse | 120 GB |
| PCAP（ring + 保留） | 108 GB |
| 日志 / spool / 规则 | 15 GB |
| 余量 | 42 GB |

磁盘到 80% 触发清理：

1. 删除最旧的 PCAP。
2. 清理过期的 DNS/TLS/HTTP。
3. 最后才动 alerts 元数据。

### 4.5 软件版本

| 软件 | 版本 |
|---|---|
| Suricata | 8.0.8 |
| ClickHouse | 26.8 LTS |
| Rust | 2024 edition，stable |
| Node.js | 24 LTS（仅构建 WebUI） |
| PostgreSQL | 不使用 |

---

## 5. 技术选型

| 层 | 选型 | 说明 |
|---|---|---|
| 检测引擎 | Suricata 8.0.8 | TCP 重组、协议解析、规则匹配、EVE 输出 |
| 采集 | Suricata AF_XDP | 物理 SPAN 口；不支持时退回 AF_PACKET |
| 控制面 | Rust 2024 + Tokio 1.54 + Axum 0.8 | 单二进制，异步 API 和后台任务 |
| 数据库访问 | sqlx 0.9 + `clickhouse` 0.15.3 | SQLite 迁移；ClickHouse 批量插入 |
| 序列化 | serde / serde_json | EVE 解析、API、配置 |
| HTTP 客户端 | reqwest + rustls | 规则下载、通知 |
| 可观测 | tracing + OpenTelemetry + Prometheus | 结构化日志、指标、链路 |
| CLI | clap | `sentinel doctor`、`rules`、`pcap`、`user` |
| WebUI | SvelteKit 2 + Svelte 5 + Tailwind 4 | 静态 SPA，嵌入 Rust 二进制 |
| 组件 | shadcn-svelte + Bits UI | 组件源码进仓库，样式可改 |
| 数据请求 | TanStack Query / Table | 缓存、轮询、服务端分页、虚拟滚动 |
| 图表 | ECharts | Sankey、gauge、bar、pie、line，按需 tree-shake |
| API 类型 | openapi-typescript + openapi-fetch | 从 Rust OpenAPI 生成 TS 类型 |
| 实时 | SSE | 告警和传感器状态推送 |
| GeoIP | maxminddb 0.32 | 离线 `.mmdb` |
| PCAP | pcap-parser + zstd | 读取 ring、写 `.pcap.zst` |
| 认证 | Argon2id + session + API token | 本地认证 |

---

## 6. 功能设计

### 6.1 采集

Suricata 配置要点：

```yaml
af-xdp:
  - interface: dpi0
    threads: 2
    disable-promisc: false

outputs:
  - eve-log:
      filetype: unix_stream
      filename: /run/sentinel/eve.sock
      community-id: yes
      types: [alert, anomaly, http, dns, tls, flow, stats]
  - pcap-log:
      enabled: yes
      filename: threat.pcap
      limit: 128 MiB
      max-files: 32
      compression: none
      mode: multi
      dir: /var/lib/sentinel/pcap/ring
      conditional: alerts
```

`mode: multi` 下 `limit` 和 `max-files` 按线程计算；2 个线程时环形缓冲为 `128 MiB × 32 × 2 = 8 GiB`。

要求：

- EVE alert 打开 rule metadata，保留 `attack_target`、`tag`、`cve`、`mitre_*`、`confidence`。
- `community-id: yes`，用于跨告警和 PCAP 关联。
- 采集口只读，Sentinel 不参与转发。

### 6.2 检测与事件归一化

每条告警入库时计算：

| 字段 | 来源 |
|---|---|
| `alert_id` | `sensor_id + flow_id + signature_id + timestamp` 的稳定哈希 |
| `event_type` | category/tag/MITRE 映射，未知归“其他” |
| `rule_source` | SID 到规则源的映射，入库时建立 |
| `rule_direction` | 规则头 `->` / `<>` 或 `flow` 关键字 |
| `src_asset` / `dst_asset` | 资产表最长前缀匹配 |
| `geoip` | 离线 `.mmdb` |
| `severity` | Suricata `alert.severity`，1=高、2=中、3=低 |

事件类型枚举：

- 扫描探测
- 网络攻击 / Web 攻击
- 暴力破解
- 恶意软件 / C2
- 异常服务
- 异常通讯
- DNS 事件
- 挖矿
- 数据外传
- 其他

一条告警只落一个 `event_type`，保证统计占比相加为 100%。

### 6.3 规则管理

规则源固定四组：

| 源 | 内容 | 许可 |
|---|---|---|
| `et/open` | 通用威胁签名 | 混合：SIDs 1-3464、100000000-100000908 为 GPLv2；2000000-2799999 为 BSD |
| `abuse.ch/feodotracker` | Botnet C2 IP | CC0-1.0 |
| `abuse.ch/urlhaus` | 恶意 URL / 域名 | CC0-1.0 |
| `abuse.ch/sslbl-ja3` | 恶意 JA3 | CC0-1.0 |

更新计划：

- 每天 03:00（配置时区）执行，加随机抖动。
- 支持 `sentinel rules update` 手动触发，`--check` 只看 diff。
- 每个源用 ETag / If-Modified-Since，没变不下载、不 reload。
- 失败重试 15 分钟、1 小时、6 小时；三次失败告警，继续用 last good。

更新流程：

1. 下载到 staging，记录 SHA256，安全解包。
2. 解析规则，检查 SID 冲突。
3. 应用本地 `disable.conf`、`enable.conf`、`modify.conf`。
4. 合并候选规则集，跑 `suricata -T`。
5. 原子切换 `rules/current`。
6. 通过 Unix socket 发 `ruleset-reload-rules`。
7. 检查 `ruleset-stats` 和 `ruleset-failed-rules`。
8. 失败或失败规则超阈值，切回上一版并 reload。
9. 保留最近 5 个版本，更新记录写 ClickHouse `rule_updates`。

约束：

- reload 不重启 Suricata，flow 表保留。
- 上游不可用时继续用 last good，不 reload 空规则集。
- 规则更新前必须校验，不能把语法错误带进生产。
- 本地覆盖文件在每次更新后重新应用。

### 6.4 威胁 PCAP

- Suricata `pcap-log` 使用 `conditional: alerts`，只写有告警的流。
- 环形缓冲 8 GB，按文件滚动。
- Sentinel 收到告警后，按五元组和时间窗从 ring 文件提取双向流量。
- 每条流写一个 `.pcap.zst`，同流多个告警共用一个文件。
- 单流上限 50 MB，超过标记 `truncated`。
- 元数据入 ClickHouse `pcap` 表：path、size、sha256、first/last packet、packets。
- 保留 90 天或 100 GB；磁盘到 80% 先删最旧 PCAP。
- WebUI 下载走 API，RBAC + 审计，文件权限 0600。
- 全流量 ring 默认关闭，需要时再开，代价是磁盘 I/O。

### 6.5 资产表

在 WebUI 维护，不做自动发现。

字段：

- 名称
- 类型：服务器 / 客户端 / 网络设备 / 其他
- 分组
- 负责人
- 关键级别：critical / high / medium / low
- IP/CIDR 列表
- 标签
- 描述

匹配规则：

- 保存后重建内存 LPM 前缀表。
- 最长前缀匹配；精确 IP 优先于 CIDR。
- 重复 IP/CIDR 给出冲突提示。
- 告警富化 `src_asset`、`dst_asset`、`asset_group`、`criticality`。
- 受害目标排行和桑基图的资产组使用同一张表；未匹配归“未分类”。

### 6.6 GeoIP

- 使用离线 `.mmdb`，支持 MaxMind GeoLite2 和 DB-IP Lite。
- 老的 GeoIP `.dat` 已停更，不直接支持。
- 文件放 `/var/lib/sentinel/geoip/`，记录来源、版本、构建日期、SHA256。
- WebUI 支持上传/替换，`ArcSwap` 热加载，不重启。
- 入库补 `src_country`、`src_asn`、`src_org`、`dst_country`、`dst_asn`、`dst_org`。
- 超过 45 天未更新，UI 显示“GeoIP 库过期”。
- 不做在线 API 查询。

### 6.7 告警关联

关联键：

- `alert_id`
- `flow_id`
- `community_id`
- 五元组
- `src_ip` / `dst_ip`
- `signature_id`
- `tag`
- `mitre_technique_id`

关联分组：

1. 同流：`flow_id` 或 `community_id`。
2. 同五元组：时间窗内完全相同的五元组。
3. 同源：时间窗内同一个源 IP。
4. 同目标：时间窗内同一个目标 IP，按端口细分。
5. 同手法：同签名、同 tag 或同 MITRE technique。

默认时间窗 1 小时，单组最多 50 条，结果缓存 30 秒。量大后再预计算 `alert_links`。

时间线合并 alert、flow、dns、tls、http，按时间排序。自动攻击链判定放到后续版本，M1 先做分组和时间线。

### 6.8 告警外发

v1.0 只做 syslog。

- 格式：RFC 5424，MSG 放 JSON。
- 传输：TCP + TLS 默认，UDP 兼容老设备。
- 端口：6514（TLS）/ 514（UDP）。
- facility 默认 `local0`。
- severity 映射：critical → 2，high → 3，medium → 4，low → 6。
- JSON 包含：`alert_id`、时间、severity、signature、五元组、`event_type`、资产名/分组、规则源、详情页 URL。
- 异步队列发送，失败重试；队列满丢弃并记 metric，告警本体仍在 ClickHouse。
- 只发新告警，抑制过的不发。
- WebUI 配 host、port、协议、TLS 证书、facility、开关，并提供测试发送。

不做 webhook、邮件、IM。

### 6.9 WebUI

视觉：浅色、卡片、高密度安全驾驶舱，中文优先。基准 1920×1080，1440 四块一排，1080 内容区 2×2，720 以下降级。

页面：

| 页面 | 内容 |
|---|---|
| 驾驶舱 | Sankey、工作台、四块统计、趋势、事件表 |
| 告警 | 列表、筛选、详情抽屉、关联、时间线、triage、PCAP |
| 流量 | 五元组、协议、字节/包数、关联告警 |
| 事件 | DNS / TLS / HTTP 三个 tab |
| PCAP | 按流/时间/签名查询、下载、保留状态 |
| 规则 | 四源状态、更新、diff、历史、回滚、本地覆盖 |
| 资产 | 资产 CRUD、IP/CIDR、分组、关键级别 |
| 传感器 | pps、带宽、丢包、EVE 延迟、ClickHouse 队列、磁盘 |
| 设置 | 采集、PCAP、ClickHouse、syslog、GeoIP、用户、审计 |

驾驶舱模块：

- Top 攻击关系 Sankey：来源 → 事件类型 → 目标 → 资产组。
- 工作台：处置进度、待处理告警。
- 威胁来源排行：Top 10 源 IP、告警数、高危数、最后出现。
- 受害目标排行：Top 10 目标 IP + 端口、资产组、告警数。
- 事件类型分布：环图 + 图例 + 总数。
- 事件类型统计：类型、数量、占比、高危数、处置率、环比。
- 事件时间趋势。
- 事件列表：规则描述、来源、目标、类型、级别、时间、ID。

交互：

- 所有筛选进 URL，刷新和分享一致。
- SSE 推新告警，不自动跳，顶部提示“N 条新告警”。
- 点排行、扇区、Sankey 节点都写筛选条件，所有模块同步刷新。
- 告警详情用右侧抽屉，保留列表上下文。
- 键盘：`/` 搜索、`j/k` 切换、`Enter` 打开、`a` 确认、`c` 关闭、`Esc` 返回。

### 6.10 认证与权限

- 只做本地认证，不接 OIDC。
- 密码 Argon2id，登录限速，密码策略可配。
- HttpOnly + Secure + SameSite session cookie，服务端 session 表，CSRF token。
- API token 存哈希，带 scope 和过期时间。
- 角色：admin / operator / viewer。
- 审计记录登录、配置、规则、triage 操作。
- 忘记密码走 `sentinel user reset`。

### 6.11 配置管理

- WebUI 是主配置面，CLI 和自动化走同一套 REST API。
- desired state 存 SQLite。
- 后端生成 `suricata.yaml`、规则包含、保留策略、syslog 配置等运行时文件。
- 变更流程：draft → validate → apply，带 diff。
- 每次 apply 生成配置版本，记录操作人、时间、结果。
- 失败保留上一版，不回滚到半成品。
- secret 只写不读，存 systemd credentials 或系统 keyring。
- 生成文件记 hash，手改显示 drift，可一键重新生成。
- 支持配置导出/导入，便于备份和迁移。

### 6.12 可观测性

`sentinel sensor status` 展示：

- pps、带宽、接口速率。
- Suricata `capture.kernel_packets`、`capture.kernel_drops`、decode/stream 错误。
- EVE 延迟、最后事件时间、规则加载数、flow/stream memcap。
- ClickHouse 插入队列、延迟、磁盘、parts。

告警条件：

- `kernel_drops` 持续大于 0。
- 接口 down。
- 十分钟无事件。
- 磁盘 80%。
- ClickHouse 不可用。
- 规则 reload 失败。
- GeoIP 库过期。

---

## 7. 数据设计

### 7.1 ClickHouse

数据库：`sentinel`。

表：

| 表 | 内容 | 默认 TTL |
|---|---|---|
| `alerts` | 告警 + 富化字段 | 180 天 |
| `flows` | 原始流 | 14 天 |
| `flows_1m` | 1 分钟聚合流 | 90 天 |
| `dns` | DNS 查询/响应 | 90 天 |
| `tls` | SNI、JA3/JA4、证书 | 90 天 |
| `http` | host、URI、method、UA | 90 天 |
| `sensor_stats` | pps、丢包、队列 | 7 天 |
| `pcap` | PCAP 元数据 | 90 天 |
| `rule_updates` | 规则版本和结果 | 180 天 |
| `rule_sources` | 规则源配置和许可 | 常驻 |

公共列：

- `ts DateTime64(6, 'UTC')`
- `sensor_id LowCardinality(String)`
- `flow_id UInt64`
- `community_id String`
- `src_ip` / `dest_ip` `IPv6`
- `src_port` / `dest_port` `UInt16`
- `proto` / `app_proto` `LowCardinality(String)`
- `raw String`（原始 EVE JSON）
- `pcap_ref String`

`alerts` 额外列：

- `alert_id UInt64`
- `signature_id UInt32`
- `signature String`
- `category LowCardinality(String)`
- `severity UInt8`
- `action LowCardinality(String)`
- `event_type LowCardinality(String)`
- `attack_target LowCardinality(String)`
- `tags Array(String)`
- `cve Array(String)`
- `confidence LowCardinality(String)`
- `signature_severity LowCardinality(String)`
- `mitre_tactic_id` / `mitre_tactic_name`
- `mitre_technique_id` / `mitre_technique_name`
- `rule_source LowCardinality(String)`
- `rule_direction LowCardinality(String)`
- `src_asset` / `dst_asset` / `asset_group`
- `src_country` / `src_asn` / `src_org`
- `dst_country` / `dst_asn` / `dst_org`

建表参数：

- `PARTITION BY toDate(ts)`
- `ORDER BY (sensor_id, ts)`
- `LowCardinality` 用于重复字符串
- `ZSTD(3)` 用于 `raw` 和大文本
- `signature_id`、`src_ip`、`dst_ip` 加 bloom filter 跳数索引

写入：

- EVE 解析后批量插入，1 秒或 1 万行。
- `RowBinary`，有界队列。
- ClickHouse 挂了先落盘 `/var/lib/sentinel/spool`，恢复后重放。
- alerts 不丢；flows 在压力下采样或丢弃。

### 7.2 SQLite

表：

- `config_versions`：配置版本、diff、状态、操作人。
- `users`：用户名、Argon2id hash、角色、禁用状态。
- `sessions`：session id、用户、过期时间。
- `api_tokens`：token hash、scope、过期时间、最后使用。
- `assets`：名称、类型、分组、负责人、关键级别、标签、描述。
- `asset_networks`：资产 ID、CIDR、备注。
- `alert_state`：alert_id、status、assignee、note、updated_at。
- `suppressions`：match 类型、值、原因、过期时间、创建人。
- `event_type_map`：category/tag/MITRE → event_type。
- `rule_sources`：源、许可、启用状态、更新周期、last_good。
- `audit_log`：操作人、动作、对象、前后值、时间。
- `geoip_files`：路径、来源、版本、构建日期、SHA256。

### 7.3 PCAP 文件

路径：

```
/var/lib/sentinel/pcap/ring/          # Suricata 环形缓冲
/var/lib/sentinel/pcap/flows/YYYY/MM/DD/<flow_id>.pcap.zst
/var/lib/sentinel/pcap/tmp/           # 提取临时文件
```

规则：

- 先写临时文件，fsync 后 rename。
- 文件名带 flow_id，重名复用。
- 记录 SHA256 和包数。
- 磁盘 80% 开始按时间删除。
- 文件权限 0600。

### 7.4 API

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/api/v1/dashboard` | 驾驶舱聚合数据 |
| GET | `/api/v1/alerts` | 告警列表、筛选、分页 |
| GET | `/api/v1/alerts/{id}` | 告警详情 |
| GET | `/api/v1/alerts/{id}/related` | 关联告警 |
| GET | `/api/v1/alerts/{id}/timeline` | 时间线 |
| POST | `/api/v1/alerts/{id}/state` | 确认/关闭/备注 |
| POST | `/api/v1/suppressions` | 创建抑制 |
| GET | `/api/v1/flows` | 流查询 |
| GET | `/api/v1/events/{type}` | DNS/TLS/HTTP 事件 |
| GET | `/api/v1/pcap` | PCAP 列表 |
| GET | `/api/v1/pcap/{flow_id}` | 下载 PCAP |
| GET | `/api/v1/rules` | 规则源和版本 |
| POST | `/api/v1/rules/update` | 立即更新 |
| POST | `/api/v1/rules/rollback` | 回滚 |
| GET | `/api/v1/assets` | 资产列表 |
| POST | `/api/v1/assets` | 新建资产 |
| PUT | `/api/v1/assets/{id}` | 修改资产 |
| DELETE | `/api/v1/assets/{id}` | 删除资产 |
| GET | `/api/v1/sensor` | 传感器健康 |
| GET | `/api/v1/settings` | 读取配置 |
| PUT | `/api/v1/settings` | 提交配置 |
| POST | `/api/v1/settings/apply` | 应用配置 |
| GET | `/api/v1/stream/alerts` | SSE 告警流 |
| GET | `/api/v1/audit` | 审计日志 |

所有写接口要求 CSRF token；API token 走 `Authorization: Bearer`。

---

## 8. 性能与容量

### 8.1 目标

- 300 Mbps 持续采集。
- 单传感器，单 ClickHouse。
- 72 小时稳定性测试。

### 8.2 容量估算

- `alerts`：数量取决于规则和流量，180 天足够。
- `flows`：14 天原始，`flows_1m` 90 天聚合。
- `dns/tls/http`：90 天元数据。
- PCAP：90 天或 100 GB。

按 300 Mbps 估算，300 GB 盘可以支撑；超过 300 Mbps 或要保留 30 天原始 flow，需要升到 8C/16G 或拆 ClickHouse。

### 8.3 升级信号

- `kernel_drops` 持续大于 0。
- ClickHouse 查询 P95 明显变长。
- 磁盘 80%。
- 持续超过 500 flow/s。
- 需要保留 30 天以上原始 flow。

---

## 9. 安全与合规

- WebUI 默认只监听管理网段，不暴露公网。
- session cookie HttpOnly/Secure/SameSite；写操作 CSRF。
- API token 哈希存储，最小权限。
- PCAP 含敏感数据，权限 0600，下载走 RBAC 和审计。
- secrets 不进日志、不进前端、不进 Git。
- 依赖使用 `cargo audit`、`cargo deny`、`npm audit`，产出 SBOM。
- ET Open 实际为混合许可：部分 GPLv2，部分 BSD；UI 显示真实许可，分发时附许可证。
- abuse.ch 为 CC0-1.0。
- GeoIP 数据库按来源许可使用；GeoLite2 需账号，DB-IP Lite 需署名。
- Sentinel 自身许可证待定，默认建议 Apache-2.0。

---

## 10. 测试策略

| 层 | 内容 |
|---|---|
| 单元测试 | Rust 解析、归一化、规则编译、资产匹配、配置校验；前端工具函数 |
| 集成测试 | EVE → ClickHouse、规则 reload、PCAP 提取、syslog 发送 |
| 端到端 | 登录、告警查询、详情、triage、配置 apply、回滚 |
| PCAP 回放 | 固定 fixture，验证告警、事件类型、PCAP 提取 |
| 性能测试 | 300 Mbps 回放、1 小时稳定性、查询 P95 |
| 故障注入 | 杀 Suricata、停 ClickHouse、磁盘 85%、坏规则、SPAN 单方向 |
| 安全测试 | 越权、CSRF、SQL 注入、XSS、路径遍历、弱密码 |

CI 门禁：

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo test`
- 前端 `lint` + `test`
- OpenAPI 契约 diff
- PCAP 回放冒烟
- 构建 WebUI 并嵌入二进制

---

## 11. 部署、升级、备份、回滚

### 11.1 部署

- 单二进制 `sentinel` + 静态 WebUI。
- systemd 单元：
  - `sentinel.service`
  - `suricata.service`
  - `clickhouse-server.service`
- 目录：
  - `/etc/sentinel/`
  - `/var/lib/sentinel/`
  - `/var/log/sentinel/`
  - `/run/sentinel/`
- 首次启动生成管理员密码，要求立即修改。

### 11.2 升级

1. 备份配置和数据库 schema 版本。
2. 停 Sentinel，保留 Suricata 和 ClickHouse。
3. 替换二进制和 WebUI。
4. 执行 SQLite / ClickHouse 迁移。
5. 启动 Sentinel，跑 `sentinel doctor`。
6. 验证告警、规则、PCAP、syslog。

### 11.3 备份

- 配置：`sentinel config export`。
- SQLite：在线备份或文件快照。
- ClickHouse：每周 `BACKUP` 到本地或 NAS。
- PCAP：按保留策略，不强制备份。
- 每季度做一次恢复演练。

### 11.4 回滚

- 应用版本回滚：保留上一版二进制。
- 配置回滚：`config_versions` 选择上一版 apply。
- 规则回滚：`rules` 历史选择上一版 reload。
- 数据库迁移只做向前兼容，破坏性变更必须带降级脚本。

---

## 12. 全周期阶段计划

### 12.1 总览

| 阶段 | 周期 | 目标 | 关键交付 |
|---|---|---|---|
| P0 可行性验证 | 3 天 | 验证采集、写入、规则、PCAP 的性能 | Spike 报告、Go/No-Go |
| P1 基础骨架 | 1 周 | 仓库、CI、schema、doctor、EVE 读取 | 可回放的最小链路 |
| P2 核心 IDS MVP | 3-4 周 | 采集、检测、规则、PCAP、告警、syslog | 可用 MVP |
| P3 WebUI 驾驶舱 | 3-4 周 | 驾驶舱、告警 triage、资产、配置 | v1.0 RC |
| P4 运营加固 | 2-3 周 | 备份、演练、安全、打包、性能 | 可交付版本 |
| P5 验收交付 | 1 周 | UAT、文档、移交、发布 | v1.0 |

单人总周期约 12-14 周；双人并行约 9-11 周。

### 12.2 P0 可行性验证

目标：用最小成本验证技术路线，不写正式产品代码。

任务：

- 安装 Debian/Ubuntu、Suricata 8.0.8、ClickHouse 26.8。
- 配 SPAN 或 PCAP 回放，跑 300 Mbps。
- 验证 EVE `unix_stream` 消费。
- 验证 ClickHouse 批量写入和查询延迟。
- 验证规则下载、`suricata -T`、reload、回滚。
- 验证 `pcap-log conditional: alerts` 和按流提取。
- 记录 CPU、内存、丢包、磁盘增量。

交付物：

- Spike 报告：环境、命令、指标、问题。
- Go/No-Go 结论。
- 需要调整的配置清单。

出口条件：

- 300 Mbps 下 `kernel_drops` < 0.1%。
- EVE → ClickHouse P95 < 1 秒。
- 规则 reload < 60 秒。
- 告警到 PCAP 可下载 < 5 秒。
- 4C/8G 内存不 OOM。

### 12.3 P1 基础骨架

目标：把工程骨架和最小数据链路搭起来。

任务：

- Cargo workspace：`sentinel`、`sentinel-eve`。
- `rust-toolchain.toml`、fmt、clippy、test。
- SQLite 迁移框架；ClickHouse schema 迁移。
- 配置模型、TOML bootstrap、JSON Schema。
- `sentinel doctor`：内核、网卡、Suricata、ClickHouse、磁盘、权限。
- `sentinel pcap replay`：回放 fixture。
- EVE 解析器和基础类型。
- WebUI 工程骨架，OpenAPI 客户端生成。
- systemd 单元草案。

交付物：

- 可编译的仓库。
- 可执行的 `doctor` 和 `pcap replay`。
- ClickHouse/SQLite 初始 schema。
- CI 跑通。

出口条件：

- PCAP 回放能产生告警并写入 ClickHouse。
- `doctor` 全绿。
- CI 无警告。
- WebUI 能构建并嵌入二进制。

### 12.4 P2 核心 IDS MVP

目标：形成可日常使用的单传感器 IDS。

任务：

- SPAN 采集、Suricata 配置模板、AF_XDP/AF_PACKET。
- EVE 消费、归一化、资产/GeoIP/event_type 富化。
- ClickHouse 批量写入、spool、重放。
- 规则管理：四源、每日更新、校验、reload、回滚。
- PCAP ring、按流提取、保留、下载 API。
- 告警 API、SSE、CLI。
- syslog 外发。
- 传感器健康指标。
- 本地认证、用户、API token、RBAC 后端。
- 资产表后端和 LPM 匹配。
- GeoIP `.mmdb` 加载和热更新。

交付物：

- 可运行的 `sentinel` 服务。
- 告警、规则、PCAP、传感器 API。
- 基础 CLI。
- 部署脚本和配置模板。

出口条件：

- 300 Mbps 连续 1 小时无丢包。
- 告警从产生到可查询 < 2 秒。
- 规则更新成功并可回滚。
- 告警 PCAP 可下载。
- syslog 能收到 JSON 消息。
- 资产和 GeoIP 能正确富化。

### 12.5 P3 WebUI 驾驶舱

目标：交付可运营的 WebUI 和告警 triage。

任务：

- 登录、session、CSRF、RBAC。
- 应用壳、侧栏、顶部筛选、响应式断点。
- 驾驶舱：Sankey、工作台、来源/目标排行、类型分布、类型统计、趋势、事件表。
- 告警列表、详情抽屉、关联分组、时间线、流、PCAP、原始 EVE。
- triage：确认、关闭、备注、抑制、下载。
- 规则页：源状态、更新、diff、历史、回滚、本地覆盖。
- 资产页：CRUD、IP/CIDR、分组、关键级别。
- 传感器页：健康指标。
- 设置页：采集、PCAP、ClickHouse、syslog、GeoIP、用户、审计。
- 配置版本、diff、apply、回滚、drift。
- E2E 测试。

交付物：

- 可用的 WebUI。
- 配置管理和审计。
- v1.0 RC。

出口条件：

- 1920×1080 四块一排，1366×768 2×2，无横向滚动。
- 告警 triage 全流程可用。
- 驾驶舱筛选联动正确。
- 配置 apply 失败能回滚。
- E2E 用例通过。

### 12.6 P4 运营加固

目标：把系统从“能用”变成“可交付”。

任务：

- 备份/恢复演练。
- 升级/回滚演练。
- 故障注入：杀 Suricata、停 ClickHouse、磁盘 85%、坏规则、SPAN 单方向。
- 24 小时稳定性测试。
- 安全审查：CSRF、XSS、越权、路径遍历、弱密码、依赖漏洞。
- 打包：二进制、systemd、安装脚本、Docker 可选。
- 文档：安装、管理员、用户、运行手册。
- SBOM 和许可证清单。

交付物：

- 可交付安装包。
- 运行手册。
- 验收测试报告。
- 已知问题清单。

出口条件：

- 所有故障演练通过。
- 备份能恢复。
- 升级和回滚不丢配置。
- 无高危漏洞。
- 24 小时稳定性通过。

### 12.7 P5 验收交付

目标：完成 UAT 和移交。

任务：

- 真实 SPAN 环境 UAT 5 天。
- 核对功能、性能、告警质量、PCAP、syslog。
- 修订文档。
- 交付培训/交接。
- 发布 v1.0。

交付物：

- 验收报告。
- 最终文档。
- 发布包和校验和。
- 移交记录。

出口条件：

- 验收清单全部通过或已知问题有明确规避方案。
- 运维能独立完成安装、升级、回滚、排障。

### 12.8 关键路径与并行

关键路径：

```
P0 → P1 → P2 → P3 → P4 → P5
```

可并行：

- P1 后期开始 WebUI 壳和 OpenAPI 客户端。
- P2 后端 API 稳定后，P3 前端可以并行开发。
- P4 的文档和打包可以提前开始。

不建议并行：

- 规则管理和 PCAP 提取都依赖 EVE 和 ClickHouse，先稳定一条链路再拆。
- 资产、GeoIP、event_type 会改告警表结构，尽量在 P2 一次定好。

### 12.9 阶段门禁汇总

| 门禁 | 条件 |
|---|---|
| G0 | 300 Mbps、CH 延迟、规则 reload、PCAP 提取达标 |
| G1 | 仓库、CI、schema、doctor、回放链路通过 |
| G2 | 采集、告警、规则、PCAP、syslog 端到端通过 |
| G3 | 驾驶舱、triage、配置管理、E2E 通过 |
| G4 | 备份恢复、故障演练、安全、稳定性通过 |
| G5 | UAT 签字、文档齐全、发布包可复现 |

---

## 13. 交付物清单

- 源码和构建脚本。
- `sentinel` 二进制。
- WebUI 静态资源。
- systemd 单元。
- Suricata / ClickHouse 配置模板。
- SQLite / ClickHouse 迁移。
- OpenAPI 文档。
- 安装手册。
- 管理员手册。
- 用户手册。
- 运行手册（故障处理、备份、升级、回滚）。
- 验收报告。
- 测试 fixture 和 PCAP 样本。
- SBOM 和许可证清单。
- 发布说明和已知问题。

---

## 14. 验收清单

### 功能

- [ ] SPAN 双向采集正常。
- [ ] ET Open + abuse.ch 四源规则加载。
- [ ] 每日规则更新成功，失败可回滚。
- [ ] 告警列表、详情、关联、时间线可用。
- [ ] triage 状态持久化。
- [ ] PCAP 可提取、可下载、可清理。
- [ ] 资产表可配置，告警能显示资产。
- [ ] GeoIP 离线匹配正常。
- [ ] syslog 能收到告警。
- [ ] 驾驶舱四块统计和 Sankey 正确联动。
- [ ] 配置 apply/回滚可用。
- [ ] 本地认证和 RBAC 生效。

### 性能

- [ ] 300 Mbps 1 小时无丢包。
- [ ] EVE → ClickHouse P95 < 1 秒。
- [ ] 规则 reload < 60 秒。
- [ ] 告警到 PCAP < 5 秒。
- [ ] 24 小时稳定性通过。

### 运维

- [ ] 安装脚本可用。
- [ ] 备份恢复演练通过。
- [ ] 升级/回滚演练通过。
- [ ] 故障演练通过。
- [ ] 文档齐全。

### 安全

- [ ] 管理面不暴露公网。
- [ ] CSRF/XSS/越权测试通过。
- [ ] 依赖无高危漏洞。
- [ ] PCAP 权限和审计生效。
- [ ] 许可证清单齐全。

---

## 15. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| SPAN 只镜像单方向 | TCP 重组失效，漏检 | 上线前抓包确认双向 |
| SPAN 带宽不足 | 静默丢包 | 监控 `kernel_drops`，采集口带宽留余量 |
| 4C/8G 资源竞争 | Suricata 丢包或 CH 查询慢 | 限 CH 内存/线程，CPUWeight 调度 |
| 300G 磁盘写满 | 入库失败 | TTL、聚合、PCAP 上限、80% 告警 |
| 规则噪声大 | 告警没人看 | 抑制、调优、只开四源 |
| 规则更新失败 | 检测缺口 | 保留 last good、校验、回滚 |
| ClickHouse 单点 | 存储不可用 | spool、降级查询、备份 |
| Suricata C/GPL | 分发合规 | 独立进程，附许可证 |
| 加密流量 | 只能看元数据 | 明确预期，不做 TLS 拦截 |
| PCAP 敏感 | 数据泄露 | 权限、审计、保留期 |
| GeoIP 库过期 | 地理信息不准 | 45 天提醒，手动更新 |
| 本地认证 | 无 SSO、密码管理 | 强密码、限速、CLI 重置 |
| UI 范围膨胀 | 延期 | 以 triage 为主线，报表/多传感器后置 |

---

## 16. 待定事项

- Sentinel 自身许可证，默认建议 Apache-2.0。
- 备份目标：本地磁盘 / NAS / S3。
- 多传感器中心化管理。
- OIDC/SSO。
- 深色主题。
- 资产 CSV 批量导入。
- ClickHouse 高可用。
- 自动攻击链判定。

---

## 附录 A：ClickHouse DDL 示例

```sql
CREATE DATABASE IF NOT EXISTS sentinel;

CREATE TABLE sentinel.alerts (
    ts DateTime64(6, 'UTC'),
    sensor_id LowCardinality(String),
    alert_id UInt64,
    flow_id UInt64,
    community_id String,
    src_ip IPv6,
    src_port UInt16,
    dest_ip IPv6,
    dest_port UInt16,
    proto LowCardinality(String),
    app_proto LowCardinality(String),
    signature_id UInt32,
    signature String,
    category LowCardinality(String),
    severity UInt8,
    action LowCardinality(String),
    event_type LowCardinality(String),
    attack_target LowCardinality(String),
    tags Array(String),
    cve Array(String),
    confidence LowCardinality(String),
    signature_severity LowCardinality(String),
    mitre_tactic_id LowCardinality(String),
    mitre_tactic_name LowCardinality(String),
    mitre_technique_id LowCardinality(String),
    mitre_technique_name LowCardinality(String),
    rule_source LowCardinality(String),
    rule_direction LowCardinality(String),
    src_asset String,
    dst_asset String,
    asset_group LowCardinality(String),
    src_country LowCardinality(String),
    src_asn UInt32,
    src_org String,
    dst_country LowCardinality(String),
    dst_asn UInt32,
    dst_org String,
    pcap_ref String,
    raw String CODEC(ZSTD(3)),
    INDEX idx_sig signature_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_src src_ip TYPE bloom_filter GRANULARITY 4,
    INDEX idx_dst dest_ip TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (sensor_id, ts)
TTL ts + INTERVAL 180 DAY DELETE;
```

```sql
CREATE TABLE sentinel.flows_1m (
    minute DateTime('UTC'),
    sensor_id LowCardinality(String),
    src_ip IPv6,
    dest_ip IPv6,
    dest_port UInt16,
    proto LowCardinality(String),
    app_proto LowCardinality(String),
    flows AggregateFunction(count),
    bytes AggregateFunction(sum, UInt64),
    packets AggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(minute)
ORDER BY (sensor_id, minute, src_ip, dest_ip, dest_port)
TTL minute + INTERVAL 90 DAY DELETE;
```

```sql
CREATE TABLE sentinel.pcap (
    ts DateTime64(6, 'UTC'),
    sensor_id LowCardinality(String),
    flow_id UInt64,
    signature_id UInt32,
    path String,
    size UInt64,
    sha256 FixedString(64),
    first_pkt_ts DateTime64(6, 'UTC'),
    last_pkt_ts DateTime64(6, 'UTC'),
    packets UInt32,
    truncated UInt8
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (sensor_id, ts, flow_id)
TTL ts + INTERVAL 90 DAY DELETE;
```

---

## 附录 B：事件类型映射

| event_type | 典型来源 |
|---|---|
| 扫描探测 | ET SCAN、port scan、nmap |
| 网络攻击 / Web 攻击 | ET EXPLOIT、Web Application Attack、SQL Injection |
| 暴力破解 | SSH/FTP/RDP brute force |
| 恶意软件 / C2 | ET MALWARE、Cobalt Strike、botnet |
| 异常服务 | 异常端口、异常协议、服务识别异常 |
| 异常通讯 | 可疑 User-Agent、异常 DNS/HTTP 通信 |
| DNS 事件 | DNS 隧道、DGA、恶意域名 |
| 挖矿 | mining、XMR、矿池域名 |
| 数据外传 | 大流量外发、异常上传 |
| 其他 | 未匹配 |

映射表存 SQLite `event_type_map`，支持 category、tag、MITRE tactic 三类匹配，按优先级取第一条。

---

## 附录 C：API 约定

- 所有接口前缀 `/api/v1`。
- JSON 请求/响应，时间 UTC ISO 8601。
- 分页使用 keyset：`cursor` + `limit`，默认 50，最大 500。
- 错误格式：

```json
{
  "error": {
    "code": "invalid_argument",
    "message": "from must be before to",
    "field": "from"
  }
}
```

- 写接口要求 `X-CSRF-Token` 或 Bearer token。
- SSE 事件：`alert`、`sensor`、`lag`。

---

## 附录 D：Suricata 关键配置

```yaml
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,192.168.0.0/16,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"

outputs:
  - eve-log:
      filetype: unix_stream
      filename: /run/sentinel/eve.sock
      community-id: yes
      types:
        - alert:
            metadata:
              rule:
                metadata: true
              app-layer: true
              flow: true
        - anomaly
        - http
        - dns
        - tls
        - flow
        - stats
  - pcap-log:
      enabled: yes
      filename: threat.pcap
      limit: 128 MiB
      max-files: 32
      compression: none
      mode: multi
      dir: /var/lib/sentinel/pcap/ring
      conditional: alerts
```

启动后用 `suricata --af-xdp=dpi0` 或配置 `af-xdp.interface`。

---

## 附录 E：阶段验收记录模板

| 项 | 结果 | 证据 | 备注 |
|---|---|---|---|
| 采集双向 | 通过/失败 | `tcpdump` 截图 |  |
| 300 Mbps 丢包 | 通过/失败 | `suri-stats` |  |
| EVE→CH 延迟 | 通过/失败 | ClickHouse 查询 |  |
| 规则更新 | 通过/失败 | `rule_updates` |  |
| PCAP 提取 | 通过/失败 | 文件 + sha256 |  |
| 告警 triage | 通过/失败 | 页面截图 |  |
| 配置回滚 | 通过/失败 | 版本记录 |  |
| 备份恢复 | 通过/失败 | 恢复记录 |  |
| 故障演练 | 通过/失败 | 演练记录 |  |
| 安全检查 | 通过/失败 | 扫描报告 |  |
