# a3 — AI Agent 行为审计平台

a3（AI Agent Audit）给 AI 编码智能体（Claude Code、Codex CLI）装上「行车记录仪 + 海关」：
**每次对话、每一步工具操作都被如实记录；高危操作（删库、泄露密钥、强推分支等）在发生前被拦下**；
所有记录汇总到一个网页控制台，由团队负责人统一查看、回放与处置，并可按企业规则灵活定制判定边界。

- 对用户：日常开发几乎感觉不到它存在，只有命令被拦截时会收到一句中文提示
- 对管理员：一个网页，看遍全团队 AI 助手干了什么、有没有违规，规则可随时调整

核心能力一览：

- **多 Agent 纳管**：插件化终端采集，`A3_PLUGINS`/`--plugins` 选择启用的 Agent 插件（默认 `all`）
- **会话审计**：用户/助手消息、工具调用与结果完整回放，风险事件红色高亮
- **高危拦截**：Claude Code PreToolUse Hook 在命令执行前判定，`block` 级规则直接阻断（退出码 2）
- **规则中心**：控制台可视化运营规则（内置 14 条 + 自定义增删改），服务端扫描即时热更新，规则集同源下发给终端
- **敏感信息防护**：密钥/私钥/连接串等 DLP 规则命中即拦截，命中片段脱敏后展示
- **断网续传**：终端本地磁盘缓存（spool），网络恢复后自动续传，事件不丢
- **出站脱敏**：会话内容、工具输入/结果在终端侧先做密钥形态二次脱敏再上报
- **设备管理**：凭据门禁注册、Token 鉴权上报、重装复用原身份（Token 不随重装轮换）、控制台吊销/恢复/换发 Token
- **告警中心**：服务端异步扫描入库事件生成告警，支持确认处置与 CSV 导出；规则启停 API 热更新生效

## 使用指南：装好之后怎么用

a3 由两部分组成：**装在开发机上的采集器**（记录 + 把关）和 **一个网页控制台**（汇总 + 展示）。
全程只有两类角色，把其中一方的流程走一遍，剩下的自然就顺了。

### 两类角色

| 角色 | 是谁 | 要做什么 |
| --- | --- | --- |
| **终端用户** | 开发机上装了采集器的人 | 装一次即可，平时正常写代码，几乎感觉不到 a3 存在 |
| **管理员** | 能登录网页控制台、看数据和管规则的人（团队/安全负责人） | 登录控制台，看概览与会话、处置告警、调整规则 |

### 终端用户：一条命令装好，之后「被拦截」才需要你知道

管理员发来接入指南页链接和一条**一次性安装凭据**后，照页面复制执行命令（脚本自动登记设备、
装拦截开关、装常驻服务，断网自动缓存，恢复后补传；首次执行按提示经终端粘贴凭据）：

```bash
curl http://<服务端地址>/install.sh | sh
```

装完就正常开工（想确认装没装好，随时 `~/.a3/bin/a3-agent doctor` 一键自检，全绿即就绪；没有子命令直接敲 `a3-agent` 也等价于此）。三站跑通后采集器开始后台工作：Claude Code / Codex 的每一次对话、每一次工具调用都会自动记录；
其中高危操作按规则在**发生前**被拦下（拦截目前仅对 Claude Code 生效，Codex 只审计不拦截）。

日常里「a3 站出来亮相」只有三种情况：

| 你看到的 | 说明 | 你要做什么 |
| --- | --- | --- |
| Claude Code 里冒出中文提示，说某条命令被审计平台拦截 | 该命令命中高危规则（如 `rm -rf /`、命令里带明文密钥） | 按提示改用其他命令重试；确认是误报就联系管理员调整对应规则 |
| 展示时一段文本被打码成 `AKIA******` 或私钥整段替换 | 涉及明文密钥，a3 先脱敏再上报/展示 | 不用管，这是安全设计 |
| 暂时断网但继续在用 | 事件先存本机，网络恢复自动补传，不丢不重 | 不用管 |

### 管理员：登录控制台，一页一页看/管

浏览器打开 `http://<服务端地址>:8080`，用部署时设置的管理员账号登录。六个页面各管一件事：

| 页面 | 用途 | 用法 |
| --- | --- | --- |
| **概览** | 一眼掌握整体 | 看会话/事件/告警计数；数字异常说明有「值得展开看看」的情况 |
| **会话** | 回放任何一次 AI 工作过程 | 按时间/设备/风险筛选，点开看消息与工具调用，风险事件红色高亮 |
| **告警** | 处置需要你盯的事 | 逐条确认或忽略（状态同步更新），支持导出 CSV 留档 |
| **设备** | 掌握都有哪些机器在采集 | 看在线状态；出现陌生设备说明有人新装了采集器 |
| **规则** | 定义「什么会被拦、被标记」 | 内置规则只管启停；「新建自定义规则」可加自家判定逻辑 |
| **导出** | 把数据带走 | 会话/告警均可导出，用于对接分析平台 |

其中「规则」是最关键的一页——它决定整个系统拦不拦、标不标：

- **内置 14 条**（删库、密钥泄露、强制推送等）默认开启，启用/停用由你随时决定；
- 想管住自家业务动作（例如禁止向某分支强推、禁止读取某目录），就新建一条**自定义规则**，支持正则与路径约束；
- 改动**即时生效**，最迟约 5 分钟同步到每一台终端（含拦截端）。

### 常见疑问

- **装了会拖慢开发吗？** —— 采集是异步的，日常几乎零感知；仅命中规则的命令多一步毫秒级裁决。
- **被拦的命令彻底用不了吗？** —— a3 只「拦」不「删」，改命令重试即可；未命中规则的调用 100% 放行。
- **我做的所有事都会被看到吗？** —— 是的，但范围限于 AI 助手会话日志（`~/.claude/projects`、`~/.codex/sessions`），a3 不扫描其他任何文件。展示前会脱敏。
- **断网 / 重启会丢数据吗？** —— 不会：断网先落本地缓存，网络恢复自动补传；采集器重启后从断点续读。
- **不想用了怎么退出？** —— `./a3-agent uninstall-hook` 摘掉拦截开关，再停掉常驻进程即可；已上报的数据按审计定位不回收。

## 部署

### 单机一体化（个人 / 小团队快速跑起来）

```bash
cp deploy/.env.example deploy/.env     # 1. 编辑 A3_ADMIN_PASSWORD 等配置
make compose-up                        # 2. 构建镜像并拉起 postgres + server
# 3. 浏览器打开 http://127.0.0.1:8080 ，用 .env 中的管理员账号登录
```

或一条命令自动完成上述配置与启动（地址换成对外地址；口令留空自动生成、非回环地址自动开放监听）：

```bash
./deploy/install-server.sh http://aa.bb.com:12345
```

> 新设备登记需**凭据门禁**：管理员登录控制台后在「安装凭据」页生成一次性凭据（限时限次、可吊销，
> 明文仅生成时出现一次）下发给待接入用户；用户照接入指南安装时按提示粘贴凭据，凭据不进命令行/URL/日志。

停止与清理：`make compose-down`（数据保留在 docker volume `a3_pgdata`）。

> 注意：PostgreSQL 容器仅在**首次初始化**空数据卷时读取 `A3_POSTGRES_PASSWORD`；
> 之后修改 `.env` 中的口令不会作用于已初始化的卷，需进入容器执行
> `ALTER USER a3 WITH PASSWORD '...'` 或删除卷重建。

服务端环境变量（见 [deploy/.env.example](deploy/.env.example)）：

| 变量 | 说明 | 默认 |
| --- | --- | --- |
| `A3_ADDR` | 监听地址：默认仅绑本机回环，避免明文意外暴露到局域网 | `127.0.0.1:8080` |
| `A3_DATABASE_URL` | PostgreSQL 连接串 | `postgres://a3:a3@127.0.0.1:5432/a3?sslmode=disable` |
| `A3_ADMIN_USER` / `A3_ADMIN_PASSWORD` | 种子凭据：仅数据库无账号时创建首个 admin（首启）；账号表为空且口令为空时**拒绝启动**，必须显式给出；已有账号即跳过，改密走控制台用户管理 | `admin` / 空(首启必填) |
| `A3_SERVER_STATE_DIR` | 服务端持久状态目录（登录密钥等重启不掉的凭据；目录 0700、密钥文件 0600）；容器部署固定 `/app/state` | `~/.a3-server` |
| `A3_JWT_SECRET` | 登录态签名密钥；留空则自动生成并持久化到服务端状态目录（重启后登录态保持）；显式设置时优先且不写文件 | 空(自动生成+持久化) |
| `A3_NOTIFY_WEBHOOK_URL` | 告警外送 webhook 地址；空则禁用外送（告警仅落控制台） | 空 |
| `A3_NOTIFY_WEBHOOK_FORMAT` | webhook 信封格式：`generic`(兼容 Slack)、`wecom`、`dingtalk`、`feishu` | `generic` |
| `A3_NOTIFY_MIN_SEVERITY` | 外送最低严重级别：`low`(全部)、`medium`、`high` | `low` |
| `A3_TLS_CERT` / `A3_TLS_KEY` | 可选 HTTPS：同时设置证书与私钥 PEM 路径才走 `ListenAndServeTLS`；仅设其一服务端启动报错 | 空(HTTP) |
| `A3_WEB_DIST` | 前端静态目录；空则不托管 | 空 |

## 客户端接入

管理员把控制台「接入指南」页（`http://<服务端地址>/setup-guide`，免登录）
发给采集端用户，连同在「安装凭据」页生成的一次性凭据；用户照页面复制执行
`curl http://<服务端地址>/install.sh | sh` 即可——脚本自动识别平台、下载采集器（服务端镜像内
已内置五平台产物）、凭据登记设备、装 Hook、装常驻服务。指南页会在采集器产物未就绪时给出警示。
详见[安装说明](docs/INSTALL.md)。

接入机制说明：设备登记持管理员下发的一次性安装凭据（限时限次/可吊销），凭据仅经终端 stdin 提交，
不进命令行参数、URL、脚本内容或日志；同一台机器重装/重复执行自动复用原设备身份、**Token 不轮换**，
无需新凭据。Token 不慎丢失时，由管理员在控制台「设备」页吊销后「换发 Token」并私下转交新 Token
（换发后旧 Token 立即失效），或吊销后重跑安装命令建立新身份。自签名 HTTPS 场景参见安装说明。

高级运维（已登记设备用环境变量固定凭据运行）：

```bash
export A3_SERVER_URL=https://a3.example.internal
export A3_DEVICE_TOKEN=a3d_xxx           # 注册成功时下发，仅此一次明文出现
./a3-agent run
```

> 注意：显式提供 Token 时要求本机已有配套设备身份文件（此前在该机器上执行过安装命令），
> 否则启动即报错提示重新登记——避免事件因归属校验失败被整批静默丢弃。
> 把凭据迁移到新机器时请在新机器上重新执行一次安装命令。

采集器常用环境变量：

| 变量 | 说明 | 默认 |
| --- | --- | --- |
| `A3_SERVER_URL` | 服务端地址 | `http://127.0.0.1:8080` |
| `A3_DEVICE_TOKEN` | 设备 Token | 无(需 register 或 env 提供) |
| `A3_SPOOL_DIR` | 断网缓存根目录（incoming/working/quarantine 三子目录） | `~/.a3/spool` |
| `A3_SPOOL_MAX_BYTES` | 断网缓存总容量（含在途租约）；超限最旧批次移入隔离区而非删除 | 512MB |
| `A3_SPOOL_QUARANTINE_MAX_BYTES` | 隔离区归档上限；仅当超限才删除最旧归档并告警 | 128MB |
| `A3_STATE_DIR` | 身份/位点状态目录 | `~/.a3` |
| `A3_BATCH_SIZE` | 上报批大小（上限 500，超限服务端整批拒绝） | 200 |
| `A3_FLUSH_INTERVAL` | 批量化冲刷间隔（秒） | 2s |
| `A3_HEARTBEAT_INTERVAL_SECONDS` | 常驻心跳周期（秒，下限 5）；心跳刷新设备在线态并上报断网缓存积压（控制台「数据滞留」判定）；≤0 关闭（仅靠事件上报维持在线） | 30 |
| `A3_MASK_ENABLED` | 敏感片段脱敏开关 | `true` |
| `A3_INSECURE_SKIP_TLS_VERIFY` | 跳过证书校验(自签名) | `false` |
| `A3_LOG_LEVEL` | debug/info/warn/error | `info` |
| `A3_PLUGINS` | 启用的采集插件，逗号分隔；`all` 或具体名单如 `claude-code,codex` | `all` |
| `A3_RULES_REFRESH_SECONDS` | 规则快照刷新周期（秒，下限 60）；≤0 关闭定时仅启动拉取 | 300 |

> 插件选择也可用命令行 `--plugins claude-code`（优先于环境变量）。未安装对应工具的插件零副作用：
> 监听目录不存在时静默空转。`all` 不可与其他取值混用。

### Hook 安装说明

`install-hook` 向宿主工具配置幂等写入 PreToolUse 配置，可重复执行不产生重复项；`uninstall-hook` 还原。
两者均支持按插件定位（可重复 `--plugin` 或位置参数）：

```bash
./a3-agent install-hook                    # 缺省安装 claude-code 的 Hook
./a3-agent install-hook claude-code        # 显式指定单个插件
./a3-agent uninstall-hook                  # 缺省卸载全部内置插件的 Hook 条目
```

写入 Claude Code `~/.claude/settings.json` 的命令行新形态为 `<a3-binary> hook pretooluse claude-code`；
旧形态 `<a3-binary> hook pretooluse` 升级后仍被识别，下次 install 时原位升级为新条目。不支持 Hook 的
插件（Codex CLI，见下文支持矩阵）在 install 时给出友好提示并正常退出，不算失败。

Hook 进程与 `run` 进程共用同一 spool 根（默认 `~/.a3/spool`），目录三分：
`incoming/`（生产者唯一写点）、`working/`（消费租约）、`quarantine/`（归档留证）。
即使采集器未常驻，被拦截的风险事件也会先落 `incoming/`，下次 `run` 启动后自动补报；
容量超限时最旧批次**移入隔离区归档而非删除**，上报被明确拒绝（400/422）或解码损坏的批次
同样归档留痕。Hook 配置读取失败时自动退回默认配置继续裁决，绝不阻断正常工作流；
Hook 进程**绝不联网**，每次调用读取本地规则快照裁决（见[风险规则](#风险规则)）。

## 架构

```mermaid
flowchart LR
    subgraph 终端
        CC[Claude Code] -->|PreToolUse Hook| HOOK[a3-agent hook]
        CC -->|~/.claude/projects/**/*.jsonl| WATCH[文件监听]
        CODEX[Codex CLI] -->|~/.codex/sessions/**/*.jsonl| WATCH
        HOOK --> CORE[a3-agent Core]
        WATCH --> CORE
        RULES[规则快照<br/>rules-snapshot.json] -.本地读取.-> HOOK
        RUN[run 常驻进程] -.周期拉取.-> RULES
        CORE -->|批量上报 / 断网落盘| SPOOL[本地 spool 缓存]
    end
    subgraph 服务端
        API[HTTP :8080<br/>ingest + console API]
        DB[(PostgreSQL)]
        WEB[Vue3 审计台静态资源]
        API --> DB
        WEB --> API
    end
    SPOOL -->|批量上报(TLS 可选)| API
    API -.devices/rules 下发.- RUN
    审计员 -->|浏览器| WEB
```

- 终端采集器 `cmd/agent`：Core 引擎 + 插件（`internal/agent/plugins/claude`、`internal/agent/plugins/codex`），插件契约见 [插件开发指南](#插件开发指南)
- 服务端 `cmd/server`：Gin，设备侧 ingest API 与控制台 API，迁移 SQL 内嵌于二进制
- 前端 `web`：Vue3 + Element Plus + Pinia，构建产物由服务端 `A3_WEB_DIST` 托管

## 插件开发指南

所有 Agent 差异化能力收敛于 `internal/agent/core/plugin.go` 的 `Plugin` 接口，
Core 只依赖该接口——新增一种 AI Agent 只需实现五个方法：

```go
type Plugin interface {
    // Name 插件唯一标识（如 claude-code），注册表据此去重。
    Name() string

    // LogWatchSpecs 声明需要监听的日志目录与文件规则；
    // homeDir 为当前用户主目录（插件据此推导工具私有日志路径）。
    LogWatchSpecs(homeDir string) []LogWatchSpec

    // ParseLine 将一行私有日志解析为标准事件序列；噪音行返回 nil 不产出事件。
    ParseLine(sourcePath string, line []byte) ([]schema.Event, error)

    // EvaluateHook 处理前置 Hook 输入并给出放行/阻断裁决与风险事件。
    EvaluateHook(hookRequest HookRequest) (HookDecision, error)

    // ConfigureHook 在宿主工具配置中安装(true)/卸载(false)前置 Hook；
    // 实现须保证幂等与可还原。
    ConfigureHook(homeDir string, enable bool) (changed bool, err error)
}
```

参考实现两例：

- `internal/agent/plugins/claude`（Claude Code 插件——JSONL 会话解析、
  PreToolUse 裁决、`~/.claude/settings.json` Hook 管理）
- `internal/agent/plugins/codex`（Codex CLI 插件——rollout 会话解析，纯审计定位）

事件模型见 `pkg/schema/event.go`。

### 内置插件支持矩阵

| 能力 | claude-code | codex |
| --- | --- | --- |
| 会话日志监听 | `~/.claude/projects/**/*.jsonl` | `~/.codex/sessions/**/*.jsonl` |
| 事件解析 | 消息/工具调用/结果全量 | message/function_call/output（reasoning 等忽略） |
| PreToolUse 本地阻断 | 支持（block 规则退出码 2） | 不支持 |
| Hook 自动装卸 | settings.json 幂等装卸 | 不适用 |

Codex 官方 hooks 尚为实验特性（仅可靠覆盖 Bash、需人工 trust、只认 deny），二期对 Codex 定位为
**纯审计**：会话流照常纳管审计，`EvaluateHook` 空裁决、`ConfigureHook` 返回 `ErrHookUnsupported`。
三期候选：官方 hooks 转正后接入本地阻断。已知盲区：`.jsonl.zst` 冷压缩会话文件不解析
（重启/resume 后物化回明文即自动覆盖）。

## 风险规则

内置 14 条预置规则（终端 `internal/agent/plugins/claude/rules.go` 与服务端种子同源，
迁移时幂等同步、守护测试保证两端一致），
类别 `dlp`(敏感信息)/`cmd`(危险命令)/`file`(敏感文件)/`git`(版本控制)，
动作 `block`(Hook 直接阻断)/`alert`(记录并告警)：

| 规则 ID | 名称 | 类别 | 等级 | 动作 |
| --- | --- | --- | --- | --- |
| dlp.aws_access_key | AWS AccessKey 泄露 | dlp | high | block |
| dlp.aws_secret_key | AWS SecretKey 泄露 | dlp | high | block |
| dlp.private_key_block | 私钥文件内容泄露 | dlp | high | block |
| dlp.generic_api_key | 通用 API 密钥泄露 | dlp | high | block |
| dlp.jwt | JWT 令牌泄露 | dlp | high | block |
| dlp.db_conn_string | 数据库连接串凭证泄露 | dlp | high | block |
| cmd.rm_rf_root | 高危递归强删(rm -rf 根/家目录) | cmd | high | block |
| cmd.git_force_push | Git 强制推送 | git | high | block |
| cmd.remote_script_exec | 远程脚本管道执行 | cmd | high | block |
| cmd.chmod_privilege | 全权限放开(chmod 777 系统路径) | cmd | high | block |
| cmd.disk_wipe | 磁盘抹写/格式化 | cmd | high | block |
| file.ssh_private_read | 敏感私钥文件访问 | file | high | block |
| file.dotenv_access | 环境变量文件访问 | file | high | alert |
| git.history_rewrite | Git 历史重写 | git | medium | alert |

### 规则运营

控制台「规则管理」页面提供可视化运营：

- **内置规则**（上表 14 条）：仅允许启停，内容随版本维护
- **自定义规则**：全量增删改（结构化表单 + 正则逐行预检）；删除为软删，审计留痕、ID 不复用
- 变更保存后服务端扫描引擎热更新，对事后扫描**即时生效**
- **操作级留痕**：规则增删改/启停与设备吊销/恢复均记录「谁在何时改了什么」（变更前后快照，
  与业务写同事务），规则页「历史」按钮可查看单条规则的完整变更时间线，另有 `GET /api/v1/audit-log` 查询接口

终端侧为**替换制下发闭环**：

1. 常驻 `run` 进程周期拉取启用规则集（默认 300s，`A3_RULES_REFRESH_SECONDS` 可调），
   落本地快照 `<StateDir>/rules-snapshot.json`（内容摘要 revision 未变则跳过写盘）
2. Hook 进程绝不联网，每次启动按三级降级瀑布取生效规则集：
   快照有效 → 服务端权威集**完全替换**内置（含显式空集 = 全部放行）；
   快照缺失/损坏 → 编译期内置清单兜底；兜底也失败 → 放行（fail-open，不把可用性武器化）
3. 因此终端阻断的生效延迟 ≤ 刷新周期（默认 5 分钟）+ 下次工具调用

两道执行链路：

- **终端侧（事前）**：PreToolUse Hook 按当前生效规则集裁决，`block` 直接拦截
- **服务端（事后）**：事件入库后由异步扫描引擎按**启用规则**二次评估，回写风险标签并落告警
  （`block` 命中一律落告警；`alert` 动作需 severity ≥ medium）；管理 API 为
  `POST/PUT/DELETE/PATCH /api/v1/rules` 系列，控制台与 API 变更均即时热更新扫描引擎

告警外送（可选）：配置 `A3_NOTIFY_WEBHOOK_URL` 后，未处理告警每分钟聚合成一条中文摘要
推送到企业微信/钉钉/飞书/Slack 兼容群机器人（格式由 `A3_NOTIFY_WEBHOOK_FORMAT` 决定）。
聚合防轰炸 + 失败指数退避；连续失败 10 次的告警不再重试（控制台仍可见）。外送为
**at-least-once**（极端情况下可能重复），处置状态以控制台为准。

## 隐私与脱敏

- 会话内容仅在企业内网服务端落库，用于安全审计；设备 Token 鉴权上报，传输走**可选 HTTPS**
  （设置 `A3_TLS_CERT`/`A3_TLS_KEY` 即启用；生产远程部署请务必启用 HTTPS 或前置反向代理终结 TLS）
- 终端出站默认**二次脱敏**：对话内容、工具结果摘要与工具输入 JSON 字符串值中的密钥形态
  （AKIA、JWT、API Key、数据库连接串等）保留前 4 后 4 字符打码，PEM 私钥块整段替换；
  `A3_MASK_ENABLED=false` 可关闭（不建议）
- 规则命中的代码/命令片段默认**脱敏展示**：命中部分超过 8 字符时保留前 4 后 2、中间打码，
  上下文窗口 ±80 字符
- Hook 阻断仅在规则命中的高风险操作上发生（退出码 2 并向 Claude Code 返回中文原因），
  其余工具调用一律放行，不影响正常开发流程
- 采集范围限于 Claude Code 自身的会话日志目录与 Hook 输入，不扫描其他用户文件

## 更多文档

- [安装说明（简明版）](docs/INSTALL.md)
- [业务说明（BRD）](docs/a3%20%28AI%20Agent%20Audit%29%20_%20开源项目业务说明%20%28README-Style%20BRD%29.md)
- [整体软件技术架构设计](docs/a3%20(AI%20Agent%20Audit)%20整体软件技术架构设计（通用可扩展基座）.md)
- [v1.0 一期落地技术方案](docs/a3%20v1.0%20一期落地技术方案（ClaudeCode%20专属实现文档）.md)
- [路线图](docs/ROADMAP.md)

## 开发

```bash
make test            # 全量测试(-p 1 串行集成测试)
make build-agent     # 构建采集器 bin/a3-agent
make build-server    # 构建服务端 bin/a3-server
make build-web       # 构建前端 web/dist
make dev-db-up       # 本地开发 PostgreSQL(:5433)

# 端到端验证（需已启动的服务端，export A3_SMOKE_BASE 与 A3_ADMIN_PASSWORD）：
make smoke           # 服务端冒烟：注册→上报高危事件→核对会话/告警/导出
make smoke-agent A3_SMOKE_BASE=... A3_ADMIN_PASSWORD=***   # 采集器端到端（沙箱 HOME，不碰真实 ~/.claude）
make offline-drill A3_SMOKE_BASE=... A3_ADMIN_PASSWORD=*** # 断网续传演练：落缓存→恢复后自动补报
```

本地起前端开发服务：`cd web && npm install && npm run dev`（Vite 默认 :5173，
接口经 `web/vite.config.js` 代理到本机服务端）。