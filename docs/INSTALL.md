# a3 安装说明

整体就两样东西：**服务端**（一台机器上跑，网页控制台 + 数据库）和**采集器**（装在每台开发机上）。
先装服务端，再往开发机上装采集器，装完就能用。两条命令各自搞定，无需手动改地址。

---

## 一、装服务端（管理员做一次）

需要：一台装了 Docker 的机器（Linux/macOS 均可）。

```bash
# 拿到代码
git clone <仓库地址> && cd a3

# 一条命令装好（把地址换成这台机器对外的地址）
./deploy/install-server.sh http://aa.bb.com:12345
```

脚本会自动：生成 `deploy/.env`（管理员口令留空则随机生成并打印）、写入公开地址与端口、
非本机地址自动开放对外监听（并提醒配置 TLS）、构建镜像并启动。

完成后终端会打印两个地址：

- **控制台** `http://aa.bb.com:12345` —— 用 `admin` + 终端打印的口令登录
- **接入指南** `http://aa.bb.com:12345/setup-guide` —— 把这个链接发给采集端用户

> 手动方式（备用）：`cp deploy/.env.example deploy/.env` 编辑后 `make compose-up`。

### 自助注册说明

一键安装脚本已自动开放自助注册（`A3_ALLOW_AUTO_REGISTER=true`）并打印关闭方法——
能连到服务端的设备均可自行注册接入，收齐设备后建议关闭。手动部署时需自行在
`deploy/.env` 设置后再 `docker compose -f deploy/docker-compose.yml up -d` 生效。

---

## 二、装采集器（每台开发机做一次）

需要：开发机上装有 Claude Code 或 Codex CLI（要审计谁就装谁的机器），以及 curl 或 wget。

管理员把**接入指南页链接**发给你后，打开页面，复制那条命令，在终端执行：

```bash
curl http://aa.bb.com:12345/install.sh | sh
```

就这么一条。脚本自动识别 macOS/Linux 和芯片架构，完成全部四步：

1. 下载采集器装到 `~/.a3/bin/a3-agent`
2. 注册设备（Token 存到 `~/.a3/`）
3. 安装 Claude Code 前置 Hook（高危命令拦截上报）
4. 安装常驻服务（开机自启、崩溃自动拉起）

装完正常写代码即可。控制台「设备」页很快能看到这台机器，会话/告警逐步出现；
如果某条高危命令被拦截，Claude Code 里会有中文提示，照着换命令就行。

**Windows**：脚本暂不支持，从指南页的下载链接手动获取 `a3-agent-windows-amd64.exe`，
按指南页说明放置并运行。

**重复执行同一条命令是安全的**：自动幂等，不会重复注册或装坏。

### 常用命令（都在 `~/.a3/bin/` 下）

```bash
~/.a3/bin/a3-agent service-status     # 查看常驻服务状态
tail -f ~/.a3/agent.log               # 看采集器日志
~/.a3/bin/a3-agent uninstall-service  # 卸载常驻服务
~/.a3/bin/a3-agent uninstall-hook     # 卸载拦截 Hook
```

### 高级：手动安装（不用脚本）

从管理员处拿到对应平台二进制（`make release-agent` 产出在 `bin/release/`）后：

```bash
./a3-agent register --server http://aa.bb.com:12345   # ① 登记
./a3-agent install-hook                               # ② 装拦截开关
./a3-agent install-service                            # ③ 装常驻服务
```

---

## 三、遇到问题

| 现象 | 处理 |
| --- | --- |
| 打不开控制台/指南页 | 确认容器在跑：`docker compose -f deploy/docker-compose.yml ps`；看日志：`docker compose -f deploy/docker-compose.yml logs server` |
| 安装命令提示 403/无权限 | 服务端自动注册开关没开，管理员按上文「让用户能自助接入」开启 |
| 安装命令提示下载为空 | 服务端未配置产物目录：容器部署镜像内已内置；二进制直跑需设 `A3_AGENT_DIST=bin/release` 并确保先跑过 `make release-agent` |
| `register` 提示需携带既有 Token | 这台机器之前登记过：命令会自动读本机旧 Token 重试；Token 丢了就找管理员在控制台「设备」页吊销它，再重新跑安装命令 |
| 被拦的命令是误报 | 找管理员在「规则」页停用或调整对应规则，改动即时生效 |

更详细的配置项、架构与隐私说明见 [README](../README.md)。
