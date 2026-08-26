// Package codex 实现 OpenAI Codex CLI 采集插件：监听 ~/.codex/sessions 下的
// rollout JSONL 会话日志并解析为 a3 标准事件。纯事后审计定位——Codex 官方
// hooks 机制仍为 feature-flag 实验特性（仅可靠覆盖 Bash、需人工 trust、只认 deny），
// 不宜用于生产阻断，故本插件不实现本地阻断；EvaluateHook 恒放行、
// ConfigureHook 返回 core.ErrHookUnsupported，待其转正后三期再评估接入。
//
// # rollout 格式速查（基于本机 codex-cli 0.149.0 真实采样 + 多方文档交叉印证）
//
// 目录：~/.codex/sessions/YYYY/MM/DD/rollout-<RFC3339时间戳冒号转连字符>-<uuidv7>.jsonl；
// $CODEX_HOME 可整体迁移根目录（LogWatchSpecs 已适配）。行结构：
//
//	{"timestamp":"RFC3339Nano(UTC)","type":"<envelope类型>","payload":{...}}
//
// envelope 类型与本插件的处置策略：
//   - session_meta   → 派生 session_start 事件（Extra 携带 cwd/cli_version/git 等）
//   - response_item  → 权威事件流：message(function_call(_output)) 映射为标准事件
//   - turn_context / world_state / event_msg / 其他未知类型 → 忽略
//
// response_item.payload.type 枚举与映射：
//   - message             role=user/assistant 且含 input_text/output_text 块 → conversation；
//     role=developer/system 为每轮注入的指令样板（skills/permissions 说明等），忽略；
//     以 <environment_context> 开头的合成 user 消息同样忽略
//   - function_call       name + arguments(JSON 字符串) + call_id → tool_call
//     （arguments 内层键名因工具而异，解析保持键名无关）
//   - function_call_output call_id + output → tool_result（摘要截断至 TruncateSummary 上限）
//   - reasoning / custom_tool_call* / web_search_call* → 一期忽略
//
// event_msg 与 response_item 双流并存且对同一用户输入各记录一次（真实样本已验证重复），
// 本插件只取 response_item 权威流、丢弃 event_msg，避免事件翻倍。
// 冷文件可能被压缩为 .jsonl.zst（重启/resume 后会物化回明文），被 MatchGlob 自然排除，
// 属一期接受的审计盲区。
package codex
