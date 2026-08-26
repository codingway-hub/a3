package schema

import "time"

// 终端规则下发共享契约：服务端（devices/rules 端点）与终端（run 常驻进程写快照、
// hook 短命进程读快照）跨进程跨机器共用的形状，字段演进只增不改。

// RulesSnapshotFileName 规则快照文件名（固定置于终端状态目录下）。
const RulesSnapshotFileName = "rules-snapshot.json"

// RulesSnapshotVersion 快照格式版本；读取方不识别即视为无效，走内置规则兜底。
const RulesSnapshotVersion = 1

// RuleDefinition 终端可执行的风险规则定义：服务端规则中心与终端
// （内置清单/下发快照）共用的最小契约。全部为普通字符串以保持 JSON 契约稳定。
type RuleDefinition struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Category  string   `json:"category"`   // dlp|cmd|file|git
	Target    string   `json:"target"`     // any|command|path|content
	Patterns  []string `json:"patterns"`   // 正则组
	PathGlobs []string `json:"path_globs"` // 路径 glob 组
	Severity  string   `json:"severity"`
	Action    string   `json:"action"`
}

// DeviceRulesPayload GET /api/v1/devices/rules 响应体：
// revision 为规则集规范序列化的 sha256 摘要，终端用于变更检测与快照跳写。
type DeviceRulesPayload struct {
	Revision string           `json:"revision"`
	Rules    []RuleDefinition `json:"rules"`
}

// RulesSnapshotFile 终端本地规则快照文件形状（run 进程原子写入、hook 进程只读）。
type RulesSnapshotFile struct {
	Version  int              `json:"version"`
	Revision string           `json:"revision"`
	SavedAt  time.Time        `json:"saved_at"`
	Rules    []RuleDefinition `json:"rules"`
}
