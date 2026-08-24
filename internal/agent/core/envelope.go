package core

import "github.com/codingway-hub/a3/pkg/schema"

// EventEnvelope 终端→服务端批量上报信封：传输层与插件的共用线上契约。
// 字段名与服务端 ingest 校验严格对齐，勿单方面改动。
type EventEnvelope struct {
	AgentVersion string         `json:"agent_version"`
	Plugins      []string       `json:"plugins,omitempty"`
	Events       []schema.Event `json:"events"`
}
