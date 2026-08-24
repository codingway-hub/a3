package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/pkg/schema"
)

// TestMaskEventContentMasksToolInputSecrets ToolInput 字符串叶子值出站前必须脱敏
// 且 JSON 结构保持合法（回归审查项 L-2 / 设计文档 §2 出站脱敏约束）。
func TestMaskEventContentMasksToolInputSecrets(t *testing.T) {
	sourceEvent := schema.Event{
		Content: "普通文本",
		ToolInput: json.RawMessage(
			`{"command":"export AWS_KEY=AKIAIOSFODNN7EXAMPLE","path":"/tmp/x","nested":{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlMzQ1Njc4"}}`),
	}
	maskEventContent(&sourceEvent)

	assert.Equal(t, "普通文本", sourceEvent.Content)

	var maskedFields map[string]any
	require.NoError(t, json.Unmarshal(sourceEvent.ToolInput, &maskedFields), "脱敏后必须是合法 JSON")

	maskedCommand, _ := maskedFields["command"].(string)
	assert.NotContains(t, maskedCommand, "AKIAIOSFODNN7EXAMPLE", "密钥原文不得出站")
	assert.Contains(t, maskedCommand, "AKIA…MPLE", "命中密钥保留首尾掩码")

	maskedPath, _ := maskedFields["path"].(string)
	assert.Equal(t, "/tmp/x", maskedPath, "非敏感字符串不应被改写")

	nestedMap, _ := maskedFields["nested"].(map[string]any)
	maskedToken, _ := nestedMap["token"].(string)
	assert.NotContains(t, maskedToken, "c2lnbmF0dXJlMzQ1Njc4", "嵌套层密钥同样须脱敏")
}

// TestMaskEventContentKeepsInvalidToolInputRaw 非对象形态的 ToolInput 解析失败时原样保留，
// 不产生非法 JSON 导致服务端 jsonb 入库失败。
func TestMaskEventContentKeepsInvalidToolInputRaw(t *testing.T) {
	rawToolInput := json.RawMessage("not-json")
	sourceEvent := schema.Event{ToolInput: rawToolInput}
	maskEventContent(&sourceEvent)
	assert.Equal(t, rawToolInput, sourceEvent.ToolInput)
}
