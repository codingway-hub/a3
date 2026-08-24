package uuidx

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// uuidShapePattern 标准 8-4-4-4-12 小写十六进制形式。
var uuidShapePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func TestNewV4RandomAndWellFormed(t *testing.T) {
	firstUUID := NewV4()
	secondUUID := NewV4()

	require.Regexp(t, uuidShapePattern, firstUUID)
	assert.NotEqual(t, firstUUID, secondUUID, "v4 应随机不重复")
	assert.Equal(t, "4", firstUUID[14:15], "版本位应为 4")
	assert.Contains(t, "89ab", firstUUID[19:20], "变体位应为 8/9/a/b")
}

func TestNewV5DeterministicAgainstKnownVector(t *testing.T) {
	// RFC 4122 官方 DNS 命名空间 + 公开测试向量 python.org
	dnsNamespace := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	derivedUUID, deriveErr := NewV5(dnsNamespace, "python.org")
	require.NoError(t, deriveErr)
	assert.Equal(t, "886313e1-3b8a-5372-9b90-0c9aee199e5d", derivedUUID,
		"应与 RFC 4122 已知测试向量一致")

	sameUUID, sameErr := NewV5(dnsNamespace, "python.org")
	require.NoError(t, sameErr)
	assert.Equal(t, derivedUUID, sameUUID, "同输入必须确定性输出")

	assert.Equal(t, "5", derivedUUID[14:15], "版本位应为 5")
}

func TestNewV5RejectsInvalidNamespace(t *testing.T) {
	_, invalidErr := NewV5("not-a-uuid", "name")
	assert.Error(t, invalidErr)

	_, shortErr := NewV5("6ba7b810-9dad-11d1-80b4", "name")
	assert.Error(t, shortErr)
}

func TestMustNewV5WithProjectNamespace(t *testing.T) {
	firstCall := MustNewV5(NamespaceA3SessionStart, "sess-abc")
	secondCall := MustNewV5(NamespaceA3SessionStart, "sess-abc")
	assert.Equal(t, firstCall, secondCall)
	assert.NotEqual(t, MustNewV5(NamespaceA3SessionStart, "sess-other"), firstCall)
}
