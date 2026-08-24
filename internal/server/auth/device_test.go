package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateDeviceTokenFormat(t *testing.T) {
	token, generateErr := GenerateDeviceToken()
	require.NoError(t, generateErr)
	assert.Regexp(t, regexp.MustCompile(`^a3d_[0-9a-f]{64}$`), token,
		"Token 应为 a3d_ 前缀 + 32 字节 hex")

	secondToken, _ := GenerateDeviceToken()
	assert.NotEqual(t, token, secondToken, "两次生成的 Token 不得重复")
}

func TestHashTokenKnownVector(t *testing.T) {
	// 与独立计算 sha256("abc") 的结果比对，锁定摘要算法与编码形态
	digest := sha256.Sum256([]byte("abc"))
	expectedHex := hex.EncodeToString(digest[:])
	assert.Equal(t, expectedHex, HashToken("abc"))
	assert.Len(t, HashToken("abc"), 64)
}
