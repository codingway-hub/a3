// Package uuidx 提供零依赖的 RFC 4122 UUID 工具：v4 随机与 v5 确定性派生。
// v5 用于需要跨进程重启保持稳定的标识（如 session_start 事件幂等键）。
package uuidx

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

// NamespaceA3SessionStart a3 自定义 v5 命名空间（任意固定 GUID，仅本项目内部使用）。
const NamespaceA3SessionStart = "a3e5a3e5-0000-5000-8000-00c04fd430c8"

// NewV4 生成随机 UUID v4 字符串（小写连字符形式）。
func NewV4() string {
	randomBytes := make([]byte, 16)
	if _, randErr := rand.Read(randomBytes); randErr != nil {
		// crypto/rand 失败意味着系统熵源异常，属不可恢复运行环境问题
		panic(fmt.Sprintf("uuidx: 读取随机熵失败: %v", randErr))
	}
	applyVersionAndVariant(randomBytes, 4)
	return formatUUID(randomBytes)
}

// MustNewV5 以给定命名空间与名字派生确定性 UUID v5；命名空间非法时 panic（仅限常量调用）。
func MustNewV5(namespaceUUID string, derivedName string) string {
	uuidString, err := NewV5(namespaceUUID, derivedName)
	if err != nil {
		panic(fmt.Sprintf("uuidx: 派生 v5 UUID 失败: %v", err))
	}
	return uuidString
}

// NewV5 按 RFC 4122 §4.3 用 SHA-1 派生 UUID v5。
func NewV5(namespaceUUID string, derivedName string) (string, error) {
	namespaceBytes, parseErr := parseUUID(namespaceUUID)
	if parseErr != nil {
		return "", fmt.Errorf("命名空间 UUID 不合法: %w", parseErr)
	}

	digest := sha1.New() //nolint:gosec // RFC 4122 v5 规定使用 SHA-1，非安全摘要用途
	_, _ = digest.Write(namespaceBytes)
	_, _ = digest.Write([]byte(derivedName))
	nameBytes := digest.Sum(nil)[:16]

	applyVersionAndVariant(nameBytes, 5)
	return formatUUID(nameBytes), nil
}

// applyVersionAndVariant 设置版本号（高 4 位）与 RFC 变体位（10xxxxxx）。
func applyVersionAndVariant(uuidBytes []byte, version byte) {
	uuidBytes[6] = (uuidBytes[6] & 0x0f) | (version << 4)
	uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80
}

// formatUUID 以标准 8-4-4-4-12 连字符形式输出。
func formatUUID(uuidBytes []byte) string {
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(uuidBytes[0:4]),
		hex.EncodeToString(uuidBytes[4:6]),
		hex.EncodeToString(uuidBytes[6:8]),
		hex.EncodeToString(uuidBytes[8:10]),
		hex.EncodeToString(uuidBytes[10:16]))
}

// parseUUID 解析连字符形式的 UUID 为 16 字节。
func parseUUID(uuidString string) ([]byte, error) {
	cleanedText := strings.ReplaceAll(strings.ToLower(uuidString), "-", "")
	if len(cleanedText) != 32 {
		return nil, fmt.Errorf("%q 长度不合法（应为含连字符 36 位或纯十六进制 32 位）", uuidString)
	}
	uuidBytes := make([]byte, 16)
	if _, decodeErr := hex.Decode(uuidBytes, []byte(cleanedText)); decodeErr != nil {
		return nil, fmt.Errorf("%q 含非十六进制字符: %w", uuidString, decodeErr)
	}
	return uuidBytes, nil
}
