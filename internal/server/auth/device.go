// Package auth 提供 a3 服务端两侧鉴权原语：
//   - 设备侧：明文 Token 一次性下发 + SHA-256 摘要入库（device.go）；
//   - 控制台侧：HS256 JWT 签发/校验（jwt.go）；
//   - gin 中间件（middleware.go）。
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// deviceTokenPrefix 是设备 Token 的可辨识前缀，便于日志/配置中肉眼区分用途。
const deviceTokenPrefix = "a3d_"

// GenerateDeviceToken 生成设备明文 Token："a3d_" + 32 字节随机数的 hex（总长 68 字符）。
// 明文仅在注册响应中出现一次；服务端只持久化 HashToken 摘要。
func GenerateDeviceToken() (string, error) {
	randomBytes := make([]byte, 32)
	if _, readErr := rand.Read(randomBytes); readErr != nil {
		return "", readErr
	}
	return deviceTokenPrefix + hex.EncodeToString(randomBytes), nil
}

// HashToken 计算设备 Token 的 SHA-256 hex 摘要（小写），即 devices.token_hash 的入库形态。
func HashToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}
