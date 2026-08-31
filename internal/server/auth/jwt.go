package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// 控制台 JWT 采用标准库手写 HS256 实现：算法固定单一，从构造上排除
// "alg:none"/算法混淆类漏洞，且不引入第三方依赖。
var (
	base64RawURL = base64.RawURLEncoding

	// ErrInvalidToken 表示 Token 格式错误或签名非法（含伪造）。
	ErrInvalidToken = errors.New("invalid token")
	// ErrTokenExpired 表示签名合法但已过有效期。
	ErrTokenExpired = errors.New("token expired")
)

// jwtHeader 固定头；Sign 时序列化，Verify 时仅比对期望值（不信任其内容分支）。
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Claims 是控制台会话声明：登录用户名 + 角色 + 过期时间戳（秒）。
// Role 无 omitempty：旧格式 token 缺字段反序列化为空串，Verify 按非法拒绝（防提权）。
type Claims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Exp  int64  `json:"exp"`
}

// 合法角色集合；与 admin_users.role 的 CHECK 约束（迁移 0010）同源。
var validRoles = map[string]bool{"admin": true, "auditor": true}

// SignJWT 以 HS256 签发控制台 Token，ttl 为有效期时长（一期约定 8h）。
func SignJWT(secret string, username string, role string, ttl time.Duration) (string, error) {
	headerBytes, headerErr := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT"})
	if headerErr != nil {
		return "", headerErr
	}
	claimsBytes, claimsErr := json.Marshal(Claims{
		Sub:  username,
		Role: role,
		Exp:  time.Now().Add(ttl).Unix(),
	})
	if claimsErr != nil {
		return "", claimsErr
	}

	signingInput := base64RawURL.EncodeToString(headerBytes) + "." + base64RawURL.EncodeToString(claimsBytes)
	signature := hmacSHA256([]byte(secret), []byte(signingInput))
	return signingInput + "." + base64RawURL.EncodeToString(signature), nil
}

// VerifyJWT 校验签名、有效期与角色合法性；成功返回声明中的用户名与角色。
// 签名比对使用 hmac.Equal 恒时比较，防时序侧信道。
// 无 role 的旧格式 token 一律拒绝：空 role 若宽容为 admin 会构成提权面（8h TTL 影响可接受）。
func VerifyJWT(secret string, tokenString string) (string, string, error) {
	// base64url 字符集不含点，合法 Token 恰好三段
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", ErrInvalidToken
	}
	signingInput := parts[0] + "." + parts[1]

	expectedSignature := hmacSHA256([]byte(secret), []byte(signingInput))
	actualSignature, decodeErr := base64RawURL.DecodeString(parts[2])
	if decodeErr != nil || !hmac.Equal(expectedSignature, actualSignature) {
		return "", "", ErrInvalidToken
	}

	headerBytes, headerDecodeErr := base64RawURL.DecodeString(parts[0])
	if headerDecodeErr != nil {
		return "", "", ErrInvalidToken
	}
	var header jwtHeader
	if headerErr := json.Unmarshal(headerBytes, &header); headerErr != nil || header.Alg != "HS256" {
		return "", "", ErrInvalidToken
	}

	claimsBytes, claimsDecodeErr := base64RawURL.DecodeString(parts[1])
	if claimsDecodeErr != nil {
		return "", "", ErrInvalidToken
	}
	var claims Claims
	if unmarshalErr := json.Unmarshal(claimsBytes, &claims); unmarshalErr != nil {
		return "", "", ErrInvalidToken
	}
	if claims.Sub == "" || claims.Exp <= 0 || !validRoles[claims.Role] {
		return "", "", ErrInvalidToken
	}
	if time.Now().Unix() > claims.Exp {
		return "", "", ErrTokenExpired
	}
	return claims.Sub, claims.Role, nil
}

func hmacSHA256(key []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
