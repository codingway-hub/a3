package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTRoundTrip(t *testing.T) {
	token, signErr := SignJWT("secret-key", "admin", 8*time.Hour)
	require.NoError(t, signErr)

	username, verifyErr := VerifyJWT("secret-key", token)
	require.NoError(t, verifyErr)
	assert.Equal(t, "admin", username)
}

func TestJWTWrongSecretRejected(t *testing.T) {
	token, signErr := SignJWT("secret-key", "admin", time.Hour)
	require.NoError(t, signErr)

	_, verifyErr := VerifyJWT("other-secret", token)
	assert.ErrorIs(t, verifyErr, ErrInvalidToken)
}

func TestJWTExpired(t *testing.T) {
	// 负 TTL 签发即得已过期 Token
	expiredToken, signErr := SignJWT("secret-key", "admin", -time.Minute)
	require.NoError(t, signErr)

	// 签名本身合法（同密钥可验），仅过期：错误类型应为 ErrTokenExpired
	_, verifyErr := VerifyJWT("secret-key", expiredToken)
	assert.ErrorIs(t, verifyErr, ErrTokenExpired)
}

func TestJWTForgedPayloadRejected(t *testing.T) {
	token, signErr := SignJWT("secret-key", "admin", time.Hour)
	require.NoError(t, signErr)

	// 篡改 payload 段（换用户）后签名不再匹配
	parts := strings.Split(token, ".")
	forgedClaims, encodeErr := json.Marshal(Claims{Sub: "attacker", Exp: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, encodeErr)
	forgedToken := parts[0] + "." + base64.RawURLEncoding.EncodeToString(forgedClaims) + "." + parts[2]

	_, verifyErr := VerifyJWT("secret-key", forgedToken)
	assert.ErrorIs(t, verifyErr, ErrInvalidToken)
}

func TestJWTMalformedRejected(t *testing.T) {
	cases := map[string]string{
		"空串":        "",
		"缺段":        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9",
		"多段":        "a.b.c.d",
		"非base64签名": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.!!!",
		"非base64声明": "eyJhbGciOiJIUzI1NiJ9.@@@.c2ln",
	}
	for name, badToken := range cases {
		_, verifyErr := VerifyJWT("secret-key", badToken)
		assert.ErrorIs(t, verifyErr, ErrInvalidToken, name)
	}
}

func TestJWTHeaderAlgPinned(t *testing.T) {
	// 攻击者把 alg 换成 none 并去掉签名的经典绕过必须被拒
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claimsBytes, _ := json.Marshal(Claims{Sub: "attacker", Exp: time.Now().Add(time.Hour).Unix()})
	noneToken := noneHeader + "." + base64.RawURLEncoding.EncodeToString(claimsBytes) + "."

	_, verifyErr := VerifyJWT("secret-key", noneToken)
	assert.ErrorIs(t, verifyErr, ErrInvalidToken)
}
