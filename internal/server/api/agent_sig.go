package api

import (
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"sync"
)

// agentSigner 对采集器发布产物签发 ed25519 签名，并按「代际」缓存：
// 首次请求某产物时对其当前字节签名；此后每次请求重算文件 sha256，内容未变返回缓存的
// 该代际签名，内容漂移则判定为「产物在签名后被修改但未重新发布」（路由据此返回 409）。
//
// 签名必须绑定代际而不是逐请求现算：现算签名会让被植毒的产物当场被签发合法签名，
// 威胁模型落空。合法升级 = 替换产物后重启服务端（新代际重新签名）；不重启的篡改会被
// 客户端验签硬失败拦截，且本机留痕。信任根 = 服务端私钥（见 config 层）。
type agentSigner struct {
	mu     sync.Mutex
	key    ed25519.PrivateKey
	cached map[string]signedGeneration
}

// signedGeneration 一次发布代际的缓存：产物的内容指纹与其签名。
type signedGeneration struct {
	sha256 [32]byte
	sig    []byte
}

func newAgentSigner(key ed25519.PrivateKey) *agentSigner {
	return &agentSigner{key: key, cached: make(map[string]signedGeneration)}
}

// sigFor 返回产物代际签名。内容与缓存代际一致时返回该签名（drifted=false）；
// 文件已在签名后改变时返回 drifted=true；读取失败时返回错误（由上层按 500 处理）。
func (signer *agentSigner) sigFor(assetName string, diskPath string) (sig []byte, drifted bool, err error) {
	content, readErr := os.ReadFile(diskPath)
	if readErr != nil {
		return nil, false, readErr
	}
	contentSHA := sha256.Sum256(content)

	signer.mu.Lock()
	defer signer.mu.Unlock()
	cachedGen, cachedBefore := signer.cached[assetName]
	switch {
	case cachedBefore && cachedGen.sha256 == contentSHA:
		return cachedGen.sig, false, nil
	case cachedBefore:
		return nil, true, nil // 内容漂移：签名后产物被改动，属于未重新发布的篡改
	default:
		signedBytes := ed25519.Sign(signer.key, content)
		signer.cached[assetName] = signedGeneration{sha256: contentSHA, sig: signedBytes}
		return signedBytes, false, nil
	}
}