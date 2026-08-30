package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var testHandler = http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(writer, "ok")
})

// freePort 返回一个刚释放的临时端口（测试用；ListenAndServe 自绑时使用）。
func freePort(t *testing.T) string {
	t.Helper()
	listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatalf("临时端口监听失败: %v", listenErr)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	return addr
}

func serveWith(certPath, keyPath string, t *testing.T) *http.Server {
	t.Helper()
	server := &http.Server{Addr: freePort(t), Handler: testHandler}
	serveCall := buildServeCall(server, certPath, keyPath)
	go func() { _ = serveCall() }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	})
	return server
}

func httpGet(t *testing.T, server *http.Server) (int, error) {
	t.Helper()
	response, getErr := (&http.Client{Timeout: 3 * time.Second}).Get("http://" + server.Addr)
	if getErr != nil {
		return 0, getErr
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode, nil
}

func TestBuildServeCallPlaintextHTTP(t *testing.T) {
	server := serveWith("", "", t)
	waitForServer(t, "http://"+server.Addr)
	statusCode, getErr := httpGet(t, server)
	if getErr != nil {
		t.Fatalf("明文 HTTP 请求失败: %v", getErr)
	}
	if statusCode != http.StatusOK {
		t.Errorf("明文 HTTP 状态码异常: %d", statusCode)
	}
}

// writeSelfSignedCert 生成 ECDSA 自签证书与私钥写入临时目录，返回两个文件路径。
func writeSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		t.Fatalf("生成私钥失败: %v", keyErr)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	derBytes, derErr := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if derErr != nil {
		t.Fatalf("创建证书失败: %v", derErr)
	}
	directory := t.TempDir()
	certPath = filepath.Join(directory, "cert.pem")
	keyPath = filepath.Join(directory, "key.pem")
	certOut, _ := os.Create(certPath)
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	_ = certOut.Close()
	keyBytes, keyEncodeErr := x509.MarshalECPrivateKey(key)
	if keyEncodeErr != nil {
		t.Fatalf("编码私钥失败: %v", keyEncodeErr)
	}
	keyOut, _ := os.Create(keyPath)
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	_ = keyOut.Close()
	return certPath, keyPath
}

func httpsGet(t *testing.T, server *http.Server) (int, error) {
	t.Helper()
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // 测试自签证书专用
		}},
	}
	response, getErr := client.Get("https://" + server.Addr)
	if getErr != nil {
		return 0, getErr
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode, nil
}

func TestBuildServeCallTLSPresent(t *testing.T) {
	certPath, keyPath := writeSelfSignedCert(t)
	server := serveWith(certPath, keyPath, t)
	waitForServerTLS(t, "https://"+server.Addr)
	statusCode, getErr := httpsGet(t, server)
	if getErr != nil {
		t.Fatalf("TLS 握手/请求失败: %v", getErr)
	}
	if statusCode != http.StatusOK {
		t.Errorf("TLS 状态码异常: %d", statusCode)
	}
	// 同一地址用明文访问不应得到 200：证明确实走了 TLS（明文 4xx/犯错均证明未透传内容）
	plainStatus, plainErr := httpGet(t, server)
	if plainErr == nil && plainStatus == http.StatusOK {
		t.Error("TLS 监听端口不应以明文 200 响应")
	}
}

// waitForServerTLS 用跳过校验的客户端轮询 TLS 端口（自签证书场景无法用默认客户端验证）。
func waitForServerTLS(t *testing.T, target string) {
	t.Helper()
	insecureClient := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 测试自签证书专用
	}}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		response, reqErr := insecureClient.Get(target)
		if reqErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("无法连通 %s", target)
}

// waitForServer 轮询探测 target 可连通，容忍监听建立延迟。
func waitForServer(t *testing.T, target string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		response, reqErr := http.Get(target)
		if reqErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("无法连通 %s", target)
}
