package main

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseServerHostPort(t *testing.T) {
	cases := []struct {
		url      string
		wantHost string
		wantPort string
	}{
		{"http://192.168.1.13:8080", "192.168.1.13", "8080"},
		{"http://192.168.1.13:8080/", "192.168.1.13", "8080"},
		{"https://a3.example.com/healthz", "a3.example.com", "443"},
		{"http://10.0.0.5", "10.0.0.5", "80"},
		{"https://localhost", "localhost", "443"},
		{"", "", ""},
	}
	for _, c := range cases {
		host, port := parseServerHostPort(c.url)
		assert.Equal(t, c.wantHost, host, "url=%s host", c.url)
		assert.Equal(t, c.wantPort, port, "url=%s port", c.url)
	}
}

func TestProbeRoutedUnreachableReachableFalse(t *testing.T) {
	listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, listenErr)
	defer listener.Close()

	assert.False(t, probeRoutedUnreachable(listener.Addr().String(), time.Second),
		"可达地址不得判为路由不可达")
}

// TestSelfHealLoopTriggersExitOnSustainedUnreachable 持续「路由不可达」并超过窗口后，
// 看门狗应打印一次授权指引、置位 selfExitTriggered 并向 triggerExit 发信号唤起优雅退出。
func TestSelfHealLoopTriggersExitOnSustainedUnreachable(t *testing.T) {
	restoreEvery, restoreTimeout := selfHealProbeEvery, selfHealProbeTimeout
	selfHealProbeEvery, selfHealProbeTimeout = 10*time.Millisecond, 100*time.Millisecond
	defer func() { selfHealProbeEvery, selfHealProbeTimeout = restoreEvery, restoreTimeout }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.DiscardHandler)
	trigger := make(chan struct{}, 1)
	report := &selfHealReport{}

	// 恒判定不可达，窗口 150ms（> 3×探针周期 30ms 的下限钳制）
	go selfHealLoop(ctx, "192.0.2.1", "8080", 150*time.Millisecond, logger, trigger, report, "",
		func(string, time.Duration) bool { return true })

	select {
	case <-trigger:
		assert.True(t, report.selfExitTriggered, "超窗后应触发自愈退出")
		assert.True(t, report.authGuidanceGiven, "首次判定不可达应置位授权指引标志")
		assert.True(t, report.unreachable)
	case <-time.After(3 * time.Second):
		t.Fatal("持续路由不可达超窗后未发出自愈信号")
	}
	cancel()
}

// TestSelfHealLoopResetsWhenBackReachable 探针由不可达恢复可达后，应复位计数，
// 且不再触发自愈退出（窗口设得极大，只验证复位路径）。
func TestSelfHealLoopResetsWhenBackReachable(t *testing.T) {
	restoreEvery := selfHealProbeEvery
	selfHealProbeEvery = 10 * time.Millisecond
	defer func() { selfHealProbeEvery = restoreEvery }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.DiscardHandler)
	trigger := make(chan struct{}, 4)
	report := &selfHealReport{}

	var probeCalls atomic.Int32
	probe := func(string, time.Duration) bool { return probeCalls.Add(1) <= 3 } // 前 3 次不可达，之后可达

	done := make(chan struct{})
	go func() {
		defer close(done)
		selfHealLoop(ctx, "10.9.8.7", "8080", time.Minute, logger, trigger, report, "", probe)
	}()
	time.Sleep(300 * time.Millisecond) // 远超前 3 次探测所需，探针早已复位

	assert.False(t, report.unreachable, "探针恢复可达后应复位到非不可达态")
	assert.False(t, report.selfExitTriggered, "仅瞬态不可达不得触发自愈退出")
	select {
	case <-trigger:
		t.Fatal("复位后不应有自愈信号")
	default:
	}
	cancel()
	<-done
}

// TestSelfHealLoopExitsCleanlyOnContextCancel 可达场景下取消上下文，看门狗应无副作用地退出。
func TestSelfHealLoopExitsCleanlyOnContextCancel(t *testing.T) {
	restoreEvery := selfHealProbeEvery
	selfHealProbeEvery = 10 * time.Millisecond
	defer func() { selfHealProbeEvery = restoreEvery }()

	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.New(slog.DiscardHandler)
	trigger := make(chan struct{}, 4)
	report := &selfHealReport{}
	probe := func(string, time.Duration) bool { return false }

	done := make(chan struct{})
	go func() {
		defer close(done)
		selfHealLoop(ctx, "127.0.0.1", "1", time.Minute, logger, trigger, report, "", probe)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("看门狗未在上下文取消后及时退出")
	}
	assert.False(t, report.unreachable)
}