package watcher

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// modTimeOf 返回文件修改时间（测试辅助）。
func modTimeOf(t *testing.T, filePath string) time.Time {
	t.Helper()
	fileInfo, statErr := os.Stat(filePath)
	require.NoError(t, statErr)
	return fileInfo.ModTime()
}

// TestIdleTicksSkipOffsetPersistence 钉住惰性落盘语义：
// 空闲拍（无任何日志追加）不重写状态文件；产生新偏移后恢复落盘。
func TestIdleTicksSkipOffsetPersistence(t *testing.T) {
	rootDirectory := t.TempDir()
	stateFile := filepath.Join(t.TempDir(), "state", "offsets.json")
	logFile := filepath.Join(rootDirectory, "idle.jsonl")
	require.NoError(t, os.WriteFile(logFile, []byte("seed\n"), 0o644))

	lineCollector := &collectedLines{}
	tailWorker, startErr := Start(rootDirectory,
		Options{MatchGlob: "*.jsonl", StateFile: stateFile, PollEvery: 20 * time.Millisecond}, lineCollector.onLines)
	require.NoError(t, startErr)
	t.Cleanup(tailWorker.Close)

	appendToFile(t, logFile, "active-1\n")
	waitForLines(t, lineCollector, 1)
	require.Eventually(t, func() bool {
		_, statErr := os.Stat(stateFile)
		return statErr == nil
	}, 2*time.Second, 10*time.Millisecond, "有消费变更后状态文件应被创建")
	savedModTime := modTimeOf(t, stateFile)

	// 跨多个空闲拍：期间不追加任何日志，状态文件不应被重写
	time.Sleep(120 * time.Millisecond)
	assert.Equal(t, savedModTime, modTimeOf(t, stateFile), "空闲拍不应重写状态文件")

	appendToFile(t, logFile, "active-2\n")
	waitForLines(t, lineCollector, 2)
	require.Eventually(t, func() bool {
		return modTimeOf(t, stateFile).After(savedModTime)
	}, 2*time.Second, 10*time.Millisecond, "新偏移产生后应再次落盘")
}
