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

// TestFilesBornDuringDowntimeAreConsumedFromHead 钉住停机期间出生文件的语义：
// 重启首轮扫描发现 mtime 晚于上次快照落盘时刻的未登记文件时，应从头消费而非跳 EOF。
func TestFilesBornDuringDowntimeAreConsumedFromHead(t *testing.T) {
	rootDirectory := t.TempDir()
	stateFile := filepath.Join(t.TempDir(), "state", "offsets.json")
	logFile := filepath.Join(rootDirectory, "existing.jsonl")
	require.NoError(t, os.WriteFile(logFile, []byte("seed\n"), 0o644))

	// 第一次运行：登记既有文件并等待锚点快照写盘
	firstCollector := &collectedLines{}
	firstTailer, startErr := Start(rootDirectory,
		Options{MatchGlob: "*.jsonl", StateFile: stateFile, PollEvery: 20 * time.Millisecond}, firstCollector.onLines)
	require.NoError(t, startErr)
	appendToFile(t, logFile, "during-run-1\n")
	waitForLines(t, firstCollector, 1)
	require.Eventually(t, func() bool {
		_, statErr := os.Stat(stateFile)
		return statErr == nil
	}, 2*time.Second, 10*time.Millisecond, "锚点快照应已写盘")
	firstTailer.Close()

	// 停机期间：新建会话日志并写入内容
	time.Sleep(20 * time.Millisecond) // 留出 mtime 粒度余量，确保出生时间晚于快照
	bornDirectory := filepath.Join(rootDirectory, "projects", "demo-app")
	require.NoError(t, os.MkdirAll(bornDirectory, 0o755))
	bornFile := filepath.Join(bornDirectory, "born-session.jsonl")
	require.NoError(t, os.WriteFile(bornFile, []byte("born-1\nborn-2\n"), 0o644))

	// 重启：born 文件应从头采集（含全部停机期内容）；既有文件无增量、不重播
	secondCollector := &collectedLines{}
	secondTailer, secondErr := Start(rootDirectory,
		Options{MatchGlob: "*.jsonl", StateFile: stateFile, PollEvery: 20 * time.Millisecond}, secondCollector.onLines)
	require.NoError(t, secondErr)
	t.Cleanup(secondTailer.Close)

	lines := waitForLines(t, secondCollector, 2)
	assert.ElementsMatch(t, []string{"born-1", "born-2"}, lines,
		"停机期间出生的会话日志应被完整采集")
	assert.Equal(t, []string{"during-run-1"}, firstCollector.snapshot(),
		"首次运行只应上报追加的增量，历史内容不回放")
}

// TestAncientUntrackedFilesStillSkipHistory 钉住历史遗留文件的语义：
// mtime 早于上次快照落盘时刻的未登记文件（真正的历史遗留）仍跳 EOF，不回灌历史。
func TestAncientUntrackedFilesStillSkipHistory(t *testing.T) {
	rootDirectory := t.TempDir()
	stateFile := filepath.Join(t.TempDir(), "state", "offsets.json")
	logFile := filepath.Join(rootDirectory, "existing.jsonl")
	require.NoError(t, os.WriteFile(logFile, []byte("seed\n"), 0o644))

	// 第一次运行：建立快照锚点
	firstCollector := &collectedLines{}
	firstTailer, startErr := Start(rootDirectory,
		Options{MatchGlob: "*.jsonl", StateFile: stateFile, PollEvery: 20 * time.Millisecond}, firstCollector.onLines)
	require.NoError(t, startErr)
	appendToFile(t, logFile, "during-run-1\n")
	waitForLines(t, firstCollector, 1)
	require.Eventually(t, func() bool {
		_, statErr := os.Stat(stateFile)
		return statErr == nil
	}, 2*time.Second, 10*time.Millisecond, "锚点快照应已写盘")
	firstTailer.Close()

	// 模拟历史遗留：mtime 设为远早于快照时刻的未登记文件
	time.Sleep(20 * time.Millisecond)
	ancientFile := filepath.Join(rootDirectory, "ancient.jsonl")
	require.NoError(t, os.WriteFile(ancientFile, []byte("ancient-history\n"), 0o644))
	staleTime := time.Now().Add(-24 * time.Hour)
	require.NoError(t, os.Chtimes(ancientFile, staleTime, staleTime))

	// 重启：ancient 文件应被跳过（不回灌历史），且不产生任何回调
	secondCollector := &collectedLines{}
	secondTailer, secondErr := Start(rootDirectory,
		Options{MatchGlob: "*.jsonl", StateFile: stateFile, PollEvery: 20 * time.Millisecond}, secondCollector.onLines)
	require.NoError(t, secondErr)
	t.Cleanup(secondTailer.Close)

	time.Sleep(120 * time.Millisecond) // 跨数拍确认无回灌
	assert.Empty(t, secondCollector.snapshot(), "历史遗留文件不应回灌内容")
}
