package watcher

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// collectedLines 线程安全地收集回调产出的行文本。
type collectedLines struct {
	mu      sync.Mutex
	entries []string
	sources []string
}

func (collector *collectedLines) onLines(sourcePath string, lines [][]byte) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	for _, lineBytes := range lines {
		collector.entries = append(collector.entries, string(lineBytes))
	}
	collector.sources = append(collector.sources, sourcePath)
}

func (collector *collectedLines) snapshot() []string {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	return append([]string(nil), collector.entries...)
}

// appendToFile 以追加模式写入内容（不扰动既有字节）。
func appendToFile(t *testing.T, filePath string, content string) {
	t.Helper()
	openedFile, openErr := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	require.NoError(t, openErr)
	defer func() { _ = openedFile.Close() }()
	_, writeErr := openedFile.WriteString(content)
	require.NoError(t, writeErr)
}

func waitForLines(t *testing.T, collector *collectedLines, expectedCount int) []string {
	t.Helper()
	require.Eventually(t, func() bool {
		return len(collector.snapshot()) >= expectedCount
	}, 3*time.Second, 10*time.Millisecond, "等待回调累计 %d 行", expectedCount)
	return collector.snapshot()
}

func TestSkipsExistingHistoryAndReportsOnlyNewLines(t *testing.T) {
	rootDirectory := t.TempDir()
	logFile := filepath.Join(rootDirectory, "session-old.jsonl")
	require.NoError(t, os.WriteFile(logFile, []byte("history-1\nhistory-2\n"), 0o644))

	lineCollector := &collectedLines{}
	tailWorker, startErr := Start(rootDirectory,
		Options{MatchGlob: "*.jsonl", PollEvery: 20 * time.Millisecond}, lineCollector.onLines)
	require.NoError(t, startErr)
	t.Cleanup(tailWorker.Close)

	time.Sleep(80 * time.Millisecond) // 跨越数拍确认历史不被回放
	assert.Empty(t, lineCollector.snapshot(), "启动时既存内容不应回放")

	// 追加（而非整写）触发增量；整写会先截断、命中防御性归零语义
	appendToFile(t, logFile, "new-line-a\n")
	lines := waitForLines(t, lineCollector, 1)
	assert.Equal(t, []string{"new-line-a"}, lines[len(lines)-1:], "只应上报新增部分")
}

func TestRestartContinuesFromPersistedOffsets(t *testing.T) {
	rootDirectory := t.TempDir()
	stateFile := filepath.Join(t.TempDir(), "state", "offsets.json")
	logFile := filepath.Join(rootDirectory, "session-run.jsonl")
	require.NoError(t, os.WriteFile(logFile, []byte("seed\n"), 0o644))

	firstCollector := &collectedLines{}
	firstTailer, startErr := Start(rootDirectory,
		Options{MatchGlob: "*.jsonl", StateFile: stateFile, PollEvery: 20 * time.Millisecond}, firstCollector.onLines)
	require.NoError(t, startErr)

	appendToFile(t, logFile, "during-1\n")
	waitForLines(t, firstCollector, 1)
	firstTailer.Close() // 模拟进程退出

	// 停机期间日志继续增长（追加）
	appendToFile(t, logFile, "while-down-1\nwhile-down-2\n")

	secondCollector := &collectedLines{}
	secondTailer, secondErr := Start(rootDirectory,
		Options{MatchGlob: "*.jsonl", StateFile: stateFile, PollEvery: 20 * time.Millisecond}, secondCollector.onLines)
	require.NoError(t, secondErr)
	secondTailer.Close()

	assert.ElementsMatch(t, []string{"during-1"}, firstCollector.snapshot())
	assert.ElementsMatch(t, []string{"while-down-1", "while-down-2"}, secondCollector.snapshot(),
		"重启后应续传停机期间的增量且不重播旧内容")
}

func TestDiscoversNestedNewFilesCreatedLater(t *testing.T) {
	rootDirectory := t.TempDir()
	nestedDirectory := filepath.Join(rootDirectory, "projects", "demo-app")

	lineCollector := &collectedLines{}
	tailWorker, startErr := Start(rootDirectory,
		Options{MatchGlob: "*.jsonl", PollEvery: 20 * time.Millisecond}, lineCollector.onLines)
	require.NoError(t, startErr)
	t.Cleanup(tailWorker.Close)

	require.NoError(t, os.MkdirAll(nestedDirectory, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(nestedDirectory, "later.jsonl"), []byte("nested-new\n"), 0o644))

	waitForLines(t, lineCollector, 1)
	assert.Equal(t, []string{"nested-new"}, lineCollector.snapshot(),
		"运行中新建的嵌套目录与文件应被发现（首见跳 EOF 后的追加才上报）")

	// 追加验证增量可读
	appendToFile(t, filepath.Join(nestedDirectory, "later.jsonl"), "appended\n")
	lines := waitForLines(t, lineCollector, 2)
	assert.Equal(t, "appended", lines[len(lines)-1])
}

func TestPartialLineWaitsForCompletion(t *testing.T) {
	rootDirectory := t.TempDir()
	logFile := filepath.Join(rootDirectory, "partial.jsonl")
	require.NoError(t, os.WriteFile(logFile, []byte("complete-1\n"), 0o644))

	lineCollector := &collectedLines{}
	tailWorker, startErr := Start(rootDirectory,
		Options{MatchGlob: "*.jsonl", PollEvery: 20 * time.Millisecond}, lineCollector.onLines)
	require.NoError(t, startErr)
	t.Cleanup(tailWorker.Close)

	time.Sleep(60 * time.Millisecond)
	appendToFile(t, logFile, "half-of-a") // 追加无换行的半行
	time.Sleep(80 * time.Millisecond)
	assert.Empty(t, lineCollector.snapshot(), "半行不应提前上报")

	appendToFile(t, logFile, "-line-done\n") // 补齐半行
	lines := waitForLines(t, lineCollector, 1)
	assert.Equal(t, []string{"half-of-a-line-done"}, lines, "拼齐后应上报完整半行")
}

func TestTruncationResetsOffsetDefensively(t *testing.T) {
	rootDirectory := t.TempDir()
	logFile := filepath.Join(rootDirectory, "truncated.jsonl")
	require.NoError(t, os.WriteFile(logFile, []byte("first-round-1\nfirst-round-2\n"), 0o644))

	lineCollector := &collectedLines{}
	tailWorker, startErr := Start(rootDirectory,
		Options{MatchGlob: "*.jsonl", PollEvery: 20 * time.Millisecond}, lineCollector.onLines)
	require.NoError(t, startErr)
	t.Cleanup(tailWorker.Close)

	time.Sleep(60 * time.Millisecond)
	// 截断到更短内容后写入新行：size < offset 触发防御性归零重读
	require.NoError(t, os.WriteFile(logFile, []byte("reborn-1\n"), 0o644))

	lines := waitForLines(t, lineCollector, 1)
	assert.Equal(t, []string{"reborn-1"}, lines, "截断后应从头消费新文件内容")
}

func TestNonMatchingFilesIgnoredAndStartValidation(t *testing.T) {
	rootDirectory := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootDirectory, "notes.txt"), []byte("ignored\n"), 0o644))

	lineCollector := &collectedLines{}
	tailWorker, startErr := Start(rootDirectory,
		Options{MatchGlob: "*.jsonl", PollEvery: 20 * time.Millisecond}, lineCollector.onLines)
	require.NoError(t, startErr)
	t.Cleanup(tailWorker.Close)
	time.Sleep(80 * time.Millisecond)
	assert.Empty(t, lineCollector.snapshot())

	_, emptyRootErr := Start("", Options{MatchGlob: "*.jsonl"}, lineCollector.onLines)
	assert.Error(t, emptyRootErr)
	_, emptyGlobErr := Start(rootDirectory, Options{}, lineCollector.onLines)
	assert.Error(t, emptyGlobErr)
	_, nilCallbackErr := Start(rootDirectory, Options{MatchGlob: "*.jsonl"}, nil)
	assert.Error(t, nilCallbackErr)
}
