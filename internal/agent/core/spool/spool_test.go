package spool

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFIFOOrderAndEmptySentinel(t *testing.T) {
	spoolQueue, newErr := New(filepath.Join(t.TempDir(), "spool"), 0)
	require.NoError(t, newErr)

	for _, batchName := range []string{"batch-A", "batch-B", "batch-C"} {
		require.NoError(t, spoolQueue.Enqueue([]byte(batchName)))
		time.Sleep(50 * time.Microsecond) // 纳秒名可能同值，稍作错开保证严格时间序
	}

	queueLength, lengthErr := spoolQueue.Len()
	require.NoError(t, lengthErr)
	assert.Equal(t, 3, queueLength)

	for _, expectedBatch := range []string{"batch-A", "batch-B", "batch-C"} {
		inflightBatch, dequeueErr := spoolQueue.Dequeue()
		require.NoError(t, dequeueErr)
		assert.Equal(t, expectedBatch, string(inflightBatch.Payload))
		require.NoError(t, inflightBatch.Commit())
	}

	_, emptyErr := spoolQueue.Dequeue()
	assert.ErrorIs(t, emptyErr, ErrEmpty)
}

func TestRestartContinuesConsumption(t *testing.T) {
	spoolDirectory := filepath.Join(t.TempDir(), "spool")

	firstQueue, newErr := New(spoolDirectory, 0)
	require.NoError(t, newErr)
	require.NoError(t, firstQueue.Enqueue([]byte(`{"events":["old-1"]}`)))
	time.Sleep(50 * time.Microsecond)
	require.NoError(t, firstQueue.Enqueue([]byte(`{"events":["old-2"]}`)))

	// 模拟进程重启：重新 New 同一目录
	restartedQueue, restartErr := New(spoolDirectory, 0)
	require.NoError(t, restartErr)

	firstBatch, firstDequeueErr := restartedQueue.Dequeue()
	require.NoError(t, firstDequeueErr)
	assert.JSONEq(t, `{"events":["old-1"]}`, string(firstBatch.Payload))
	require.NoError(t, firstBatch.Commit())

	// 重启后新入队排在存量之后
	require.NoError(t, restartedQueue.Enqueue([]byte(`{"events":["new-1"]}`)))
	secondBatch, secondDequeueErr := restartedQueue.Dequeue()
	require.NoError(t, secondDequeueErr)
	assert.JSONEq(t, `{"events":["old-2"]}`, string(secondBatch.Payload))
	require.NoError(t, secondBatch.Commit())

	thirdBatch, thirdDequeueErr := restartedQueue.Dequeue()
	require.NoError(t, thirdDequeueErr)
	assert.JSONEq(t, `{"events":["new-1"]}`, string(thirdBatch.Payload))
	require.NoError(t, thirdBatch.Commit())
}

func TestCapacityEvictsOldestBatches(t *testing.T) {
	spoolQueue, newErr := New(filepath.Join(t.TempDir(), "spool"), 100) // 上限 100 字节
	require.NoError(t, newErr)

	largePayloadA := make([]byte, 60)
	largePayloadB := make([]byte, 60)
	for payloadIndex := range largePayloadA {
		largePayloadA[payloadIndex] = 'a'
	}
	for payloadIndex := range largePayloadB {
		largePayloadB[payloadIndex] = 'b'
	}

	require.NoError(t, spoolQueue.Enqueue(largePayloadA)) // 总量 60 ≤ 100
	require.NoError(t, spoolQueue.Enqueue(largePayloadB)) // 总量 120 > 100 → 淘汰 A
	time.Sleep(50 * time.Microsecond)

	inflightBatch, dequeueErr := spoolQueue.Dequeue()
	require.NoError(t, dequeueErr)
	assert.Equal(t, largePayloadB, inflightBatch.Payload, "超限后最旧批次应被淘汰，仅剩最新批次")
	require.NoError(t, inflightBatch.Commit())

	_, emptyErr := spoolQueue.Dequeue()
	assert.ErrorIs(t, emptyErr, ErrEmpty)
}

func TestNewCleansLeftoverTempFiles(t *testing.T) {
	spoolDirectory := filepath.Join(t.TempDir(), "spool")
	require.NoError(t, os.MkdirAll(spoolDirectory, 0o755))
	leftoverPath := filepath.Join(spoolDirectory, "batch-tmp-123.part")
	require.NoError(t, os.WriteFile(leftoverPath, []byte("half-written"), 0o644))

	_, newErr := New(spoolDirectory, 0)
	require.NoError(t, newErr)

	_, statErr := os.Stat(leftoverPath)
	assert.True(t, os.IsNotExist(statErr), "历史残留临时文件应在初始化时清理")
}

func TestNewValidation(t *testing.T) {
	_, emptyErr := New("", 0)
	assert.Error(t, emptyErr)
}

// TestUncommittedBatchRecoversOnRestart 钉住改名确认法语义：
// 出队后未 Commit 即崩溃（模拟：持有租约不提交、直接重建 Spool），
// 下次启动应把在途批次还原回队首原位——先于存量与后入队批次被重新消费。
func TestUncommittedBatchRecoversOnRestart(t *testing.T) {
	spoolDirectory := filepath.Join(t.TempDir(), "spool")
	firstQueue, newErr := New(spoolDirectory, 0)
	require.NoError(t, newErr)
	require.NoError(t, firstQueue.Enqueue([]byte("batch-A")))
	time.Sleep(50 * time.Microsecond)
	require.NoError(t, firstQueue.Enqueue([]byte("batch-B")))

	// 出队 batch-A 但不 Commit（模拟处理期间进程被杀）
	inflightBatch, dequeueErr := firstQueue.Dequeue()
	require.NoError(t, dequeueErr)
	assert.Equal(t, "batch-A", string(inflightBatch.Payload))
	flightLength, flightLengthErr := firstQueue.Len()
	require.NoError(t, flightLengthErr)
	assert.Equal(t, 1, flightLength, "在途批次不应计入队列长度，也不应再被 Dequeue 取到")

	// 重建 Spool 模拟重启：在途批次应归位队首原位重新排队
	restartedQueue, restartErr := New(spoolDirectory, 0)
	require.NoError(t, restartErr)

	queueLength, lengthErr := restartedQueue.Len()
	require.NoError(t, lengthErr)
	assert.Equal(t, 2, queueLength, "未提交的在途批次重启后应回到队列")

	firstBatch, firstDequeueErr := restartedQueue.Dequeue()
	require.NoError(t, firstDequeueErr)
	assert.Equal(t, "batch-A", string(firstBatch.Payload))
	require.NoError(t, firstBatch.Commit())
}

// fillerPayload 生成指定字节数的可控内容（用于容量类测试）。
func fillerPayload(sizeBytes int, fillChar byte) []byte {
	payload := make([]byte, sizeBytes)
	for payloadIndex := range payload {
		payload[payloadIndex] = fillChar
	}
	return payload
}

// TestCapacityOverflowMovesToQuarantineNotDelete 钉住「超限归档不删除」语义：
// 超容量最旧批位移入隔离区，incoming 侧仍按 FIFO 提供服务，证据不焚。
func TestCapacityOverflowMovesToQuarantineNotDelete(t *testing.T) {
	spoolQueue, newErr := NewWithLimits(filepath.Join(t.TempDir(), "spool"), 100, DefaultQuarantineMaxBytes)
	require.NoError(t, newErr)

	require.NoError(t, spoolQueue.Enqueue(fillerPayload(60, 'a'))) // 60 ≤ 100
	time.Sleep(50 * time.Microsecond)
	require.NoError(t, spoolQueue.Enqueue(fillerPayload(60, 'b'))) // 120 > 100 → A 移入隔离区

	queueLength, lengthErr := spoolQueue.Len()
	require.NoError(t, lengthErr)
	assert.Equal(t, 1, queueLength, "隔离区不影响 incoming 队列长度")

	inflightBatch, dequeueErr := spoolQueue.Dequeue()
	require.NoError(t, dequeueErr)
	assert.Equal(t, fillerPayload(60, 'b'), inflightBatch.Payload, "超限后最旧批次被移出，最新批次按 FIFO 出队")
	require.NoError(t, inflightBatch.Commit())

	quarantinedNames, listErr := spoolQueue.listQuarantine()
	require.NoError(t, listErr)
	require.Len(t, quarantinedNames, 1, "超限批次应归档于隔离区而非删除（证据保留）")
	assert.Contains(t, quarantinedNames[0], ".q-capacity", "隔离区文件名应标记归档原因")
}

// TestQuarantineLimitEvictsOldestQuarantine 钉住隔离区独立限额：
// 超过隔离区上限才删最旧归档（与 incoming 容量无关），至少保留最新一份。
func TestQuarantineLimitEvictsOldestQuarantine(t *testing.T) {
	spoolQueue, newErr := NewWithLimits(filepath.Join(t.TempDir(), "spool"), 180 /* incoming+working */, 100 /* quarantine */)
	require.NoError(t, newErr)

	for enqueueIndex := 0; enqueueIndex < 5; enqueueIndex++ {
		require.NoError(t, spoolQueue.Enqueue(fillerPayload(60, byte('a'+enqueueIndex))))
	}

	queueLength, lengthErr := spoolQueue.Len()
	require.NoError(t, lengthErr)
	assert.Equal(t, 3, queueLength, "总容量 180 下 5×60 应淘汰 2 批")

	quarantinedNames, listErr := spoolQueue.listQuarantine()
	require.NoError(t, listErr)
	assert.Len(t, quarantinedNames, 1, "隔离区上限 100 < 两批 120，最旧归档被限额删除，保留最新一份")
}

// TestBatchRestoreAndQuarantine 钉住租约的两个处置方法：
// Restore 把批次放回队里可再取；Quarantine 归档留证且不占 incoming 队列。
func TestBatchRestoreAndQuarantine(t *testing.T) {
	spoolQueue, newErr := NewWithLimits(filepath.Join(t.TempDir(), "spool"), 0, DefaultQuarantineMaxBytes)
	require.NoError(t, newErr)
	require.NoError(t, spoolQueue.Enqueue([]byte("payload-A")))

	// Restore：放回原位重新排队
	firstBatch, dequeueErr := spoolQueue.Dequeue()
	require.NoError(t, dequeueErr)
	require.NoError(t, firstBatch.Restore())
	queueLength, lengthErr := spoolQueue.Len()
	require.NoError(t, lengthErr)
	assert.Equal(t, 1, queueLength, "Restore 后批次应回到 incoming 队列")

	restoredBatch, restoredDequeueErr := spoolQueue.Dequeue()
	require.NoError(t, restoredDequeueErr)
	assert.Equal(t, "payload-A", string(restoredBatch.Payload), "Restore 的批次内容完整可再取")

	// Quarantine：归档留证，注入原因标记
	require.NoError(t, restoredBatch.Quarantine("reject-400"))
	queueLengthAfterQuarantine, _ := spoolQueue.Len()
	assert.Equal(t, 0, queueLengthAfterQuarantine, "归档批次不再占 incoming 队列")

	quarantinedNames, listErr := spoolQueue.listQuarantine()
	require.NoError(t, listErr)
	require.Len(t, quarantinedNames, 1)
	assert.Contains(t, quarantinedNames[0], ".q-reject-400", "归档文件名应携带原因供诊断")
	archivedBytes, readErr := os.ReadFile(filepath.Join(spoolQueue.quarantinePath, quarantinedNames[0]))
	require.NoError(t, readErr)
	assert.Equal(t, "payload-A", string(archivedBytes), "归档批次内容完整保留")
}

// TestCapacityIncludesWorkingInflight 钉住容量含在途租金：working 在途批次计入总容量，
// 否则会出现「内存视角未超限、磁盘实际撑爆」的漏算。此处置在途批次加入后的差额
// 决定 incoming 是否触发淘汰。
func TestCapacityIncludesWorkingInflight(t *testing.T) {
	spoolQueue, newErr := NewWithLimits(filepath.Join(t.TempDir(), "spool"), 100, DefaultQuarantineMaxBytes)
	require.NoError(t, newErr)
	require.NoError(t, spoolQueue.Enqueue(fillerPayload(40, 'a'))) // A
	time.Sleep(50 * time.Microsecond)
	require.NoError(t, spoolQueue.Enqueue(fillerPayload(40, 'b'))) // B；40+40=80 ≤ 100 不淘汰

	inflightBatch, dequeueErr := spoolQueue.Dequeue() // A 入 working，仍占 40 字节
	require.NoError(t, dequeueErr)
	assert.Equal(t, fillerPayload(40, 'a'), inflightBatch.Payload)

	require.NoError(t, spoolQueue.Enqueue(fillerPayload(40, 'c'))) // C；working 40 + incoming 80 = 120 > 100 → 淘汰 incoming 最旧 B
	quarantinedNames, quarantineErr := spoolQueue.listQuarantine()
	require.NoError(t, quarantineErr)
	require.Len(t, quarantinedNames, 1, "在途批次计入容量：B 因 working A 的存在被淘汰")
	assert.Contains(t, quarantinedNames[0], ".q-capacity")

	incomingNames, listErr := spoolQueue.listIncoming()
	require.NoError(t, listErr)
	require.Len(t, incomingNames, 1, "incoming 应仅剩最新批次 C")

	inflightBatch.Commit() // 清理租约，避免影响 t.TempDir 清理

	// 直接校验 C 的内容：incoming 中唯一批次的载荷应为 'c'
	remainingBatch, dequeueRemainingErr := spoolQueue.Dequeue()
	require.NoError(t, dequeueRemainingErr)
	assert.Equal(t, fillerPayload(40, 'c'), remainingBatch.Payload, "在途 A 之后，最新 C 才是队首")
	require.NoError(t, remainingBatch.Commit())
}

// TestLegacyLayoutMigration 钉住旧版根目录布局迁移：
// 根目录直排批次 → incoming；根目录在途 → incoming 还原；根目录 temp 无条件删。
func TestLegacyLayoutMigration(t *testing.T) {
	spoolDirectory := filepath.Join(t.TempDir(), "spool")
	require.NoError(t, os.MkdirAll(spoolDirectory, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(spoolDirectory, "batch-100.jsonl"), []byte("old-batch"), 0o644))
	// 旧版在途文件为双扩展 batch-<ns>.jsonl.jsonl.inflight（历史真实格式）
	require.NoError(t, os.WriteFile(filepath.Join(spoolDirectory, "batch-200.jsonl.jsonl.inflight"), []byte("old-inflight"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(spoolDirectory, "batch-tmp-55.part"), []byte("half"), 0o644))

	spoolQueue, newErr := New(spoolDirectory, 0)
	require.NoError(t, newErr)

	incomingNames, listErr := spoolQueue.listIncoming()
	require.NoError(t, listErr)
	require.Len(t, incomingNames, 2, "根目录批次与在途文件都应收敛到 incoming")
	assert.Contains(t, incomingNames, "batch-100.jsonl")
	assert.Contains(t, incomingNames, "batch-200.jsonl", "旧版在途文件应还原为标准批次名")

	restoredBatch, dequeueErr := spoolQueue.Dequeue()
	require.NoError(t, dequeueErr)
	assert.Equal(t, "old-batch", string(restoredBatch.Payload), "迁移后 FIFO 语义不变：字典序在前者先出队")
	require.NoError(t, restoredBatch.Commit())

	secondBatch, secondDequeueErr := spoolQueue.Dequeue()
	require.NoError(t, secondDequeueErr)
	assert.Equal(t, "old-inflight", string(secondBatch.Payload), "根目录在途文件还原后内容完整")
	require.NoError(t, secondBatch.Commit())

	_, tempStatErr := os.Stat(filepath.Join(spoolDirectory, "batch-tmp-55.part"))
	assert.True(t, os.IsNotExist(tempStatErr), "根目录临时半成品无条件删除")
}

// TestStaleTempProtectsConcurrentProducer 钉住临时文件年龄保护：
// 启动清理只删 mtime 超过 1 小时的崩溃残留，刚创建的临时文件（并发 hook 正在写盘）
// 绝不被误删——这是对旧版「每次 New 无条件删临时文件」缺陷的直接修复。
func TestStaleTempProtectsConcurrentProducer(t *testing.T) {
	spoolDirectory := filepath.Join(t.TempDir(), "spool")
	firstQueue, newErr := New(spoolDirectory, 0)
	require.NoError(t, newErr)

	// 模拟并发进程正在写的临时文件（mtime=now）与历史崩溃残留（mtime 超 1h）
	freshTempPath := filepath.Join(firstQueue.incomingPath, "batch-tmp-fresh.part")
	require.NoError(t, os.WriteFile(freshTempPath, []byte("being-written"), 0o644))
	staleTempPath := filepath.Join(firstQueue.incomingPath, "batch-tmp-stale.part")
	require.NoError(t, os.WriteFile(staleTempPath, []byte("crash-leftover"), 0o644))
	staleTime := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(staleTempPath, staleTime, staleTime))

	// 重启（常驻进程启动）不得误删并发写入方刚创建的临时文件
	restartedQueue, restartErr := New(spoolDirectory, 0)
	require.NoError(t, restartErr)
	_, freshStatErr := os.Stat(freshTempPath)
	assert.NoError(t, freshStatErr, "并发生产者正在写的临时文件不应被启动清理误删")
	_, staleStatErr := os.Stat(staleTempPath)
	assert.True(t, os.IsNotExist(staleStatErr), "超过 1 小时的崩溃残留临时文件应在启动时清理")
	_ = restartedQueue
}
