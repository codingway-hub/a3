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
