// Package spool 提供断网磁盘缓存队列：上报失败的事件批次落盘排队，
// 服务恢复后由调用方按 FIFO 重放。文件名内嵌零填充纳秒时间戳保证字典序即时间序；
// 写入采用临时文件+原子改名，进程任意时刻崩溃都不会留下半截批次。
package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultMaxTotalBytes 默认容量上限 512MB；超过后淘汰最旧批次。
const DefaultMaxTotalBytes int64 = 512 << 20

// batchFilePrefix 批次文件名前缀；batchFileNameGlob 为其匹配模式。
const (
	batchFilePrefix   = "batch-"
	batchFileSuffix   = ".jsonl"
	tempFilePattern   = "batch-tmp-*.part"
	batchFileNameGlob = batchFilePrefix + "*" + batchFileSuffix
)

// ErrEmpty 队列已空。
var ErrEmpty = errors.New("spool 队列为空")

// Spool 基于目录的 FIFO 磁盘队列。单进程使用假设：文件名以纳秒时间戳保证唯一与有序。
type Spool struct {
	directory     string
	maxTotalBytes int64
}

// New 打开（或初始化）队列目录，并清理上次进程残留的临时半成品文件。
// maxTotalBytes 非 正 时取 DefaultMaxTotalBytes。
func New(directory string, maxTotalBytes int64) (*Spool, error) {
	if directory == "" {
		return nil, fmt.Errorf("spool 目录不能为空")
	}
	if maxTotalBytes <= 0 {
		maxTotalBytes = DefaultMaxTotalBytes
	}
	if mkdirErr := os.MkdirAll(directory, 0o755); mkdirErr != nil {
		return nil, fmt.Errorf("创建 spool 目录失败: %w", mkdirErr)
	}
	spoolQueue := &Spool{directory: directory, maxTotalBytes: maxTotalBytes}
	spoolQueue.cleanLeftoverTempFiles()
	return spoolQueue, nil
}

// Directory 返回队列目录（诊断用）。
func (spoolQueue *Spool) Directory() string { return spoolQueue.directory }

// Enqueue 将一个批次写入队尾（原子改名可见）；必要时淘汰最旧批次控制总容量。
func (spoolQueue *Spool) Enqueue(batchPayload []byte) error {
	batchName := fmt.Sprintf("%s%019d%s", batchFilePrefix, time.Now().UnixNano(), batchFileSuffix)
	tempFile, createErr := os.CreateTemp(spoolQueue.directory, tempFilePattern)
	if createErr != nil {
		return fmt.Errorf("创建批次临时文件失败: %w", createErr)
	}
	tempName := tempFile.Name()
	if _, writeErr := tempFile.Write(batchPayload); writeErr != nil {
		_ = tempFile.Close()
		_ = os.Remove(tempName)
		return fmt.Errorf("写批次内容失败: %w", writeErr)
	}
	if closeErr := tempFile.Close(); closeErr != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("关闭批次临时文件失败: %w", closeErr)
	}
	if renameErr := os.Rename(tempName, filepath.Join(spoolQueue.directory, batchName)); renameErr != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("提交批次文件失败: %w", renameErr)
	}
	return spoolQueue.evictOverflow()
}

// Dequeue 取出并删除最旧批次，返回其内容；空队列返回 ErrEmpty。
// 删除先于调用方处理完成时若进程崩溃，极端情况下该批丢失——服务端按 event_id 幂等，
// 调用方对上传失败批次应自行重新 Enqueue（会排到队尾）。
func (spoolQueue *Spool) Dequeue() ([]byte, error) {
	batchNames, listErr := spoolQueue.listBatches()
	if listErr != nil {
		return nil, listErr
	}
	if len(batchNames) == 0 {
		return nil, ErrEmpty
	}

	oldestPath := filepath.Join(spoolQueue.directory, batchNames[0])
	batchPayload, readErr := os.ReadFile(oldestPath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return nil, ErrEmpty // 恰被并发清空（防御）
		}
		return nil, fmt.Errorf("读取批次文件失败: %w", readErr)
	}
	_ = os.Remove(oldestPath) // 内容已读出，删除失败仅导致下次重复消费，由服务端幂等兜底
	return batchPayload, nil
}

// Len 返回当前排队批次数（诊断用）。
func (spoolQueue *Spool) Len() (int, error) {
	batchNames, listErr := spoolQueue.listBatches()
	if listErr != nil {
		return 0, listErr
	}
	return len(batchNames), nil
}

// listBatches 返回按文件名字典序（即时间序）排列的批次文件名列表。
func (spoolQueue *Spool) listBatches() ([]string, error) {
	dirEntries, readErr := os.ReadDir(spoolQueue.directory)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return nil, nil // 目录被外部删掉：视为空队列，Enqueue 会重建
		}
		return nil, fmt.Errorf("读取 spool 目录失败: %w", readErr)
	}
	var batchNames []string
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() && strings.HasPrefix(dirEntry.Name(), batchFilePrefix) && strings.HasSuffix(dirEntry.Name(), batchFileSuffix) {
			batchNames = append(batchNames, dirEntry.Name())
		}
	}
	sort.Strings(batchNames)
	return batchNames, nil
}

// totalBytesOf 统计批次文件总字节数。
func (spoolQueue *Spool) totalBytesOf(batchNames []string) int64 {
	var totalBytes int64
	for _, batchName := range batchNames {
		if fileStat, statErr := os.Stat(filepath.Join(spoolQueue.directory, batchName)); statErr == nil {
			totalBytes += fileStat.Size()
		}
	}
	return totalBytes
}

// evictOverflow 当批次总体积超限时从最旧开始淘汰，直至回到限额之内（至少保留刚入队的最新一批）。
func (spoolQueue *Spool) evictOverflow() error {
	for {
		batchNames, listErr := spoolQueue.listBatches()
		if listErr != nil {
			return listErr
		}
		if len(batchNames) <= 1 || spoolQueue.totalBytesOf(batchNames) <= spoolQueue.maxTotalBytes {
			return nil
		}
		if removeErr := os.Remove(filepath.Join(spoolQueue.directory, batchNames[0])); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("淘汰超容量旧批次失败: %w", removeErr)
		}
	}
}

// cleanLeftoverTempFiles 移除历史进程崩溃遗留的临时半成品。
func (spoolQueue *Spool) cleanLeftoverTempFiles() {
	leftovers, _ := filepath.Glob(filepath.Join(spoolQueue.directory, "batch-tmp-*.part"))
	for _, leftoverPath := range leftovers {
		_ = os.Remove(leftoverPath)
	}
}
