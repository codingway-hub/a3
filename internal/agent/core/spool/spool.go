// Package spool 提供断网磁盘缓存队列：上报失败的事件批次落盘排队，
// 服务恢复后由调用方按 FIFO 重放。文件名内嵌零填充纳秒时间戳保证字典序即时间序；
// 写入采用临时文件+原子改名，进程任意时刻崩溃都不会留下半截批次。
// 出队采用「改名取走+显式确认」：批次先改名到 working/ 在途再交付，调用方处理
// 成功后 Commit 删除、失败可 Restore 放回原队或 Quarantine 归档；处理期间任意
// 时刻崩溃，下次启动都会把 working/ 在途文件还原回队首原位重新排队
// （至少一次语义，重复由服务端幂等兜底）。
//
// 目录结构（<root> 下三个子目录）：
//
//	incoming/   生产者唯一写点，FIFO 排队批次
//	working/    消费租约（出队后在途租借）
//	quarantine/ 归档区：容量淘汰与服务端明确拒绝的批次按证据移入，超限才删最旧
//
// 容量口径：incoming + working 合计受限（在途文件计入总容量，杜绝产销并行时漏算）；
// 超限优先把 incoming 最旧批位移入 quarantine 归档而非删除；quarantine 自有独立
// 上限，超限才删最旧并大声告警。写入临时文件与分批文件同处 incoming，启动清理
// 仅删除 mtime 超过 1 小时的残留临时文件——保护并发生产者（短命 hook 进程）正在
// 写盘的内容不被启动方误删。
package spool

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// 容量上限默认值。
const (
	// DefaultMaxTotalBytes 默认容量上限 512MB；超过后把最旧批次移入隔离区。
	DefaultMaxTotalBytes int64 = 512 << 20
	// DefaultQuarantineMaxBytes 隔离区默认上限 128MB；超过后删最旧归档批次。
	DefaultQuarantineMaxBytes int64 = 128 << 20
)

// 文件名约定与目录名。
const (
	batchFilePrefix      = "batch-"
	batchFileSuffix      = ".jsonl"
	inflightFileSuffix   = ".inflight"                          // 出队后在途文件后缀：batch-<ns>.jsonl.inflight
	legacyInflightSuffix = batchFileSuffix + inflightFileSuffix // 旧版双扩展：batch-<ns>.jsonl.jsonl.inflight
	tempFilePattern      = "batch-tmp-*.part"
	batchFileNameGlob    = batchFilePrefix + "*" + batchFileSuffix
	quarantineSuffix     = ".q-" // 隔离区文件名后缀，后随归档原因
	// tempStaleAfter 启动清理临时文件的年龄门槛：仅删除超过 1 小时的崩溃残留，
	// 保护并发写盘的短命 hook 进程（其临时文件 mtime 很近，绝不被启动方误删）。
	tempStaleAfter = time.Hour

	incomingDir   = "incoming"
	workingDir    = "working"
	quarantineDir = "quarantine"
)

// ErrEmpty 队列已空。
var ErrEmpty = errors.New("spool 队列为空")

// Spool 基于目录的 FIFO 磁盘队列。单进程生产假设（多写入方为短命 hook 进程，
// 各自临时文件+原子改名互不干扰）：文件名以纳秒时间戳保证唯一与有序。
type Spool struct {
	directory          string
	incomingPath       string
	workingPath        string
	quarantinePath     string
	maxTotalBytes      int64
	quarantineMaxBytes int64
}

// New 打开（或初始化）队列目录：兼容旧版签名，隔离区容量取默认值。
func New(directory string, maxTotalBytes int64) (*Spool, error) {
	return NewWithLimits(directory, maxTotalBytes, DefaultQuarantineMaxBytes)
}

// NewWithLimits 打开（或初始化）队列目录并显式指定容量上限。
// 任一上限非正即取对应默认值。初始化做幂等迁移：旧版根目录布局（批次/在途/临时
// 文件直排根目录）收敛到新子目录结构，遗留在途批次还原回队，残留临时文件按年龄清理。
func NewWithLimits(directory string, maxTotalBytes, quarantineMaxBytes int64) (*Spool, error) {
	if directory == "" {
		return nil, fmt.Errorf("spool 目录不能为空")
	}
	if maxTotalBytes <= 0 {
		maxTotalBytes = DefaultMaxTotalBytes
	}
	if quarantineMaxBytes <= 0 {
		quarantineMaxBytes = DefaultQuarantineMaxBytes
	}
	spoolQueue := &Spool{
		directory:          directory,
		incomingPath:       filepath.Join(directory, incomingDir),
		workingPath:        filepath.Join(directory, workingDir),
		quarantinePath:     filepath.Join(directory, quarantineDir),
		maxTotalBytes:      maxTotalBytes,
		quarantineMaxBytes: quarantineMaxBytes,
	}
	for _, subdirectory := range []string{spoolQueue.incomingPath, spoolQueue.workingPath, spoolQueue.quarantinePath} {
		if mkdirErr := os.MkdirAll(subdirectory, 0o755); mkdirErr != nil {
			return nil, fmt.Errorf("创建 spool 子目录失败: %w", mkdirErr)
		}
	}
	spoolQueue.migrateLegacyLayout()
	spoolQueue.reclaimWorkingInflightBatches()
	spoolQueue.cleanStaleTempFiles()
	spoolQueue.enforceQuarantineLimit(slog.Default())
	return spoolQueue, nil
}

// Directory 返回队列目录（诊断用）。
func (spoolQueue *Spool) Directory() string { return spoolQueue.directory }

// Enqueue 将一个批次写入 incoming 队尾（原子改名可见）；总量超限时把最旧批移入隔离区。
func (spoolQueue *Spool) Enqueue(batchPayload []byte) error {
	batchName := fmt.Sprintf("%s%019d%s", batchFilePrefix, time.Now().UnixNano(), batchFileSuffix)
	tempFile, createErr := os.CreateTemp(spoolQueue.incomingPath, tempFilePattern)
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
	if renameErr := os.Rename(tempName, filepath.Join(spoolQueue.incomingPath, batchName)); renameErr != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("提交批次文件失败: %w", renameErr)
	}
	if evictErr := spoolQueue.evictOverflow(); evictErr != nil {
		return evictErr
	}
	spoolQueue.enforceQuarantineLimit(slog.Default())
	return nil
}

// Batch 是一次 Dequeue 得到的在途批次租约：Payload 交由调用方处理，在途文件在
// Commit 前始终留存——处理期间任意时刻崩溃，下次启动都会把它还原回队首原位重新
// 排队，批次不丢。成功 Commit 删除；失败按语义选 Restore（放回队里重试）或
// Quarantine（归档留证，进入隔离区与容量淘汰同源管理）。
type Batch struct {
	leasePath      string // working/<name>.inflight
	restorePath    string // incoming/<name>（原位放回目标）
	quarantinePath string // 归档目标目录
	name           string // batch-<ns>.jsonl
	Payload        []byte
}

// Commit 确认批次处理完毕（上报成功，或已判定为不可重试而放弃），删除在途文件。
// 删除失败时在途文件留存，下次启动归位重试（至多多送一次，服务端幂等兜底）。
func (inflightBatch *Batch) Commit() error {
	if removeErr := os.Remove(inflightBatch.leasePath); removeErr != nil && !os.IsNotExist(removeErr) {
		return fmt.Errorf("确认消费批次失败: %w", removeErr)
	}
	return nil
}

// Restore 把在途批次放回 incoming 原位重新排队（文件名保留原始纳秒时间戳，
// 重排后回到队列原相对位置，先于更新批次被重试）。用于可重试但需长退避的分类
// （如鉴权失效、服务端 5xx）：不删证据，放回队里等下一轮再试。
func (inflightBatch *Batch) Restore() error {
	if renameErr := os.Rename(inflightBatch.leasePath, inflightBatch.restorePath); renameErr != nil {
		if os.IsNotExist(renameErr) {
			return nil // 在途文件已被并发清理：视为已完成
		}
		return fmt.Errorf("还原批次回队失败: %w", renameErr)
	}
	return nil
}

// Quarantine 把在途批次移入隔离区归档并在文件名标记原因（如 corrupt / reject-400）。
// 归档不同于删除：证据保留，由隔离区容量上限决定何时才淘汰最旧归档。
func (inflightBatch *Batch) Quarantine(reason string) error {
	targetName := inflightBatch.name + quarantineSuffix + sanitizeReason(reason)
	if renameErr := os.Rename(inflightBatch.leasePath, filepath.Join(inflightBatch.quarantinePath, targetName)); renameErr != nil {
		if os.IsNotExist(renameErr) {
			return nil
		}
		return fmt.Errorf("归档批次失败: %w", renameErr)
	}
	return nil
}

// Dequeue 以「改名取走」方式取出 incoming 最旧批次并返回其租约；空队列返回 ErrEmpty。
// 先把批次文件原子改名到 working/<原名>.inflight 再读取交付：取走与删除从此是两步，
// 处理期间崩溃只会让批次回到队首原位重新排队（见 reclaimWorkingInflightBatches），
// 不会凭空消失。改名后读取失败则尽力还原改名并报错（还原失败也无妨，重启仍会归位）。
func (spoolQueue *Spool) Dequeue() (*Batch, error) {
	batchNames, listErr := spoolQueue.listIncoming()
	if listErr != nil {
		return nil, listErr
	}
	if len(batchNames) == 0 {
		return nil, ErrEmpty
	}

	oldestName := batchNames[0]
	oldestPath := filepath.Join(spoolQueue.incomingPath, oldestName)
	leasePath := filepath.Join(spoolQueue.workingPath, oldestName+inflightFileSuffix)
	if renameErr := os.Rename(oldestPath, leasePath); renameErr != nil {
		if os.IsNotExist(renameErr) {
			return nil, ErrEmpty // 恰被并发清空（防御）
		}
		return nil, fmt.Errorf("取出批次失败: %w", renameErr)
	}
	batchPayload, readErr := os.ReadFile(leasePath)
	if readErr != nil {
		_ = os.Rename(leasePath, oldestPath) // 尽力还原改名；失败也无妨，重启会归位
		if os.IsNotExist(readErr) {
			return nil, ErrEmpty
		}
		return nil, fmt.Errorf("读取批次内容失败: %w", readErr)
	}
	return &Batch{
		leasePath:      leasePath,
		restorePath:    oldestPath,
		quarantinePath: spoolQueue.quarantinePath,
		name:           oldestName,
		Payload:        batchPayload,
	}, nil
}

// Len 返回当前等待重放的批次数（在途租约不计入，正被处理中）。
func (spoolQueue *Spool) Len() (int, error) {
	batchNames, listErr := spoolQueue.listIncoming()
	if listErr != nil {
		return 0, listErr
	}
	return len(batchNames), nil
}

// Status 返回待送达服务端的积压量：incoming 排队批与 working 在途租约的
// 批次数与字节数合计。「待送达」口径——在途批次尚未确认送达服务端，仍算未脱困；
// 隔离区属终局归档，不计入积压。结果供常驻心跳上报服务端，其在线窗口 + 非零积压
// 联合判定设备「数据滞留(abnormal)」。临时半成品与隔离文件不重复计数。
func (spoolQueue *Spool) Status() (pendingBatches int64, pendingBytes int64, err error) {
	for directoryIndex, directory := range []string{spoolQueue.incomingPath, spoolQueue.workingPath} {
		dirEntries, readErr := os.ReadDir(directory)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			return 0, 0, fmt.Errorf("读取 spool 目录失败: %w", readErr)
		}
		for _, dirEntry := range dirEntries {
			if dirEntry.IsDir() {
				continue
			}
			// incoming 除常规批次外还有临时半成品，只计批次（working 下必为在途租约）
			if directoryIndex == 0 && !isPlainBatchName(dirEntry.Name()) {
				continue
			}
			pendingBatches++
			if fileStat, statErr := dirEntry.Info(); statErr == nil {
				pendingBytes += fileStat.Size()
			}
		}
	}
	return pendingBatches, pendingBytes, nil
}

// listIncoming 返回 incoming 下按文件名字典序（即时间序）排列的批次文件名列表。
func (spoolQueue *Spool) listIncoming() ([]string, error) {
	dirEntries, readErr := os.ReadDir(spoolQueue.incomingPath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return nil, nil // 目录被外部删掉：视为空队列，Enqueue 会重建
		}
		return nil, fmt.Errorf("读取 spool incoming 目录失败: %w", readErr)
	}
	return collectNames(dirEntries, true), nil
}

// listQuarantine 返回 quarantine 下按字典序排列的归档文件名列表。
func (spoolQueue *Spool) listQuarantine() ([]string, error) {
	dirEntries, readErr := os.ReadDir(spoolQueue.quarantinePath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取 spool 隔离区目录失败: %w", readErr)
	}
	names := make([]string, 0, len(dirEntries))
	for _, dirEntry := range dirEntries {
		if !dirEntry.IsDir() {
			names = append(names, dirEntry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// collectNames 提取目录项中的批次文件名（incoming 仅收普通批次名，排除在途/隔离文件）。
func collectNames(dirEntries []os.DirEntry, excludeNonBatch bool) []string {
	var batchNames []string
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			continue
		}
		if excludeNonBatch && !isPlainBatchName(dirEntry.Name()) {
			continue
		}
		batchNames = append(batchNames, dirEntry.Name())
	}
	sort.Strings(batchNames)
	return batchNames
}

// isPlainBatchName 判定是否为普通批次文件名（incoming 队里的 batch-<ns>.jsonl）。
func isPlainBatchName(name string) bool {
	return strings.HasPrefix(name, batchFilePrefix) &&
		strings.HasSuffix(name, batchFileSuffix) && !strings.HasSuffix(name, inflightFileSuffix)
}

// totalPendingBytes 统计 incoming + working 两个目录的文件字节总数（在途计入容量）。
func (spoolQueue *Spool) totalPendingBytes() (int64, error) {
	var totalBytes int64
	for _, directory := range []string{spoolQueue.incomingPath, spoolQueue.workingPath} {
		dirEntries, readErr := os.ReadDir(directory)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			return 0, fmt.Errorf("读取 spool 目录失败: %w", readErr)
		}
		for _, dirEntry := range dirEntries {
			if dirEntry.IsDir() {
				continue
			}
			if fileStat, statErr := dirEntry.Info(); statErr == nil {
				totalBytes += fileStat.Size()
			}
		}
	}
	return totalBytes, nil
}

// evictOverflow 当 incoming+working 总体积超限时，把 incoming 最旧的批位移入隔离区
// 归档（而非删除），直至回到限额或仅剩最新一批（本批不入库不淘汰，spool 至少保障
// 最新证据被保留）。在途（working）批次受租约保护，只计入容量、不被此路径移动。
func (spoolQueue *Spool) evictOverflow() error {
	for {
		incomingNames, listErr := spoolQueue.listIncoming()
		if listErr != nil {
			return listErr
		}
		totalBytes, totalErr := spoolQueue.totalPendingBytes()
		if totalErr != nil {
			return totalErr
		}
		if len(incomingNames) <= 1 || totalBytes <= spoolQueue.maxTotalBytes {
			return nil
		}
		oldestName := incomingNames[0]
		if quarantineErr := spoolQueue.quarantineByMove(
			filepath.Join(spoolQueue.incomingPath, oldestName), oldestName, "capacity"); quarantineErr != nil {
			return quarantineErr
		}
	}
}

// quarantineByMove 把来源文件移入隔离区并归一命名（原名 + 原因后缀）。
func (spoolQueue *Spool) quarantineByMove(sourcePath, name, reason string) error {
	targetName := name + quarantineSuffix + sanitizeReason(reason)
	if renameErr := os.Rename(sourcePath, filepath.Join(spoolQueue.quarantinePath, targetName)); renameErr != nil {
		if os.IsNotExist(renameErr) {
			return nil
		}
		return fmt.Errorf("移入隔离区失败: %w", renameErr)
	}
	return nil
}

// enforceQuarantineLimit 隔离区超过独立上限时从最旧开始删除，并大声告警。
// 至少保留最新一份归档（单条超限的大文件不得清空全部证据）。
func (spoolQueue *Spool) enforceQuarantineLimit(logger *slog.Logger) {
	for {
		quarantinedNames, listErr := spoolQueue.listQuarantine()
		if listErr != nil || len(quarantinedNames) <= 1 {
			return
		}
		var totalBytes int64
		for _, quarantinedName := range quarantinedNames {
			if fileStat, statErr := os.Stat(filepath.Join(spoolQueue.quarantinePath, quarantinedName)); statErr == nil {
				totalBytes += fileStat.Size()
			}
		}
		if totalBytes <= spoolQueue.quarantineMaxBytes {
			return
		}
		oldestPath := filepath.Join(spoolQueue.quarantinePath, quarantinedNames[0])
		if removeErr := os.Remove(oldestPath); removeErr != nil {
			return // 删除失败：下轮再试
		}
		logger.Error("spool 隔离区容量超限，删除最旧归档批次",
			slog.String("path", oldestPath), slog.Int64("quarantine_bytes", totalBytes))
	}
}

// migrateLegacyLayout 幂等迁移旧版根目录布局：根目录直排的批次移到 incoming，
// 根目录在途文件还原为 incoming 批次，根目录临时半成品无条件删除
// （旧布局无并发写入方，根目录残留必属崩溃遗留）。新临时文件只在 incoming 下，
// 由 cleanStaleTempFiles 按年龄保护。
func (spoolQueue *Spool) migrateLegacyLayout() {
	legacyBatches, _ := filepath.Glob(filepath.Join(spoolQueue.directory, batchFilePrefix+"*"+batchFileSuffix))
	for _, legacyPath := range legacyBatches {
		_ = os.Rename(legacyPath, filepath.Join(spoolQueue.incomingPath, filepath.Base(legacyPath)))
	}
	legacyInflight, _ := filepath.Glob(filepath.Join(spoolQueue.directory, batchFilePrefix+"*"+legacyInflightSuffix))
	for _, legacyPath := range legacyInflight {
		restoredName := restoreLegacyInflightName(filepath.Base(legacyPath))
		_ = os.Rename(legacyPath, filepath.Join(spoolQueue.incomingPath, restoredName))
	}
	leftoverTemp, _ := filepath.Glob(filepath.Join(spoolQueue.directory, tempFilePattern))
	for _, leftoverPath := range leftoverTemp {
		_ = os.Remove(leftoverPath)
	}
}

// restoreLegacyInflightName 把旧版根目录在途文件还原为批次文件名。
// 旧版在途命名形如 batch-<ns>.jsonl.jsonl.inflight（.jsonl 内嵌于在途后缀），
// 当前规范命名是 batch-<ns>.jsonl.inflight；两者统一还原为 batch-<ns>.jsonl。
func restoreLegacyInflightName(inflightName string) string {
	if strings.HasSuffix(inflightName, legacyInflightSuffix) {
		return strings.TrimSuffix(inflightName, legacyInflightSuffix)
	}
	if strings.HasSuffix(inflightName, batchFileSuffix+inflightFileSuffix) {
		return strings.TrimSuffix(inflightName, batchFileSuffix+inflightFileSuffix)
	}
	return strings.TrimSuffix(inflightName, inflightFileSuffix)
}

// reclaimWorkingInflightBatches 把上次进程遗留的 working 在途批次还原回 incoming
// 原位重新排队：这些批次已被取出但从未 Commit，必须重试（至少一次语义）。
func (spoolQueue *Spool) reclaimWorkingInflightBatches() {
	leftovers, _ := filepath.Glob(filepath.Join(spoolQueue.workingPath, batchFilePrefix+"*"+inflightFileSuffix))
	for _, leasePath := range leftovers {
		restoredName := strings.TrimSuffix(filepath.Base(leasePath), inflightFileSuffix)
		_ = os.Rename(leasePath, filepath.Join(spoolQueue.incomingPath, restoredName))
	}
}

// cleanStaleTempFiles 清理崩溃残留的临时半成品，但只清理 mtime 超过 1 小时的：
// 短命 hook 进程可能与常驻启动方并发写盘，刚创建的临时文件属于在途写入，
// 绝不能删（对旧版「每次 New 无条件删临时文件」缺陷的直接修复）。
func (spoolQueue *Spool) cleanStaleTempFiles() {
	leftovers, _ := filepath.Glob(filepath.Join(spoolQueue.incomingPath, tempFilePattern))
	for _, tempPath := range leftovers {
		tempInfo, statErr := os.Stat(tempPath)
		if statErr != nil || time.Since(tempInfo.ModTime()) <= tempStaleAfter {
			continue
		}
		_ = os.Remove(tempPath)
	}
}

// sanitizeReason 把归档原因归一为文件名安全段：仅保留字母数字与连字符，长度截断。
func sanitizeReason(reason string) string {
	var safeBuilder strings.Builder
	for _, charRune := range reason {
		isLetterOrDigit := (charRune >= 'a' && charRune <= 'z') ||
			(charRune >= 'A' && charRune <= 'Z') ||
			(charRune >= '0' && charRune <= '9')
		if isLetterOrDigit || charRune == '-' {
			safeBuilder.WriteRune(charRune)
		} else {
			safeBuilder.WriteByte('-')
		}
		if safeBuilder.Len() >= 32 {
			break
		}
	}
	safeReason := safeBuilder.String()
	if safeReason == "" {
		return "unknown"
	}
	return safeReason
}
