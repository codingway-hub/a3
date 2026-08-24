// Package watcher 提供通用文件监听引擎：对目录树内匹配文件做增量行级读取。
//
// 实现采用轮询扫描而非 OS 事件订阅：审计采集容忍亚秒延迟，轮询天然合并高频写入
// （等价于事件方案的写事件去抖），无需逐目录注册 watch，跨平台行为一致且零额外依赖。
// 扫描每拍进行，偏移按脏标记惰性持久化——空闲拍只读不写（扫得勤、写得懒）。
package watcher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultPollEvery 默认轮询间隔；测试可注入更短间隔加速用例。
const DefaultPollEvery = 300 * time.Millisecond

// Options Tailer 启动选项。
type Options struct {
	MatchGlob string        // 匹配的文件名 glob（对 base 名生效），如 "*.jsonl"
	StateFile string        // 偏移持久化文件路径；空字符串表示不持久化（仅内存）
	PollEvery time.Duration // 轮询间隔；零值使用 DefaultPollEvery
}

// Tailer 目录树增量行监听器：
// 启动时既存的文件跳到当前 EOF（不回溯历史）；运行期新建的文件从头消费（保住新建会话首批事件）；
// 已知文件从上次偏移继续读增量；只回调完整行（末尾半行留待下次）；文件截断时防御性归零重读。
type Tailer struct {
	root    string
	options Options
	onLines func(sourcePath string, lines [][]byte)

	stopOnce sync.Once
	stopChan chan struct{}
	doneChan chan struct{}

	mu              sync.Mutex
	lineOffsets     map[string]int64 // 文件绝对路径 → 已消费字节偏移（指向下一个未读字节）
	offsetsDirty    bool             // 偏移自上次成功落盘后是否有变更；false 时 saveOffsets 跳过写盘
	startupScanDone bool             // 首轮扫描是否已完成（区分「启动既有」与「运行期新建」）
}

// offsetSnapshot 偏移持久化文件的磁盘结构。
type offsetSnapshot struct {
	Offsets map[string]int64 `json:"offsets"`
}

// Start 启动监听：恢复历史偏移并同步完成首轮扫描（此后新建的文件一律从头消费），
// 再进入后台轮询，直到 Close。
// root 与 onLines 必填；onLines 在后台协程内被串行调用，须自行保证线程安全且不可阻塞过久。
func Start(rootDirectory string, options Options, onLines func(sourcePath string, lines [][]byte)) (*Tailer, error) {
	if rootDirectory == "" {
		return nil, fmt.Errorf("watcher 根目录不能为空")
	}
	if options.MatchGlob == "" {
		return nil, fmt.Errorf("watcher 文件匹配 glob 不能为空")
	}
	if onLines == nil {
		return nil, fmt.Errorf("watcher 行回调不能为空")
	}
	absoluteRoot, absErr := filepath.Abs(rootDirectory)
	if absErr != nil {
		return nil, fmt.Errorf("watcher 根目录转绝对路径失败: %w", absErr)
	}
	if options.PollEvery <= 0 {
		options.PollEvery = DefaultPollEvery
	}

	tailWorker := &Tailer{
		root:        absoluteRoot,
		options:     options,
		onLines:     onLines,
		stopChan:    make(chan struct{}),
		doneChan:    make(chan struct{}),
		lineOffsets: make(map[string]int64),
	}
	if restoreErr := tailWorker.restoreOffsets(); restoreErr != nil {
		return nil, restoreErr
	}
	tailWorker.scanOnce() // 同步首轮：Start 返回前既存的文件全部按「启动既有」跳过历史
	go tailWorker.pollLoop()
	return tailWorker, nil
}

// Close 停止轮询并落盘最终偏移；重复调用安全。等待后台协程退出后返回。
func (tailWorker *Tailer) Close() {
	tailWorker.stopOnce.Do(func() { close(tailWorker.stopChan) })
	<-tailWorker.doneChan
}

// pollLoop 主循环：每拍全量扫描目录树并消费增量，退出前保存最终偏移。
func (tailWorker *Tailer) pollLoop() {
	defer close(tailWorker.doneChan)
	tickTimer := time.NewTicker(tailWorker.options.PollEvery)
	defer tickTimer.Stop()
	for {
		select {
		case <-tailWorker.stopChan:
			tailWorker.saveOffsets()
			return
		case <-tickTimer.C:
			tailWorker.scanOnce()
		}
	}
}

// scanOnce 单次扫描：遍历根目录树下全部匹配文件，逐个消费自上次数以来的新增完整行。
func (tailWorker *Tailer) scanOnce() {
	walkErr := filepath.WalkDir(tailWorker.root, func(currentPath string, dirEntry os.DirEntry, walkItemErr error) error {
		if walkItemErr != nil {
			return nil // 单个条目不可达（被删等）不影响其余文件
		}
		if dirEntry.IsDir() {
			return nil
		}
		matched, matchErr := filepath.Match(tailWorker.options.MatchGlob, dirEntry.Name())
		if matchErr != nil || !matched {
			return nil
		}
		sourceInfo, sourceReady := tailWorker.resolveSourceInfo(currentPath, dirEntry)
		if !sourceReady {
			return nil // 本拍遍历间隙文件消失或暂不可达：偏移已清理，下拍重试
		}
		if sourceInfo.IsDir() {
			return nil // 非常规情形兜底（如软链指向目录）：不作为日志消费
		}
		tailWorker.consumeIncrement(currentPath, sourceInfo.Size())
		return nil
	})
	_ = walkErr // 根目录整体消失时静默跳过本拍，下拍重试
	tailWorker.mu.Lock()
	tailWorker.startupScanDone = true // 首轮扫描后新建的文件按「运行期新建」从头消费
	tailWorker.mu.Unlock()
	tailWorker.saveOffsets()
}

// resolveSourceInfo 从目录遍历结果获取匹配文件的信息，替代逐文件独立 Stat：
// 常规文件直接复用遍历所得信息（Windows 上零额外系统调用）；符号链接跟随目标取真实大小，
// 与原 os.Stat 语义一致。取值失败（文件在遍历间隙消失等）返回 false 并清除其历史偏移。
func (tailWorker *Tailer) resolveSourceInfo(sourcePath string, dirEntry os.DirEntry) (os.FileInfo, bool) {
	if dirEntry.Type()&os.ModeSymlink == 0 {
		sourceInfo, infoErr := dirEntry.Info()
		if infoErr == nil {
			return sourceInfo, true
		}
		tailWorker.markFileVanished(sourcePath)
		return nil, false
	}
	resolvedInfo, statErr := os.Stat(sourcePath) // lstat 只反映链接自身，须跟随目标取真实大小
	if statErr != nil {
		tailWorker.markFileVanished(sourcePath)
		return nil, false
	}
	return resolvedInfo, true
}

// markFileVanished 清除单文件的历史偏移（重建后视为新文件），并标记待落盘。
func (tailWorker *Tailer) markFileVanished(sourcePath string) {
	tailWorker.mu.Lock()
	delete(tailWorker.lineOffsets, sourcePath)
	tailWorker.offsetsDirty = true
	tailWorker.mu.Unlock()
}

// consumeIncrement 从已记录偏移处读取单文件新增内容，回调其中全部完整行并推进偏移。
// fileSize 来自本拍目录遍历（见 resolveSourceInfo），用于增量判定与截断检测。
func (tailWorker *Tailer) consumeIncrement(sourcePath string, fileSize int64) {
	tailWorker.mu.Lock()
	consumedOffset, tracked := tailWorker.lineOffsets[sourcePath]
	if !tracked {
		if tailWorker.startupScanDone {
			// 运行期新建的文件：从头消费（新建会话的首批事件不能丢）
			consumedOffset = 0
		} else {
			// 启动时既存的文件：跳到当前 EOF，不回溯历史内容
			consumedOffset = fileSize
		}
		tailWorker.lineOffsets[sourcePath] = consumedOffset
		tailWorker.offsetsDirty = true
		tailWorker.mu.Unlock()
		return
	}
	if fileSize < consumedOffset {
		consumedOffset = 0 // 截断/重建设置：防御性从头重读
		tailWorker.lineOffsets[sourcePath] = 0
		tailWorker.offsetsDirty = true
	}
	tailWorker.mu.Unlock()

	if fileSize == consumedOffset {
		return // 无新增
	}

	sourceFile, openErr := os.Open(sourcePath)
	if openErr != nil {
		return // 本拍打开失败（权限/竞争删除）下拍重试
	}
	defer func() { _ = sourceFile.Close() }()

	if _, seekErr := sourceFile.Seek(consumedOffset, io.SeekStart); seekErr != nil {
		return
	}
	incrementBytes, readErr := io.ReadAll(sourceFile)
	if readErr != nil {
		return // 读一半失败：偏移未推进，下拍重读同区间
	}

	lastNewlineIndex := bytes.LastIndexByte(incrementBytes, '\n')
	if lastNewlineIndex < 0 {
		return // 尚无完整行（半行等待后续写入拼齐）
	}
	completeChunk := incrementBytes[:lastNewlineIndex+1]
	rawLines := bytes.Split(completeChunk[:len(completeChunk)-1], []byte("\n"))
	lines := make([][]byte, 0, len(rawLines))
	for _, rawLine := range rawLines {
		lines = append(lines, rawLine) // 保留原始字节（含空白），交由解析层决定去留
	}

	nextOffset := consumedOffset + int64(lastNewlineIndex+1)
	tailWorker.onLines(sourcePath, lines)

	tailWorker.mu.Lock()
	tailWorker.lineOffsets[sourcePath] = nextOffset
	tailWorker.offsetsDirty = true
	tailWorker.mu.Unlock()
}

// restoreOffsets 启动时从状态文件加载历史偏移。
func (tailWorker *Tailer) restoreOffsets() error {
	if tailWorker.options.StateFile == "" {
		return nil
	}
	snapshotBytes, readErr := os.ReadFile(tailWorker.options.StateFile)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return nil // 首次运行无历史状态
		}
		return fmt.Errorf("读取偏移状态文件失败: %w", readErr)
	}
	var snapshot offsetSnapshot
	if unmarshalErr := json.Unmarshal(snapshotBytes, &snapshot); unmarshalErr != nil {
		return fmt.Errorf("偏移状态文件损坏: %w", unmarshalErr)
	}
	for trackedPath, trackedOffset := range snapshot.Offsets {
		tailWorker.lineOffsets[trackedPath] = trackedOffset
	}
	return nil
}

// saveOffsets 按脏标记惰性持久化偏移：自上次成功落盘后无任何变更时直接返回，
// 空闲轮询拍零磁盘写入。快照仅记录仍然存在的文件（Stat 探活），避免已删路径残留进状态文件。
// 仅当快照完整覆盖全部跟踪项时才视为同步完成；个别文件 Stat 瞬时失败则保持脏标记下拍重试。
func (tailWorker *Tailer) saveOffsets() {
	if tailWorker.options.StateFile == "" {
		return
	}
	tailWorker.mu.Lock()
	if !tailWorker.offsetsDirty {
		tailWorker.mu.Unlock()
		return // 偏移无变更：本拍跳过写盘（扫得勤、写得懒）
	}
	liveOffsets := make(map[string]int64, len(tailWorker.lineOffsets))
	for trackedPath, trackedOffset := range tailWorker.lineOffsets {
		if _, statErr := os.Stat(trackedPath); statErr == nil {
			liveOffsets[trackedPath] = trackedOffset
		}
	}
	// 先摘脏标记再落盘；若个别文件探活失败导致快照不完整则保持标记等待重试
	tailWorker.offsetsDirty = len(liveOffsets) != len(tailWorker.lineOffsets)
	tailWorker.mu.Unlock()

	if len(liveOffsets) == 0 {
		return // 无可持久化状态，避免空文件覆盖有效历史
	}

	snapshotBytes, marshalErr := json.Marshal(offsetSnapshot{Offsets: liveOffsets})
	if marshalErr != nil {
		tailWorker.markOffsetsDirtyForRetry()
		return
	}
	if persistErr := tailWorker.writeSnapshotAtomic(snapshotBytes); persistErr != nil {
		tailWorker.markOffsetsDirtyForRetry()
	}
}

// writeSnapshotAtomic 将快照字节经临时文件+原子改名写入状态文件。
func (tailWorker *Tailer) writeSnapshotAtomic(snapshotBytes []byte) error {
	stateDirectory := filepath.Dir(tailWorker.options.StateFile)
	if mkdirErr := os.MkdirAll(stateDirectory, 0o755); mkdirErr != nil {
		return mkdirErr
	}
	tempFile, createErr := os.CreateTemp(stateDirectory, ".offsets-*.tmp")
	if createErr != nil {
		return createErr
	}
	tempName := tempFile.Name()
	if _, writeErr := tempFile.Write(snapshotBytes); writeErr != nil {
		_ = tempFile.Close()
		_ = os.Remove(tempName)
		return writeErr
	}
	if closeErr := tempFile.Close(); closeErr != nil {
		_ = os.Remove(tempName)
		return closeErr
	}
	if renameErr := os.Rename(tempName, tailWorker.options.StateFile); renameErr != nil {
		_ = os.Remove(tempName)
		return renameErr
	}
	return nil
}

// markOffsetsDirtyForRetry 落盘失败后恢复脏标记，确保待持久化偏移在后续轮询拍重试不丢。
func (tailWorker *Tailer) markOffsetsDirtyForRetry() {
	tailWorker.mu.Lock()
	tailWorker.offsetsDirty = true
	tailWorker.mu.Unlock()
}
