package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/codingway-hub/a3/internal/agent/core/transport"
	"github.com/codingway-hub/a3/pkg/schema"
)

// rulesRefreshDefaultSeconds / rulesRefreshFloorSeconds 规则周期刷新默认值与下限：
// 下限防止误配过短周期把服务端当轮询靶子；≤0 关闭周期仅保留启动拉取。
const (
	rulesRefreshDefaultSeconds = 300
	rulesRefreshFloorSeconds   = 60
)

// parseRulesRefreshSeconds 解析 A3_RULES_REFRESH_SECONDS：缺省 300s；
// >0 时钳到下限；≤0（显式关闭）返回 0。
func parseRulesRefreshSeconds(rawText string) time.Duration {
	trimmedText := strings.TrimSpace(rawText)
	if trimmedText == "" {
		return rulesRefreshDefaultSeconds * time.Second
	}
	parsedSeconds, parseErr := strconv.Atoi(trimmedText)
	if parseErr != nil {
		return rulesRefreshDefaultSeconds * time.Second
	}
	if parsedSeconds <= 0 {
		return 0
	}
	if parsedSeconds < rulesRefreshFloorSeconds {
		return rulesRefreshFloorSeconds * time.Second
	}
	return time.Duration(parsedSeconds) * time.Second
}

// writeRulesSnapshotIfChanged 把下发载荷落盘为规则快照：revision 未变则跳过
// （避免无谓写放大与 hook 侧缓存失效）；变更时临时文件+改名原子写、权限 0600。
// 返回是否实际写盘。
func writeRulesSnapshotIfChanged(snapshotPath string, rulesPayload schema.DeviceRulesPayload) (bool, error) {
	if existingBytes, readErr := os.ReadFile(snapshotPath); readErr == nil {
		var existingSnapshot schema.RulesSnapshotFile
		if unmarshalErr := json.Unmarshal(existingBytes, &existingSnapshot); unmarshalErr == nil &&
			existingSnapshot.Version == schema.RulesSnapshotVersion &&
			existingSnapshot.Revision == rulesPayload.Revision {
			return false, nil
		}
	}

	snapshotBytes, marshalErr := json.MarshalIndent(schema.RulesSnapshotFile{
		Version:  schema.RulesSnapshotVersion,
		Revision: rulesPayload.Revision,
		SavedAt:  time.Now().UTC(),
		Rules:    rulesPayload.Rules,
	}, "", "  ")
	if marshalErr != nil {
		return false, marshalErr
	}
	snapshotBytes = append(snapshotBytes, '\n')

	snapshotDirectory := filepath.Dir(snapshotPath)
	if mkdirErr := os.MkdirAll(snapshotDirectory, 0o700); mkdirErr != nil {
		return false, mkdirErr
	}
	tempFile, createErr := os.CreateTemp(snapshotDirectory, ".rules-snapshot-*.tmp")
	if createErr != nil {
		return false, createErr
	}
	tempName := tempFile.Name()
	if _, writeErr := tempFile.Write(snapshotBytes); writeErr != nil {
		_ = tempFile.Close()
		_ = os.Remove(tempName)
		return false, writeErr
	}
	if closeErr := tempFile.Close(); closeErr != nil {
		_ = os.Remove(tempName)
		return false, closeErr
	}
	if chmodErr := os.Chmod(tempName, 0o600); chmodErr != nil {
		_ = os.Remove(tempName)
		return false, chmodErr
	}
	if renameErr := os.Rename(tempName, snapshotPath); renameErr != nil {
		_ = os.Remove(tempName)
		return false, renameErr
	}
	return true, nil
}

// ruleSyncLoop 常驻进程的规则下发循环：启动立即拉取一次，此后按配置周期刷新。
// 拉取/写盘失败仅记日志——hook 侧有三级降级瀑布，规则同步不影响既有裁决能力，
// 也绝不因规则通道故障中断采集主流程。生命周期与主 ctx 同步。
func ruleSyncLoop(runCtx context.Context, uploaderClient *transport.Uploader,
	stateDirectory string, logger *slog.Logger, doneChan chan<- struct{}) {
	defer close(doneChan)

	snapshotPath := filepath.Join(stateDirectory, schema.RulesSnapshotFileName)
	syncAttempt := 0
	syncOnce := func() {
		syncAttempt++
		rulesPayload, fetchErr := uploaderClient.GetDeviceRules(runCtx)
		if fetchErr != nil {
			logger.Warn("规则下发拉取失败(沿用最近可用快照)",
				slog.Int("attempt", syncAttempt), slog.String("error", fetchErr.Error()))
			return
		}
		changed, writeErr := writeRulesSnapshotIfChanged(snapshotPath, rulesPayload)
		switch {
		case writeErr != nil:
			logger.Warn("规则快照写盘失败",
				slog.String("error", writeErr.Error()))
		case changed:
			logger.Info("规则快照已更新",
				slog.String("revision", rulesPayload.Revision),
				slog.Int("rules", len(rulesPayload.Rules)))
		default:
			logger.Debug("规则快照未变化", slog.String("revision", rulesPayload.Revision))
		}
	}

	syncOnce()
	refreshEvery := parseRulesRefreshSeconds(os.Getenv("A3_RULES_REFRESH_SECONDS"))
	if refreshEvery <= 0 {
		logger.Info("规则周期同步已关闭(仅完成启动拉取)", slog.String("env", "A3_RULES_REFRESH_SECONDS"))
		return
	}
	refreshTicker := time.NewTicker(refreshEvery)
	defer refreshTicker.Stop()
	for {
		select {
		case <-runCtx.Done():
			return
		case <-refreshTicker.C:
			syncOnce()
		}
	}
}
