package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// rollbackCommand 回滚采集器到上一版本：a3-agent.prev ↔ a3-agent 交换，供升级后
// 异常立退。拷贝前沿换 + rename：A3_AGENT_DIST 产物安装采用同目录 stage 原子落位，
// 回滚同样全程不出现「a3-agent 缺失」的窗口。.sig 配对同构交换，缺失宽容——pre-P2
// 的无签名 .prev 回滚后当前版本为无签名态，doctor 按 [跳过] 处置而非误报失败。
// 仅替换安装目录字节，不擅自重启常驻进程（launchd/systemd 以绝对路径引用，重启后生效）。
func rollbackCommand(flagArguments []string) int {
	homeDir, homeErr := resolveServiceHomeDir()
	if homeErr != nil {
		fmt.Fprintf(os.Stderr, "%v\n", homeErr)
		return 1
	}
	binDir := filepath.Join(homeDir, ".a3", "bin")
	agentPath := agentBinPathFor(homeDir)
	prevPath := filepath.Join(binDir, "a3-agent.prev")

	if _, statErr := os.Stat(agentPath); os.IsNotExist(statErr) {
		fmt.Fprintf(os.Stderr, "采集器未安装（%s 不存在），无从回滚\n", agentPath)
		return 1
	}
	if _, statErr := os.Stat(prevPath); os.IsNotExist(statErr) {
		fmt.Fprintf(os.Stderr, "没有上一版本可回滚（%s 不存在）——需先完成一次升级安装\n", prevPath)
		return 1
	}

	// 现版本搬到同目录临时位（copy 而非 rename：a3-agent 全程保有一个可运行字节），
	// prev 晋升为当前，临时位落回 prev。三者同目录（同文件系统），rename 原子。
	stagedBin := filepath.Join(binDir, fmt.Sprintf(".a3-agent.rollback.%d", os.Getpid()))
	defer func() { _ = os.Remove(stagedBin) }()
	if copyErr := copyFilePreservingMode(agentPath, stagedBin); copyErr != nil {
		fmt.Fprintf(os.Stderr, "回滚准备失败（当前版本未受影响）: %v\n", copyErr)
		return 1
	}
	if renameErr := os.Rename(prevPath, agentPath); renameErr != nil {
		fmt.Fprintf(os.Stderr, "回滚失败（当前版本未受影响）: %v\n", renameErr)
		return 1
	}
	if renameErr := os.Rename(stagedBin, prevPath); renameErr != nil {
		fmt.Fprintf(os.Stderr, "上一版本位落回失败（a3-agent 已切到 prev）: %v\n", renameErr)
		return 1
	}

	// .sig 三拍交换：现版本签名退为 prev（保存回滚前版本仍可再滚回），prev 签名晋升为
	// 当前；对侧缺失即保持缺失（doctor 跳过），不强行配对。任何一步 rename 失败都仅
	// 告警——字节交换已先完成且一致，签名错位由 doctor 签名自检显形。
	sigCur := agentPath + ".sig"
	sigPrev := prevPath + ".sig"
	stagedSig := filepath.Join(binDir, fmt.Sprintf(".a3-agent.rollback.%d.sig", os.Getpid()))
	defer func() { _ = os.Remove(stagedSig) }()
	sigSwapErr := error(nil)
	switch {
	case fileExists(sigCur) && fileExists(sigPrev):
		switch {
		case os.Rename(sigCur, stagedSig) != nil:
			sigSwapErr = fmt.Errorf("当前签名退位失败")
		case os.Rename(sigPrev, sigCur) != nil:
			_ = os.Rename(stagedSig, sigPrev)
			sigSwapErr = fmt.Errorf("上一版签名晋升失败")
		case os.Rename(stagedSig, sigPrev) != nil:
			sigSwapErr = fmt.Errorf("当前签名落回 prev 失败")
		}
	case fileExists(sigCur):
		if renameErr := os.Rename(sigCur, sigPrev); renameErr != nil {
			sigSwapErr = fmt.Errorf("签名退位失败: %w", renameErr)
		}
	case fileExists(sigPrev):
		if renameErr := os.Rename(sigPrev, sigCur); renameErr != nil {
			sigSwapErr = fmt.Errorf("签名晋升失败: %w", renameErr)
		}
	}
	if sigSwapErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️ %v（doctor 会提示签名不匹配）\n", sigSwapErr)
	}

	fmt.Println("✅ 已回滚到上一版本（a3-agent.prev → a3-agent）")
	fmt.Println("   若常驻服务在运行，重启后生效（macOS: launchctl kickstart -k gui/$(id -u)/com.a3.agent；Linux: systemctl --user restart a3-agent）")
	fmt.Printf("   验证: \"%s\" doctor\n", agentPath)
	return 0
}

// copyFilePreservingMode 保留源文件权限位复制（回滚临时位需与源字节完全一致，含可执行位）。
func copyFilePreservingMode(sourcePath string, targetPath string) error {
	sourceFile, openErr := os.Open(sourcePath)
	if openErr != nil {
		return openErr
	}
	defer sourceFile.Close()
	sourceInfo, statErr := sourceFile.Stat()
	if statErr != nil {
		return statErr
	}
	targetFile, createErr := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, sourceInfo.Mode())
	if createErr != nil {
		return createErr
	}
	if _, copyErr := io.Copy(targetFile, sourceFile); copyErr != nil {
		_ = targetFile.Close()
		return copyErr
	}
	return targetFile.Close()
}