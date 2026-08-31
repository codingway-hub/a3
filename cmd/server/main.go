// a3 服务端入口：装配存储、规则扫描、HTTP 路由与优雅关闭。
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/codingway-hub/a3/internal/server/alert"
	"github.com/codingway-hub/a3/internal/server/api"
	"github.com/codingway-hub/a3/internal/server/config"
	"github.com/codingway-hub/a3/internal/server/ingest"
	"github.com/codingway-hub/a3/internal/server/notify"
	"github.com/codingway-hub/a3/internal/server/store"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	serverConfig, loadErr := config.Load()
	if loadErr != nil {
		logger.Error("配置加载失败", "error", loadErr)
		os.Exit(1)
	}
	if serverConfig.JWTSecretGenerated {
		logger.Warn("A3_JWT_SECRET 未设置，已随机生成临时密钥（重启后控制台会话全部失效）；生产环境请显式配置")
	}
	if serverConfig.AdminPasswordGenerated {
		logger.Warn("A3_ADMIN_PASSWORD 未设置，本次启动随机生成管理员口令",
			"username", serverConfig.AdminUsername, "password", serverConfig.AdminPassword)
	}

	ctx := context.Background()

	// 存储层：连接池 + 迁移
	eventStore, closePool, storeErr := setupStore(ctx, serverConfig.DatabaseURL, logger)
	if storeErr != nil {
		logger.Error("存储层初始化失败", "error", storeErr)
		os.Exit(1)
	}
	defer closePool()

	// 首次启动用 env 凭据种子 admin 账号（表空才种；之后账号增删改密走控制台）
	if seedErr := seedAdminUser(ctx, eventStore, serverConfig, logger); seedErr != nil {
		logger.Error("管理员账号种子失败", "error", seedErr)
		os.Exit(1)
	}

	// 规则扫描服务：加载启用规则并后台消费
	alertService := alert.NewService(eventStore)
	if reloadErr := alertService.ReloadRules(ctx); reloadErr != nil {
		logger.Error("规则加载失败", "error", reloadErr)
		os.Exit(1)
	}
	serviceCtx, stopService := context.WithCancel(context.Background())
	defer stopService()
	go alertService.Run(serviceCtx)

	// 告警通知外送：未配置 webhook 即禁用（照 WebDist 可选装配模式）
	if serverConfig.NotifyWebhookURL != "" {
		notifyChannel := notify.NewWebhookChannel(serverConfig.NotifyWebhookURL,
			serverConfig.NotifyWebhookFormat, nil, logger)
		notifyWorker := notify.NewWorker(eventStore, notifyChannel, serverConfig.NotifySeverities(), logger)
		go notifyWorker.Run(serviceCtx)
		logger.Info("告警通知外送已启用", "format", serverConfig.NotifyWebhookFormat,
			"min_severity", serverConfig.NotifyMinSeverity)
	}

	// HTTP 装配
	router := api.NewRouter(eventStore, alertService, api.RouterConfig{
		JWTSecret:         serverConfig.JWTSecret,
		WebDist:           serverConfig.WebDist,
		AgentDist:         serverConfig.AgentDist,
		AllowAutoRegister: serverConfig.AllowAutoRegister,
		PublicURL:         serverConfig.PublicURL,
		DeviceAPI:         ingest.NewHandler(ingest.NewService(eventStore, alertService, serverConfig.AllowAutoRegister)),
	})
	engine := router.Setup()

	httpServer := &http.Server{
		Addr:              serverConfig.Addr,
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
	}

	serverErrorCh := make(chan error, 1)
	go func() {
		tlsEnabled := serverConfig.TLSKeyPath != ""
		logger.Info("a3 服务端已启动", "addr", serverConfig.Addr,
			"tls", tlsEnabled, "auto_register", serverConfig.AllowAutoRegister,
			"web_dist", serverConfig.WebDist != "")
		serverErrorCh <- buildServeCall(httpServer, serverConfig.TLSCertPath, serverConfig.TLSKeyPath)()
	}()

	// 优雅关闭：等待 SIGINT/SIGTERM 或监听失败
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case listenErr := <-serverErrorCh:
		if listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			logger.Error("HTTP 监听失败", "error", listenErr)
			os.Exit(1)
		}
	case receivedSignal := <-signalCh:
		logger.Info("收到退出信号，开始优雅关闭", "signal", receivedSignal.String())
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelShutdown()
		if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
			logger.Error("优雅关闭超时", "error", shutdownErr)
		}
		stopService()
		logger.Info("a3 服务端已退出")
	}
}

// setupStore 建立连接池并应用迁移；返回业务存储、连接池关闭函数。
func setupStore(ctx context.Context, databaseURL string, logger *slog.Logger) (*store.Store, func(), error) {
	pool, connectErr := store.NewPool(ctx, databaseURL)
	if connectErr != nil {
		return nil, nil, connectErr
	}
	connection, acquireErr := pool.Acquire(ctx)
	if acquireErr != nil {
		pool.Close()
		return nil, nil, acquireErr
	}
	migrateErr := store.Migrate(ctx, connection.Conn())
	connection.Release()
	if migrateErr != nil {
		pool.Close()
		return nil, nil, migrateErr
	}

	// 监听前对账：全量重算会话 event_count。历史批次落库但计数补充失败会留下
	// 永久漂移，启动时据此自愈（title/risk_count 不覆盖，与后续增量并存）。
	eventStore := store.NewStore(pool)
	if rebuildErr := eventStore.RebuildSessionEventCounts(ctx); rebuildErr != nil {
		pool.Close()
		return nil, nil, rebuildErr
	}

	logger.Info("数据库迁移与会话计数对账完成", "database", maskDatabaseURL(databaseURL))
	return eventStore, pool.Close, nil
}

// seedAdminUser 首次启动（账号表为空）用 env 凭据种子 admin 账号；
// 已有账号时跳过——此后口令改走控制台「用户管理」，env 改动不影响已建账号。
func seedAdminUser(ctx context.Context, eventStore *store.Store, serverConfig *config.Config, logger *slog.Logger) error {
	userCount, countErr := eventStore.CountAdminUsers(ctx)
	if countErr != nil {
		return countErr
	}
	if userCount > 0 {
		logger.Info("控制台已存在账号，跳过 env 凭据种子", "accounts", userCount)
		return nil
	}
	passwordHash, hashErr := bcrypt.GenerateFromPassword([]byte(serverConfig.AdminPassword), bcrypt.DefaultCost)
	if hashErr != nil {
		return hashErr
	}
	if createErr := eventStore.CreateAdminUser(ctx, serverConfig.AdminUsername, string(passwordHash), "admin"); createErr != nil {
		return createErr
	}
	logger.Info("已用环境变量凭据种子首个管理员账号", "username", serverConfig.AdminUsername)
	return nil
}

// buildServeCall 决定监听方式：证书与私钥齐备时走 HTTPS，否则明文 HTTP。
// 两者缺一是配置层错误（Load 已拒绝），此处仅做非空判定。
func buildServeCall(server *http.Server, certPath, keyPath string) func() error {
	if certPath != "" && keyPath != "" {
		return func() error { return server.ListenAndServeTLS(certPath, keyPath) }
	}
	return server.ListenAndServe
}

// maskDatabaseURL 隐藏连接串口令后用于日志输出；解析失败时原样返回主机段。
func maskDatabaseURL(databaseURL string) string {
	parsedURL, parseErr := url.Parse(databaseURL)
	if parseErr != nil || parsedURL.Host == "" {
		return "(unparsable)"
	}
	return parsedURL.Host + parsedURL.Path
}
