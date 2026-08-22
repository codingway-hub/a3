package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/server/alert"
	"github.com/codingway-hub/a3/internal/server/auth"
	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/internal/servetest"
	"github.com/codingway-hub/a3/pkg/schema"
)

// newHandlerRouter 组装含设备侧路由的测试引擎。
func newHandlerRouter(t *testing.T) (*gin.Engine, *store.Store, *alert.Service) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	testPool := servetest.NewTestPool(t)
	servetest.ResetTablesForTest(t, testPool, "alerts", "sessions", "events", "devices")

	eventStore := store.NewStore(testPool)
	alertService := alert.NewService(eventStore)
	require.NoError(t, alertService.ReloadRules(context.Background()))

	ingestService := NewService(eventStore, alertService, true)
	engine := gin.New()
	NewHandler(ingestService).RegisterRoutes(engine)
	return engine, eventStore, alertService
}

func postJSON(engine *gin.Engine, target string, body string, bearerToken string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	engine.ServeHTTP(recorder, request)
	return recorder
}

func TestFullChainRegisterSubmitReplay(t *testing.T) {
	engine, eventStore, _ := newHandlerRouter(t)

	// ① 注册设备
	registered := postJSON(engine, "/api/v1/devices/register",
		`{"hostname":"macbook","os":"darwin","arch":"arm64","machine_fingerprint":"fp-e2e-1"}`, "")
	require.Equal(t, http.StatusOK, registered.Code, registered.Body.String())
	var registerResponse struct {
		DeviceID string `json:"device_id"`
		Token    string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(registered.Body.Bytes(), &registerResponse))
	assert.NotEmpty(t, registerResponse.DeviceID)
	assert.NotEmpty(t, registerResponse.Token)

	buildEvent := func(eventID string) schema.Event {
		return schema.Event{
			EventID: eventID, EventType: schema.EventTypeConversation, Role: "user",
			AgentType: schema.AgentTypeClaudeCode, SessionID: "sess-e2e", DeviceID: registerResponse.DeviceID,
			OccurredAt: time.Now().UTC(), Content: "第" + eventID + "条消息", SourceMethod: schema.SourceMethodFileLog,
		}
	}
	envelopeBytes := func(events []schema.Event) string {
		envelope := BatchEnvelope{AgentVersion: "1.0.0", Plugins: []string{"claude-code"}, Events: events}
		marshalJSON, marshalErr := json.Marshal(envelope)
		require.NoError(t, marshalErr)
		return string(marshalJSON)
	}

	// ② 无 Token 上报 → 401；伪造 Token → 401
	unauthorized := postJSON(engine, "/api/v1/events/batch", envelopeBytes([]schema.Event{buildEvent("evt-1")}), "")
	assert.Equal(t, http.StatusUnauthorized, unauthorized.Code)
	forgedToken, forgeErr := auth.GenerateDeviceToken()
	require.NoError(t, forgeErr)
	forbidden := postJSON(engine, "/api/v1/events/batch",
		envelopeBytes([]schema.Event{buildEvent("evt-1")}), forgedToken)
	assert.Equal(t, http.StatusUnauthorized, forbidden.Code)

	// ③ 带 Token 上报 3 条事件
	firstBatch := []schema.Event{buildEvent("evt-e2e-1"), buildEvent("evt-e2e-2"), buildEvent("evt-e2e-3")}
	submitted := postJSON(engine, "/api/v1/events/batch",
		envelopeBytes(firstBatch), registerResponse.Token)
	require.Equal(t, http.StatusOK, submitted.Code, submitted.Body.String())
	var firstResult BatchResult
	require.NoError(t, json.Unmarshal(submitted.Body.Bytes(), &firstResult))
	assert.Equal(t, 3, firstResult.Accepted)

	// ④ 重报同批 → accepted=0 / duplicates=3
	replayed := postJSON(engine, "/api/v1/events/batch",
		envelopeBytes(firstBatch), registerResponse.Token)
	require.Equal(t, http.StatusOK, replayed.Code)
	var replayResult BatchResult
	require.NoError(t, json.Unmarshal(replayed.Body.Bytes(), &replayResult))
	assert.Equal(t, 0, replayResult.Accepted)
	assert.Equal(t, 3, replayResult.Duplicates)

	// ⑤ sessions 表出现会话行且计数为 3（重放不重复累计）
	sessionRow, sessionErr := eventStore.GetSession(context.Background(),
		registerResponse.DeviceID, "sess-e2e")
	require.NoError(t, sessionErr)
	assert.Equal(t, 3, sessionRow.EventCount)

	// ⑥ 非法事件整批 400
	badSubmitted := postJSON(engine, "/api/v1/events/batch",
		`{"events":[{"event_id":"x"}]}`, registerResponse.Token)
	assert.Equal(t, http.StatusBadRequest, badSubmitted.Code)
}
