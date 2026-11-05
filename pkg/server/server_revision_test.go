/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/threagile/threagile/pkg/types"
)

// minimal config mock satisfying serverConfigReader
type mockConfig struct {
	serverFolder string
	tempFolder   string
}

func (m *mockConfig) GetBuildTimestamp() string                            { return "test" }
func (m *mockConfig) GetVerbose() bool                                     { return false }
func (m *mockConfig) GetInteractive() bool                                 { return false }
func (m *mockConfig) GetAppFolder() string                                 { return m.serverFolder }
func (m *mockConfig) GetPluginFolder() string                              { return "" }
func (m *mockConfig) GetDataFolder() string                                { return filepath.Join(m.serverFolder, "data") }
func (m *mockConfig) GetOutputFolder() string                              { return "output" }
func (m *mockConfig) GetServerFolder() string                              { return m.serverFolder }
func (m *mockConfig) GetTempFolder() string                                { return m.tempFolder }
func (m *mockConfig) GetKeyFolder() string                                 { return "keys" }
func (m *mockConfig) GetInputFile() string                                 { return "threagile.yaml" }
func (m *mockConfig) GetImportedInputFile() string                         { return "threagile.yaml" }
func (m *mockConfig) GetDataFlowDiagramFilenamePNG() string                { return "data-flow-diagram.png" }
func (m *mockConfig) GetDataAssetDiagramFilenamePNG() string               { return "data-asset-diagram.png" }
func (m *mockConfig) GetDataFlowDiagramFilenameDOT() string                { return "data-flow-diagram.dot" }
func (m *mockConfig) GetDataAssetDiagramFilenameDOT() string               { return "data-asset-diagram.dot" }
func (m *mockConfig) GetReportFilename() string                            { return "threagile-report.pdf" }
func (m *mockConfig) GetExcelRisksFilename() string                        { return "threagile-risks.xlsx" }
func (m *mockConfig) GetRiskExcelConfigHideColumns() []string              { return nil }
func (m *mockConfig) GetRiskExcelConfigSortByColumns() []string            { return nil }
func (m *mockConfig) GetRiskExcelConfigWidthOfColumns() map[string]float64 { return nil }
func (m *mockConfig) GetExcelTagsFilename() string                         { return "threagile-tags.xlsx" }
func (m *mockConfig) GetJsonRisksFilename() string                         { return "threagile-risks.json" }
func (m *mockConfig) GetJsonTechnicalAssetsFilename() string {
	return "threagile-technical-assets.json"
}
func (m *mockConfig) GetJsonStatsFilename() string                { return "threagile-stats.json" }
func (m *mockConfig) GetTemplateFilename() string                 { return "threagile-template.yaml" }
func (m *mockConfig) GetTechnologyFilename() string               { return "threagile-technologies.yaml" }
func (m *mockConfig) GetRiskRulePlugins() []string                { return nil }
func (m *mockConfig) GetSkipRiskRules() []string                  { return nil }
func (m *mockConfig) GetExecuteModelMacro() string                { return "" }
func (m *mockConfig) GetServerMode() bool                         { return false }
func (m *mockConfig) GetDiagramDPI() int                          { return 120 }
func (m *mockConfig) GetServerPort() int                          { return 8080 }
func (m *mockConfig) GetGraphvizDPI() int                         { return 120 }
func (m *mockConfig) GetMaxGraphvizDPI() int                      { return 600 }
func (m *mockConfig) GetBackupHistoryFilesToKeep() int            { return 50 }
func (m *mockConfig) GetAddModelTitle() bool                      { return false }
func (m *mockConfig) GetAddLegend() bool                          { return false }
func (m *mockConfig) GetKeepDiagramSourceFiles() bool             { return false }
func (m *mockConfig) GetIgnoreOrphanedRiskTracking() bool         { return false }
func (m *mockConfig) GetThreagileVersion() string                 { return "test-version" }
func (m *mockConfig) GetProgressReporter() types.ProgressReporter { return nil }

func newTestServer(t *testing.T) (*server, *httptest.Server) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "static"), 0700); err != nil {
		t.Fatalf("mkdir static failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "static", "index.html"), []byte("<html></html>"), 0600); err != nil {
		t.Fatalf("write static file failed: %v", err)
	}
	cfg := &mockConfig{serverFolder: root, tempFolder: t.TempDir()}
	s := &server{
		config:                      cfg,
		createdObjectsThrottler:     make(map[string][]int64),
		mapTokenHashToTimeoutStruct: make(map[string]timeoutStruct),
		mapFolderNameToTokenHash:    make(map[string]string),
		locksByFolderName:           make(map[string]*folderLock),
		store:                       newModelStore(cfg.GetInputFile(), cfg.GetBackupHistoryFilesToKeep()),
	}
	router := s.newRouter(nil)
	return s, httptest.NewServer(router)
}

func httpDo(t *testing.T, ts *httptest.Server, method, path string, headers map[string]string, body any) (int, map[string]any, http.Header) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequest(method, ts.URL+path, reader)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("http call failed: %v", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	result := make(map[string]any)
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatalf("unmarshal response failed: %v (body=%s)", err, string(raw))
		}
	}
	return response.StatusCode, result, response.Header
}

func revisionFromETag(etag string) string {
	return strings.Trim(strings.TrimPrefix(etag, "W/"), "\"")
}

func TestRevisionProtocolOverHTTP(t *testing.T) {
	_, ts := newTestServer(t)
	defer ts.Close()

	// key + token
	status, body, _ := httpDo(t, ts, http.MethodPost, "/auth/keys", nil, nil)
	if status != http.StatusCreated {
		t.Fatalf("create key status = %d body=%v", status, body)
	}
	key := body["key"].(string)
	status, body, _ = httpDo(t, ts, http.MethodPost, "/auth/tokens", map[string]string{"key": key}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create token status = %d body=%v", status, body)
	}
	token := body["token"].(string)
	auth := map[string]string{"token": token}

	// create model -> revision returned
	status, body, headers := httpDo(t, ts, http.MethodPost, "/models", auth, nil)
	if status != http.StatusCreated {
		t.Fatalf("create model status = %d body=%v", status, body)
	}
	createdRevision, ok := body["revision"].(string)
	if !ok || len(createdRevision) != 64 {
		t.Fatalf("missing revision in create response: %v", body)
	}
	if revisionFromETag(headers.Get("ETag")) != createdRevision {
		t.Fatal("ETag of created model does not match revision")
	}
	modelID := body["id"].(string)
	coverPath := "/models/" + modelID + "/cover"

	// read -> revision header present
	status, body, headers = httpDo(t, ts, http.MethodGet, coverPath, auth, nil)
	if status != http.StatusOK {
		t.Fatalf("get cover status = %d body=%v", status, body)
	}
	etag1 := headers.Get("ETag")
	rev1 := headers.Get("X-Revision")
	if rev1 == "" || revisionFromETag(etag1) != rev1 {
		t.Fatalf("revision headers missing/inconsistent: etag=%q x-revision=%q", etag1, rev1)
	}
	if rev1 != createdRevision {
		t.Fatal("read revision does not match created revision")
	}

	// update without precondition -> 428
	status, body, _ = httpDo(t, ts, http.MethodPut, coverPath, auth, map[string]string{"title": "no precondition"})
	if status != http.StatusPreconditionRequired {
		t.Fatalf("expected 428 without If-Match, got %d body=%v", status, body)
	}

	// update against wrong revision -> 409 with current revision
	headersWrong := withToken(auth, map[string]string{"If-Match": `"deadbeef"`})
	status, body, _ = httpDo(t, ts, http.MethodPut, coverPath, headersWrong, map[string]string{"title": "wrong base"})
	if status != http.StatusConflict {
		t.Fatalf("expected 409 on stale revision, got %d body=%v", status, body)
	}
	if body["current_revision"] != rev1 {
		t.Fatalf("409 must report current revision, got %v", body["current_revision"])
	}

	// update against correct revision -> 200 with new revision
	headersOK := withToken(auth, map[string]string{"If-Match": etag1})
	status, body, headers = httpDo(t, ts, http.MethodPut, coverPath, headersOK, map[string]string{"title": "AAA"})
	if status != http.StatusOK {
		t.Fatalf("expected 200 on current revision, got %d body=%v", status, body)
	}
	rev2, ok := body["revision"].(string)
	if !ok || rev2 == rev1 {
		t.Fatalf("commit must return a new revision: %v", body)
	}
	if revisionFromETag(headers.Get("ETag")) != rev2 {
		t.Fatal("response ETag does not match new revision")
	}

	// a concurrent client still holding rev1 must not overwrite rev2
	status, body, _ = httpDo(t, ts, http.MethodPut, coverPath, headersOK, map[string]string{"title": "STALE"})
	if status != http.StatusConflict {
		t.Fatalf("expected 409 for concurrent stale edit, got %d body=%v", status, body)
	}
	status, body, _ = httpDo(t, ts, http.MethodGet, coverPath, auth, nil)
	if status != http.StatusOK || body["title"] != "AAA" {
		t.Fatalf("stale edit overwrote the newer version: status=%d body=%v", status, body)
	}

	// weak ETag and X-Expected-Revision are accepted too
	headersWeak := withToken(auth, map[string]string{"If-Match": `W/"` + rev2 + `"`})
	status, body, headers = httpDo(t, ts, http.MethodPut, coverPath, headersWeak, map[string]string{"title": "BBB"})
	if status != http.StatusOK {
		t.Fatalf("weak ETag precondition failed: %d body=%v", status, body)
	}
	rev3 := body["revision"].(string)
	headersAlt := withToken(auth, map[string]string{"X-Expected-Revision": rev3})
	status, body, _ = httpDo(t, ts, http.MethodPut, coverPath, headersAlt, map[string]string{"title": "CCC"})
	if status != http.StatusOK {
		t.Fatalf("X-Expected-Revision precondition failed: %d body=%v", status, body)
	}
	status, body, _ = httpDo(t, ts, http.MethodGet, coverPath, auth, nil)
	if status != http.StatusOK || body["title"] != "CCC" {
		t.Fatalf("final model state wrong: status=%d body=%v", status, body)
	}
}

func withToken(base map[string]string, extra map[string]string) map[string]string {
	merged := make(map[string]string, len(base)+len(extra))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range extra {
		merged[key] = value
	}
	return merged
}
