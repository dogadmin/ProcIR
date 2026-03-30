package gui

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"procir/internal/i18n"
	"procir/internal/iocmonitor"
	"procir/internal/memory"
	"procir/internal/scoring"
	"procir/internal/types"
	"procir/internal/yara"
)

// Version is the current application version.
const Version = "1.5.3"

var (
	scanMu     sync.Mutex
	lastResult *scoring.ScanResult
	scanning   bool

	// YARA scan progress
	yaraProgress atomic.Int64 // current
	yaraTotal    atomic.Int64 // total
	yaraRunning  atomic.Int32 // 1 = scanning
)

func Run() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/scan", handleScan)
	mux.HandleFunc("/api/records", handleRecords)
	mux.HandleFunc("/api/triggers", handleTriggers)
	mux.HandleFunc("/api/execobjects", handleExecObjects)
	mux.HandleFunc("/api/forensics", handleForensics)
	mux.HandleFunc("/api/timeline", handleTimeline)
	mux.HandleFunc("/api/chains", handleChains)
	mux.HandleFunc("/api/indicators", handleIndicators)
	mux.HandleFunc("/api/proctree", handleProcTree)
	mux.HandleFunc("/api/events", handleEvents)
	mux.HandleFunc("/api/modules", handleModules)
	mux.HandleFunc("/api/memory/analyze", handleMemoryAnalyze)
	mux.HandleFunc("/api/ioc/load", handleIOCLoad)
	mux.HandleFunc("/api/ioc/start", handleIOCStart)
	mux.HandleFunc("/api/ioc/stop", handleIOCStop)
	mux.HandleFunc("/api/ioc/status", handleIOCStatus)
	mux.HandleFunc("/api/ioc/hits", handleIOCHits)
	mux.HandleFunc("/api/yara/upload", handleYaraUpload)
	mux.HandleFunc("/api/yara/reload", handleYaraReload)
	mux.HandleFunc("/api/yara/loadpath", handleYaraLoadPath)
	mux.HandleFunc("/api/yara/status", handleYaraStatus)
	mux.HandleFunc("/api/yara/scanall", handleYaraScanAll)
	mux.HandleFunc("/api/yara/scanone", handleYaraScanOne)
	mux.HandleFunc("/api/yara/progress", handleYaraProgress)
	mux.HandleFunc("/api/yara/results", handleYaraResults)
	mux.HandleFunc("/api/lang", handleLang)
	mux.HandleFunc("/api/ai/analyze", handleAIAnalyze)
	mux.HandleFunc("/api/ai/claude", handleClaudeAnalyze)
	mux.HandleFunc("/api/export", handleExport)
	mux.HandleFunc("/api/opendir", handleOpenDir)
	mux.HandleFunc("/api/checkupdate", handleCheckUpdate)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	fmt.Printf("ProcIR started at %s\n", url)
	exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	log.Fatal(http.Serve(listener, mux))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(indexHTML))
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	scanMu.Lock()
	if scanning {
		scanMu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"status": "already_scanning"})
		return
	}
	scanning = true
	scanMu.Unlock()

	result := scoring.Scan(nil)

	scanMu.Lock()
	lastResult = result
	scanning = false
	scanMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":      "done",
		"processes":   len(result.Records),
		"triggers":    len(result.Triggers),
		"forensics":   len(result.Forensics),
		"execObjects": len(result.ExecObjects),
		"timeline":    len(result.Correlation.Timeline),
		"chains":      len(result.Correlation.Chains),
		"indicators":  len(result.Correlation.Indicators),
		"events":      len(result.EventResults),
		"modules":     len(result.ModuleAnalyses),
	})
}

func handleRecords(w http.ResponseWriter, r *http.Request) {
	jsonResult(w, func(res *scoring.ScanResult) any { return res.Records })
}
func handleTriggers(w http.ResponseWriter, r *http.Request) {
	jsonResult(w, func(res *scoring.ScanResult) any { return res.Triggers })
}
func handleExecObjects(w http.ResponseWriter, r *http.Request) {
	jsonResult(w, func(res *scoring.ScanResult) any { return res.ExecObjects })
}
func handleForensics(w http.ResponseWriter, r *http.Request) {
	jsonResult(w, func(res *scoring.ScanResult) any { return res.Forensics })
}
func handleTimeline(w http.ResponseWriter, r *http.Request) {
	jsonCorrelation(w, func(c *types.CorrelationResult) any { return c.Timeline })
}
func handleChains(w http.ResponseWriter, r *http.Request) {
	jsonCorrelation(w, func(c *types.CorrelationResult) any { return c.Chains })
}
func handleIndicators(w http.ResponseWriter, r *http.Request) {
	jsonCorrelation(w, func(c *types.CorrelationResult) any { return c.Indicators })
}
func handleProcTree(w http.ResponseWriter, r *http.Request) {
	jsonCorrelation(w, func(c *types.CorrelationResult) any { return c.ProcessTree })
}
func handleEvents(w http.ResponseWriter, r *http.Request) {
	jsonResult(w, func(res *scoring.ScanResult) any { return res.EventResults })
}
func handleModules(w http.ResponseWriter, r *http.Request) {
	jsonResult(w, func(res *scoring.ScanResult) any { return res.ModuleAnalyses })
}

func jsonResult(w http.ResponseWriter, fn func(*scoring.ScanResult) any) {
	scanMu.Lock()
	result := lastResult
	scanMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if result == nil {
		json.NewEncoder(w).Encode([]any{})
		return
	}
	json.NewEncoder(w).Encode(fn(result))
}

func jsonCorrelation(w http.ResponseWriter, fn func(*types.CorrelationResult) any) {
	scanMu.Lock()
	result := lastResult
	scanMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if result == nil || result.Correlation == nil {
		json.NewEncoder(w).Encode([]any{})
		return
	}
	json.NewEncoder(w).Encode(fn(result.Correlation))
}

// --- IOC Monitor APIs ---

func handleIOCLoad(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Text == "" {
		http.Error(w, "Bad request", 400)
		return
	}
	mon := iocmonitor.GetMonitor()
	count := mon.LoadIOCs(req.Text)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "count": count})
}

func handleIOCStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var req struct {
		Duration int `json:"duration"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Duration <= 0 {
		req.Duration = 600
	} // default 10min

	mon := iocmonitor.GetMonitor()
	err := mon.Start(req.Duration)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func handleIOCStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	iocmonitor.GetMonitor().Stop()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func handleIOCStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(iocmonitor.GetMonitor().Status())
}

func handleIOCHits(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(iocmonitor.GetMonitor().Hits())
}

// --- Memory Analysis API ---

func handleMemoryAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var req struct {
		PID uint32 `json:"pid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PID == 0 {
		http.Error(w, "Bad request: need pid", 400)
		return
	}

	// Lookup process info from scan results
	procName, procPath, user, signed, signer := "", "", "", false, ""
	scanMu.Lock()
	if lastResult != nil {
		for _, rec := range lastResult.Records {
			if rec.PID == req.PID {
				procName = rec.Name
				procPath = rec.Path
				user = rec.User
				signed = rec.Signed
				signer = rec.Signer
				break
			}
		}
	}
	scanMu.Unlock()

	result := memory.Analyze(req.PID, procName, procPath, user, signed, signer)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// --- YARA APIs ---

// handleYaraUpload accepts file upload of .yar/.yara rules
func handleYaraUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	r.ParseMultipartForm(10 << 20) // 10MB max

	file, header, err := r.FormFile("rulefile")
	if err != nil {
		http.Error(w, i18n.T("api_upload_fail"), 400)
		return
	}
	defer file.Close()

	// Save to temp dir — sanitize filename to prevent path traversal
	tmpDir := filepath.Join(os.TempDir(), "procir_yara")
	os.MkdirAll(tmpDir, 0755)
	safeName := filepath.Base(header.Filename)
	dstPath := filepath.Join(tmpDir, safeName)

	dst, err := os.Create(dstPath)
	if err != nil {
		jsonErr(w, i18n.T("api_tmpfile_fail"))
		return
	}
	if _, err := io.Copy(dst, file); err != nil {
		dst.Close()
		jsonErr(w, "Failed to save rule file: "+err.Error())
		return
	}
	if err := dst.Close(); err != nil {
		jsonErr(w, "Failed to save rule file: "+err.Error())
		return
	}

	// Save only — caller should POST /api/yara/reload after all files are uploaded
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "saved": true, "filename": header.Filename})
}

// handleYaraLoadPath loads rules from a local path
func handleYaraLoadPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		http.Error(w, "Bad request", 400)
		return
	}
	count, err := loadYaraRules(req.Path)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": fmt.Sprintf("%v", err)})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "rules": count, "path": req.Path})
}

// handleYaraStatus returns current YARA engine status
func handleYaraStatus(w http.ResponseWriter, r *http.Request) {
	e := scoring.YaraEngine
	w.Header().Set("Content-Type", "application/json")
	if e == nil || !e.Enabled() {
		json.NewEncoder(w).Encode(map[string]any{"loaded": false})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"loaded": true,
		"rules":  e.RuleCount(),
		"errors": e.Errors(),
	})
}

// handleYaraScanAll triggers full YARA scan with progress tracking
func handleYaraScanAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	engine := scoring.YaraEngine
	if engine == nil || !engine.Enabled() {
		jsonErr(w, i18n.T("api_yara_not_loaded"))
		return
	}

	scanMu.Lock()
	result := lastResult
	scanMu.Unlock()
	if result == nil || len(result.ExecObjects) == 0 {
		jsonErr(w, i18n.T("api_need_scan"))
		return
	}

	if yaraRunning.Load() == 1 {
		jsonErr(w, i18n.T("api_yara_in_progress"))
		return
	}

	// Count scannable objects
	var targets []*types.ExecutionObject
	for _, obj := range result.ExecObjects {
		if obj.Path != "" && obj.Exists {
			targets = append(targets, obj)
		}
	}

	yaraProgress.Store(0)
	yaraTotal.Store(int64(len(targets)))
	yaraRunning.Store(1)

	// Run in background
	go func() {
		defer yaraRunning.Store(0)

		for i, obj := range targets {
			yaraProgress.Store(int64(i + 1))

			hits := engine.ScanSingleFile(obj.Path)
			if len(hits) > 0 {
				obj.YaraMatched = true
				obj.YaraHits = hits

				yaraScore := 0
				for _, hit := range hits {
					ruleScore := 20
					for _, tag := range hit.Tags {
						tl := strings.ToLower(tag)
						if tl == "backdoor" || tl == "trojan" || tl == "ransomware" ||
							tl == "loader" || tl == "inject" || tl == "beacon" ||
							tl == "webshell" || tl == "rat" || tl == "malware" {
							ruleScore = 30
							break
						}
					}
					yaraScore += ruleScore
					obj.Reasons = append(obj.Reasons, "[YARA] "+hit.RuleName)
				}
				if len(hits) >= 2 {
					yaraScore += 15
				}
				obj.YaraScore = yaraScore
				obj.FinalScore += yaraScore
				obj.RiskLevel = types.CalcRiskLevel(obj.FinalScore)
			}
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "total": len(targets)})
}

// handleYaraProgress returns current scan progress
func handleYaraProgress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"running": yaraRunning.Load() == 1,
		"current": yaraProgress.Load(),
		"total":   yaraTotal.Load(),
	})
}

// handleYaraResults returns all YARA-matched objects
func handleYaraResults(w http.ResponseWriter, r *http.Request) {
	scanMu.Lock()
	result := lastResult
	scanMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if result == nil {
		json.NewEncoder(w).Encode([]any{})
		return
	}

	type yaraResultItem struct {
		Path      string      `json:"Path"`
		IsRunning bool        `json:"IsRunning"`
		Signed    bool        `json:"Signed"`
		Signer    string      `json:"Signer"`
		Location  string      `json:"Location"`
		Score     int         `json:"Score"`
		YaraScore int         `json:"YaraScore"`
		RiskLevel string      `json:"RiskLevel"`
		Hits      interface{} `json:"Hits"`
		HitCount  int         `json:"HitCount"`
		Reasons   []string    `json:"Reasons"`
	}

	var items []yaraResultItem
	for _, obj := range result.ExecObjects {
		if !obj.YaraMatched {
			continue
		}
		items = append(items, yaraResultItem{
			Path:      obj.Path,
			IsRunning: obj.IsRunning,
			Signed:    obj.Signed,
			Signer:    obj.Signer,
			Location:  obj.LocationType,
			Score:     obj.FinalScore,
			YaraScore: obj.YaraScore,
			RiskLevel: obj.RiskLevel,
			Hits:      obj.YaraHits,
			HitCount:  obj.YaraScore / 20, // approximate
			Reasons:   obj.Reasons,
		})
	}
	json.NewEncoder(w).Encode(items)
}

// handleYaraScanOne scans a single file
func handleYaraScanOne(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		http.Error(w, "Bad request", 400)
		return
	}
	engine := scoring.YaraEngine
	if engine == nil || !engine.Enabled() {
		jsonErr(w, i18n.T("api_yara_short"))
		return
	}
	hits := engine.ScanSingleFile(req.Path)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "hits": hits, "count": len(hits)})
}

// handleYaraReload loads all rules from the upload temp directory.
func handleYaraReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	tmpDir := filepath.Join(os.TempDir(), "procir_yara")
	count, err := loadYaraRules(tmpDir)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": fmt.Sprintf("%v", err)})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "rules": count})
}

func loadYaraRules(path string) (int, error) {
	engine := yara.NewEngine(path)
	if engine == nil || !engine.Enabled() {
		return 0, fmt.Errorf(i18n.T("api_yara_not_loaded"))
	}
	scoring.YaraEngine = engine
	return engine.RuleCount(), nil
}

func jsonErr(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
}

// --- Export & Open Dir ---

func handleExport(w http.ResponseWriter, r *http.Request) {
	scanMu.Lock()
	result := lastResult
	scanMu.Unlock()
	if result == nil || len(result.Records) == 0 {
		http.Error(w, "No scan data", 400)
		return
	}

	filename := fmt.Sprintf("procir_scan_%s.csv", time.Now().Format("20060102_150405"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Write([]byte{0xEF, 0xBB, 0xBF})

	csvW := csv.NewWriter(w)
	csvW.Write([]string{
		"RiskLevel", "RiskScore", "Process", "PID", "PPID", "ParentName",
		"Path", "CommandLine", "User", "StartTime",
		"SHA256", "MD5", "Signed", "SignValid", "Signer",
		"Company", "Product", "OriginalName",
		"HasNetwork", "RemoteIPs", "HasPublicIP",
		"Persistence", "Reasons",
	})
	for _, rec := range result.Records {
		csvW.Write([]string{
			rec.RiskLevel, strconv.Itoa(rec.RiskScore), rec.Name,
			strconv.Itoa(int(rec.PID)), strconv.Itoa(int(rec.PPID)), rec.ParentName,
			rec.Path, rec.CommandLine, rec.User, rec.StartTime,
			rec.SHA256, rec.MD5,
			strconv.FormatBool(rec.Signed), strconv.FormatBool(rec.SignValid), rec.Signer,
			rec.Company, rec.Product, rec.OriginalName,
			strconv.FormatBool(rec.HasNetwork), strings.Join(rec.RemoteIPs, ";"), strconv.FormatBool(rec.HasPublicIP),
			strings.Join(rec.Persistence, ";"), strings.Join(rec.Reasons, ";"),
		})
	}
	csvW.Flush()
}

func handleOpenDir(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		http.Error(w, "Bad request", 400)
		return
	}
	dir := req.Path
	if idx := strings.LastIndex(dir, `\`); idx >= 0 {
		dir = dir[:idx]
	}
	if _, err := os.Stat(dir); err != nil {
		jsonErr(w, i18n.T("api_dir_not_exist"))
		return
	}
	exec.Command("explorer.exe", dir).Start()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// --- Language Setting ---

func handleLang(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var req struct {
			Lang string `json:"lang"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			i18n.SetLang(req.Lang)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"lang": i18n.Lang()})
}

// --- AI Analysis API (MiniMax) ---

var aiClient = &http.Client{Timeout: 180 * time.Second}

func handleAIAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		APIKey   string              `json:"apiKey"`
		Model    string              `json:"model"`
		Messages []map[string]string `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", 400)
		return
	}
	if req.APIKey == "" || req.Model == "" || len(req.Messages) == 0 {
		jsonErr(w, i18n.T("api_need_key_model_msg"))
		return
	}

	apiBody := map[string]any{
		"model":       req.Model,
		"messages":    req.Messages,
		"temperature": 0.1,
		"max_tokens":  16384,
	}

	bodyJSON, err := json.Marshal(apiBody)
	if err != nil {
		jsonErr(w, "Failed to build request")
		return
	}

	apiReq, err := http.NewRequest("POST", "https://api.minimaxi.com/v1/chat/completions", bytes.NewReader(bodyJSON))
	if err != nil {
		jsonErr(w, "Failed to create request")
		return
	}
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set("Authorization", "Bearer "+req.APIKey)

	resp, err := aiClient.Do(apiReq)
	if err != nil {
		jsonErr(w, "MiniMax API failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		jsonErr(w, "Failed to read response")
		return
	}

	if resp.StatusCode != 200 {
		jsonErr(w, fmt.Sprintf("MiniMax API error (%d): %s", resp.StatusCode, string(respBody)))
		return
	}

	var apiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			TotalTokens      int `json:"total_tokens"`
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
		BaseResp struct {
			StatusCode int    `json:"status_code"`
			StatusMsg  string `json:"status_msg"`
		} `json:"base_resp"`
	}

	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "content": string(respBody), "raw": true})
		return
	}

	if apiResp.BaseResp.StatusCode != 0 {
		jsonErr(w, fmt.Sprintf("MiniMax API error (%d): %s", apiResp.BaseResp.StatusCode, apiResp.BaseResp.StatusMsg))
		return
	}

	content := ""
	if len(apiResp.Choices) > 0 {
		content = apiResp.Choices[0].Message.Content
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"ok":               true,
		"content":          content,
		"totalTokens":      apiResp.Usage.TotalTokens,
		"promptTokens":     apiResp.Usage.PromptTokens,
		"completionTokens": apiResp.Usage.CompletionTokens,
	})
}

// --- AI Analysis API (Claude / Anthropic) ---

func handleClaudeAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		APIKey   string              `json:"apiKey"`
		Model    string              `json:"model"`
		Messages []map[string]string `json:"messages"`
		System   string              `json:"system"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", 400)
		return
	}
	if req.APIKey == "" || req.Model == "" || len(req.Messages) == 0 {
		jsonErr(w, "Please provide API Key, select model, and send a message")
		return
	}

	apiBody := map[string]any{
		"model":      req.Model,
		"max_tokens": 16384,
		"messages":   req.Messages,
	}
	if req.System != "" {
		apiBody["system"] = req.System
	}

	bodyJSON, err := json.Marshal(apiBody)
	if err != nil {
		jsonErr(w, "Failed to build request")
		return
	}

	apiReq, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(bodyJSON))
	if err != nil {
		jsonErr(w, "Failed to create request")
		return
	}
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set("x-api-key", req.APIKey)
	apiReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := aiClient.Do(apiReq)
	if err != nil {
		jsonErr(w, "Claude API request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		jsonErr(w, "Failed to read response")
		return
	}

	if resp.StatusCode != 200 {
		jsonErr(w, fmt.Sprintf("Claude API error (%d): %s", resp.StatusCode, string(respBody)))
		return
	}

	var apiResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
		Error *struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "content": string(respBody), "raw": true})
		return
	}

	if apiResp.Error != nil {
		jsonErr(w, fmt.Sprintf("Claude API error: %s", apiResp.Error.Message))
		return
	}

	content := ""
	for _, block := range apiResp.Content {
		if block.Type == "text" {
			content += block.Text
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"ok":               true,
		"content":          content,
		"promptTokens":     apiResp.Usage.InputTokens,
		"completionTokens": apiResp.Usage.OutputTokens,
		"totalTokens":      apiResp.Usage.InputTokens + apiResp.Usage.OutputTokens,
	})
}

// --- Check for Updates ---

var updateClient = &http.Client{Timeout: 10 * time.Second}

func handleCheckUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	req, err := http.NewRequest("GET", "https://api.github.com/repos/dogadmin/ProcIR/releases/latest", nil)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "Failed to create request"})
		return
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := updateClient.Do(req)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": i18n.T("update_network_err")})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": fmt.Sprintf("GitHub API: %d", resp.StatusCode)})
		return
	}

	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Body    string `json:"body"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "Failed to parse response"})
		return
	}

	latestVer := strings.TrimPrefix(release.TagName, "v")
	hasUpdate := latestVer != Version

	json.NewEncoder(w).Encode(map[string]any{
		"ok":         true,
		"current":    Version,
		"latest":     latestVer,
		"hasUpdate":  hasUpdate,
		"releaseURL": release.HTMLURL,
	})
}
