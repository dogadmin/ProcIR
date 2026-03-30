package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"procir/internal/i18n"
	"procir/internal/scoring"
	"procir/internal/types"
	"procir/internal/yara"
)

// Format represents the export file format.
type Format string

const (
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
)

// ExportFull writes the complete scan result to a file.
func ExportFull(result *scoring.ScanResult, path string, format Format) error {
	switch format {
	case FormatJSON:
		return exportJSON(result, path)
	case FormatCSV:
		return exportCSV(result, path)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// ExportYARA writes only YARA-matched objects to a file.
func ExportYARA(result *scoring.ScanResult, path string, format Format) error {
	switch format {
	case FormatJSON:
		return exportYARAJSON(result, path)
	case FormatCSV:
		return exportYARACSV(result, path)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// --- JSON exports ---

// jsonFullResult is the top-level JSON structure for full export.
type jsonFullResult struct {
	ExportTime  string                   `json:"ExportTime"`
	Summary     jsonSummary              `json:"Summary"`
	ExecObjects []*types.ExecutionObject `json:"ExecObjects"`
	Processes   []*types.ProcessRecord   `json:"Processes"`
	Triggers    []*types.TriggerEntry    `json:"Triggers"`
	Forensics   []*types.ForensicEntry   `json:"Forensics"`
	Events      []*types.EventEvidence   `json:"Events"`
	Modules     []*types.ModuleAnalysis  `json:"Modules"`
	Timeline    []*types.TimelineEvent   `json:"Timeline,omitempty"`
	Chains      []*types.BehaviorChain   `json:"Chains,omitempty"`
	Indicators  []*types.Indicator       `json:"Indicators,omitempty"`
	YaraLoaded  bool                     `json:"YaraLoaded"`
	YaraRules   int                      `json:"YaraRules"`
}

type jsonSummary struct {
	Processes   int `json:"Processes"`
	Triggers    int `json:"Triggers"`
	Forensics   int `json:"Forensics"`
	ExecObjects int `json:"ExecObjects"`
	Events      int `json:"Events"`
	Modules     int `json:"Modules"`
	Critical    int `json:"Critical"`
	High        int `json:"High"`
	Medium      int `json:"Medium"`
	Suspicious  int `json:"Suspicious"`
	YaraMatched int `json:"YaraMatched"`
}

func exportJSON(result *scoring.ScanResult, path string) error {
	summary := buildSummary(result)

	out := jsonFullResult{
		ExportTime:  time.Now().Format("2006-01-02 15:04:05"),
		Summary:     summary,
		ExecObjects: result.ExecObjects,
		Processes:   result.Records,
		Triggers:    result.Triggers,
		Forensics:   result.Forensics,
		Events:      result.EventResults,
		Modules:     result.ModuleAnalyses,
		YaraLoaded:  result.YaraLoaded,
		YaraRules:   result.YaraRules,
	}
	if result.Correlation != nil {
		out.Timeline = result.Correlation.Timeline
		out.Chains = result.Correlation.Chains
		out.Indicators = result.Correlation.Indicators
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// --- YARA JSON export ---

type yaraExportItem struct {
	Path      string      `json:"Path"`
	ObjType   string      `json:"ObjType"`
	IsRunning bool        `json:"IsRunning"`
	Signed    bool        `json:"Signed"`
	Signer    string      `json:"Signer"`
	Location  string      `json:"Location"`
	SHA256    string      `json:"SHA256"`
	MD5       string      `json:"MD5"`
	FinalScore int        `json:"FinalScore"`
	YaraScore  int        `json:"YaraScore"`
	RiskLevel  string     `json:"RiskLevel"`
	YaraHits   interface{} `json:"YaraHits"`
	Reasons    []string   `json:"Reasons"`
}

type yaraExportResult struct {
	ExportTime   string           `json:"ExportTime"`
	YaraRules    int              `json:"YaraRules"`
	TotalScanned int              `json:"TotalScanned"`
	MatchedCount int              `json:"MatchedCount"`
	Matches      []yaraExportItem `json:"Matches"`
}

func exportYARAJSON(result *scoring.ScanResult, path string) error {
	var items []yaraExportItem
	for _, obj := range result.ExecObjects {
		if !obj.YaraMatched {
			continue
		}
		items = append(items, yaraExportItem{
			Path:       obj.Path,
			ObjType:    obj.ObjType,
			IsRunning:  obj.IsRunning,
			Signed:     obj.Signed,
			Signer:     obj.Signer,
			Location:   obj.LocationType,
			SHA256:     obj.SHA256,
			MD5:        obj.MD5,
			FinalScore: obj.FinalScore,
			YaraScore:  obj.YaraScore,
			RiskLevel:  obj.RiskLevel,
			YaraHits:   obj.YaraHits,
			Reasons:    obj.Reasons,
		})
	}

	out := yaraExportResult{
		ExportTime:   time.Now().Format("2006-01-02 15:04:05"),
		YaraRules:    result.YaraRules,
		TotalScanned: len(result.ExecObjects),
		MatchedCount: len(items),
		Matches:      items,
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// --- CSV exports ---

func exportCSV(result *scoring.ScanResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// UTF-8 BOM
	f.Write([]byte{0xEF, 0xBB, 0xBF})

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	w.Write([]string{
		"RiskLevel", "FinalScore", "Path", "ObjType", "LocationType",
		"IsRunning", "PIDs", "Sources",
		"SHA256", "MD5",
		"Signed", "SignValid", "Signer", "Company", "Product",
		"NetworkObserved", "RemoteIPs", "HasPublicIP",
		"TriggerCount", "TriggerTypes",
		"ForensicHits", "ForensicScore",
		"EventCount", "EventScore",
		"YaraMatched", "YaraScore",
		"Reasons",
	})

	for _, obj := range result.ExecObjects {
		var pids []string
		for _, p := range obj.PIDs {
			pids = append(pids, strconv.Itoa(int(p)))
		}

		w.Write([]string{
			obj.RiskLevel,
			strconv.Itoa(obj.FinalScore),
			obj.Path,
			obj.ObjType,
			obj.LocationType,
			strconv.FormatBool(obj.IsRunning),
			strings.Join(pids, ";"),
			strings.Join(obj.Sources, ";"),
			obj.SHA256,
			obj.MD5,
			strconv.FormatBool(obj.Signed),
			strconv.FormatBool(obj.SignValid),
			obj.Signer,
			obj.Company,
			obj.Product,
			strconv.FormatBool(obj.NetworkObserved),
			strings.Join(obj.RemoteIPs, ";"),
			strconv.FormatBool(obj.HasPublicIP),
			strconv.Itoa(obj.TriggerCount),
			strings.Join(obj.TriggerTypes, ";"),
			strconv.Itoa(obj.ForensicHits),
			strconv.Itoa(obj.ForensicScore),
			strconv.Itoa(obj.EventCount),
			strconv.Itoa(obj.EventScore),
			strconv.FormatBool(obj.YaraMatched),
			strconv.Itoa(obj.YaraScore),
			strings.Join(obj.Reasons, ";"),
		})
	}

	return nil
}

func exportYARACSV(result *scoring.ScanResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// UTF-8 BOM
	f.Write([]byte{0xEF, 0xBB, 0xBF})

	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write([]string{
		"Path", "RiskLevel", "FinalScore", "YaraScore",
		"YaraRules", "YaraRuleTags",
		"ObjType", "LocationType", "IsRunning",
		"Signed", "Signer",
		"SHA256", "MD5",
		"Reasons",
	})

	for _, obj := range result.ExecObjects {
		if !obj.YaraMatched {
			continue
		}

		ruleNames, ruleTags := extractYaraInfo(obj.YaraHits)

		w.Write([]string{
			obj.Path,
			obj.RiskLevel,
			strconv.Itoa(obj.FinalScore),
			strconv.Itoa(obj.YaraScore),
			strings.Join(ruleNames, ";"),
			strings.Join(ruleTags, ";"),
			obj.ObjType,
			obj.LocationType,
			strconv.FormatBool(obj.IsRunning),
			strconv.FormatBool(obj.Signed),
			obj.Signer,
			obj.SHA256,
			obj.MD5,
			strings.Join(obj.Reasons, ";"),
		})
	}

	return nil
}

// extractYaraInfo extracts rule names and tags from YaraHits interface.
func extractYaraInfo(hits interface{}) (ruleNames []string, ruleTags []string) {
	if hits == nil {
		return
	}

	// YaraHits can be []yara.YaraHit or []interface{} depending on source
	switch v := hits.(type) {
	case []*yara.YaraHit:
		for _, h := range v {
			ruleNames = append(ruleNames, h.RuleName)
			ruleTags = append(ruleTags, h.Tags...)
		}
	case []yara.YaraHit:
		for _, h := range v {
			ruleNames = append(ruleNames, h.RuleName)
			ruleTags = append(ruleTags, h.Tags...)
		}
	}
	return
}

// buildSummary counts risk levels from ExecObjects.
func buildSummary(result *scoring.ScanResult) jsonSummary {
	s := jsonSummary{
		Processes:   len(result.Records),
		Triggers:    len(result.Triggers),
		Forensics:   len(result.Forensics),
		ExecObjects: len(result.ExecObjects),
		Events:      len(result.EventResults),
		Modules:     len(result.ModuleAnalyses),
	}
	for _, obj := range result.ExecObjects {
		switch obj.RiskLevel {
		case "Critical":
			s.Critical++
		case "High":
			s.High++
		case "Medium":
			s.Medium++
		case "Suspicious":
			s.Suspicious++
		}
		if obj.YaraMatched {
			s.YaraMatched++
		}
	}
	return s
}

// DefaultFileName generates a default export filename.
func DefaultFileName(prefix string, format Format) string {
	ts := time.Now().Format("20060102_150405")
	return fmt.Sprintf("%s_%s.%s", prefix, ts, format)
}

// PrintSummary prints a summary to stdout after export.
func PrintSummary(result *scoring.ScanResult) {
	s := buildSummary(result)
	fmt.Printf("\n"+i18n.T("cli_scan_summary")+"\n", s.ExecObjects, s.Processes, s.Triggers, s.Forensics, s.Events, s.Modules)
	fmt.Printf(i18n.T("cli_risk_summary")+"\n", s.Critical, s.High, s.Medium, s.Suspicious)
	if result.YaraLoaded {
		fmt.Printf(i18n.T("cli_yara_summary")+"\n", result.YaraRules, s.YaraMatched)
	}
	if result.Correlation != nil {
		fmt.Printf(i18n.T("cli_correlation_summary")+"\n",
			len(result.Correlation.Chains),
			len(result.Correlation.Indicators),
			len(result.Correlation.Timeline))
	}
}
