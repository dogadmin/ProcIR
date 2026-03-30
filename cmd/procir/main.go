package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"procir/internal/export"
	"procir/internal/gui"
	"procir/internal/i18n"
	"procir/internal/scoring"
	"procir/internal/yara"
)

func main() {
	yaraPath := flag.String("yara", "", "YARA rules file or directory path")
	cliMode := flag.Bool("cli", false, "Run in CLI mode (no GUI), scan and export data")
	outputPath := flag.String("o", "", "Output file path (CLI mode)")
	formatStr := flag.String("format", "json", "Export format: json or csv (CLI mode)")
	yaraOnly := flag.Bool("yara-export", false, "Export only YARA matched results (CLI mode)")
	flag.Parse()

	// Auto-detect yara rules in same directory as executable
	if *yaraPath == "" {
		exePath, _ := os.Executable()
		if exePath != "" {
			exeDir := filepath.Dir(exePath)
			candidates := []string{
				filepath.Join(exeDir, "rules"),
				filepath.Join(exeDir, "yara"),
				filepath.Join(exeDir, "rules.yar"),
			}
			for _, c := range candidates {
				if _, err := os.Stat(c); err == nil {
					*yaraPath = c
					break
				}
			}
		}
	}

	if *yaraPath != "" {
		engine := yara.NewEngine(*yaraPath)
		if engine != nil && engine.Enabled() {
			scoring.YaraEngine = engine
			fmt.Printf(i18n.T("cli_yara_loaded")+"\n", engine.RuleCount(), *yaraPath)
			if errs := engine.Errors(); len(errs) > 0 {
				for _, e := range errs {
					fmt.Printf("  "+i18n.T("cli_warning")+"\n", e)
				}
			}
		} else {
			fmt.Printf(i18n.T("cli_yara_fail")+"\n", *yaraPath)
		}
	}

	if *cliMode {
		runCLI(*outputPath, *formatStr, *yaraOnly)
		return
	}

	gui.Run()
}

func runCLI(outputPath, formatStr string, yaraOnly bool) {
	// Determine export format
	var format export.Format
	switch strings.ToLower(formatStr) {
	case "csv":
		format = export.FormatCSV
	default:
		format = export.FormatJSON
	}

	// Generate default output path if not specified
	if outputPath == "" {
		prefix := "procir_scan"
		if yaraOnly {
			prefix = "procir_yara"
		}
		outputPath = export.DefaultFileName(prefix, format)
	}

	// YARA-only export requires YARA engine
	if yaraOnly && (scoring.YaraEngine == nil || !scoring.YaraEngine.Enabled()) {
		fmt.Println(i18n.T("cli_yara_required"))
		os.Exit(1)
	}

	fmt.Println(i18n.T("cli_scan_start"))
	startTime := time.Now()

	// Progress callback
	progressFn := func(current, total int) {
		if current%10 == 0 || current == total {
			fmt.Printf("\r  "+i18n.T("cli_scan_progress"), current, total)
		}
	}

	result := scoring.Scan(progressFn)
	fmt.Println()

	elapsed := time.Since(startTime)
	fmt.Printf(i18n.T("cli_scan_done")+"\n", elapsed.Seconds())

	// Print summary
	export.PrintSummary(result)

	// Export
	fmt.Printf("\n"+i18n.T("cli_exporting")+"\n", outputPath)

	var err error
	if yaraOnly {
		err = export.ExportYARA(result, outputPath, format)
	} else {
		err = export.ExportFull(result, outputPath, format)
	}

	if err != nil {
		fmt.Printf(i18n.T("cli_export_fail")+"\n", err)
		os.Exit(1)
	}

	// Get file size
	info, _ := os.Stat(outputPath)
	size := int64(0)
	if info != nil {
		size = info.Size()
	}

	fmt.Printf(i18n.T("cli_export_done")+"\n", outputPath, formatFileSize(size))
}

func formatFileSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
	)
	switch {
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
