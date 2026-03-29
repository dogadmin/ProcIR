package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"procir/internal/gui"
	"procir/internal/i18n"
	"procir/internal/scoring"
	"procir/internal/yara"
)

func main() {
	yaraPath := flag.String("yara", "", "YARA rules file or directory path")
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

	gui.Run()
}
