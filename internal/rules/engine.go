package rules

import (
	"math"
	"strings"

	"procir/internal/context"
	"procir/internal/i18n"
	"procir/internal/types"
)

// Apply evaluates the enhanced scoring model against a ProcessRecord.
//
// Flow:
//  1. Base Rules → accumulate base score + track flags
//  2. Override Rules → enforce minimum score for known-bad patterns
//  3. Synergy Bonus → extra points for multi-feature combinations
//  4. Anti-FP → reduce score for known-good signals
//  5. Context Weight → multiply score for high-confidence behavioral hits
//  6. Final score + risk level
func Apply(r *types.ProcessRecord) {
	r.RiskScore = 0
	r.Reasons = nil

	cmdLower := strings.ToLower(r.CommandLine)
	nameLower := strings.ToLower(r.Name)
	pathLower := strings.ToLower(r.Path)

	// Internal flags to track what triggered
	var (
		hasCmdLineHit     bool
		hasParentChainHit bool
		hasPathHit        bool
		hasNetworkHit     bool
		hasPersistenceHit bool
		overrideMin       int
	)

	// ========================================
	// Step 1: Base Rules
	// ========================================

	// --- 1.1 签名 & 路径 ---

	pathCat := classifyPath(pathLower)

	// 微软有效签名: -8
	if r.Signed && r.SignValid && context.IsMicrosoftSigner(r.Signer) {
		r.RiskScore -= 8
	}

	// 非微软有效签名: -5
	if r.Signed && r.SignValid && !context.IsMicrosoftSigner(r.Signer) {
		r.RiskScore -= 5
	}

	// 无签名: +12
	if r.Path != "" && r.FileExists && !r.Signed {
		r.RiskScore += 12
		r.Reasons = append(r.Reasons, i18n.T("unsigned_exe"))
	}

	// 签名无效: +20
	if r.Signed && !r.SignValid {
		r.RiskScore += 20
		r.Reasons = append(r.Reasons, i18n.T("invalid_signature"))
	}

	// 路径评分
	switch pathCat {
	case context.PathUserDir:
		r.RiskScore += 20
		r.Reasons = append(r.Reasons, i18n.T("user_dir_exec"))
		hasPathHit = true
	case context.PathTemp:
		r.RiskScore += 20
		r.Reasons = append(r.Reasons, i18n.T("temp_dir_exec"))
		hasPathHit = true
	case context.PathProgramData:
		r.RiskScore += 15
		r.Reasons = append(r.Reasons, i18n.T("programdata_exec"))
		hasPathHit = true
	case context.PathSystem32:
		r.RiskScore -= 5
	case context.PathProgramFiles:
		if r.Signed && r.SignValid {
			r.RiskScore -= 8
		}
	case context.PathWindowsApps:
		if r.Signed && r.SignValid {
			r.RiskScore -= 10
		}
	}

	// --- 1.2 伪装检测 ---

	// 系统文件名伪装: +30
	if r.IsMasquerade {
		r.RiskScore += 30
		r.Reasons = append(r.Reasons, i18n.T("masquerade_path"))
	}

	// OriginalFileName 不匹配: +10
	if r.OriginalNameMismatch {
		r.RiskScore += 10
		r.Reasons = append(r.Reasons, i18n.T("masquerade_origname"))
	}

	// --- 1.3 父子进程异常 ---

	// Office → 脚本引擎: +25
	if context.IsOfficeProcess(r.ParentName) && context.IsScriptEngine(r.Name) {
		r.RiskScore += 25
		r.Reasons = append(r.Reasons, i18n.T("office_spawn_script"))
		hasParentChainHit = true
	}

	// 浏览器 → 系统工具: +20
	if context.IsBrowser(r.ParentName) && context.IsSystemTool(r.Name) {
		r.RiskScore += 20
		r.Reasons = append(r.Reasons, i18n.T("browser_spawn_tool"))
		hasParentChainHit = true
	}

	// 异常父进程链: +10
	if r.AbnormalParentChain {
		r.RiskScore += 10
		r.Reasons = append(r.Reasons, i18n.T("abnormal_parent"))
		hasParentChainHit = true
	}

	// --- 1.4 命令行检测（核心） ---

	isPowerShell := nameLower == "powershell.exe" || nameLower == "pwsh.exe"

	// PowerShell 编码执行: +30
	if isPowerShell &&
		(strings.Contains(cmdLower, "-encodedcommand") ||
			strings.Contains(cmdLower, "-enc ") ||
			strings.Contains(cmdLower, "-e ") ||
			strings.Contains(cmdLower, "frombase64")) {
		r.RiskScore += 30
		r.Reasons = append(r.Reasons, i18n.T("ps_encoded"))
		hasCmdLineHit = true
	}

	// PowerShell 隐藏窗口: +20
	if isPowerShell {
		if strings.Contains(cmdLower, "-nop") || strings.Contains(cmdLower, "-noprofile") {
			if strings.Contains(cmdLower, "-w hidden") || strings.Contains(cmdLower, "-windowstyle hidden") {
				r.RiskScore += 20
				r.Reasons = append(r.Reasons, i18n.T("ps_hidden"))
				hasCmdLineHit = true
			}
		}
	}

	// PowerShell 下载行为: +25
	if isPowerShell &&
		(strings.Contains(cmdLower, "downloadstring") || strings.Contains(cmdLower, "downloadfile") ||
			strings.Contains(cmdLower, "invoke-webrequest") || strings.Contains(cmdLower, "iwr ") ||
			strings.Contains(cmdLower, "wget ") || strings.Contains(cmdLower, "curl ") ||
			strings.Contains(cmdLower, "net.webclient") || strings.Contains(cmdLower, "bitstransfer") ||
			strings.Contains(cmdLower, "start-bitstransfer")) {
		r.RiskScore += 25
		r.Reasons = append(r.Reasons, i18n.T("ps_download"))
		hasCmdLineHit = true
	}

	// PowerShell IEX: +25
	psHasIEX := false
	if isPowerShell &&
		(strings.Contains(cmdLower, "invoke-expression") ||
			strings.Contains(cmdLower, "iex ") || strings.Contains(cmdLower, "iex(") ||
			strings.Contains(cmdLower, "iex\"") || strings.Contains(cmdLower, "iex'")) {
		r.RiskScore += 25
		r.Reasons = append(r.Reasons, i18n.T("ps_iex"))
		hasCmdLineHit = true
		psHasIEX = true
	}

	// PowerShell download + IEX combo (tracked for Override)
	psHasDownload := isPowerShell &&
		(strings.Contains(cmdLower, "downloadstring") || strings.Contains(cmdLower, "downloadfile") ||
			strings.Contains(cmdLower, "invoke-webrequest") || strings.Contains(cmdLower, "net.webclient"))

	// rundll32 加载用户目录DLL: +30
	rundll32UserDLL := false
	if nameLower == "rundll32.exe" && r.CommandLine != "" {
		if strings.Contains(cmdLower, `\users\`) ||
			strings.Contains(cmdLower, `\temp\`) ||
			strings.Contains(cmdLower, `\appdata\`) ||
			strings.Contains(cmdLower, `\downloads\`) {
			r.RiskScore += 30
			r.Reasons = append(r.Reasons, i18n.T("rundll32_user_dll"))
			hasCmdLineHit = true
			rundll32UserDLL = true
		}
	}

	// regsvr32 可疑用法: +30
	regsvr32Http := false
	if nameLower == "regsvr32.exe" && r.CommandLine != "" {
		if strings.Contains(cmdLower, "/i:") && strings.Contains(cmdLower, "http") {
			regsvr32Http = true
		}
		if strings.Contains(cmdLower, "/s") || strings.Contains(cmdLower, "/i:") ||
			strings.Contains(cmdLower, "scrobj") || strings.Contains(cmdLower, "http") {
			r.RiskScore += 30
			r.Reasons = append(r.Reasons, i18n.T("regsvr32_suspicious"))
			hasCmdLineHit = true
		}
	}

	// mshta 可疑执行: +30
	mshtaRemote := false
	if nameLower == "mshta.exe" && r.CommandLine != "" {
		if strings.Contains(cmdLower, "http") {
			mshtaRemote = true
		}
		if strings.Contains(cmdLower, "http") || strings.Contains(cmdLower, "javascript") ||
			strings.Contains(cmdLower, "vbscript") {
			r.RiskScore += 30
			r.Reasons = append(r.Reasons, i18n.T("mshta_suspicious"))
			hasCmdLineHit = true
		}
	}

	// cmd /c 执行: +20
	cmdSlashC := false
	if nameLower == "cmd.exe" && strings.Contains(cmdLower, "/c") {
		r.RiskScore += 20
		r.Reasons = append(r.Reasons, i18n.T("cmd_c_exec"))
		hasCmdLineHit = true
		cmdSlashC = true
	}

	// certutil 可疑用法: +25
	if nameLower == "certutil.exe" && r.CommandLine != "" {
		if strings.Contains(cmdLower, "-urlcache") || strings.Contains(cmdLower, "-decode") ||
			strings.Contains(cmdLower, "-encode") || strings.Contains(cmdLower, "http") {
			r.RiskScore += 25
			r.Reasons = append(r.Reasons, i18n.T("certutil_suspicious"))
			hasCmdLineHit = true
		}
	}

	// bitsadmin 文件传输: +25
	if nameLower == "bitsadmin.exe" && strings.Contains(cmdLower, "/transfer") {
		r.RiskScore += 25
		r.Reasons = append(r.Reasons, i18n.T("bitsadmin_transfer"))
		hasCmdLineHit = true
	}

	// LOLBin 通用命中: +12
	if r.IsLOLBin {
		r.RiskScore += 12
		r.Reasons = append(r.Reasons, i18n.T("lolbin_process"))
	}

	// --- 1.5 网络 & 持久化 ---

	// 存在外联: +10
	if r.HasNetwork && len(r.RemoteIPs) > 0 {
		r.RiskScore += 10
		r.Reasons = append(r.Reasons, i18n.T("has_external_conn"))
		hasNetworkHit = true
	}

	// 公网连接: +10
	if r.HasPublicIP {
		r.RiskScore += 10
		r.Reasons = append(r.Reasons, i18n.T("public_ip_conn"))
		hasNetworkHit = true
	}

	// 持久化: +20 per mechanism (cap at 25)
	if len(r.Persistence) > 0 {
		score := len(r.Persistence) * 20
		if score > 25 {
			score = 25
		}
		r.RiskScore += score
		r.Reasons = append(r.Reasons, i18n.T("has_persistence"))
		hasPersistenceHit = true
	}

	// ========================================
	// Step 2: 强规则 Override
	// ========================================

	// --- 严重 Critical (>=80) ---

	// Office → PowerShell + 编码
	if context.IsOfficeProcess(r.ParentName) && isPowerShell &&
		(strings.Contains(cmdLower, "-enc") || strings.Contains(cmdLower, "-encodedcommand")) {
		if overrideMin < 80 {
			overrideMin = 80
			r.Reasons = append(r.Reasons, i18n.T("strong_office_ps_enc"))
		}
	}

	// regsvr32 /i:http 远程加载
	if regsvr32Http {
		if overrideMin < 80 {
			overrideMin = 80
			r.Reasons = append(r.Reasons, i18n.T("strong_regsvr32_remote"))
		}
	}

	// mshta 远程URL
	if mshtaRemote {
		if overrideMin < 80 {
			overrideMin = 80
			r.Reasons = append(r.Reasons, i18n.T("strong_mshta_remote"))
		}
	}

	// PowerShell 下载 + IEX
	if psHasDownload && psHasIEX {
		if overrideMin < 80 {
			overrideMin = 80
			r.Reasons = append(r.Reasons, i18n.T("strong_ps_download_iex"))
		}
	}

	// rundll32 用户DLL + 外联
	if rundll32UserDLL && hasNetworkHit {
		if overrideMin < 80 {
			overrideMin = 80
			r.Reasons = append(r.Reasons, i18n.T("strong_rundll32_user_net"))
		}
	}

	// --- 高危 High (>=60) ---

	// LOLBin + 恶意命令行
	if r.IsLOLBin && hasCmdLineHit {
		if overrideMin < 60 {
			overrideMin = 60
			r.Reasons = append(r.Reasons, i18n.T("strong_lolbin_malcmd"))
		}
	}

	// 浏览器 → cmd/powershell + 执行参数
	if context.IsBrowser(r.ParentName) &&
		(nameLower == "cmd.exe" || isPowerShell) &&
		(strings.Contains(cmdLower, "/c") || strings.Contains(cmdLower, "-enc") ||
			strings.Contains(cmdLower, "-command") || strings.Contains(cmdLower, "-file")) {
		if overrideMin < 60 {
			overrideMin = 60
			r.Reasons = append(r.Reasons, i18n.T("strong_browser_shell"))
		}
	}

	// cmd /c + 下载 + 执行链
	if cmdSlashC &&
		(strings.Contains(cmdLower, "curl") || strings.Contains(cmdLower, "wget") ||
			strings.Contains(cmdLower, "certutil") || strings.Contains(cmdLower, "bitsadmin") ||
			strings.Contains(cmdLower, "powershell")) {
		if overrideMin < 60 {
			overrideMin = 60
			r.Reasons = append(r.Reasons, i18n.T("strong_cmd_download"))
		}
	}

	// 应用 Override 保底分
	if r.RiskScore < overrideMin {
		r.RiskScore = overrideMin
	}

	// ========================================
	// Step 3: 组合加权 Synergy
	// ========================================

	// LOLBin + 命令行异常: +15
	if r.IsLOLBin && hasCmdLineHit {
		r.RiskScore += 15
		r.Reasons = append(r.Reasons, i18n.T("combo_lolbin_cmdline"))
	}

	// 命令行异常 + 用户目录: +10
	if hasCmdLineHit && hasPathHit {
		r.RiskScore += 10
		r.Reasons = append(r.Reasons, i18n.T("combo_cmdline_path"))
	}

	// 命令行异常 + 外联: +15
	if hasCmdLineHit && hasNetworkHit {
		r.RiskScore += 15
		r.Reasons = append(r.Reasons, i18n.T("combo_cmdline_net"))
	}

	// 外联 + 持久化: +20
	if hasNetworkHit && hasPersistenceHit {
		r.RiskScore += 20
		r.Reasons = append(r.Reasons, i18n.T("combo_net_persist"))
	}

	// 父子链异常 + 命令行异常: +15
	if hasParentChainHit && hasCmdLineHit {
		r.RiskScore += 15
		r.Reasons = append(r.Reasons, i18n.T("combo_parent_cmdline"))
	}

	// ========================================
	// Step 4: 白特征抵消 Anti-FP
	// ========================================

	// 已知可信厂商 + 有效签名: -5 ~ -10
	if r.Signed && r.SignValid {
		if context.IsTrustedVendor(r.Signer, r.Company) && !context.IsMicrosoftSigner(r.Signer) {
			r.RiskScore -= 5
			if pathCat == context.PathProgramFiles || pathCat == context.PathSystem32 {
				r.RiskScore -= 5
			}
		}
	}

	// 浏览器 Native Messaging: -15
	if context.IsBrowser(r.ParentName) &&
		(strings.Contains(cmdLower, "chrome-extension://") ||
			strings.Contains(cmdLower, "nativemessaging") ||
			strings.Contains(cmdLower, "native-messaging") ||
			strings.Contains(cmdLower, "--parent-window")) {
		r.RiskScore -= 15
		r.Reasons = filterReason(r.Reasons, i18n.T("browser_spawn_tool"))
	}

	// ========================================
	// Step 5: 上下文权重
	// ========================================

	// 命令行命中: score × 1.5
	if hasCmdLineHit && r.RiskScore > 0 {
		r.RiskScore = int(math.Round(float64(r.RiskScore) * 1.5))
	} else if hasParentChainHit && r.RiskScore > 0 {
		// 父子链命中: score × 1.2
		r.RiskScore = int(math.Round(float64(r.RiskScore) * 1.2))
	}

	// ========================================
	// Step 6: 最终评分
	// ========================================

	// 重新应用 Override 保底
	if r.RiskScore < overrideMin {
		r.RiskScore = overrideMin
	}

	if r.RiskScore < 0 {
		r.RiskScore = 0
	}

	r.RiskLevel = types.CalcRiskLevel(r.RiskScore)
}

// classifyPath mirrors context.classifyPath for use in rules.
func classifyPath(pathLower string) context.PathCategory {
	if pathLower == "" {
		return context.PathUnknown
	}

	if strings.HasPrefix(pathLower, `c:\windows\system32`) || strings.HasPrefix(pathLower, `c:\windows\syswow64`) {
		return context.PathSystem32
	}
	if strings.Contains(pathLower, `\windowsapps\`) {
		return context.PathWindowsApps
	}
	if strings.HasPrefix(pathLower, `c:\program files\`) || strings.HasPrefix(pathLower, `c:\program files (x86)\`) {
		return context.PathProgramFiles
	}
	if strings.HasPrefix(pathLower, `c:\programdata\`) {
		return context.PathProgramData
	}
	if strings.HasPrefix(pathLower, `c:\windows\temp`) || strings.HasPrefix(pathLower, `c:\temp`) {
		return context.PathTemp
	}
	if strings.HasPrefix(pathLower, `c:\users\`) {
		if strings.Contains(pathLower, `\appdata\local\microsoft\`) {
			return context.PathProgramFiles
		}
		if strings.Contains(pathLower, `\appdata\local\programs\`) {
			return context.PathProgramFiles
		}
		return context.PathUserDir
	}
	if strings.HasPrefix(pathLower, `c:\windows\`) {
		return context.PathWindows
	}
	return context.PathOther
}

func filterReason(reasons []string, remove string) []string {
	result := reasons[:0]
	for _, r := range reasons {
		if r != remove {
			result = append(result, r)
		}
	}
	return result
}
