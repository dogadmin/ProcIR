package memory

import (
	"fmt"
	"strings"
	"unsafe"

	"procir/internal/i18n"
	"procir/internal/types"

	"golang.org/x/sys/windows"
)

// Memory protection constants.
const (
	PAGE_NOACCESS          = 0x01
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_WRITECOPY         = 0x08
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80
	PAGE_GUARD             = 0x100

	MEM_COMMIT  = 0x1000
	MEM_RESERVE = 0x2000
	MEM_FREE    = 0x10000

	MEM_PRIVATE = 0x20000
	MEM_MAPPED  = 0x40000
	MEM_IMAGE   = 0x1000000
)

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	_                 [4]byte // padding for alignment
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	_2                [4]byte
}

var (
	modKernel32      = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualQueryEx = modKernel32.NewProc("VirtualQueryEx")
)

// Known processes that commonly have RWX regions (JIT engines).
var jitProcesses = map[string]bool{
	"chrome.exe": true, "msedge.exe": true, "firefox.exe": true,
	"brave.exe": true, "opera.exe": true, "iexplore.exe": true,
	"java.exe": true, "javaw.exe": true, "node.exe": true,
	"dotnet.exe": true, "pwsh.exe": true, "powershell_ise.exe": true,
	"code.exe": true, "devenv.exe": true, // VS Code, Visual Studio
}

// Analyze performs memory analysis on a single PID.
func Analyze(pid uint32, procName, procPath, user string, signed bool, signer string) *types.MemoryAnalysis {
	result := &types.MemoryAnalysis{
		PID:         pid,
		ProcessName: procName,
		Path:        procPath,
		User:        user,
		Signed:      signed,
		Signer:      signer,
	}

	if pid == 0 || pid == 4 {
		result.Error = i18n.T("mem_system_process")
		return result
	}

	// Open process
	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false, pid,
	)
	if err != nil {
		result.Error = fmt.Sprintf(i18n.T("mem_open_fail"), err)
		return result
	}
	defer windows.CloseHandle(h)

	// Enumerate memory regions
	var addr uintptr
	var mbi memoryBasicInformation
	mbiSize := unsafe.Sizeof(mbi)
	maxRegions := 10000 // safety limit

	for i := 0; i < maxRegions; i++ {
		ret, _, _ := procVirtualQueryEx.Call(
			uintptr(h),
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			mbiSize,
		)
		if ret == 0 {
			break
		}

		result.TotalRegions++

		// Only analyze committed regions
		if mbi.State == MEM_COMMIT {
			result.CommittedRegions++

			region := &types.MemoryRegion{
				BaseAddress:  fmt.Sprintf("0x%X", mbi.BaseAddress),
				Size:         uint64(mbi.RegionSize),
				SizeHuman:    humanSize(uint64(mbi.RegionSize)),
				Protect:      protectString(mbi.Protect),
				ProtectRaw:   mbi.Protect,
				Type:         typeString(mbi.Type),
				TypeRaw:      mbi.Type,
				State:        "COMMIT",
				IsExecutable: isExecutable(mbi.Protect),
				IsWritable:   isWritable(mbi.Protect),
			}

			region.IsRWX = region.IsExecutable && region.IsWritable
			region.IsPrivateExec = (mbi.Type == MEM_PRIVATE) && region.IsExecutable
			region.IsNoImageExec = (mbi.Type != MEM_IMAGE) && region.IsExecutable

			if region.IsExecutable {
				result.ExecutableRegions++
			}

			// Classify suspicious regions
			if region.IsRWX {
				result.RWXCount++
				region.IsSuspicious = true
				region.Reason = i18n.T("mem_rwx_region")
			}
			if region.IsPrivateExec {
				result.PrivateExecCount++
				region.IsSuspicious = true
				if region.Reason == "" {
					region.Reason = i18n.T("mem_private_exec")
				} else {
					region.Reason += " + " + i18n.T("mem_private_exec_short")
				}
			}
			if region.IsNoImageExec && !region.IsRWX && !region.IsPrivateExec {
				result.NoImageExecCount++
				region.IsSuspicious = true
				region.Reason = i18n.T("mem_noimage_exec")
			}

			result.AllRegions = append(result.AllRegions, region)
			if region.IsSuspicious {
				result.SuspiciousRegions = append(result.SuspiciousRegions, region)
				result.SuspiciousCount++
			}
		}

		// Advance to next region
		addr = mbi.BaseAddress + uintptr(mbi.RegionSize)
		if addr < mbi.BaseAddress { // overflow
			break
		}
	}

	// Apply scoring
	scoreMemory(result, procName)

	return result
}

func scoreMemory(r *types.MemoryAnalysis, procName string) {
	r.Score = 0
	r.Reasons = nil
	isJIT := jitProcesses[strings.ToLower(procName)]

	// Rule 1: RWX exists → +20
	if r.RWXCount > 0 {
		r.Score += 20
		r.Reasons = append(r.Reasons, fmt.Sprintf(i18n.T("mem_has_rwx"), r.RWXCount))
	}

	// Rule 2: Multiple RWX → +10
	if r.RWXCount > 1 {
		r.Score += 10
		r.Reasons = append(r.Reasons, i18n.T("mem_multi_rwx"))
	}

	// Rule 3: Private + Executable → +30
	if r.PrivateExecCount > 0 {
		r.Score += 30
		r.Reasons = append(r.Reasons, fmt.Sprintf(i18n.T("mem_has_private_exec"), r.PrivateExecCount))
	}

	// Rule 4: NoImage Executable → +40
	if r.NoImageExecCount > 0 {
		r.Score += 40
		r.Reasons = append(r.Reasons, fmt.Sprintf(i18n.T("mem_has_noimage_exec"), r.NoImageExecCount))
	}

	// Rule 5: RWX + Private combo → +20
	if r.RWXCount > 0 && r.PrivateExecCount > 0 {
		r.Score += 20
		r.Reasons = append(r.Reasons, i18n.T("mem_rwx_private_combo"))
	}

	// Anti-FP: JIT process with only RWX (no PrivateExec) → -15
	if isJIT && r.PrivateExecCount == 0 && r.NoImageExecCount == 0 {
		r.Score -= 15
		if r.Score < 0 {
			r.Score = 0
		}
	}

	// Risk level
	switch {
	case r.Score >= 60:
		r.RiskLevel = "High"
	case r.Score >= 40:
		r.RiskLevel = "Medium"
	case r.Score >= 20:
		r.RiskLevel = "Suspicious"
	default:
		r.RiskLevel = "Low"
	}
}

func isExecutable(protect uint32) bool {
	p := protect & 0xFF
	return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ ||
		p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY
}

func isWritable(protect uint32) bool {
	p := protect & 0xFF
	return p == PAGE_READWRITE || p == PAGE_EXECUTE_READWRITE || p == PAGE_WRITECOPY || p == PAGE_EXECUTE_WRITECOPY
}

func protectString(p uint32) string {
	base := p & 0xFF
	names := map[uint32]string{
		PAGE_NOACCESS:          "NOACCESS",
		PAGE_READONLY:          "READONLY",
		PAGE_READWRITE:         "RW",
		PAGE_WRITECOPY:         "WRITECOPY",
		PAGE_EXECUTE:           "EXEC",
		PAGE_EXECUTE_READ:      "EXEC_READ",
		PAGE_EXECUTE_READWRITE: "RWX",
		PAGE_EXECUTE_WRITECOPY: "EXEC_WRITECOPY",
	}
	name, ok := names[base]
	if !ok {
		name = fmt.Sprintf("0x%X", p)
	}
	if p&PAGE_GUARD != 0 {
		name += "+GUARD"
	}
	return name
}

func typeString(t uint32) string {
	switch t {
	case MEM_IMAGE:
		return "IMAGE"
	case MEM_MAPPED:
		return "MAPPED"
	case MEM_PRIVATE:
		return "PRIVATE"
	default:
		return fmt.Sprintf("0x%X", t)
	}
}

func humanSize(bytes uint64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	} else if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/1024/1024)
	}
	return fmt.Sprintf("%.1f GB", float64(bytes)/1024/1024/1024)
}
