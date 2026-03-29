package iocmonitor

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"procir/internal/i18n"
	"procir/internal/types"

	"golang.org/x/sys/windows"
)

var (
	modIPHlpAPI     = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetTcpTable = modIPHlpAPI.NewProc("GetExtendedTcpTable")
)

type processInfo struct {
	Name    string
	Path    string
	User    string
	LOLBin  bool
	UserDir bool
}

type Monitor struct {
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}

	iocs      map[string]*types.IOCEntry // IP → entry
	domains   map[string]*types.IOCEntry // domain → entry
	procCache map[uint32]*processInfo
	seenConns map[string]bool            // dedup by "remoteIP:remotePort"
	ipPIDHist map[string]uint32          // "remoteIP:remotePort" → last known non-zero PID

	hits    []*types.IOCHit
	hitPIDs map[uint32]bool

	startTime  time.Time
	duration   int
	cycleCount int
}

var globalMonitor = &Monitor{}

func GetMonitor() *Monitor { return globalMonitor }

func (m *Monitor) LoadIOCs(text string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.iocs = make(map[string]*types.IOCEntry)
	m.domains = make(map[string]*types.IOCEntry)

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ",", 4)
		value := strings.TrimSpace(parts[0])
		if value == "" {
			continue
		}

		entry := &types.IOCEntry{Value: value, Confidence: "high"}
		if len(parts) >= 2 {
			entry.Confidence = strings.TrimSpace(parts[1])
		}
		if len(parts) >= 3 {
			entry.Source = strings.TrimSpace(parts[2])
		}
		if len(parts) >= 4 {
			entry.Comment = strings.TrimSpace(parts[3])
		}

		if ip := net.ParseIP(value); ip != nil {
			entry.Type = "ip"
			m.iocs[value] = entry
		} else {
			entry.Type = "domain"
			m.domains[strings.ToLower(value)] = entry
		}
	}

	// Resolve domain IOCs to IPs immediately (one-time, non-disruptive)
	for domain, entry := range m.domains {
		ips, err := net.LookupHost(domain)
		if err == nil {
			for _, ip := range ips {
				if _, exists := m.iocs[ip]; !exists {
					m.iocs[ip] = &types.IOCEntry{
						Value:      entry.Value,
						Type:       "domain",
						Confidence: entry.Confidence,
						Source:     entry.Source,
						Comment:    entry.Comment + " (" + i18n.T("iocmon_dns_resolve") + domain + " → " + ip + ")",
					}
				}
			}
		}
	}

	return len(m.iocs) + len(m.domains)
}

func (m *Monitor) Start(durationSec int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("%s", i18n.T("iocmon_already_running"))
	}
	if len(m.iocs) == 0 {
		return fmt.Errorf("%s", i18n.T("iocmon_no_ioc"))
	}

	m.running = true
	m.stopCh = make(chan struct{})
	m.hits = nil
	m.hitPIDs = make(map[uint32]bool)
	m.seenConns = make(map[string]bool)
	m.ipPIDHist = make(map[string]uint32)
	m.procCache = make(map[uint32]*processInfo)
	m.startTime = time.Now()
	m.duration = durationSec
	m.cycleCount = 0

	go m.runLoop()
	return nil
}

func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		close(m.stopCh)
		m.running = false
	}
}

func (m *Monitor) Status() *types.MonitorStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := &types.MonitorStatus{
		Running:    m.running,
		IOCCount:   len(m.iocs),
		HitCount:   len(m.hits),
		HitPIDs:    len(m.hitPIDs),
		CycleCount: m.cycleCount,
		Duration:   m.duration,
	}
	if !m.startTime.IsZero() {
		st.StartTime = m.startTime.Format("15:04:05")
		st.Elapsed = time.Since(m.startTime).Truncate(time.Second).String()
	}
	return st
}

func (m *Monitor) Hits() []*types.IOCHit {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*types.IOCHit, len(m.hits))
	copy(result, m.hits)
	return result
}

func (m *Monitor) runLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var timer <-chan time.Time
	if m.duration > 0 {
		t := time.NewTimer(time.Duration(m.duration) * time.Second)
		timer = t.C
		defer t.Stop()
	}

	// Initial process snapshot
	m.refreshProcessCache()

	for {
		select {
		case <-m.stopCh:
			return
		case <-timer:
			m.mu.Lock()
			m.running = false
			m.mu.Unlock()
			return
		case <-ticker.C:
			m.mu.Lock()
			m.cycleCount++
			m.mu.Unlock()

			m.refreshProcessCache()
			m.pollOnce()
		}
	}
}

// ==========================================
// Process cache: zero network impact
// ==========================================

func (m *Monitor) refreshProcessCache() {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if windows.Process32First(snap, &entry) != nil {
		return
	}

	lolbins := map[string]bool{
		"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true,
		"mshta.exe": true, "rundll32.exe": true, "regsvr32.exe": true,
		"certutil.exe": true, "bitsadmin.exe": true, "wscript.exe": true,
		"cscript.exe": true, "curl.exe": true,
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Accumulate — never delete old entries so short-lived processes are preserved
	for {
		pid := entry.ProcessID
		if pid == 0 || pid == 4 {
			if windows.Process32Next(snap, &entry) != nil { break }
			continue
		}

		// Skip if already cached (don't re-query)
		if _, exists := m.procCache[pid]; exists {
			if windows.Process32Next(snap, &entry) != nil { break }
			continue
		}

		name := windows.UTF16ToString(entry.ExeFile[:])
		pi := &processInfo{Name: name}

		if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid); err == nil {
			buf := make([]uint16, 1024)
			size := uint32(len(buf))
			modK := windows.NewLazySystemDLL("kernel32.dll")
			pQ := modK.NewProc("QueryFullProcessImageNameW")
			r, _, _ := pQ.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
			if r != 0 {
				pi.Path = windows.UTF16ToString(buf[:size])
			}

			var token syscall.Token
			if syscall.OpenProcessToken(syscall.Handle(h), syscall.TOKEN_QUERY, &token) == nil {
				if user, err := token.GetTokenUser(); err == nil {
					account, domain, _, lookupErr := user.User.Sid.LookupAccount("")
					if lookupErr == nil {
						pi.User = domain + `\` + account
					}
				}
				token.Close()
			}
			windows.CloseHandle(h)
		}

		pathLower := strings.ToLower(pi.Path)
		pi.UserDir = strings.HasPrefix(pathLower, `c:\users\`) &&
			!strings.Contains(pathLower, `\appdata\local\microsoft\`)
		pi.LOLBin = lolbins[strings.ToLower(name)]

		m.procCache[pid] = pi

		if windows.Process32Next(snap, &entry) != nil {
			break
		}
	}
}

// ==========================================
// Poll: TCP connection table only
// Zero network impact — reads kernel memory
// ==========================================

func (m *Monitor) pollOnce() {
	conns := collectTCP()

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().Format("2006-01-02 15:04:05")

	// Step 1: Update IP→PID history for ALL connections (not just IOC matches)
	// This builds the lookup table BEFORE connections go to TIME_WAIT (PID=0)
	for _, conn := range conns {
		if conn.PID > 0 && conn.PID != 4 && conn.RemoteIP != "0.0.0.0" {
			connKey := conn.RemoteIP + ":" + fmt.Sprint(conn.RemotePort)
			m.ipPIDHist[connKey] = conn.PID
		}
	}

	// Step 2: Check connections against IOCs
	for _, conn := range conns {
		if conn.RemoteIP == "0.0.0.0" || conn.RemoteIP == "127.0.0.1" {
			continue
		}

		ioc, ok := m.iocs[conn.RemoteIP]
		if !ok {
			continue
		}

		// Dedup by remote IP:Port (not PID — same connection can appear with PID then PID=0)
		connKey := conn.RemoteIP + ":" + fmt.Sprint(conn.RemotePort)
		if m.seenConns[connKey] {
			continue
		}
		m.seenConns[connKey] = true

		// Resolve the real PID: prefer current, fall back to history
		realPID := conn.PID
		if realPID == 0 || realPID == 4 {
			if histPID, ok := m.ipPIDHist[connKey]; ok {
				realPID = histPID
			}
		}

		hit := &types.IOCHit{
			Time:        now,
			IOC:         ioc.Value,
			IOCType:     ioc.Type,
			IOCComment:  ioc.Comment,
			PID:         realPID,
			RemoteIP:    conn.RemoteIP,
			RemotePort:  conn.RemotePort,
			Protocol:    "TCP",
			MatchSource: "tcp",
			Confidence:  ioc.Confidence,
		}

		// Enrich from process cache
		if realPID > 0 && realPID != 4 {
			if pi, ok := m.procCache[realPID]; ok {
				hit.ProcessName = pi.Name
				hit.ProcessPath = pi.Path
				hit.User = pi.User
				hit.IsLOLBin = pi.LOLBin
				hit.IsUserPath = pi.UserDir
			} else {
				hit.ProcessName = getProcessName(realPID)
			}
		}

		// If still no process info after all lookups
		if hit.ProcessName == "" && realPID > 0 && realPID != 4 {
			hit.ProcessName = getProcessName(realPID)
		}

		m.hits = append(m.hits, hit)
		if realPID > 0 && realPID != 4 {
			m.hitPIDs[realPID] = true
		}
	}
}

func getProcessName(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Sprintf(i18n.T("iocmon_pid_exited"), pid)
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	modK := windows.NewLazySystemDLL("kernel32.dll")
	pQ := modK.NewProc("QueryFullProcessImageNameW")
	r, _, _ := pQ.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		path := windows.UTF16ToString(buf[:size])
		parts := strings.Split(path, `\`)
		return parts[len(parts)-1]
	}
	return fmt.Sprintf("PID:%d", pid)
}

// ==========================================
// TCP table — pure kernel memory read
// ==========================================

type mibTcpRow struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type tcpConn struct {
	PID        uint32
	RemoteIP   string
	RemotePort uint16
}

func collectTCP() []tcpConn {
	var size uint32
	procGetTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, 2, 5, 0)
	if size == 0 {
		return nil
	}

	buf := make([]byte, size)
	r, _, _ := procGetTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 1, 2, 5, 0,
	)
	if r != 0 {
		return nil
	}

	numEntries := binary.LittleEndian.Uint32(buf[:4])
	rowSize := unsafe.Sizeof(mibTcpRow{})
	offset := uintptr(4)

	var conns []tcpConn
	for i := uint32(0); i < numEntries; i++ {
		if offset+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*mibTcpRow)(unsafe.Pointer(&buf[offset]))
		offset += rowSize

		// Skip CLOSED(1), LISTEN(2), DELETE_TCB(12)
		if row.State <= 2 || row.State >= 12 {
			continue
		}

		remoteIP := ipv4Str(row.RemoteAddr)
		if remoteIP != "0.0.0.0" {
			conns = append(conns, tcpConn{
				PID:        row.OwningPid,
				RemoteIP:   remoteIP,
				RemotePort: uint16(ntohs(row.RemotePort)),
			})
		}
	}

	return conns
}

func ipv4Str(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", addr&0xFF, (addr>>8)&0xFF, (addr>>16)&0xFF, (addr>>24)&0xFF)
}

func ntohs(port uint32) uint32 {
	return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)
}
