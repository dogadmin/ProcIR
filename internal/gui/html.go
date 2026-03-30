package gui

const indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>ProcIR - Windows 应急响应进程排查工具</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: 'Microsoft YaHei', 'Segoe UI', Consolas, monospace;
  background: #1a1a2e;
  color: #e0e0e0;
  font-size: 13px;
  overflow: hidden;
  height: 100vh;
  display: flex;
  flex-direction: column;
}
a { color: #64b5f6; }

.toolbar {
  display: flex; align-items: center; gap: 8px;
  padding: 10px 16px; background: #16213e;
  border-bottom: 1px solid #0f3460; flex-shrink: 0;
}
.toolbar h1 { font-size: 16px; color: #e94560; margin-right: 16px; white-space: nowrap; }
.btn {
  padding: 6px 14px; border: 1px solid #0f3460; background: #16213e;
  color: #e0e0e0; border-radius: 4px; cursor: pointer; font-size: 13px;
  white-space: nowrap; transition: all 0.15s;
}
.btn:hover { background: #1a365d; border-color: #64b5f6; }
.btn-primary { background: #e94560; border-color: #e94560; color: #fff; font-weight: bold; }
.btn-primary:hover { background: #c62828; }
.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
.separator { width: 1px; height: 28px; background: #0f3460; }

/* Tabs */
.tab-bar {
  display: flex; gap: 0; background: #16213e;
  border-bottom: 2px solid #0f3460; flex-shrink: 0;
}
.tab {
  padding: 8px 20px; cursor: pointer; font-size: 13px;
  border-bottom: 2px solid transparent; margin-bottom: -2px;
  color: #888; transition: all 0.15s; user-select: none;
}
.tab:hover { color: #e0e0e0; background: #1a1a2e; }
.tab.active { color: #e94560; border-bottom-color: #e94560; font-weight: bold; }
.tab .badge {
  display: inline-block; padding: 0 6px; border-radius: 8px;
  font-size: 11px; margin-left: 4px; background: #0f3460; color: #aaa;
}
.tab.active .badge { background: #e94560; color: #fff; }

.filter-bar {
  display: flex; align-items: center; gap: 8px;
  padding: 8px 16px; background: #16213e;
  border-bottom: 1px solid #0f3460; flex-shrink: 0;
}
.filter-bar input {
  flex: 1; padding: 5px 10px; background: #1a1a2e;
  border: 1px solid #0f3460; color: #e0e0e0; border-radius: 4px; font-size: 13px; font-family: inherit;
}
.filter-bar input:focus { outline: none; border-color: #64b5f6; }
.filter-bar select {
  padding: 5px 8px; background: #1a1a2e; border: 1px solid #0f3460;
  color: #e0e0e0; border-radius: 4px; font-size: 13px;
}

.table-wrap { flex: 1; overflow: auto; position: relative; }
table { width: 100%; border-collapse: collapse; table-layout: fixed; }
thead { position: sticky; top: 0; z-index: 10; }
th {
  background: #0f3460; color: #e0e0e0; padding: 8px 6px; text-align: left;
  font-weight: 600; border-bottom: 2px solid #e94560; cursor: pointer;
  white-space: nowrap; user-select: none; font-size: 12px;
}
th:hover { background: #1a365d; }
th .sa { font-size: 10px; margin-left: 3px; color: #e94560; }
td {
  padding: 5px 6px; border-bottom: 1px solid #1e2a4a; white-space: nowrap;
  overflow: hidden; text-overflow: ellipsis; max-width: 400px; font-size: 12px;
}
tr:hover { background: #1e2a4a !important; }
tr.selected { background: #1a365d !important; }

tr.risk-critical { border-left: 3px solid #ff1744; }
tr.risk-critical td:first-child { color: #ff1744; font-weight: bold; }
tr.risk-high { border-left: 3px solid #ff9100; }
tr.risk-high td:first-child { color: #ff9100; font-weight: bold; }
tr.risk-medium { border-left: 3px solid #ffd600; }
tr.risk-medium td:first-child { color: #ffd600; font-weight: bold; }
tr.risk-suspicious { border-left: 3px solid #64b5f6; }
tr.risk-suspicious td:first-child { color: #64b5f6; }
tr.risk-low { border-left: 3px solid #4caf50; opacity: 0.7; }

.status-bar {
  display: flex; align-items: center; justify-content: space-between;
  padding: 6px 16px; background: #16213e; border-top: 1px solid #0f3460;
  font-size: 12px; flex-shrink: 0;
}
.status-bar .stats span { margin-right: 12px; }
.stats .critical { color: #ff1744; }
.stats .high { color: #ff9100; }
.stats .medium { color: #ffd600; }
.stats .suspicious { color: #64b5f6; }

.context-menu {
  display: none; position: fixed; z-index: 1000; background: #16213e;
  border: 1px solid #0f3460; border-radius: 6px; padding: 4px 0;
  min-width: 220px; box-shadow: 0 8px 24px rgba(0,0,0,0.5);
}
.context-menu.show { display: block; }
.context-menu .item { padding: 8px 16px; cursor: pointer; display: flex; align-items: center; gap: 8px; }
.context-menu .item:hover { background: #1a365d; }
.context-menu .divider { height: 1px; background: #0f3460; margin: 4px 0; }

.progress-bar { height: 3px; background: #0f3460; flex-shrink: 0; overflow: hidden; }
.progress-bar .fill { height: 100%; width: 0%; background: linear-gradient(90deg, #e94560, #64b5f6); transition: width 0.3s; }
.progress-bar.scanning .fill { width: 100%; animation: loading 1.5s ease-in-out infinite; }
@keyframes loading { 0% { transform: translateX(-100%); } 100% { transform: translateX(100%); } }

.modal-overlay {
  display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.7); z-index: 500; justify-content: center; align-items: center;
}
.modal-overlay.show { display: flex; }
.modal {
  background: #1a1a2e; border: 1px solid #0f3460; border-radius: 8px;
  width: 800px; max-height: 85vh; display: flex; flex-direction: column;
}
.modal-header {
  display: flex; justify-content: space-between; align-items: center;
  padding: 12px 16px; background: #16213e; border-bottom: 1px solid #0f3460; border-radius: 8px 8px 0 0;
}
.modal-header h2 { font-size: 15px; color: #e94560; }
.modal-header .close-btn { cursor: pointer; font-size: 18px; color: #aaa; }
.modal-header .close-btn:hover { color: #fff; }
.modal-body { padding: 16px; overflow-y: auto; flex: 1; }
.detail-section { margin-bottom: 16px; }
.detail-section h3 { font-size: 13px; color: #e94560; margin-bottom: 8px; border-bottom: 1px solid #0f3460; padding-bottom: 4px; }
.detail-row { display: flex; padding: 3px 0; font-size: 12px; }
.detail-label { width: 130px; color: #888; flex-shrink: 0; }
.detail-value { flex: 1; word-break: break-all; color: #e0e0e0; }
.detail-value.mono { font-family: Consolas, monospace; }
.tag { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 11px; margin: 1px 2px; }
.tag-red { background: #5c1a1a; color: #ff8a80; }
.tag-orange { background: #4a3000; color: #ffcc80; }
.tag-blue { background: #1a3a5c; color: #80d8ff; }
.tag-green { background: #1a3a1a; color: #a5d6a7; }

.view-panel { display: none; flex: 1; flex-direction: column; overflow: hidden; }
.view-panel.active { display: flex; }
</style>
</head>
<body>

<div class="toolbar">
  <h1>ProcIR</h1>
  <button class="btn btn-primary" id="scanBtn" onclick="startScan()">开始扫描</button>
  <div class="separator"></div>
  <button class="btn" onclick="copySHA256()" id="btnCopySHA">复制SHA256</button>
  <button class="btn" onclick="openVT()" id="btnVT">查询VT</button>
  <button class="btn" onclick="copyVTLink()" id="btnCopyVT">复制VT链接</button>
  <button class="btn" onclick="openDir()" id="btnOpenDir">打开目录</button>
  <button class="btn" onclick="showDetail()" id="btnDetail">详情</button>
  <div class="separator"></div>
  <button class="btn" onclick="exportCSV()" id="btnExport">导出CSV</button>
  <button class="btn" onclick="checkUpdate()" id="btnUpdate">检查更新</button>
  <div style="flex:1"></div>
  <span id="versionLabel" style="color:#666;font-size:11px;margin-right:8px"></span>
  <button class="btn" id="langToggle" onclick="toggleLang()" style="padding:4px 10px;font-size:12px;font-weight:bold">EN</button>
</div>

<div class="tab-bar">
  <div class="tab active" onclick="switchView('process')" id="tab_process">活跃进程 <span class="badge" id="badge_process">0</span></div>
  <div class="tab" onclick="switchView('trigger')" id="tab_trigger">触发器 <span class="badge" id="badge_trigger">0</span></div>
  <div class="tab" onclick="switchView('execobj')" id="tab_execobj">执行对象 <span class="badge" id="badge_execobj">0</span></div>
  <div class="tab" onclick="switchView('forensic')" id="tab_forensic">历史取证 <span class="badge" id="badge_forensic">0</span></div>
  <div class="tab" onclick="switchView('timeline')" id="tab_timeline">时间线 <span class="badge" id="badge_timeline">0</span></div>
  <div class="tab" onclick="switchView('chain')" id="tab_chain">行为链 <span class="badge" id="badge_chain">0</span></div>
  <div class="tab" onclick="switchView('ioc')" id="tab_ioc">IOC <span class="badge" id="badge_ioc">0</span></div>
  <div class="tab" onclick="switchView('event')" id="tab_event">事件日志 <span class="badge" id="badge_event">0</span></div>
  <div class="tab" onclick="switchView('module')" id="tab_module">模块分析 <span class="badge" id="badge_module">0</span></div>
  <div class="tab" onclick="switchView('yara')" id="tab_yara">YARA</div>
  <div class="tab" onclick="switchView('memory')" id="tab_memory">内存分析</div>
  <div class="tab" onclick="switchView('iocmon')" id="tab_iocmon">IOC监控</div>
  <div class="tab" onclick="switchView('ai')" id="tab_ai">AI分析</div>
</div>

<div class="filter-bar">
  <label id="lbl_filter">筛选：</label>
  <input id="filterInput" placeholder="搜索进程名、路径、SHA256、签发者、命令行..." oninput="applyFilter()">
  <label id="lbl_risk">风险：</label>
  <select id="riskFilter" onchange="applyFilter()">
    <option value="" id="opt_all">全部</option>
    <option value="Critical" id="opt_crit">严重</option>
    <option value="High" id="opt_high">高危</option>
    <option value="Medium" id="opt_med">中危</option>
    <option value="Suspicious" id="opt_susp">可疑</option>
    <option value="Low" id="opt_low">低危</option>
  </select>
</div>

<div class="progress-bar" id="progressBar"><div class="fill"></div></div>

<!-- Process View -->
<div class="view-panel active" id="view_process">
  <div class="table-wrap"><table><thead><tr>
    <th style="width:60px" onclick="sortProc('RiskLevel')">风险<span class="sa" id="sp_RiskLevel"></span></th>
    <th style="width:45px" onclick="sortProc('RiskScore')">评分<span class="sa" id="sp_RiskScore"></span></th>
    <th style="width:130px" onclick="sortProc('Name')">进程名<span class="sa" id="sp_Name"></span></th>
    <th style="width:50px" onclick="sortProc('PID')">PID<span class="sa" id="sp_PID"></span></th>
    <th style="width:120px" onclick="sortProc('ParentName')">父进程<span class="sa" id="sp_ParentName"></span></th>
    <th style="width:240px">路径</th>
    <th style="width:250px">命令行</th>
    <th style="width:140px">SHA256</th>
    <th style="width:120px" onclick="sortProc('Signer')">签名者<span class="sa" id="sp_Signer"></span></th>
    <th style="width:90px">网络</th>
    <th style="width:70px">持久化</th>
    <th style="width:200px">风险原因</th>
  </tr></thead><tbody id="procBody"></tbody></table></div>
</div>

<!-- Trigger View -->
<div class="view-panel" id="view_trigger">
  <div class="table-wrap"><table><thead><tr>
    <th style="width:55px" onclick="sortTrig('Score')">评分<span class="sa" id="st_Score"></span></th>
    <th style="width:80px" onclick="sortTrig('Type')">类型<span class="sa" id="st_Type"></span></th>
    <th style="width:180px" onclick="sortTrig('Name')">名称<span class="sa" id="st_Name"></span></th>
    <th style="width:250px">路径</th>
    <th style="width:300px">命令行</th>
    <th style="width:250px">详情</th>
    <th style="width:200px">风险原因</th>
  </tr></thead><tbody id="trigBody"></tbody></table></div>
</div>

<!-- Execution Object View -->
<div class="view-panel" id="view_execobj">
  <div class="table-wrap"><table><thead><tr>
    <th style="width:60px" onclick="sortExec('RiskLevel')">风险<span class="sa" id="se_RiskLevel"></span></th>
    <th style="width:55px" onclick="sortExec('FinalScore')">评分<span class="sa" id="se_FinalScore"></span></th>
    <th style="width:60px">状态</th>
    <th style="width:250px">路径</th>
    <th style="width:90px">位置</th>
    <th style="width:120px">签名者</th>
    <th style="width:90px">触发器</th>
    <th style="width:150px">来源</th>
    <th style="width:90px">网络</th>
    <th style="width:250px">风险原因</th>
  </tr></thead><tbody id="execBody"></tbody></table></div>
</div>

<!-- Forensic View -->
<div class="view-panel" id="view_forensic">
  <div class="table-wrap"><table><thead><tr>
    <th style="width:55px" onclick="sortFore('Score')">评分<span class="sa" id="sf_Score"></span></th>
    <th style="width:80px" onclick="sortFore('Source')">来源<span class="sa" id="sf_Source"></span></th>
    <th style="width:250px">路径</th>
    <th style="width:300px">详情</th>
    <th style="width:130px">时间</th>
    <th style="width:80px">文件类型</th>
    <th style="width:250px">风险原因</th>
  </tr></thead><tbody id="foreBody"></tbody></table></div>
</div>

<!-- Timeline View -->
<div class="view-panel" id="view_timeline">
  <div class="table-wrap"><table><thead><tr>
    <th style="width:145px" onclick="sortTL('Time')">时间<span class="sa" id="stl_Time"></span></th>
    <th style="width:80px" onclick="sortTL('Type')">类型<span class="sa" id="stl_Type"></span></th>
    <th style="width:55px" onclick="sortTL('Score')">评分<span class="sa" id="stl_Score"></span></th>
    <th style="width:150px">对象</th>
    <th style="width:350px">详情</th>
    <th style="width:100px">来源</th>
  </tr></thead><tbody id="tlBody"></tbody></table></div>
</div>

<!-- Behavior Chain View -->
<div class="view-panel" id="view_chain">
  <div class="table-wrap"><table><thead><tr>
    <th style="width:55px">评分</th>
    <th style="width:220px">攻击链</th>
    <th style="width:500px">证据</th>
    <th style="width:300px">涉及对象</th>
  </tr></thead><tbody id="chainBody"></tbody></table></div>
</div>

<!-- IOC View -->
<div class="view-panel" id="view_ioc">
  <div class="table-wrap"><table><thead><tr>
    <th style="width:80px" onclick="sortIOC('Type')">类型<span class="sa" id="si_Type"></span></th>
    <th style="width:350px">值</th>
    <th style="width:200px">来源对象</th>
    <th style="width:200px">上下文</th>
  </tr></thead><tbody id="iocBody"></tbody></table></div>
</div>

<!-- Event View -->
<div class="view-panel" id="view_event">
  <div class="table-wrap"><table><thead><tr>
    <th style="width:55px" onclick="sortEvt('Score')">评分<span class="sa" id="sev_Score"></span></th>
    <th style="width:145px" onclick="sortEvt('Time')">时间<span class="sa" id="sev_Time"></span></th>
    <th style="width:55px" onclick="sortEvt('EventID')">事件ID<span class="sa" id="sev_EventID"></span></th>
    <th style="width:80px" onclick="sortEvt('Source')">来源<span class="sa" id="sev_Source"></span></th>
    <th style="width:110px">用户</th>
    <th style="width:300px">描述</th>
    <th style="width:200px">进程/目标</th>
    <th style="width:200px">风险原因</th>
  </tr></thead><tbody id="evtBody"></tbody></table></div>
</div>

<!-- Module View -->
<div class="view-panel" id="view_module">
  <div class="table-wrap"><table><thead><tr>
    <th style="width:55px" onclick="sortMod('Score')">评分<span class="sa" id="sm_Score"></span></th>
    <th style="width:60px">DLL劫持</th>
    <th style="width:130px" onclick="sortMod('ExeName')">宿主进程<span class="sa" id="sm_ExeName"></span></th>
    <th style="width:50px">PID</th>
    <th style="width:70px">进程签名</th>
    <th style="width:55px">可疑DLL</th>
    <th style="width:300px">宿主路径</th>
    <th style="width:300px">风险原因</th>
  </tr></thead><tbody id="modBody"></tbody></table></div>
</div>

<!-- YARA View -->
<div class="view-panel" id="view_yara">
  <div style="padding:20px;display:flex;flex-direction:column;gap:16px;height:100%;overflow:hidden">
    <!-- Control panel -->
    <div style="background:#16213e;border-radius:8px;padding:16px;flex-shrink:0">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
        <h3 style="color:#e94560;margin:0;white-space:nowrap">YARA 规则引擎</h3>
        <span id="yaraStatusBadge" style="padding:2px 10px;border-radius:10px;font-size:12px;background:#333;color:#888">未加载</span>
      </div>
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <!-- Single file upload -->
        <input type="file" id="yaraFileInput" accept=".yar,.yara,.rule" multiple style="display:none" onchange="handleYaraFileUpload(event)">
        <button class="btn btn-primary" onclick="document.getElementById('yaraFileInput').click()" id="yaraSelectFileBtn">选择规则文件</button>
        <!-- Folder upload -->
        <input type="file" id="yaraFolderInput" webkitdirectory style="display:none" onchange="handleYaraFolderUpload(event)">
        <button class="btn btn-primary" onclick="document.getElementById('yaraFolderInput').click()" id="yaraSelectFolderBtn">加载规则文件夹</button>
        <!-- Path input fallback -->
        <span style="color:#666" id="yaraOrSpan">或</span>
        <input id="yaraPathInput" placeholder="输入规则文件/目录路径" style="flex:1;min-width:200px;padding:5px 10px;background:#1a1a2e;border:1px solid #0f3460;color:#e0e0e0;border-radius:4px;font-size:13px">
        <button class="btn" onclick="loadYaraFromPath()" id="yaraLoadPathBtn">加载路径</button>
        <div class="separator"></div>
        <button class="btn btn-primary" id="yaraScanBtn" onclick="startYaraScan()" disabled>开始扫描全部对象</button>
      </div>
      <!-- Progress -->
      <div id="yaraProgressArea" style="display:none;margin-top:12px">
        <div style="display:flex;align-items:center;gap:10px">
          <div style="flex:1;height:6px;background:#0f3460;border-radius:3px;overflow:hidden">
            <div id="yaraProgressFill" style="height:100%;width:0%;background:linear-gradient(90deg,#e94560,#64b5f6);transition:width 0.3s"></div>
          </div>
          <span id="yaraProgressText" style="color:#888;font-size:12px;white-space:nowrap">0 / 0</span>
        </div>
      </div>
      <!-- Status message -->
      <div id="yaraMsg" style="margin-top:8px;font-size:12px;color:#888"></div>
    </div>
    <!-- Results table -->
    <div style="flex:1;overflow:auto;border-radius:8px;border:1px solid #0f3460">
      <table>
        <thead><tr>
          <th style="width:60px">风险</th>
          <th style="width:55px">评分</th>
          <th style="width:65px">YARA分</th>
          <th style="width:60px">状态</th>
          <th style="width:300px">路径</th>
          <th style="width:90px">位置</th>
          <th style="width:120px">签名者</th>
          <th style="width:250px">命中规则</th>
          <th style="width:200px">风险原因</th>
        </tr></thead>
        <tbody id="yaraResultsBody"></tbody>
      </table>
      <div id="yaraEmptyMsg" style="text-align:center;padding:40px;color:#666">
        加载 YARA 规则并扫描后，命中的对象将显示在此处
      </div>
    </div>
  </div>
</div>

<!-- Memory View -->
<div class="view-panel" id="view_memory">
  <div style="padding:20px;display:flex;flex-direction:column;gap:16px;height:100%;overflow:hidden">
    <!-- Control -->
    <div style="background:#16213e;border-radius:8px;padding:16px;flex-shrink:0">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
        <h3 style="color:#e94560;margin:0">内存异常分析</h3>
        <span style="color:#666;font-size:12px">针对指定 PID 进行内存布局深度检测</span>
      </div>
      <div style="display:flex;align-items:center;gap:10px">
        <label>PID:</label>
        <input id="memPidInput" type="number" placeholder="输入进程PID" style="width:120px;padding:5px 10px;background:#1a1a2e;border:1px solid #0f3460;color:#e0e0e0;border-radius:4px;font-size:13px">
        <button class="btn btn-primary" id="memAnalyzeBtn" onclick="startMemoryAnalysis()">开始分析</button>
        <button class="btn" onclick="clearMemoryResult()">清空结果</button>
        <span id="memStatus" style="color:#888;font-size:12px"></span>
      </div>
    </div>
    <!-- Process Info -->
    <div id="memProcInfo" style="display:none;background:#16213e;border-radius:8px;padding:12px;flex-shrink:0">
      <div style="display:flex;gap:20px;font-size:12px;flex-wrap:wrap" id="memProcFields"></div>
    </div>
    <!-- Risk Summary -->
    <div id="memRiskSummary" style="display:none;background:#16213e;border-radius:8px;padding:12px;flex-shrink:0">
      <div style="display:flex;align-items:center;gap:16px" id="memRiskFields"></div>
    </div>
    <!-- Results: two tables side by side -->
    <div style="flex:1;display:flex;gap:12px;overflow:hidden">
      <!-- Suspicious regions -->
      <div style="flex:1;overflow:auto;border-radius:8px;border:1px solid #0f3460">
        <div style="background:#0f3460;padding:6px 12px;font-size:12px;font-weight:bold;position:sticky;top:0">可疑内存区域 <span id="memSuspCount" style="color:#e94560"></span></div>
        <table><thead><tr>
          <th style="width:120px">基地址</th>
          <th style="width:80px">大小</th>
          <th style="width:70px">保护</th>
          <th style="width:70px">类型</th>
          <th style="width:200px">原因</th>
        </tr></thead><tbody id="memSuspBody"></tbody></table>
      </div>
      <!-- All executable regions -->
      <div style="flex:1;overflow:auto;border-radius:8px;border:1px solid #0f3460">
        <div style="background:#0f3460;padding:6px 12px;font-size:12px;font-weight:bold;position:sticky;top:0">所有可执行区域 <span id="memExecCount" style="color:#888"></span></div>
        <table><thead><tr>
          <th style="width:120px">基地址</th>
          <th style="width:80px">大小</th>
          <th style="width:70px">保护</th>
          <th style="width:70px">类型</th>
          <th style="width:50px">RWX</th>
        </tr></thead><tbody id="memExecBody"></tbody></table>
      </div>
    </div>
  </div>
</div>

<!-- IOC Monitor View -->
<div class="view-panel" id="view_iocmon">
  <div style="padding:20px;display:flex;flex-direction:column;gap:12px;height:100%;overflow:hidden">
    <!-- Control -->
    <div style="background:#16213e;border-radius:8px;padding:16px;flex-shrink:0">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
        <h3 style="color:#e94560;margin:0">IOC 动态命中监控</h3>
        <span id="iocMonBadge" style="padding:2px 10px;border-radius:10px;font-size:12px;background:#333;color:#888">未启动</span>
      </div>
      <div style="display:flex;gap:10px;margin-bottom:10px">
        <textarea id="iocInput" rows="3" placeholder="输入IOC（一行一个，支持IP和域名）&#10;示例:&#10;1.2.3.4&#10;evil.com&#10;1.2.3.4,high,intel_feed,C2 server" style="flex:1;background:#1a1a2e;border:1px solid #0f3460;color:#e0e0e0;border-radius:4px;padding:8px;font-size:12px;font-family:Consolas,monospace;resize:none"></textarea>
        <div style="display:flex;flex-direction:column;gap:6px">
          <button class="btn" onclick="loadIOCText()">加载IOC</button>
          <input type="file" id="iocFileInput" accept=".txt,.csv,.ioc" style="display:none" onchange="loadIOCFile(event)">
          <button class="btn" onclick="document.getElementById('iocFileInput').click()">导入文件</button>
          <div style="display:flex;align-items:center;gap:4px">
            <input id="iocDurInput" type="number" value="10" min="1" max="1440" style="width:50px;padding:4px;background:#1a1a2e;border:1px solid #0f3460;color:#e0e0e0;border-radius:4px;font-size:12px;text-align:center">
            <select id="iocDurUnit" style="padding:4px;background:#1a1a2e;border:1px solid #0f3460;color:#e0e0e0;border-radius:4px;font-size:12px">
              <option value="60">分钟</option>
              <option value="3600">小时</option>
              <option value="1">秒</option>
            </select>
          </div>
          <button class="btn btn-primary" id="iocStartBtn" onclick="startIOCMonitor()">开始监控</button>
          <button class="btn" onclick="stopIOCMonitor()">停止</button>
        </div>
      </div>
      <!-- Status -->
      <div id="iocMonStatus" style="display:flex;gap:16px;font-size:12px;color:#888">
        <span>IOC: <strong id="iocMonCount">0</strong></span>
        <span>已运行: <strong id="iocMonElapsed">-</strong></span>
        <span>轮询: <strong id="iocMonCycles">0</strong></span>
        <span style="color:#e94560">命中: <strong id="iocMonHits">0</strong></span>
        <span style="color:#ff9100">命中进程: <strong id="iocMonPIDs">0</strong></span>
      </div>
    </div>
    <!-- Hits table -->
    <div style="flex:1;overflow:auto;border-radius:8px;border:1px solid #0f3460">
      <table><thead><tr>
        <th style="width:80px">时间</th>
        <th style="width:130px">IOC</th>
        <th style="width:50px">类型</th>
        <th style="width:50px">PID</th>
        <th style="width:110px">进程</th>
        <th style="width:200px">路径</th>
        <th style="width:100px">远程IP</th>
        <th style="width:50px">端口</th>
        <th style="width:60px">置信度</th>
        <th style="width:70px">用户</th>
        <th style="width:80px">备注</th>
      </tr></thead><tbody id="iocHitBody"></tbody></table>
      <div id="iocEmptyMsg" style="text-align:center;padding:40px;color:#666">加载IOC并开始监控后，命中事件将显示在此处</div>
    </div>
  </div>
</div>

<!-- AI Analysis View -->
<div class="view-panel" id="view_ai">
  <div style="display:flex;flex-direction:column;height:100%;overflow:hidden">
    <!-- Top bar: config -->
    <div style="background:#16213e;padding:10px 16px;flex-shrink:0;border-bottom:1px solid #0f3460">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <h3 style="color:#e94560;margin:0;white-space:nowrap;font-size:14px">MiniMax AI</h3>
        <span id="aiStatusBadge" style="padding:2px 8px;border-radius:10px;font-size:11px;background:#333;color:#888">就绪</span>
        <div class="separator"></div>
        <label style="white-space:nowrap;font-size:12px">API Key:</label>
        <input id="aiApiKey" type="password" placeholder="输入MiniMax API Key" style="width:220px;padding:4px 8px;background:#1a1a2e;border:1px solid #0f3460;color:#e0e0e0;border-radius:4px;font-size:12px;font-family:Consolas,monospace">
        <label style="white-space:nowrap;font-size:12px">模型:</label>
        <select id="aiModel" style="padding:4px 6px;background:#1a1a2e;border:1px solid #0f3460;color:#e0e0e0;border-radius:4px;font-size:12px">
          <option value="MiniMax-M2.5">M2.5</option>
          <option value="MiniMax-M2.5-highspeed">M2.5 高速</option>
          <option value="MiniMax-M2.7" selected>M2.7</option>
          <option value="MiniMax-M2.7-highspeed">M2.7 高速</option>
        </select>
        <label style="font-size:11px;color:#666;cursor:pointer"><input type="checkbox" id="aiSaveKey" onchange="toggleAISaveKey()" style="margin-right:3px">记住Key</label>
        <div style="flex:1"></div>
        <span id="aiTokenCounter" style="font-size:11px;color:#555"></span>
        <button class="btn" onclick="clearAIChat()" style="padding:4px 10px;font-size:12px">清空对话</button>
      </div>
    </div>
    <!-- Chat messages area -->
    <div id="aiChatArea" style="flex:1;overflow-y:auto;padding:16px 20px;display:flex;flex-direction:column;gap:12px">
      <div id="aiWelcome" style="text-align:center;padding:40px 20px;color:#666">
        <div style="font-size:16px;margin-bottom:12px;color:#e94560">MiniMax AI 安全分析助手</div>
        <div style="margin-bottom:8px">您可以直接输入问题，或点击下方「发送扫描数据」将扫描结果发送给AI分析</div>
        <div style="font-size:11px;color:#555">支持多轮对话 | M2.5 / M2.7 模型 | 申请Key: platform.minimax.io</div>
      </div>
    </div>
    <!-- Input area -->
    <div style="background:#16213e;padding:12px 16px;flex-shrink:0;border-top:1px solid #0f3460">
      <div style="display:flex;gap:8px;margin-bottom:8px">
        <button class="btn" onclick="sendScanData()" style="padding:4px 10px;font-size:12px">发送扫描数据</button>
        <button class="btn" onclick="sendScanDataBrief()" style="padding:4px 10px;font-size:12px">发送摘要</button>
      </div>
      <div style="display:flex;gap:8px;align-items:flex-end">
        <textarea id="aiInput" rows="2" placeholder="输入消息... (Ctrl+Enter 发送)" style="flex:1;padding:8px 10px;background:#1a1a2e;border:1px solid #0f3460;color:#e0e0e0;border-radius:6px;font-size:13px;font-family:inherit;resize:none;line-height:1.5" onkeydown="aiInputKeydown(event)"></textarea>
        <button class="btn btn-primary" id="aiSendBtn" onclick="sendAIMessage()" style="padding:8px 20px;height:fit-content">发送</button>
      </div>
    </div>
  </div>
</div>

<div class="status-bar">
  <div id="statusText">就绪 - 点击「开始扫描」</div>
  <div class="stats" id="statsText"></div>
</div>

<!-- Context Menu -->
<div class="context-menu" id="ctxMenu">
  <div class="item" onclick="copySHA256()" id="ctx_sha">复制 SHA256</div>
  <div class="item" onclick="copyMD5()" id="ctx_md5">复制 MD5</div>
  <div class="divider"></div>
  <div class="item" onclick="openVT()" id="ctx_vt">在 VirusTotal 中查询</div>
  <div class="item" onclick="copyVTLink()" id="ctx_vtlink">复制 VT 链接</div>
  <div class="divider"></div>
  <div class="item" onclick="openDir()" id="ctx_dir">打开所在目录</div>
  <div class="item" onclick="showDetail()" id="ctx_detail">查看详情</div>
  <div class="divider"></div>
  <div class="item" onclick="filterParent()" id="ctx_parent">按父进程筛选</div>
  <div class="item" onclick="copyCmdLine()" id="ctx_cmd">复制命令行</div>
  <div class="divider"></div>
  <div class="item" onclick="yaraScan()" id="ctx_yara">YARA 扫描</div>
</div>

<!-- Detail Modal -->
<div class="modal-overlay" id="modalOverlay" onclick="closeModal(event)">
  <div class="modal">
    <div class="modal-header">
      <h2 id="modalTitle">详情</h2>
      <span class="close-btn" onclick="document.getElementById('modalOverlay').classList.remove('show')">&times;</span>
    </div>
    <div class="modal-body" id="modalBody"></div>
  </div>
</div>

<script>
// --- i18n System ---
let curLang = localStorage.getItem('procir_lang') || 'zh';

const I18N = {
zh: {
  // Toolbar
  startScan:'开始扫描', scanning:'扫描中...', copySHA:'复制SHA256', queryVT:'查询VT', copyVTLink:'复制VT链接',
  openDir:'打开目录', detail:'详情', exportCSV:'导出CSV', checkUpdate:'检查更新',
  updateChecking:'检查中...', updateLatest:'当前已是最新版本', updateAvail:'发现新版本 v%s，点击下载',
  updateFail:'检查更新失败',
  // Tabs
  tab_process:'活跃进程', tab_trigger:'触发器', tab_execobj:'执行对象', tab_forensic:'历史取证',
  tab_timeline:'时间线', tab_chain:'行为链', tab_ioc:'IOC', tab_event:'事件日志',
  tab_module:'模块分析', tab_yara:'YARA', tab_memory:'内存分析', tab_iocmon:'IOC监控', tab_ai:'AI分析',
  // Filter
  filter:'筛选：', risk:'风险：', all:'全部', critical:'严重', high:'高危', medium:'中危', suspicious:'可疑', low:'低危',
  filterPH:'搜索进程名、路径、SHA256、签发者、命令行...',
  // Process columns
  colRisk:'风险', colScore:'评分', colName:'进程名', colPID:'PID', colParent:'父进程', colPath:'路径',
  colCmd:'命令行', colSHA:'SHA256', colSigner:'签名者', colNet:'网络', colPersist:'持久化', colReason:'风险原因',
  // Trigger columns
  colType:'类型', colTrigName:'名称', colDetail:'详情',
  // Exec columns
  colStatus:'状态', colLocation:'位置', colTriggers:'触发器', colSource:'来源',
  // Forensic columns
  colTime:'时间', colFileType:'文件类型',
  // Timeline columns
  colObject:'对象',
  // Chain columns
  colChain:'攻击链', colEvidence:'证据', colInvolved:'涉及对象',
  // IOC columns
  colValue:'值', colSrcObj:'来源对象', colContext:'上下文',
  // Event columns
  colEventID:'事件ID', colUser:'用户', colDesc:'描述', colProcTarget:'进程/目标',
  // Module columns
  colDLLHijack:'DLL劫持', colHostProc:'宿主进程', colProcSign:'进程签名', colSuspDLL:'可疑DLL', colHostPath:'宿主路径',
  // Context menu
  ctx_sha:'复制 SHA256', ctx_md5:'复制 MD5', ctx_vt:'在 VirusTotal 中查询', ctx_vtlink:'复制 VT 链接',
  ctx_dir:'打开所在目录', ctx_detail:'查看详情', ctx_parent:'按父进程筛选', ctx_cmd:'复制命令行', ctx_yara:'YARA 扫描',
  // Status
  ready:'就绪 - 点击「开始扫描」', scanMsg:'正在扫描进程/触发器/历史痕迹，请稍候...', scanErr:'扫描出错: ',
  showN:'显示 ', ofN:' / ', records:' 条记录',
  copiedSHA:'已复制 SHA256', copiedMD5:'已复制 MD5', copiedVT:'已复制VT链接', copiedCmd:'已复制命令行',
  dirOpened:'已打开目录', dirFail:'打开失败: ', error:'出错: ',
  // Risk levels (for display)
  rl:{ Critical:'严重', High:'高危', Medium:'中危', Suspicious:'可疑', Low:'低危' },
  tt:{ RunKey:'注册表自启', Startup:'启动文件夹', Task:'计划任务', Service:'系统服务', WMI:'WMI订阅', IFEO:'IFEO劫持', Winlogon:'Winlogon' },
  fs:{ Prefetch:'Prefetch', RecentFile:'最近文件', EventLog:'事件日志', Module:'加载模块' },
  tle:{ execution:'执行', trigger:'触发器', file:'文件', network:'网络', module:'模块', eventlog:'日志' },
  iot:{ ip:'IP', domain:'域名', url:'URL', base64:'Base64', filepath:'路径' },
  // Render
  localOnly:'仅本地', items:'项', running:'运行中', notRunning:'未运行', yes:'是', no:'否',
  // Stats
  statCrit:'严重:', statHigh:'高危:', statMed:'中危:', statSusp:'可疑:', statLow:'低危:',
  statProc:'进程:', statTrig:'触发器:', statEvt:'事件:', statChain:'行为链:', statIOC:'IOC:',
  // YARA
  yaraEngine:'YARA 规则引擎', yaraNotLoaded:'未加载', yaraSelectFile:'选择规则文件', yaraSelectFolder:'加载规则文件夹', yaraOr:'或',
  yaraPathPH:'输入规则文件/目录路径', yaraLoadPath:'加载路径', yaraScanAll:'开始扫描全部对象',
  yaraEmpty:'加载 YARA 规则并扫描后，命中的对象将显示在此处', yaraScore:'YARA分', yaraRules:'命中规则',
  yaraLoading:'加载中...', yaraRulesLoaded:'条规则已加载', yaraHits:'个命中',
  yaraNoRuleInFolder:'文件夹中未找到 .yar/.yara/.rule 文件', yaraFolderUploading:'正在上传 %d 个规则文件...',
  yaraLoadFail:'加载失败', yaraUploadErr:'上传出错: ', yaraFolderDone:'已从文件夹加载 %d 个规则文件，可以开始扫描',
  yaraFilesDone:'已加载 %d 个规则文件，可以开始扫描', yaraPathLoaded:'从 %s 加载成功',
  yaraScanRunning:'正在扫描所有对象...',
  yaraScanDone:'扫描完成！', yaraNoMatch:'未发现命中', yaraObjMatch:'个对象命中 YARA 规则',
  // Memory
  memTitle:'内存异常分析', memDesc:'针对指定 PID 进行内存布局深度检测', memPIDPH:'输入进程PID',
  memStart:'开始分析', memClear:'清空结果', memAnalyzing:'分析中...', memAnalyzingPID:'正在分析PID ',
  memLayout:' 的内存布局...', memDone:'分析完成', memErr:'分析出错: ', memEnterPID:'请输入PID', memInvalidPID:'无效的PID',
  memSusp:'可疑内存区域', memAllExec:'所有可执行区域', memBase:'基地址', memSize:'大小',
  memProtect:'保护', memType:'类型', memReason:'原因',
  memProc:'进程:', memPath:'路径:', memUser:'用户:', memSign:'签名:',
  memPrivExec:'私有可执行:', memNoImgExec:'非映像可执行:',
  memHighRisk:'高危', memMedRisk:'中危', memSuspRisk:'可疑', memLowRisk:'低危',
  // IOC Monitor
  iocTitle:'IOC 动态命中监控', iocNotStarted:'未启动', iocInputPH:'输入IOC（一行一个，支持IP和域名）',
  iocLoad:'加载IOC', iocImport:'导入文件', iocMinutes:'分钟', iocHours:'小时', iocSeconds:'秒',
  iocStart:'开始监控', iocStop:'停止', iocLoaded:'已加载 ', iocCount:'个IOC',
  iocElapsed:'已运行:', iocCycles:'轮询:', iocHits:'命中:', iocHitProcs:'命中进程:',
  iocEmpty:'加载IOC并开始监控后，命中事件将显示在此处',
  iocProcess:'进程', iocRemoteIP:'远程IP', iocPort:'端口', iocConfidence:'置信度', iocNotes:'备注',
  iocMonitoring:'监控中', iocStopped:'已停止', iocCompleted:'已完成', iocNoIOC:'未加载IOC',
  iocNoValid:'无有效IOC', iocEnterIOC:'请输入IOC', iocEnterFirst:'请先在左侧输入框中输入IOC（IP或域名）',
  // AI
  aiTitle:'MiniMax AI', aiReady:'就绪', aiKeyPH:'输入MiniMax API Key', aiModel:'模型:',
  aiRememberKey:'记住Key', aiClearChat:'清空对话',
  aiWelcomeTitle:'MiniMax AI 安全分析助手',
  aiWelcomeMsg:'您可以直接输入问题，或点击下方「发送扫描数据」将扫描结果发送给AI分析',
  aiWelcomeHint:'支持多轮对话 | M2.5 / M2.7 模型 | 申请Key: platform.minimax.io',
  aiSendData:'发送扫描数据', aiSendBrief:'发送摘要', aiInputPH:'输入消息... (Ctrl+Enter 发送)', aiSend:'发送',
  aiThinking:'思考中...', aiRequesting:'请求中', aiFailed:'失败', aiError:'出错', aiNoReturn:'(无返回)',
  aiRound:'本轮:', aiTotal:'累计:', aiNeedKey:'请输入MiniMax API Key', aiNeedScan:'请先执行系统扫描',
  // Detail modals
  dtlDetail:'详情', dtlProcInfo:'进程信息', dtlFileInfo:'文件信息', dtlSignInfo:'签名信息',
  dtlContextAnalysis:'上下文分析', dtlNetConn:'网络连接', dtlRiskAssess:'风险评估',
  dtlProcName:'进程名', dtlPID:'PID', dtlParent:'父进程', dtlPath:'路径', dtlCmd:'命令行',
  dtlUser:'用户', dtlStartTime:'启动时间', dtlSHA256:'SHA256', dtlMD5:'MD5',
  dtlFileSize:'文件大小', dtlModTime:'修改时间', dtlSigned:'签名', dtlValid:'有效',
  dtlSigner:'签发者', dtlCompany:'公司', dtlProduct:'产品', dtlOrigName:'原始文件名',
  dtlLOLBin:'LOLBin', dtlPathAbnormal:'路径异常', dtlMasquerade:'文件名伪装',
  dtlAbnormalParent:'异常父进程链', dtlHasNetwork:'有网络活动', dtlRemoteIP:'远程IP',
  dtlPublicIP:'公网连接', dtlScore:'评分', dtlLevel:'等级', dtlReasons:'风险原因',
  dtlBytes:'字节', dtlVTView:'在 VirusTotal 中查看',
  dtlBasicInfo:'基本信息', dtlType:'类型', dtlExists:'存在', dtlSources:'来源',
  dtlExecScore:'进程评分', dtlTrigScore:'触发器评分', dtlForeScore:'取证评分',
  dtlYaraScore:'YARA评分', dtlEvtScore:'事件评分', dtlModScore:'模块评分',
  dtlSynergy:'组合加权', dtlWhiteReduce:'白特征抵消', dtlFinalScore:'最终评分',
  dtlScoreCompose:'评分构成', dtlNetInfo:'网络',
  dtlHostProc:'宿主进程', dtlTotalMod:'总模块数', dtlSuspMod:'可疑模块数',
  dtlDLLDetect:'DLL劫持检测', dtlDLLHijack:'DLL劫持', dtlDLLDetected:'检测到DLL劫持',
  dtlDLLScore:'DLL劫持评分', dtlSuspModules:'可疑模块', dtlDLLPath:'DLL路径',
  dtlDLLModScore:'DLL评分', dtlUnsigned:'未签名', dtlSysDLLName:'系统DLL名',
  dtlUserDir:'用户目录', dtlTempDir:'临时目录', dtlSameDirLoad:'同目录加载', dtlTags:'标记', dtlReason:'原因',
  dtlTaskInfo:'计划任务详情', dtlServiceInfo:'服务详情', dtlWMIInfo:'WMI详情',
  dtlAuthor:'作者', dtlTrigType:'触发方式', dtlRunAs:'运行账户', dtlHidden:'隐藏',
  dtlInterval:'执行间隔', dtlLastRun:'上次运行', dtlNextRun:'下次运行',
  dtlStartType:'启动类型', dtlSvcAccount:'运行账户', dtlSvcState:'状态',
  dtlWMIFilter:'过滤器', dtlWMIQuery:'过滤查询', dtlWMIConsumer:'消费者', dtlWMICmd:'消费者命令',
  dtlEvtInfo:'事件信息', dtlEvtID:'事件ID', dtlComputer:'计算机',
  dtlProcPath:'进程路径', dtlParentProc:'父进程',
  dtlTargetInfo:'目标信息', dtlTargetPath:'目标路径', dtlSvcName:'服务名', dtlTaskName:'任务名',
  dtlNetLogin:'网络/登录', dtlIPAddr:'IP地址', dtlPort:'端口', dtlDomain:'域名', dtlLogonType:'登录类型',
  dtlLinkedObj:'关联对象', dtlLinkedExecObj:'关联ExecutionObject',
  dtlPrefetchInfo:'Prefetch信息', dtlExeName:'可执行文件名', dtlLastRunTime:'最后执行时间',
  dtlFirstSeen:'首次发现', dtlEvtLog:'事件日志', dtlEvtSource:'事件源',
  dtlModInfo:'模块信息', dtlModPath:'模块路径',
  // AI scan data
  aiDataIntro:'以下是ProcIR扫描结果，请进行全面安全分析：',
  aiOverall:'总体统计', aiHighProc:'高风险进程', aiMedProc:'中危进程', aiSuspTrig:'可疑触发器',
  aiBehavior:'行为链', aiHighExec:'高危执行对象', aiSuspMod:'可疑模块/DLL劫持',
  aiSuspFore:'可疑历史取证', aiHighEvt:'高危事件',
  aiSigned:'签名:', aiUnsigned:'[未签名]', aiPublic:'[公网]', aiRunning:'[运行中]', aiNotRunning:'[未运行]',
  aiHostUnsigned:'[宿主未签名]', aiHasNet:'[有网络]', aiYaraHit:'[YARA命中]', aiDLLHijack:'[DLL劫持]',
  aiScoreBreak:'评分构成:', aiExec:'执行', aiTrig:'触发', aiForensic:'取证', aiEvent:'事件', aiModule:'模块',
  aiReasonLabel:'原因:', aiSuspDLL:'可疑DLL:', aiTime:'时间:',
  aiBriefIntro:'扫描摘要', aiBriefHighProc:'高风险进程:', aiBriefQuestion:'请分析这些结果，有什么安全问题？',
  aiProcess:'进程:', aiTrigger:'触发器:', aiChain:'行为链:',
},
en: {
  startScan:'Start Scan', scanning:'Scanning...', copySHA:'Copy SHA256', queryVT:'Query VT', copyVTLink:'Copy VT Link',
  openDir:'Open Dir', detail:'Details', exportCSV:'Export CSV', checkUpdate:'Check Update',
  updateChecking:'Checking...', updateLatest:'You are on the latest version', updateAvail:'New version v%s available, click to download',
  updateFail:'Update check failed',
  tab_process:'Processes', tab_trigger:'Triggers', tab_execobj:'Exec Objects', tab_forensic:'Forensics',
  tab_timeline:'Timeline', tab_chain:'Attack Chains', tab_ioc:'IOC', tab_event:'Events',
  tab_module:'Modules', tab_yara:'YARA', tab_memory:'Memory', tab_iocmon:'IOC Monitor', tab_ai:'AI Analysis',
  filter:'Filter:', risk:'Risk:', all:'All', critical:'Critical', high:'High', medium:'Medium', suspicious:'Suspicious', low:'Low',
  filterPH:'Search process name, path, SHA256, signer, command line...',
  colRisk:'Risk', colScore:'Score', colName:'Process', colPID:'PID', colParent:'Parent', colPath:'Path',
  colCmd:'Command Line', colSHA:'SHA256', colSigner:'Signer', colNet:'Network', colPersist:'Persist', colReason:'Risk Reason',
  colType:'Type', colTrigName:'Name', colDetail:'Details',
  colStatus:'Status', colLocation:'Location', colTriggers:'Triggers', colSource:'Source',
  colTime:'Time', colFileType:'File Type',
  colObject:'Object',
  colChain:'Attack Chain', colEvidence:'Evidence', colInvolved:'Objects',
  colValue:'Value', colSrcObj:'Source Object', colContext:'Context',
  colEventID:'Event ID', colUser:'User', colDesc:'Description', colProcTarget:'Process/Target',
  colDLLHijack:'DLL Hijack', colHostProc:'Host Process', colProcSign:'Proc Signed', colSuspDLL:'Susp DLL', colHostPath:'Host Path',
  ctx_sha:'Copy SHA256', ctx_md5:'Copy MD5', ctx_vt:'Query on VirusTotal', ctx_vtlink:'Copy VT Link',
  ctx_dir:'Open Directory', ctx_detail:'View Details', ctx_parent:'Filter by Parent', ctx_cmd:'Copy Command Line', ctx_yara:'YARA Scan',
  ready:'Ready - Click "Start Scan"', scanMsg:'Scanning processes/triggers/forensics, please wait...', scanErr:'Scan error: ',
  showN:'Showing ', ofN:' / ', records:' records',
  copiedSHA:'SHA256 copied', copiedMD5:'MD5 copied', copiedVT:'VT link copied', copiedCmd:'Command line copied',
  dirOpened:'Directory opened', dirFail:'Open failed: ', error:'Error: ',
  rl:{ Critical:'Critical', High:'High', Medium:'Medium', Suspicious:'Suspicious', Low:'Low' },
  tt:{ RunKey:'Run Key', Startup:'Startup Folder', Task:'Sched Task', Service:'Service', WMI:'WMI Sub', IFEO:'IFEO Hijack', Winlogon:'Winlogon' },
  fs:{ Prefetch:'Prefetch', RecentFile:'Recent File', EventLog:'Event Log', Module:'Module' },
  tle:{ execution:'Exec', trigger:'Trigger', file:'File', network:'Network', module:'Module', eventlog:'Log' },
  iot:{ ip:'IP', domain:'Domain', url:'URL', base64:'Base64', filepath:'Path' },
  localOnly:'local only', items:'items', running:'Running', notRunning:'Stopped', yes:'Yes', no:'No',
  statCrit:'Crit:', statHigh:'High:', statMed:'Med:', statSusp:'Susp:', statLow:'Low:',
  statProc:'Proc:', statTrig:'Trig:', statEvt:'Events:', statChain:'Chains:', statIOC:'IOC:',
  yaraEngine:'YARA Rule Engine', yaraNotLoaded:'Not Loaded', yaraSelectFile:'Select Rule File', yaraSelectFolder:'Load Rule Folder', yaraOr:'or',
  yaraPathPH:'Enter rule file/directory path', yaraLoadPath:'Load Path', yaraScanAll:'Scan All Objects',
  yaraEmpty:'Load YARA rules and scan to see matched objects here', yaraScore:'YARA', yaraRules:'Matched Rules',
  yaraLoading:'Loading...', yaraRulesLoaded:' rules loaded', yaraHits:' hits',
  yaraNoRuleInFolder:'No .yar/.yara/.rule files found in folder', yaraFolderUploading:'Uploading %d rule files...',
  yaraLoadFail:'Load failed', yaraUploadErr:'Upload error: ', yaraFolderDone:'Loaded %d rule files from folder, ready to scan',
  yaraFilesDone:'Loaded %d rule files, ready to scan', yaraPathLoaded:'Loaded from %s',
  yaraScanRunning:'Scanning all objects...',
  yaraScanDone:'Scan complete! ', yaraNoMatch:'No matches found', yaraObjMatch:' objects matched YARA rules',
  memTitle:'Memory Anomaly Analysis', memDesc:'Deep memory layout detection for specified PID', memPIDPH:'Enter PID',
  memStart:'Analyze', memClear:'Clear', memAnalyzing:'Analyzing...', memAnalyzingPID:'Analyzing PID ',
  memLayout:' memory layout...', memDone:'Analysis complete', memErr:'Analysis error: ', memEnterPID:'Enter PID', memInvalidPID:'Invalid PID',
  memSusp:'Suspicious Memory Regions', memAllExec:'All Executable Regions', memBase:'Base Address', memSize:'Size',
  memProtect:'Protection', memType:'Type', memReason:'Reason',
  memProc:'Process:', memPath:'Path:', memUser:'User:', memSign:'Signature:',
  memPrivExec:'Private Exec:', memNoImgExec:'No-Image Exec:',
  memHighRisk:'High', memMedRisk:'Medium', memSuspRisk:'Suspicious', memLowRisk:'Low',
  iocTitle:'IOC Dynamic Monitor', iocNotStarted:'Not Started', iocInputPH:'Enter IOC (one per line, IP or domain)',
  iocLoad:'Load IOC', iocImport:'Import File', iocMinutes:'Minutes', iocHours:'Hours', iocSeconds:'Seconds',
  iocStart:'Start Monitor', iocStop:'Stop', iocLoaded:'Loaded ', iocCount:' IOCs',
  iocElapsed:'Elapsed:', iocCycles:'Cycles:', iocHits:'Hits:', iocHitProcs:'Hit Procs:',
  iocEmpty:'Load IOC and start monitoring to see hit events here',
  iocProcess:'Process', iocRemoteIP:'Remote IP', iocPort:'Port', iocConfidence:'Confidence', iocNotes:'Notes',
  iocMonitoring:'Monitoring', iocStopped:'Stopped', iocCompleted:'Completed', iocNoIOC:'No IOC loaded',
  iocNoValid:'No valid IOC', iocEnterIOC:'Please enter IOC', iocEnterFirst:'Please enter IOC (IP or domain) in the input box first',
  aiTitle:'Claude AI', aiReady:'Ready', aiKeyPH:'Enter Anthropic API Key', aiModel:'Model:',
  aiRememberKey:'Save Key', aiClearChat:'Clear Chat',
  aiWelcomeTitle:'Claude AI Security Analyst',
  aiWelcomeMsg:'Ask questions directly, or click "Send Scan Data" to send scan results to AI for analysis',
  aiWelcomeHint:'Multi-turn dialogue | Claude Sonnet / Opus | Get Key: console.anthropic.com',
  aiSendData:'Send Scan Data', aiSendBrief:'Send Summary', aiInputPH:'Enter message... (Ctrl+Enter to send)', aiSend:'Send',
  aiThinking:'Thinking...', aiRequesting:'Requesting', aiFailed:'Failed', aiError:'Error', aiNoReturn:'(No response)',
  aiRound:'Round:', aiTotal:'Total:', aiNeedKey:'Please enter Anthropic API Key', aiNeedScan:'Please run a scan first',
  dtlDetail:'Details', dtlProcInfo:'Process Information', dtlFileInfo:'File Information', dtlSignInfo:'Signature',
  dtlContextAnalysis:'Context Analysis', dtlNetConn:'Network Connections', dtlRiskAssess:'Risk Assessment',
  dtlProcName:'Process', dtlPID:'PID', dtlParent:'Parent', dtlPath:'Path', dtlCmd:'Command Line',
  dtlUser:'User', dtlStartTime:'Start Time', dtlSHA256:'SHA256', dtlMD5:'MD5',
  dtlFileSize:'File Size', dtlModTime:'Modified', dtlSigned:'Signed', dtlValid:'Valid',
  dtlSigner:'Signer', dtlCompany:'Company', dtlProduct:'Product', dtlOrigName:'Original Name',
  dtlLOLBin:'LOLBin', dtlPathAbnormal:'Path Abnormal', dtlMasquerade:'Name Masquerade',
  dtlAbnormalParent:'Abnormal Parent Chain', dtlHasNetwork:'Network Activity', dtlRemoteIP:'Remote IP',
  dtlPublicIP:'Public IP', dtlScore:'Score', dtlLevel:'Level', dtlReasons:'Risk Reasons',
  dtlBytes:'bytes', dtlVTView:'View on VirusTotal',
  dtlBasicInfo:'Basic Info', dtlType:'Type', dtlExists:'Exists', dtlSources:'Sources',
  dtlExecScore:'Execution Score', dtlTrigScore:'Trigger Score', dtlForeScore:'Forensic Score',
  dtlYaraScore:'YARA Score', dtlEvtScore:'Event Score', dtlModScore:'Module Score',
  dtlSynergy:'Synergy Bonus', dtlWhiteReduce:'White Reduction', dtlFinalScore:'Final Score',
  dtlScoreCompose:'Score Composition', dtlNetInfo:'Network',
  dtlHostProc:'Host Process', dtlTotalMod:'Total Modules', dtlSuspMod:'Suspicious Modules',
  dtlDLLDetect:'DLL Hijack Detection', dtlDLLHijack:'DLL Hijack', dtlDLLDetected:'DLL Hijack Detected',
  dtlDLLScore:'DLL Hijack Score', dtlSuspModules:'Suspicious Modules', dtlDLLPath:'DLL Path',
  dtlDLLModScore:'DLL Score', dtlUnsigned:'Unsigned', dtlSysDLLName:'System DLL Name',
  dtlUserDir:'User Directory', dtlTempDir:'Temp Directory', dtlSameDirLoad:'Same Dir Load', dtlTags:'Tags', dtlReason:'Reason',
  dtlTaskInfo:'Scheduled Task', dtlServiceInfo:'Service Details', dtlWMIInfo:'WMI Details',
  dtlAuthor:'Author', dtlTrigType:'Trigger Type', dtlRunAs:'Run As', dtlHidden:'Hidden',
  dtlInterval:'Interval', dtlLastRun:'Last Run', dtlNextRun:'Next Run',
  dtlStartType:'Start Type', dtlSvcAccount:'Account', dtlSvcState:'State',
  dtlWMIFilter:'Filter', dtlWMIQuery:'Filter Query', dtlWMIConsumer:'Consumer', dtlWMICmd:'Consumer Command',
  dtlEvtInfo:'Event Information', dtlEvtID:'Event ID', dtlComputer:'Computer',
  dtlProcPath:'Process Path', dtlParentProc:'Parent Process',
  dtlTargetInfo:'Target Info', dtlTargetPath:'Target Path', dtlSvcName:'Service Name', dtlTaskName:'Task Name',
  dtlNetLogin:'Network/Logon', dtlIPAddr:'IP Address', dtlPort:'Port', dtlDomain:'Domain', dtlLogonType:'Logon Type',
  dtlLinkedObj:'Related Objects', dtlLinkedExecObj:'Related ExecutionObject',
  dtlPrefetchInfo:'Prefetch Info', dtlExeName:'Executable', dtlLastRunTime:'Last Run Time',
  dtlFirstSeen:'First Seen', dtlEvtLog:'Event Log', dtlEvtSource:'Event Source',
  dtlModInfo:'Module Info', dtlModPath:'Module Path',
  aiDataIntro:'Below is the ProcIR scan result. Please conduct a comprehensive security analysis:',
  aiOverall:'Overall Statistics', aiHighProc:'High-Risk Processes', aiMedProc:'Medium-Risk Processes', aiSuspTrig:'Suspicious Triggers',
  aiBehavior:'Behavior Chains', aiHighExec:'High-Risk Execution Objects', aiSuspMod:'Suspicious Modules/DLL Hijack',
  aiSuspFore:'Suspicious Forensics', aiHighEvt:'High-Risk Events',
  aiSigned:'Signed:', aiUnsigned:'[Unsigned]', aiPublic:'[Public IP]', aiRunning:'[Running]', aiNotRunning:'[Not Running]',
  aiHostUnsigned:'[Host Unsigned]', aiHasNet:'[Network]', aiYaraHit:'[YARA Hit]', aiDLLHijack:'[DLL Hijack]',
  aiScoreBreak:'Scores:', aiExec:'Exec', aiTrig:'Trig', aiForensic:'Fore', aiEvent:'Event', aiModule:'Module',
  aiReasonLabel:'Reason:', aiSuspDLL:'Susp DLL:', aiTime:'Time:',
  aiBriefIntro:'Scan Summary', aiBriefHighProc:'High-Risk Processes:', aiBriefQuestion:'Please analyze these results. What security issues exist?',
  aiProcess:'Proc:', aiTrigger:'Trig:', aiChain:'Chains:',
}
};

function t(k) { return (I18N[curLang]||I18N.zh)[k] || I18N.zh[k] || k; }

// Dynamic translation maps (updated on language switch)
let RL, TT, FS, TLE, IOT;
function updateLangMaps() {
  const L = I18N[curLang] || I18N.zh;
  RL = L.rl; TT = L.tt; FS = L.fs; TLE = L.tle; IOT = L.iot;
}
updateLangMaps();

function setLang(lang) {
  curLang = lang;
  localStorage.setItem('procir_lang', lang);
  updateLangMaps();
  // Notify backend
  fetch('/api/lang', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({lang:lang})}).catch(()=>{});
  const L = I18N[lang];

  // Page title
  document.title = lang==='en' ? 'ProcIR - Windows Incident Response Tool' : 'ProcIR - Windows 应急响应进程排查工具';

  // Toggle button
  document.getElementById('langToggle').textContent = lang==='en' ? '中文' : 'EN';

  // Toolbar
  if (!document.getElementById('scanBtn').disabled) document.getElementById('scanBtn').textContent = L.startScan;
  document.getElementById('btnCopySHA').textContent = L.copySHA;
  document.getElementById('btnVT').textContent = L.queryVT;
  document.getElementById('btnCopyVT').textContent = L.copyVTLink;
  document.getElementById('btnOpenDir').textContent = L.openDir;
  document.getElementById('btnDetail').textContent = L.detail;
  document.getElementById('btnExport').textContent = L.exportCSV;
  document.getElementById('btnUpdate').textContent = L.checkUpdate;

  // Tabs (preserve badges)
  const tabs = ['process','trigger','execobj','forensic','timeline','chain','ioc','event','module','yara','memory','iocmon','ai'];
  tabs.forEach(id => {
    const el = document.getElementById('tab_'+id);
    const badge = el.querySelector('.badge');
    const badgeHTML = badge ? ' ' + badge.outerHTML : '';
    el.innerHTML = L['tab_'+id] + badgeHTML;
  });

  // Filter bar
  document.getElementById('lbl_filter').textContent = L.filter;
  document.getElementById('lbl_risk').textContent = L.risk;
  document.getElementById('filterInput').placeholder = L.filterPH;
  document.getElementById('opt_all').textContent = L.all;
  document.getElementById('opt_crit').textContent = L.critical;
  document.getElementById('opt_high').textContent = L.high;
  document.getElementById('opt_med').textContent = L.medium;
  document.getElementById('opt_susp').textContent = L.suspicious;
  document.getElementById('opt_low').textContent = L.low;

  // Column headers - Process
  const procTH = document.querySelectorAll('#view_process thead th');
  if (procTH.length>=12) {
    [L.colRisk,L.colScore,L.colName,'PID',L.colParent,L.colPath,L.colCmd,L.colSHA,L.colSigner,L.colNet,L.colPersist,L.colReason].forEach((txt,i) => {
      const sa = procTH[i].querySelector('.sa');
      procTH[i].textContent = txt;
      if (sa) procTH[i].appendChild(sa);
    });
  }
  // Trigger
  const trigTH = document.querySelectorAll('#view_trigger thead th');
  if (trigTH.length>=7) [L.colScore,L.colType,L.colTrigName,L.colPath,L.colCmd,L.colDetail,L.colReason].forEach((txt,i) => { const sa=trigTH[i].querySelector('.sa'); trigTH[i].textContent=txt; if(sa)trigTH[i].appendChild(sa); });
  // Exec
  const execTH = document.querySelectorAll('#view_execobj thead th');
  if (execTH.length>=10) [L.colRisk,L.colScore,L.colStatus,L.colPath,L.colLocation,L.colSigner,L.colTriggers,L.colSource,L.colNet,L.colReason].forEach((txt,i) => { const sa=execTH[i].querySelector('.sa'); execTH[i].textContent=txt; if(sa)execTH[i].appendChild(sa); });
  // Forensic
  const foreTH = document.querySelectorAll('#view_forensic thead th');
  if (foreTH.length>=7) [L.colScore,L.colSource,L.colPath,L.colDetail,L.colTime,L.colFileType,L.colReason].forEach((txt,i) => { const sa=foreTH[i].querySelector('.sa'); foreTH[i].textContent=txt; if(sa)foreTH[i].appendChild(sa); });
  // Timeline
  const tlTH = document.querySelectorAll('#view_timeline thead th');
  if (tlTH.length>=6) [L.colTime,L.colType,L.colScore,L.colObject,L.colDetail,L.colSource].forEach((txt,i) => { const sa=tlTH[i].querySelector('.sa'); tlTH[i].textContent=txt; if(sa)tlTH[i].appendChild(sa); });
  // Chain
  const chainTH = document.querySelectorAll('#view_chain thead th');
  if (chainTH.length>=4) [L.colScore,L.colChain,L.colEvidence,L.colInvolved].forEach((txt,i) => { chainTH[i].textContent=txt; });
  // IOC
  const iocTH = document.querySelectorAll('#view_ioc thead th');
  if (iocTH.length>=4) [L.colType,L.colValue,L.colSrcObj,L.colContext].forEach((txt,i) => { const sa=iocTH[i].querySelector('.sa'); iocTH[i].textContent=txt; if(sa)iocTH[i].appendChild(sa); });
  // Event
  const evtTH = document.querySelectorAll('#view_event thead th');
  if (evtTH.length>=8) [L.colScore,L.colTime,L.colEventID,L.colSource,L.colUser,L.colDesc,L.colProcTarget,L.colReason].forEach((txt,i) => { const sa=evtTH[i].querySelector('.sa'); evtTH[i].textContent=txt; if(sa)evtTH[i].appendChild(sa); });
  // Module
  const modTH = document.querySelectorAll('#view_module thead th');
  if (modTH.length>=8) [L.colScore,L.colDLLHijack,L.colHostProc,'PID',L.colProcSign,L.colSuspDLL,L.colHostPath,L.colReason].forEach((txt,i) => { const sa=modTH[i].querySelector('.sa'); modTH[i].textContent=txt; if(sa)modTH[i].appendChild(sa); });

  // Context menu
  document.getElementById('ctx_sha').textContent = L.ctx_sha;
  document.getElementById('ctx_md5').textContent = L.ctx_md5;
  document.getElementById('ctx_vt').textContent = L.ctx_vt;
  document.getElementById('ctx_vtlink').textContent = L.ctx_vtlink;
  document.getElementById('ctx_dir').textContent = L.ctx_dir;
  document.getElementById('ctx_detail').textContent = L.ctx_detail;
  document.getElementById('ctx_parent').textContent = L.ctx_parent;
  document.getElementById('ctx_cmd').textContent = L.ctx_cmd;
  document.getElementById('ctx_yara').textContent = L.ctx_yara;

  // YARA panel
  document.getElementById('yaraSelectFileBtn').textContent = L.yaraSelectFile;
  document.getElementById('yaraSelectFolderBtn').textContent = L.yaraSelectFolder;
  document.getElementById('yaraOrSpan').textContent = L.yaraOr;
  document.getElementById('yaraPathInput').placeholder = L.yaraPathPH;
  document.getElementById('yaraLoadPathBtn').textContent = L.yaraLoadPath;
  if (!document.getElementById('yaraScanBtn').disabled) document.getElementById('yaraScanBtn').textContent = L.yaraScanAll;

  // Status bar
  document.getElementById('statusText').textContent = L.ready;

  // AI panel - switch provider
  updateAIPanel(lang);

  // Re-render
  updateStats();
  render();
}

function toggleLang() {
  setLang(curLang === 'zh' ? 'en' : 'zh');
}

// Apply saved language on load
document.addEventListener('DOMContentLoaded', function() {
  fetch('/api/lang', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({lang:curLang})}).catch(()=>{});
  if (curLang !== 'zh') setLang(curLang);
});

let currentView = 'process';
let allProc=[], allTrig=[], allExec=[], allFore=[], allTL=[], allChain=[], allIOC=[], allEvt=[], allMod=[];
let filtProc=[], filtTrig=[], filtExec=[], filtFore=[], filtTL=[], filtChain=[], filtIOC=[], filtEvt=[], filtMod=[];
let selIdx = -1;

let sortState = { process:{field:'RiskScore',asc:false}, trigger:{field:'Score',asc:false}, execobj:{field:'FinalScore',asc:false}, forensic:{field:'Score',asc:false}, timeline:{field:'Time',asc:false}, chain:{field:'PatternScore',asc:false}, ioc:{field:'Type',asc:true}, event:{field:'Score',asc:false}, module:{field:'Score',asc:false} };

async function startScan() {
  const btn = document.getElementById('scanBtn');
  btn.disabled = true; btn.textContent = t('scanning');
  document.getElementById('statusText').textContent = t('scanMsg');
  document.getElementById('progressBar').classList.add('scanning');

  try {
    const resp = await fetch('/api/scan', { method: 'POST' });
    const data = await resp.json();
    if (data.status === 'done') await loadAll();
  } catch(e) {
    document.getElementById('statusText').textContent = t('scanErr') + e.message;
  }

  btn.disabled = false; btn.textContent = t('startScan');
  document.getElementById('progressBar').classList.remove('scanning');
}

async function loadAll() {
  const [r1,r2,r3,r4,r5,r6,r7,r8,r9] = await Promise.all([
    fetch('/api/records').then(r=>r.json()),
    fetch('/api/triggers').then(r=>r.json()),
    fetch('/api/execobjects').then(r=>r.json()),
    fetch('/api/forensics').then(r=>r.json()),
    fetch('/api/timeline').then(r=>r.json()),
    fetch('/api/chains').then(r=>r.json()),
    fetch('/api/indicators').then(r=>r.json()),
    fetch('/api/events').then(r=>r.json()),
    fetch('/api/modules').then(r=>r.json()),
  ]);
  allProc=r1||[]; allTrig=r2||[]; allExec=r3||[]; allFore=r4||[];
  allTL=r5||[]; allChain=r6||[]; allIOC=r7||[]; allEvt=r8||[]; allMod=r9||[];
  document.getElementById('badge_process').textContent = allProc.length;
  document.getElementById('badge_trigger').textContent = allTrig.length;
  document.getElementById('badge_execobj').textContent = allExec.length;
  document.getElementById('badge_forensic').textContent = allFore.length;
  document.getElementById('badge_timeline').textContent = allTL.length;
  document.getElementById('badge_chain').textContent = allChain.length;
  document.getElementById('badge_ioc').textContent = allIOC.length;
  document.getElementById('badge_event').textContent = allEvt.length;
  document.getElementById('badge_module').textContent = allMod.length;
  applyFilter();
  updateStats();
}

function switchView(v) {
  currentView = v; selIdx = -1;
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab_' + v).classList.add('active');
  document.getElementById('view_' + v).classList.add('active');
  applyFilter();
}

function applyFilter() {
  const q = document.getElementById('filterInput').value.toLowerCase();
  const risk = document.getElementById('riskFilter').value;

  filtProc = allProc.filter(r => {
    if (risk && r.RiskLevel !== risk) return false;
    if (q) { const s = [r.Name,r.Path,r.SHA256,r.Signer,r.CommandLine,r.User,String(r.PID),r.ParentName,(r.Reasons||[]).join(' ')].join(' ').toLowerCase(); if (!s.includes(q)) return false; }
    return true;
  });
  filtTrig = allTrig.filter(t => {
    if (risk) { const lv = riskLevelFromScore(t.Score); if (lv !== risk) return false; }
    if (q) { const s = [t.Name,t.Path,t.CommandLine,t.Detail,t.Type,(t.Reasons||[]).join(' ')].join(' ').toLowerCase(); if (!s.includes(q)) return false; }
    return true;
  });
  filtExec = allExec.filter(e => {
    if (risk && e.RiskLevel !== risk) return false;
    if (q) { const s = [e.Path,e.CommandLine,e.Signer,(e.Sources||[]).join(' '),(e.Reasons||[]).join(' ')].join(' ').toLowerCase(); if (!s.includes(q)) return false; }
    return true;
  });
  filtFore = allFore.filter(f => {
    if (risk) { const lv = riskLevelFromScore(f.Score); if (lv !== risk) return false; }
    if (q) { const s = [f.Path,f.Detail,f.Source,f.CommandLine,(f.Reasons||[]).join(' ')].join(' ').toLowerCase(); if (!s.includes(q)) return false; }
    return true;
  });
  filtTL = allTL.filter(e => {
    if (q) { const s = [e.ObjectPath,e.ObjectName,e.Detail,e.Type,e.Source].join(' ').toLowerCase(); if (!s.includes(q)) return false; }
    return true;
  });
  filtChain = allChain.filter(c => {
    if (q) { const s = [c.PatternName,...(c.Evidence||[]),...(c.ObjectPaths||[])].join(' ').toLowerCase(); if (!s.includes(q)) return false; }
    return true;
  });
  filtIOC = allIOC.filter(i => {
    if (q) { const s = [i.Type,i.Value,i.SourceObject,i.Context].join(' ').toLowerCase(); if (!s.includes(q)) return false; }
    return true;
  });
  filtEvt = allEvt.filter(e => {
    if (risk) { const lv = riskLevelFromScore(e.Score); if (lv !== risk) return false; }
    if (q) { const s = [e.Source,e.Description,e.ProcessPath,e.CommandLine,e.User,e.TargetPath,String(e.EventID),(e.Reasons||[]).join(' ')].join(' ').toLowerCase(); if (!s.includes(q)) return false; }
    return true;
  });
  filtMod = allMod.filter(m => {
    if (risk) { const lv = riskLevelFromScore(m.Score); if (lv !== risk) return false; }
    if (q) { const s = [m.ExeName,m.ExePath,m.ExeSigner,(m.Reasons||[]).join(' ')].join(' ').toLowerCase(); if (!s.includes(q)) return false; }
    return true;
  });

  doSort(currentView); render();
}

function riskLevelFromScore(s) {
  if (s>=80) return 'Critical'; if (s>=60) return 'High'; if (s>=40) return 'Medium'; if (s>=20) return 'Suspicious'; return 'Low';
}

function doSort(view) {
  const st = sortState[view];
  const arrs = {process:filtProc, trigger:filtTrig, execobj:filtExec, forensic:filtFore, timeline:filtTL, chain:filtChain, ioc:filtIOC, event:filtEvt, module:filtMod};
  const arr = arrs[view] || [];
  arr.sort((a,b) => {
    let va = a[st.field], vb = b[st.field];
    if (typeof va==='number' && typeof vb==='number') return st.asc ? va-vb : vb-va;
    va = String(va||'').toLowerCase(); vb = String(vb||'').toLowerCase();
    if (va<vb) return st.asc ? -1 : 1; if (va>vb) return st.asc ? 1 : -1; return 0;
  });
}

function sortProc(f) { toggleSort('process', f, 'sp_'); }
function sortTrig(f) { toggleSort('trigger', f, 'st_'); }
function sortExec(f) { toggleSort('execobj', f, 'se_'); }
function sortFore(f) { toggleSort('forensic', f, 'sf_'); }
function sortTL(f) { toggleSort('timeline', f, 'stl_'); }
function sortIOC(f) { toggleSort('ioc', f, 'si_'); }
function sortEvt(f) { toggleSort('event', f, 'sev_'); }
function sortMod(f) { toggleSort('module', f, 'sm_'); }

function toggleSort(view, field, prefix) {
  const st = sortState[view];
  if (st.field===field) st.asc=!st.asc; else { st.field=field; st.asc=false; }
  document.querySelectorAll('.sa').forEach(el => { if(el.id.startsWith(prefix)) el.textContent=''; });
  const el = document.getElementById(prefix+field);
  if (el) el.textContent = st.asc ? '▲' : '▼';
  doSort(view); render();
}

function render() {
  if (currentView === 'ai' || currentView === 'yara' || currentView === 'memory' || currentView === 'iocmon') return;
  const renderers = {process:renderProc, trigger:renderTrig, execobj:renderExec, forensic:renderFore, timeline:renderTL, chain:renderChain, ioc:renderIOC, event:renderEvt, module:renderMod};
  (renderers[currentView]||renderProc)();
  const totals = {process:allProc.length, trigger:allTrig.length, execobj:allExec.length, forensic:allFore.length, timeline:allTL.length, chain:allChain.length, ioc:allIOC.length, event:allEvt.length, module:allMod.length};
  const showns = {process:filtProc.length, trigger:filtTrig.length, execobj:filtExec.length, forensic:filtFore.length, timeline:filtTL.length, chain:filtChain.length, ioc:filtIOC.length, event:filtEvt.length, module:filtMod.length};
  document.getElementById('statusText').textContent = t('showN') + showns[currentView] + t('ofN') + totals[currentView] + t('records');
}

function renderProc() {
  const tbody = document.getElementById('procBody');
  const f = document.createDocumentFragment();
  filtProc.forEach((r,i) => {
    const tr = document.createElement('tr');
    tr.className = 'risk-' + r.RiskLevel.toLowerCase();
    if (i===selIdx) tr.classList.add('selected');
    tr.onclick = () => sel(i); tr.oncontextmenu = e => { sel(i); ctxMenu(e); };
    tr.ondblclick = () => { sel(i); showDetail(); };
    const sha = r.SHA256 ? r.SHA256.substring(0,16)+'...' : '';
    const par = r.ParentName ? r.ParentName+'('+r.PPID+')' : String(r.PPID);
    const net = r.HasNetwork ? ((r.RemoteIPs||[]).join(',')||t('localOnly')) : '';
    const pers = (r.Persistence||[]).length;
    tr.innerHTML =
      '<td>'+esc(RL[r.RiskLevel]||r.RiskLevel)+'</td><td>'+r.RiskScore+'</td>'+
      '<td title="'+esc(r.Name)+'">'+esc(r.Name)+'</td><td>'+r.PID+'</td>'+
      '<td title="'+esc(par)+'">'+esc(par)+'</td>'+
      '<td title="'+esc(r.Path)+'">'+esc(r.Path)+'</td>'+
      '<td title="'+esc(r.CommandLine)+'">'+esc(r.CommandLine)+'</td>'+
      '<td title="'+esc(r.SHA256)+'">'+esc(sha)+'</td>'+
      '<td title="'+esc(r.Signer)+'">'+esc(r.Signer)+'</td>'+
      '<td>'+esc(net)+'</td><td>'+(pers>0?pers+' '+t('items'):'')+'</td>'+
      '<td title="'+esc((r.Reasons||[]).join('; '))+'">'+esc((r.Reasons||[]).join('; '))+'</td>';
    f.appendChild(tr);
  });
  tbody.innerHTML=''; tbody.appendChild(f);
}

function renderTrig() {
  const tbody = document.getElementById('trigBody');
  const f = document.createDocumentFragment();
  filtTrig.forEach((t,i) => {
    const tr = document.createElement('tr');
    const lv = riskLevelFromScore(t.Score);
    tr.className = 'risk-' + lv.toLowerCase();
    if (i===selIdx) tr.classList.add('selected');
    tr.onclick = () => sel(i); tr.oncontextmenu = e => { sel(i); ctxMenu(e); };
    tr.ondblclick = () => { sel(i); showTrigDetail(i); };
    tr.innerHTML =
      '<td>'+t.Score+'</td>'+
      '<td>'+esc(TT[t.Type]||t.Type)+'</td>'+
      '<td title="'+esc(t.Name)+'">'+esc(t.Name)+'</td>'+
      '<td title="'+esc(t.Path)+'">'+esc(t.Path)+'</td>'+
      '<td title="'+esc(t.CommandLine)+'">'+esc(t.CommandLine)+'</td>'+
      '<td title="'+esc(t.Detail)+'">'+esc(t.Detail)+'</td>'+
      '<td title="'+esc((t.Reasons||[]).join('; '))+'">'+esc((t.Reasons||[]).join('; '))+'</td>';
    f.appendChild(tr);
  });
  tbody.innerHTML=''; tbody.appendChild(f);
}

function renderExec() {
  const tbody = document.getElementById('execBody');
  const f = document.createDocumentFragment();
  filtExec.forEach((e,i) => {
    const tr = document.createElement('tr');
    tr.className = 'risk-' + (e.RiskLevel||'low').toLowerCase();
    if (i===selIdx) tr.classList.add('selected');
    tr.onclick = () => sel(i); tr.oncontextmenu = ev => { sel(i); ctxMenu(ev); };
    tr.ondblclick = () => { sel(i); showExecDetail(i); };
    const trigs = (e.TriggerTypes||[]).map(tp=>TT[tp]||tp).join('+');
    const srcs = (e.Sources||[]).join(', ');
    const net = e.NetworkObserved ? ((e.RemoteIPs||[]).join(',')||t('yes')) : '';
    tr.innerHTML =
      '<td>'+esc(RL[e.RiskLevel]||e.RiskLevel)+'</td><td>'+e.FinalScore+'</td>'+
      '<td>'+(e.IsRunning?'<span class="tag tag-red">'+t('running')+'</span>':'<span class="tag tag-blue">'+t('notRunning')+'</span>')+'</td>'+
      '<td title="'+esc(e.Path)+'">'+esc(e.Path)+'</td>'+
      '<td>'+esc(e.LocationType)+'</td>'+
      '<td title="'+esc(e.Signer)+'">'+esc(e.Signer)+'</td>'+
      '<td>'+(e.TriggerCount>0?e.TriggerCount+'个('+esc(trigs)+')':'')+'</td>'+
      '<td>'+esc(srcs)+'</td>'+
      '<td>'+esc(net)+'</td>'+
      '<td title="'+esc((e.Reasons||[]).join('; '))+'">'+esc((e.Reasons||[]).join('; '))+'</td>';
    f.appendChild(tr);
  });
  tbody.innerHTML=''; tbody.appendChild(f);
}

function renderFore() {
  const tbody = document.getElementById('foreBody');
  const f = document.createDocumentFragment();
  filtFore.forEach((r,i) => {
    const tr = document.createElement('tr');
    const lv = riskLevelFromScore(r.Score);
    tr.className = 'risk-' + lv.toLowerCase();
    if (i===selIdx) tr.classList.add('selected');
    tr.onclick = () => sel(i); tr.oncontextmenu = e => { sel(i); ctxMenu(e); };
    tr.ondblclick = () => { sel(i); showForeDetail(i); };
    const timeStr = r.EventTime || r.LastRunTime || r.FileModTime || '';
    const srcCN = FS[r.Source] || r.Source;
    tr.innerHTML =
      '<td>'+r.Score+'</td>'+
      '<td>'+esc(srcCN)+'</td>'+
      '<td title="'+esc(r.Path)+'">'+esc(r.Path)+'</td>'+
      '<td title="'+esc(r.Detail)+'">'+esc(r.Detail)+'</td>'+
      '<td>'+esc(timeStr)+'</td>'+
      '<td>'+esc(r.FileType||r.Source)+'</td>'+
      '<td title="'+esc((r.Reasons||[]).join('; '))+'">'+esc((r.Reasons||[]).join('; '))+'</td>';
    f.appendChild(tr);
  });
  tbody.innerHTML=''; tbody.appendChild(f);
}

function renderMod() {
  const tbody = document.getElementById('modBody');
  const f = document.createDocumentFragment();
  filtMod.forEach((m,i) => {
    const tr = document.createElement('tr');
    const lv = riskLevelFromScore(m.Score);
    tr.className = 'risk-' + lv.toLowerCase();
    if (i===selIdx) tr.classList.add('selected');
    tr.onclick = () => sel(i);
    tr.ondblclick = () => { sel(i); showModDetail(i); };
    tr.innerHTML =
      '<td>'+m.Score+'</td>'+
      '<td>'+(m.HasDLLHijack?'<span class="tag tag-red">是</span>':'<span class="tag tag-green">否</span>')+'</td>'+
      '<td title="'+esc(m.ExeName)+'">'+esc(m.ExeName)+'</td>'+
      '<td>'+m.PID+'</td>'+
      '<td>'+(m.ExeSigned?'<span class="tag tag-green">'+esc(m.ExeSigner||'是')+'</span>':'<span class="tag tag-orange">否</span>')+'</td>'+
      '<td>'+m.SuspiciousCount+'</td>'+
      '<td title="'+esc(m.ExePath)+'">'+esc(m.ExePath)+'</td>'+
      '<td title="'+esc((m.Reasons||[]).join('; '))+'">'+esc((m.Reasons||[]).join('; '))+'</td>';
    f.appendChild(tr);
  });
  tbody.innerHTML=''; tbody.appendChild(f);
}

function showModDetail(i) {
  const m = filtMod[i]; if (!m) return;
  document.getElementById('modalTitle').textContent = '模块分析: ' + m.ExeName + ' (PID ' + m.PID + ')';
  let h = '';
  h += sec('宿主进程', [['进程名',m.ExeName],['PID',m.PID],['路径',m.ExePath,1],['签名',m.ExeSigned?'✓ 是':'✗ 否'],['签发者',m.ExeSigner],['总模块数',m.TotalModules],['可疑模块数',m.SuspiciousCount]]);
  h += '<div class="detail-section"><h3>DLL劫持检测</h3>';
  h += '<div class="detail-row"><div class="detail-label">DLL劫持</div><div class="detail-value">'+(m.HasDLLHijack?'<span class="tag tag-red">检测到DLL劫持</span>':'否')+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">DLL劫持评分</div><div class="detail-value"><strong>'+m.DLLHijackScore+'</strong></div></div>';
  h += '</div>';
  if ((m.SuspiciousModules||[]).length > 0) {
    h += '<div class="detail-section"><h3>可疑模块 ('+m.SuspiciousModules.length+')</h3>';
    m.SuspiciousModules.forEach(mod => {
      h += '<div style="padding:8px 0;border-bottom:1px solid #1e2a4a">';
      h += '<div class="detail-row"><div class="detail-label">DLL路径</div><div class="detail-value mono">'+esc(mod.Path)+'</div></div>';
      h += '<div class="detail-row"><div class="detail-label">DLL评分</div><div class="detail-value"><strong style="color:#e94560">'+mod.Score+'</strong></div></div>';
      h += '<div class="detail-row"><div class="detail-label">签名</div><div class="detail-value">'+(mod.Signed?'✓ '+esc(mod.Signer):'<span class="tag tag-red">未签名</span>')+'</div></div>';
      const flags = [];
      if (mod.IsSystemDLLName) flags.push('<span class="tag tag-red">系统DLL名</span>');
      if (mod.IsUserPath) flags.push('<span class="tag tag-red">用户目录</span>');
      if (mod.IsTempPath) flags.push('<span class="tag tag-red">临时目录</span>');
      if (mod.IsSameDirAsExe) flags.push('<span class="tag tag-orange">同目录加载</span>');
      if (flags.length) h += '<div class="detail-row"><div class="detail-label">标记</div><div class="detail-value">'+flags.join(' ')+'</div></div>';
      if ((mod.Reasons||[]).length) {
        h += '<div class="detail-row"><div class="detail-label">原因</div><div class="detail-value">';
        mod.Reasons.forEach(r => { h += '<div class="tag tag-red" style="display:block;margin:2px 0">'+esc(r)+'</div>'; });
        h += '</div></div>';
      }
      h += '</div>';
    });
    h += '</div>';
  }
  h += reasonBlock(m.Score, riskLevelFromScore(m.Score), m.Reasons);
  document.getElementById('modalBody').innerHTML = h;
  document.getElementById('modalOverlay').classList.add('show');
}

function renderEvt() {
  const tbody = document.getElementById('evtBody');
  const f = document.createDocumentFragment();
  filtEvt.forEach((e,i) => {
    const tr = document.createElement('tr');
    const lv = riskLevelFromScore(e.Score);
    tr.className = 'risk-' + lv.toLowerCase();
    if (i===selIdx) tr.classList.add('selected');
    tr.onclick = () => sel(i);
    tr.ondblclick = () => { sel(i); showEvtDetail(i); };
    const procTarget = e.ProcessPath ? baseName(e.ProcessPath) : (e.TargetPath ? baseName(e.TargetPath) : '');
    tr.innerHTML =
      '<td>'+e.Score+'</td>'+
      '<td>'+esc(e.Time)+'</td>'+
      '<td>'+e.EventID+'</td>'+
      '<td>'+esc(e.Source)+'</td>'+
      '<td title="'+esc(e.User)+'">'+esc(e.User)+'</td>'+
      '<td title="'+esc(e.Description)+'">'+esc(e.Description)+'</td>'+
      '<td title="'+esc(e.ProcessPath||e.TargetPath)+'">'+esc(procTarget)+'</td>'+
      '<td title="'+esc((e.Reasons||[]).join('; '))+'">'+esc((e.Reasons||[]).join('; '))+'</td>';
    f.appendChild(tr);
  });
  tbody.innerHTML=''; tbody.appendChild(f);
}

function baseName(p) { if (!p) return ''; const i = p.lastIndexOf('\\'); return i>=0 ? p.substring(i+1) : p; }

function showEvtDetail(i) {
  const e = filtEvt[i]; if (!e) return;
  document.getElementById('modalTitle').textContent = '事件详情: EventID ' + e.EventID + ' (' + e.Source + ')';
  let h = '';
  h += sec('事件信息', [['事件ID',e.EventID],['来源',e.Source],['时间',e.Time],['计算机',e.Computer],['用户',e.User],['描述',e.Description]]);
  if (e.ProcessPath||e.CommandLine||e.ParentPath) h += sec('进程信息', [['进程路径',e.ProcessPath,1],['命令行',e.CommandLine,1],['父进程',e.ParentPath,1],['PID',e.ProcessID]]);
  if (e.TargetPath||e.ServiceName||e.TaskName) h += sec('目标信息', [['目标路径',e.TargetPath,1],['服务名',e.ServiceName],['任务名',e.TaskName]]);
  if (e.IPAddress||e.Domain||e.LogonType) h += sec('网络/登录', [['IP地址',e.IPAddress],['端口',e.Port],['域名',e.Domain],['登录类型',e.LogonType]]);
  if (e.LinkedObject) h += sec('关联对象', [['关联ExecutionObject',e.LinkedObject,1]]);
  h += reasonBlock(e.Score, riskLevelFromScore(e.Score), e.Reasons);
  document.getElementById('modalBody').innerHTML = h;
  document.getElementById('modalOverlay').classList.add('show');
}

function renderTL() {
  const tbody = document.getElementById('tlBody');
  const f = document.createDocumentFragment();
  filtTL.forEach((e,i) => {
    const tr = document.createElement('tr');
    const lv = riskLevelFromScore(e.Score);
    tr.className = 'risk-' + lv.toLowerCase();
    if (i===selIdx) tr.classList.add('selected');
    tr.onclick = () => sel(i);
    const typeCN = TLE[e.Type] || e.Type;
    tr.innerHTML =
      '<td>'+esc(e.Time)+'</td>'+
      '<td>'+esc(typeCN)+'</td>'+
      '<td>'+e.Score+'</td>'+
      '<td title="'+esc(e.ObjectPath)+'">'+esc(e.ObjectName||e.ObjectPath)+'</td>'+
      '<td title="'+esc(e.Detail)+'">'+esc(e.Detail)+'</td>'+
      '<td>'+esc(e.Source)+'</td>';
    f.appendChild(tr);
  });
  tbody.innerHTML=''; tbody.appendChild(f);
}

function renderChain() {
  const tbody = document.getElementById('chainBody');
  const f = document.createDocumentFragment();
  filtChain.forEach((c,i) => {
    const tr = document.createElement('tr');
    tr.className = c.PatternScore>=30 ? 'risk-critical' : c.PatternScore>=20 ? 'risk-high' : 'risk-medium';
    if (i===selIdx) tr.classList.add('selected');
    tr.onclick = () => sel(i);
    tr.innerHTML =
      '<td>'+c.PatternScore+'</td>'+
      '<td>'+esc(c.PatternName)+'</td>'+
      '<td>'+esc((c.Evidence||[]).join(' → '))+'</td>'+
      '<td title="'+esc((c.ObjectPaths||[]).join(', '))+'">'+esc((c.ObjectPaths||[]).join(', '))+'</td>';
    f.appendChild(tr);
  });
  tbody.innerHTML=''; tbody.appendChild(f);
}

function renderIOC() {
  const tbody = document.getElementById('iocBody');
  const f = document.createDocumentFragment();
  filtIOC.forEach((c,i) => {
    const tr = document.createElement('tr');
    tr.className = c.Type==='url'||c.Type==='ip' ? 'risk-high' : 'risk-suspicious';
    if (i===selIdx) tr.classList.add('selected');
    tr.onclick = () => sel(i);
    tr.innerHTML =
      '<td><span class="tag tag-'+(c.Type==='ip'||c.Type==='url'?'red':'orange')+'">'+esc(IOT[c.Type]||c.Type)+'</span></td>'+
      '<td title="'+esc(c.Value)+'" style="font-family:Consolas,monospace">'+esc(c.Value)+'</td>'+
      '<td title="'+esc(c.SourceObject)+'">'+esc(c.SourceObject)+'</td>'+
      '<td title="'+esc(c.Context)+'">'+esc(c.Context)+'</td>';
    f.appendChild(tr);
  });
  tbody.innerHTML=''; tbody.appendChild(f);
}

function sel(i) { selIdx=i; document.querySelectorAll('.view-panel.active tbody tr').forEach((tr,idx)=>tr.classList.toggle('selected',idx===i)); }
function getSelProc() { return selIdx>=0 && selIdx<filtProc.length ? filtProc[selIdx] : null; }
function getSelTrig() { return selIdx>=0 && selIdx<filtTrig.length ? filtTrig[selIdx] : null; }
function getSelExec() { return selIdx>=0 && selIdx<filtExec.length ? filtExec[selIdx] : null; }

function getSelFore() { return selIdx>=0 && selIdx<filtFore.length ? filtFore[selIdx] : null; }
function getSelectedPath() {
  if (currentView==='process') { const r=getSelProc(); return r?{sha:r.SHA256,md5:r.MD5,path:r.Path,cmd:r.CommandLine,name:r.Name}:null; }
  if (currentView==='trigger') { const t=getSelTrig(); return t?{sha:'',md5:'',path:t.Path,cmd:t.CommandLine,name:t.Name}:null; }
  if (currentView==='forensic') { const f=getSelFore(); return f?{sha:'',md5:'',path:f.Path,cmd:f.CommandLine||'',name:f.Path}:null; }
  const e=getSelExec(); return e?{sha:e.SHA256,md5:e.MD5,path:e.Path,cmd:e.CommandLine,name:e.Path}:null;
}

function countRiskLevels() {
  let c=0,h=0,m=0,s=0,l=0;
  allProc.forEach(r => { switch(r.RiskLevel){ case 'Critical':c++;break; case 'High':h++;break; case 'Medium':m++;break; case 'Suspicious':s++;break; default:l++; } });
  return {c,h,m,s,l};
}

function updateStats() {
  const {c,h,m,s,l} = countRiskLevels();
  document.getElementById('statsText').innerHTML =
    '<span class="critical">'+t('statCrit')+c+'</span><span class="high">'+t('statHigh')+h+'</span>'+
    '<span class="medium">'+t('statMed')+m+'</span><span class="suspicious">'+t('statSusp')+s+'</span>'+
    '<span>'+t('statLow')+l+'</span><span>'+t('statProc')+allProc.length+' '+t('statTrig')+allTrig.length+' '+t('statEvt')+allEvt.length+' '+t('statChain')+allChain.length+' '+t('statIOC')+allIOC.length+'</span>';
}

function ctxMenu(e) { e.preventDefault(); const m=document.getElementById('ctxMenu'); m.classList.add('show'); m.style.left=e.clientX+'px'; m.style.top=e.clientY+'px'; const r=m.getBoundingClientRect(); if(r.right>window.innerWidth)m.style.left=(e.clientX-r.width)+'px'; if(r.bottom>window.innerHeight)m.style.top=(e.clientY-r.height)+'px'; }
document.addEventListener('click', ()=>document.getElementById('ctxMenu').classList.remove('show'));

function copySHA256() { const s=getSelectedPath(); if(s&&s.sha){navigator.clipboard.writeText(s.sha);flash(t('copiedSHA'));} }
function copyMD5() { const s=getSelectedPath(); if(s&&s.md5){navigator.clipboard.writeText(s.md5);flash(t('copiedMD5'));} }
function openVT() { const s=getSelectedPath(); if(s&&s.sha) window.open('https://www.virustotal.com/gui/file/'+s.sha,'_blank'); }
function copyVTLink() { const s=getSelectedPath(); if(s&&s.sha){navigator.clipboard.writeText('https://www.virustotal.com/gui/file/'+s.sha);flash(t('copiedVT'));} }
async function openDir() { const s=getSelectedPath(); if(s&&s.path){try{const r=await fetch('/api/opendir',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:s.path})});const d=await r.json();flash(d.ok?t('dirOpened'):t('dirFail')+(d.error||''));}catch(e){flash(t('error')+e.message);}} }
function copyCmdLine() { const s=getSelectedPath(); if(s&&s.cmd){navigator.clipboard.writeText(s.cmd);flash(t('copiedCmd'));} }
function filterParent() { if(currentView==='process'){const r=getSelProc();if(r&&r.ParentName){document.getElementById('filterInput').value=r.ParentName;applyFilter();}} }
// --- IOC Monitor Logic ---

async function loadIOCText() {
  const text = document.getElementById('iocInput').value.trim();
  if (!text) { flash('请输入IOC'); return; }
  try {
    const resp = await fetch('/api/ioc/load', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:text})});
    const data = await resp.json();
    if (data.ok) flash('已加载 '+data.count+' 个IOC');
  } catch(e) { flash('加载出错: '+e.message); }
}

async function loadIOCFile(event) {
  const file = event.target.files[0];
  if (!file) return;
  const text = await file.text();
  document.getElementById('iocInput').value = text;
  loadIOCText();
  event.target.value = '';
}

let iocPollTimer = null;
async function startIOCMonitor() {
  const badge = document.getElementById('iocMonBadge');
  const btn = document.getElementById('iocStartBtn');

  // Step 1: Auto-load IOC from input if not loaded yet
  const text = document.getElementById('iocInput').value.trim();
  if (!text) {
    badge.textContent = '未加载IOC'; badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
    flash('请先在左侧输入框中输入IOC（IP或域名）');
    return;
  }

  btn.disabled = true; btn.textContent = '加载中...';
  try {
    const loadResp = await fetch('/api/ioc/load', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:text})});
    const loadData = await loadResp.json();
    if (!loadData.ok || loadData.count === 0) {
      badge.textContent = '无有效IOC'; badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
      flash('未识别到有效的IOC，请检查格式');
      btn.disabled = false; btn.textContent = '开始监控';
      return;
    }
    document.getElementById('iocMonCount').textContent = loadData.count;
  } catch(e) {
    flash('加载IOC出错: '+e.message);
    btn.disabled = false; btn.textContent = '开始监控';
    return;
  }

  // Step 2: Calculate duration
  const durValue = parseInt(document.getElementById('iocDurInput').value) || 10;
  const durUnit = parseInt(document.getElementById('iocDurUnit').value) || 60;
  const durSec = durValue * durUnit;

  // Step 3: Start monitoring
  try {
    const resp = await fetch('/api/ioc/start', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({duration:durSec})});
    const data = await resp.json();
    if (!data.ok) {
      badge.textContent = '启动失败'; badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
      flash('启动失败: '+(data.error||''));
      btn.disabled = false; btn.textContent = '开始监控';
      return;
    }
    badge.textContent = '监控中'; badge.style.background = '#1a3a1a'; badge.style.color = '#a5d6a7';
    btn.textContent = '监控中...';
    iocPollTimer = setInterval(pollIOCStatus, 1000);
  } catch(e) {
    flash('启动出错: '+e.message);
    btn.disabled = false; btn.textContent = '开始监控';
  }
}

async function stopIOCMonitor() {
  await fetch('/api/ioc/stop', {method:'POST'});
  if (iocPollTimer) { clearInterval(iocPollTimer); iocPollTimer = null; }
  const badge = document.getElementById('iocMonBadge');
  badge.textContent = '已停止'; badge.style.background = '#4a3000'; badge.style.color = '#ffcc80';
  const btn = document.getElementById('iocStartBtn');
  btn.disabled = false; btn.textContent = '开始监控';
  pollIOCStatus();
}

async function pollIOCStatus() {
  try {
    const [statusResp, hitsResp] = await Promise.all([
      fetch('/api/ioc/status').then(r=>r.json()),
      fetch('/api/ioc/hits').then(r=>r.json()),
    ]);
    document.getElementById('iocMonCount').textContent = statusResp.IOCCount;
    document.getElementById('iocMonElapsed').textContent = statusResp.Elapsed || '-';
    document.getElementById('iocMonCycles').textContent = statusResp.CycleCount;
    document.getElementById('iocMonHits').textContent = statusResp.HitCount;
    document.getElementById('iocMonPIDs').textContent = statusResp.HitPIDs;

    if (!statusResp.Running && iocPollTimer) {
      clearInterval(iocPollTimer); iocPollTimer = null;
      const badge = document.getElementById('iocMonBadge');
      badge.textContent = '已完成'; badge.style.background = '#4a3000'; badge.style.color = '#ffcc80';
      const btn = document.getElementById('iocStartBtn');
      btn.disabled = false; btn.textContent = '开始监控';
    }

    renderIOCHits(hitsResp || []);
  } catch(e) {}
}

function renderIOCHits(hits) {
  const tbody = document.getElementById('iocHitBody');
  const emptyMsg = document.getElementById('iocEmptyMsg');
  if (hits.length === 0) { tbody.innerHTML=''; emptyMsg.style.display='block'; return; }
  emptyMsg.style.display = 'none';
  const frag = document.createDocumentFragment();
  hits.forEach(h => {
    const tr = document.createElement('tr');
    tr.className = h.Confidence==='high' ? 'risk-critical' : 'risk-high';
    const timeShort = h.Time ? h.Time.substring(11) : '';
    tr.innerHTML =
      '<td>'+esc(timeShort)+'</td>'+
      '<td title="'+esc(h.IOC)+'"><strong>'+esc(h.IOC)+'</strong></td>'+
      '<td><span class="tag tag-'+(h.IOCType==='ip'?'red':'orange')+'">'+esc(h.IOCType)+'</span></td>'+
      '<td>'+h.PID+'</td>'+
      '<td title="'+esc(h.ProcessName)+'">'+esc(h.ProcessName)+(h.IsLOLBin?' <span class="tag tag-orange">LOLBin</span>':'')+'</td>'+
      '<td title="'+esc(h.ProcessPath)+'">'+esc(h.ProcessPath)+'</td>'+
      '<td>'+esc(h.RemoteIP)+'</td>'+
      '<td>'+h.RemotePort+'</td>'+
      '<td><span class="tag tag-'+(h.Confidence==='high'?'red':'orange')+'">'+esc(h.Confidence)+'</span></td>'+
      '<td>'+esc(h.User)+'</td>'+
      '<td>'+esc(h.IOCComment)+'</td>';
    frag.appendChild(tr);
  });
  tbody.innerHTML=''; tbody.appendChild(frag);
}

// --- Memory Analysis Logic ---

async function startMemoryAnalysis() {
  const pidStr = document.getElementById('memPidInput').value.trim();
  if (!pidStr) { flash('请输入PID'); return; }
  const pid = parseInt(pidStr);
  if (!pid || pid <= 0) { flash('无效的PID'); return; }

  const btn = document.getElementById('memAnalyzeBtn');
  const status = document.getElementById('memStatus');
  btn.disabled = true; btn.textContent = '分析中...';
  status.textContent = '正在分析PID ' + pid + ' 的内存布局...';
  status.style.color = '#ffd600';

  try {
    const resp = await fetch('/api/memory/analyze', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({pid: pid})
    });
    const data = await resp.json();
    renderMemoryResult(data);
  } catch(e) {
    status.textContent = '分析出错: ' + e.message;
    status.style.color = '#ff1744';
  }
  btn.disabled = false; btn.textContent = '开始分析';
}

function clearMemoryResult() {
  document.getElementById('memProcInfo').style.display = 'none';
  document.getElementById('memRiskSummary').style.display = 'none';
  document.getElementById('memSuspBody').innerHTML = '';
  document.getElementById('memExecBody').innerHTML = '';
  document.getElementById('memSuspCount').textContent = '';
  document.getElementById('memExecCount').textContent = '';
  document.getElementById('memStatus').textContent = '';
}

function renderMemoryResult(data) {
  const status = document.getElementById('memStatus');
  if (data.Error) {
    status.textContent = '错误: ' + data.Error;
    status.style.color = '#ff1744';
    return;
  }
  status.textContent = '分析完成';
  status.style.color = '#4caf50';

  // Process info
  const procInfo = document.getElementById('memProcInfo');
  procInfo.style.display = 'block';
  document.getElementById('memProcFields').innerHTML =
    '<span><strong>进程:</strong> '+esc(data.ProcessName)+'</span>'+
    '<span><strong>PID:</strong> '+data.PID+'</span>'+
    '<span><strong>路径:</strong> '+esc(data.Path)+'</span>'+
    '<span><strong>用户:</strong> '+esc(data.User)+'</span>'+
    '<span><strong>签名:</strong> '+(data.Signed?'✓ '+esc(data.Signer):'✗ 否')+'</span>';

  // Risk summary
  const riskDiv = document.getElementById('memRiskSummary');
  riskDiv.style.display = 'block';
  const lvColor = data.RiskLevel==='High'?'#ff1744':data.RiskLevel==='Medium'?'#ffd600':data.RiskLevel==='Suspicious'?'#64b5f6':'#4caf50';
  const lvCN = {High:'高危',Medium:'中危',Suspicious:'可疑',Low:'低危'}[data.RiskLevel]||data.RiskLevel;
  document.getElementById('memRiskFields').innerHTML =
    '<span style="font-size:16px;font-weight:bold;color:'+lvColor+'">'+lvCN+' ('+data.Score+'分)</span>'+
    '<span class="tag tag-red">RWX: '+data.RWXCount+'</span>'+
    '<span class="tag tag-orange">私有可执行: '+data.PrivateExecCount+'</span>'+
    '<span class="tag tag-blue">非映像可执行: '+data.NoImageExecCount+'</span>'+
    '<span style="color:#888">总区域: '+data.TotalRegions+' | 已提交: '+data.CommittedRegions+' | 可执行: '+data.ExecutableRegions+'</span>'+
    (data.Reasons||[]).map(r=>'<div class="tag tag-red" style="font-size:11px">'+esc(r)+'</div>').join('');

  // Suspicious regions table
  document.getElementById('memSuspCount').textContent = data.SuspiciousCount > 0 ? '('+data.SuspiciousCount+'个)' : '';
  const suspBody = document.getElementById('memSuspBody');
  suspBody.innerHTML = '';
  (data.SuspiciousRegions||[]).forEach(r => {
    const tr = document.createElement('tr');
    tr.className = r.IsRWX ? 'risk-critical' : r.IsPrivateExec ? 'risk-high' : 'risk-medium';
    tr.innerHTML =
      '<td style="font-family:Consolas">'+esc(r.BaseAddress)+'</td>'+
      '<td>'+esc(r.SizeHuman)+'</td>'+
      '<td><span class="tag tag-'+(r.IsRWX?'red':'orange')+'">'+esc(r.Protect)+'</span></td>'+
      '<td>'+esc(r.Type)+'</td>'+
      '<td>'+esc(r.Reason)+'</td>';
    suspBody.appendChild(tr);
  });

  // All executable regions table
  const execRegions = (data.AllRegions||[]).filter(r=>r.IsExecutable);
  document.getElementById('memExecCount').textContent = '('+execRegions.length+'个)';
  const execBody = document.getElementById('memExecBody');
  execBody.innerHTML = '';
  execRegions.forEach(r => {
    const tr = document.createElement('tr');
    if (r.IsSuspicious) tr.className = 'risk-high';
    tr.innerHTML =
      '<td style="font-family:Consolas">'+esc(r.BaseAddress)+'</td>'+
      '<td>'+esc(r.SizeHuman)+'</td>'+
      '<td>'+esc(r.Protect)+'</td>'+
      '<td>'+esc(r.Type)+'</td>'+
      '<td>'+(r.IsRWX?'<span class="tag tag-red">是</span>':'否')+'</td>';
    execBody.appendChild(tr);
  });
}

// --- YARA Page Logic ---

function handleYaraFileUpload(event) {
  uploadYaraFiles(Array.from(event.target.files || []), event);
}

function handleYaraFolderUpload(event) {
  const all = Array.from(event.target.files || []);
  const ruleFiles = all.filter(f => {
    const n = f.name.toLowerCase();
    return n.endsWith('.yar') || n.endsWith('.yara') || n.endsWith('.rule');
  });
  if (all.length > 0 && ruleFiles.length === 0) {
    flash(t('yaraNoRuleInFolder')); event.target.value = ''; return;
  }
  uploadYaraFiles(ruleFiles, event);
}

async function uploadYaraFiles(files, event) {
  if (!files || files.length === 0) return;
  const badge = document.getElementById('yaraStatusBadge');
  const msg = document.getElementById('yaraMsg');
  badge.textContent = t('yaraLoading'); badge.style.background = '#4a3000'; badge.style.color = '#ffd600';
  msg.textContent = t('yaraFolderUploading').replace('%d', files.length); msg.style.color = '#ffd600';

  // Upload all files (save only, no re-parse per file)
  for (const file of files) {
    const form = new FormData();
    form.append('rulefile', file);
    try {
      const resp = await fetch('/api/yara/upload', { method: 'POST', body: form });
      const data = await resp.json();
      if (!data.ok) {
        msg.textContent = t('yaraLoadFail') + ': ' + (data.error||''); msg.style.color = '#ff1744';
        badge.textContent = t('yaraLoadFail'); badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
        event.target.value = ''; return;
      }
    } catch(e) {
      msg.textContent = t('yaraUploadErr') + e.message; msg.style.color = '#ff1744';
      event.target.value = ''; return;
    }
  }

  // Single reload after all files saved
  try {
    const resp = await fetch('/api/yara/reload', { method: 'POST' });
    const data = await resp.json();
    if (data.ok) {
      badge.textContent = data.rules + t('yaraRulesLoaded'); badge.style.background = '#1a3a1a'; badge.style.color = '#a5d6a7';
      msg.textContent = t('yaraFilesDone').replace('%d', files.length); msg.style.color = '#4caf50';
      document.getElementById('yaraScanBtn').disabled = false;
    } else {
      badge.textContent = t('yaraLoadFail'); badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
      msg.textContent = data.error || t('yaraLoadFail'); msg.style.color = '#ff1744';
    }
  } catch(e) {
    badge.textContent = t('yaraLoadFail'); badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
    msg.textContent = e.message; msg.style.color = '#ff1744';
  }
  event.target.value = '';
}

async function loadYaraFromPath() {
  const path = document.getElementById('yaraPathInput').value.trim();
  if (!path) { flash(t('yaraPathPH')); return; }
  const badge = document.getElementById('yaraStatusBadge');
  const msg = document.getElementById('yaraMsg');
  badge.textContent = t('yaraLoading'); badge.style.background = '#4a3000'; badge.style.color = '#ffd600';
  try {
    const resp = await fetch('/api/yara/loadpath', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({path: path})
    });
    const data = await resp.json();
    if (data.ok) {
      badge.textContent = data.rules + t('yaraRulesLoaded'); badge.style.background = '#1a3a1a'; badge.style.color = '#a5d6a7';
      msg.textContent = t('yaraPathLoaded').replace('%s', path); msg.style.color = '#4caf50';
      document.getElementById('yaraScanBtn').disabled = false;
    } else {
      badge.textContent = t('yaraLoadFail'); badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
      msg.textContent = data.error || t('yaraLoadFail'); msg.style.color = '#ff1744';
    }
  } catch(e) {
    badge.textContent = t('yaraLoadFail'); badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
    msg.textContent = e.message; msg.style.color = '#ff1744';
  }
}

let yaraPolling = null;
async function startYaraScan() {
  const btn = document.getElementById('yaraScanBtn');
  const msg = document.getElementById('yaraMsg');
  const progArea = document.getElementById('yaraProgressArea');
  btn.disabled = true; btn.textContent = t('yaraLoading');
  progArea.style.display = 'block';
  msg.textContent = t('yaraScanRunning'); msg.style.color = '#ffd600';

  try {
    const resp = await fetch('/api/yara/scanall', { method: 'POST' });
    const data = await resp.json();
    if (!data.ok) {
      msg.textContent = data.error || t('yaraLoadFail'); msg.style.color = '#ff1744';
      btn.disabled = false; btn.textContent = t('yaraScanAll');
      progArea.style.display = 'none';
      return;
    }
    yaraPolling = setInterval(pollYaraProgress, 500);
  } catch(e) {
    msg.textContent = t('yaraUploadErr') + e.message; msg.style.color = '#ff1744';
    btn.disabled = false; btn.textContent = t('yaraScanAll');
    progArea.style.display = 'none';
  }
}

async function pollYaraProgress() {
  try {
    const resp = await fetch('/api/yara/progress');
    const data = await resp.json();
    const fill = document.getElementById('yaraProgressFill');
    const text = document.getElementById('yaraProgressText');
    const pct = data.total > 0 ? (data.current / data.total * 100) : 0;
    fill.style.width = pct + '%';
    text.textContent = data.current + ' / ' + data.total;

    if (!data.running) {
      clearInterval(yaraPolling); yaraPolling = null;
      onYaraScanDone();
    }
  } catch(e) {}
}

async function onYaraScanDone() {
  const btn = document.getElementById('yaraScanBtn');
  const msg = document.getElementById('yaraMsg');
  const progArea = document.getElementById('yaraProgressArea');
  const fill = document.getElementById('yaraProgressFill');
  fill.style.width = '100%';
  btn.disabled = false; btn.textContent = t('yaraScanAll');

  try {
    const resp = await fetch('/api/yara/results');
    const items = await resp.json();
    renderYaraResults(items || []);
    const cnt = (items||[]).length;
    msg.textContent = t('yaraScanDone') + (cnt > 0 ? cnt + t('yaraObjMatch') : t('yaraNoMatch'));
    msg.style.color = cnt > 0 ? '#ff9100' : '#4caf50';
    const badge = document.getElementById('yaraStatusBadge');
    if (cnt > 0) {
      badge.textContent = cnt + t('yaraHits'); badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
    }
    // Also refresh exec objects
    const r = await fetch('/api/execobjects').then(r=>r.json());
    allExec = r || [];
    document.getElementById('badge_execobj').textContent = allExec.length;
  } catch(e) {}

  setTimeout(() => { progArea.style.display = 'none'; }, 2000);
}

function renderYaraResults(items) {
  const tbody = document.getElementById('yaraResultsBody');
  const emptyMsg = document.getElementById('yaraEmptyMsg');
  if (items.length === 0) {
    tbody.innerHTML = '';
    emptyMsg.style.display = 'block';
    return;
  }
  emptyMsg.style.display = 'none';
  const frag = document.createDocumentFragment();
  items.forEach((item, i) => {
    const tr = document.createElement('tr');
    tr.className = 'risk-' + (item.RiskLevel||'low').toLowerCase();
    tr.onclick = () => {
      document.querySelectorAll('#yaraResultsBody tr').forEach(r=>r.classList.remove('selected'));
      tr.classList.add('selected');
    };
    tr.ondblclick = () => showYaraDetail(item);
    // Extract rule names from hits
    let ruleNames = '';
    if (item.Hits && Array.isArray(item.Hits)) {
      ruleNames = item.Hits.map(h => h.RuleName).join(', ');
    }
    const status = item.IsRunning ? '<span class="tag tag-red">运行中</span>' : '<span class="tag tag-blue">未运行</span>';
    tr.innerHTML =
      '<td>'+esc(RL[item.RiskLevel]||item.RiskLevel)+'</td>'+
      '<td>'+item.Score+'</td>'+
      '<td><strong style="color:#e94560">'+item.YaraScore+'</strong></td>'+
      '<td>'+status+'</td>'+
      '<td title="'+esc(item.Path)+'">'+esc(item.Path)+'</td>'+
      '<td>'+esc(item.Location)+'</td>'+
      '<td>'+esc(item.Signer)+'</td>'+
      '<td title="'+esc(ruleNames)+'">'+esc(ruleNames)+'</td>'+
      '<td title="'+esc((item.Reasons||[]).join('; '))+'">'+esc((item.Reasons||[]).join('; '))+'</td>';
    frag.appendChild(tr);
  });
  tbody.innerHTML = '';
  tbody.appendChild(frag);
}

function showYaraDetail(item) {
  document.getElementById('modalTitle').textContent = 'YARA 命中详情: ' + item.Path;
  let h = '';
  h += sec('文件信息', [['路径',item.Path,1],['位置',item.Location],['签名',item.Signed?'是':'否'],['签名者',item.Signer],['状态',item.IsRunning?'运行中':'未运行']]);
  h += '<div class="detail-section"><h3>YARA 命中规则 (YARA评分: '+item.YaraScore+')</h3>';
  if (item.Hits && Array.isArray(item.Hits)) {
    item.Hits.forEach(hit => {
      h += '<div class="detail-row" style="padding:6px 0;border-bottom:1px solid #1e2a4a"><div class="detail-value">';
      h += '<span class="tag tag-red" style="font-size:13px">'+esc(hit.RuleName)+'</span>';
      if ((hit.Tags||[]).length) h += ' <span class="tag tag-orange">'+esc(hit.Tags.join(', '))+'</span>';
      if (hit.Meta) { const desc = hit.Meta.description||hit.Meta.desc||''; if (desc) h += '<br><span style="color:#888;font-size:11px">'+esc(desc)+'</span>'; }
      if ((hit.Strings||[]).length) h += '<br><span style="color:#64b5f6;font-size:11px">匹配: '+esc(hit.Strings.join(', '))+'</span>';
      h += '</div></div>';
    });
  }
  h += '</div>';
  h += reasonBlock(item.Score, item.RiskLevel, item.Reasons);
  document.getElementById('modalBody').innerHTML = h;
  document.getElementById('modalOverlay').classList.add('show');
}

// Single file YARA scan (right-click menu)
async function yaraScan() {
  const s = getSelectedPath();
  if (!s || !s.path) return;
  try {
    const resp = await fetch('/api/yara/scanone', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ path: s.path })
    });
    const data = await resp.json();
    if (!data.ok) { flash('YARA: '+(data.error||'未加载')); return; }
    if (data.count === 0) { flash('YARA: 未命中任何规则'); return; }
    flash('YARA: 命中 '+data.count+' 条规则');
    // Show detail modal
    let h = '<div class="detail-section"><h3>YARA 扫描结果 ('+data.count+' 条命中)</h3>';
    (data.hits||[]).forEach(hit => {
      h += '<div class="detail-row"><div class="detail-value">';
      h += '<span class="tag tag-red">'+esc(hit.RuleName)+'</span>';
      if ((hit.Tags||[]).length) h += ' <span class="tag tag-orange">'+esc(hit.Tags.join(','))+'</span>';
      if ((hit.Strings||[]).length) h += ' 匹配: '+esc(hit.Strings.join(', '));
      h += '</div></div>';
    });
    h += '</div>';
    document.getElementById('modalTitle').textContent = 'YARA 扫描: ' + s.path;
    document.getElementById('modalBody').innerHTML = h;
    document.getElementById('modalOverlay').classList.add('show');
  } catch(e) { flash('YARA出错: '+e.message); }
}

// On page load, check YARA status
(async function checkYaraStatus() {
  try {
    const resp = await fetch('/api/yara/status');
    const data = await resp.json();
    if (data.loaded) {
      const badge = document.getElementById('yaraStatusBadge');
      badge.textContent = data.rules + ' 条规则已加载';
      badge.style.background = '#1a3a1a'; badge.style.color = '#a5d6a7';
      document.getElementById('yaraScanBtn').disabled = false;
    }
  } catch(e) {}
})();
function exportCSV() { window.open('/api/export','_blank'); }

async function checkUpdate() {
  const btn = document.getElementById('btnUpdate');
  btn.disabled = true;
  btn.textContent = t('updateChecking');
  try {
    const resp = await fetch('/api/checkupdate');
    const data = await resp.json();
    if (!data.ok) {
      flash(t('updateFail') + ': ' + (data.error||'')); return;
    }
    document.getElementById('versionLabel').textContent = 'v' + data.current;
    if (data.hasUpdate) {
      const msg = t('updateAvail').replace('%s', data.latest);
      if (confirm(msg)) {
        window.open(data.releaseURL, '_blank');
      }
    } else {
      flash(t('updateLatest') + ' (v' + data.current + ')');
    }
  } catch(e) {
    flash(t('updateFail'));
  } finally {
    btn.disabled = false;
    btn.textContent = t('checkUpdate');
  }
}

function flash(msg) { document.getElementById('statusText').textContent=msg; setTimeout(()=>render(),2000); }

// Detail views
function showDetail() {
  if (currentView==='process') showProcDetail();
  else if (currentView==='trigger') showTrigDetail(selIdx);
  else if (currentView==='forensic') showForeDetail(selIdx);
  else if (currentView==='event') showEvtDetail(selIdx);
  else if (currentView==='module') showModDetail(selIdx);
  else showExecDetail(selIdx);
}

function showProcDetail() {
  const r = getSelProc(); if (!r) return;
  document.getElementById('modalTitle').textContent = t('dtlProcInfo') + ': ' + r.Name + ' (PID ' + r.PID + ')';
  let h = '';
  h += sec(t('dtlProcInfo'), [[t('dtlProcName'),r.Name],[t('dtlPID'),r.PID],[t('dtlParent'),r.PPID+(r.ParentName?' ('+r.ParentName+')':'')],[t('dtlPath'),r.Path,1],[t('dtlCmd'),r.CommandLine,1],[t('dtlUser'),r.User],[t('dtlStartTime'),r.StartTime]]);
  h += sec(t('dtlFileInfo'), [[t('dtlSHA256'),r.SHA256,1],[t('dtlMD5'),r.MD5,1],[t('dtlFileSize'),r.FileSize?r.FileSize+' '+t('dtlBytes'):''],[t('dtlModTime'),r.FileModTime]]);
  h += sec(t('dtlSignInfo'), [[t('dtlSigned'),r.Signed?'✓ '+t('yes'):'✗ '+t('no')],[t('dtlValid'),r.SignValid?'✓ '+t('yes'):'✗ '+t('no')],[t('dtlSigner'),r.Signer],[t('dtlCompany'),r.Company],[t('dtlProduct'),r.Product],[t('dtlOrigName'),r.OriginalName]]);
  h += sec(t('dtlContextAnalysis'), [[t('dtlLOLBin'),r.IsLOLBin?'<span class="tag tag-orange">'+t('yes')+'</span>':t('no')],[t('dtlPathAbnormal'),r.PathAbnormal?'<span class="tag tag-red">'+t('yes')+'</span>':t('no')],[t('dtlMasquerade'),r.IsMasquerade?'<span class="tag tag-red">'+t('yes')+'</span>':t('no')],[t('dtlAbnormalParent'),r.AbnormalParentChain?'<span class="tag tag-red">'+t('yes')+'</span>':t('no')]]);
  h += sec(t('dtlNetConn'), [[t('dtlHasNetwork'),r.HasNetwork?t('yes'):t('no')],[t('dtlRemoteIP'),(r.RemoteIPs||[]).join(', ')],[t('dtlPublicIP'),r.HasPublicIP?'<span class="tag tag-red">'+t('yes')+'</span>':t('no')]]);
  h += reasonBlock(r.RiskScore, r.RiskLevel, r.Reasons);
  if (r.SHA256) h += '<div class="detail-section"><h3>VirusTotal</h3><div class="detail-row"><div class="detail-value"><a href="https://www.virustotal.com/gui/file/'+r.SHA256+'" target="_blank">'+t('dtlVTView')+'</a></div></div></div>';
  document.getElementById('modalBody').innerHTML = h;
  document.getElementById('modalOverlay').classList.add('show');
}

function showTrigDetail(i) {
  const t = filtTrig[i]; if (!t) return;
  document.getElementById('modalTitle').textContent = '触发器详情: ' + (TT[t.Type]||t.Type) + ' - ' + t.Name;
  let h = '';
  h += sec('基本信息', [['类型',TT[t.Type]||t.Type],['名称',t.Name],['路径',t.Path,1],['命令行',t.CommandLine,1],['详情',t.Detail]]);
  if (t.Type==='Task') h += sec('计划任务详情', [['作者',t.TaskAuthor],['描述',t.TaskDescription],['触发方式',t.TaskTriggerType],['运行账户',t.TaskRunAs],['隐藏',t.TaskHidden?'<span class="tag tag-red">是</span>':'否'],['执行间隔',t.TaskInterval],['上次运行',t.TaskLastRun],['下次运行',t.TaskNextRun]]);
  if (t.Type==='Service') h += sec('服务详情', [['启动类型',t.ServiceStartType],['运行账户',t.ServiceAccount],['状态',t.ServiceState],['ServiceDLL',t.ServiceDLL]]);
  if (t.Type==='WMI') h += sec('WMI详情', [['过滤器',t.WMIFilterName],['过滤查询',t.WMIFilterQuery],['消费者',t.WMIConsumerName],['消费者命令',t.WMIConsumerCmd]]);
  h += reasonBlock(t.Score, riskLevelFromScore(t.Score), t.Reasons);
  document.getElementById('modalBody').innerHTML = h;
  document.getElementById('modalOverlay').classList.add('show');
}

function showExecDetail(i) {
  const e = filtExec[i]; if (!e) return;
  document.getElementById('modalTitle').textContent = t('dtlDetail') + ': ' + (e.Path||e.CommandLine);
  let h = '';
  h += sec(t('dtlBasicInfo'), [[t('dtlPath'),e.Path,1],[t('dtlType'),e.ObjType],[t('colLocation'),e.LocationType],[t('colStatus'),e.IsRunning?'<span class="tag tag-red">'+t('running')+'</span>':'<span class="tag tag-blue">'+t('notRunning')+'</span>'],['PID',(e.PIDs||[]).join(', ')],[t('dtlSources'),(e.Sources||[]).join(', ')]]);
  h += sec(t('dtlFileInfo'), [['SHA256',e.SHA256,1],['MD5',e.MD5,1],[t('dtlExists'),e.Exists?t('yes'):t('no')]]);
  h += sec(t('dtlSignInfo'), [[t('dtlSigned'),e.Signed?'✓ '+t('yes'):'✗ '+t('no')],[t('dtlValid'),e.SignValid?'✓ '+t('yes'):'✗ '+t('no')],[t('dtlSigner'),e.Signer],[t('dtlCompany'),e.Company]]);
  h += sec(t('dtlNetInfo'), [[t('dtlHasNetwork'),e.NetworkObserved?t('yes'):t('no')],[t('dtlRemoteIP'),(e.RemoteIPs||[]).join(', ')],[t('dtlPublicIP'),e.HasPublicIP?'<span class="tag tag-red">'+t('yes')+'</span>':t('no')]]);
  if ((e.Triggers||[]).length > 0) {
    h += '<div class="detail-section"><h3>'+t('colTriggers')+' ('+e.Triggers.length+')</h3>';
    e.Triggers.forEach(tr => { h += '<div class="detail-row"><div class="detail-value"><span class="tag tag-orange">['+esc(TT[tr.Type]||tr.Type)+'] '+esc(tr.Name)+'</span> '+esc(tr.Detail)+'</div></div>'; });
    h += '</div>';
  }
  h += '<div class="detail-section"><h3>'+t('dtlScoreCompose')+'</h3>';
  h += '<div class="detail-row"><div class="detail-label">'+t('dtlExecScore')+'</div><div class="detail-value">'+e.ExecutionScore+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">'+t('dtlTrigScore')+'</div><div class="detail-value">'+e.TriggerScore+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">'+t('dtlForeScore')+'</div><div class="detail-value">'+e.ForensicScore+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">'+t('dtlYaraScore')+'</div><div class="detail-value">'+e.YaraScore+(e.YaraMatched?' <span class="tag tag-red">YARA</span>':'')+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">'+t('dtlEvtScore')+'</div><div class="detail-value">'+e.EventScore+(e.EventCount>0?' ('+e.EventCount+')':'')+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">'+t('dtlModScore')+'</div><div class="detail-value">'+e.DLLHijackScore+(e.HasDLLHijack?' <span class="tag tag-red">'+t('dtlDLLHijack')+'</span>':'')+(e.SuspiciousModuleCount>0?' ('+e.SuspiciousModuleCount+')':'')+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">'+t('dtlSynergy')+'</div><div class="detail-value">+'+e.SynergyBonus+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">'+t('dtlWhiteReduce')+'</div><div class="detail-value">-'+e.WhiteReduction+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label"><strong>'+t('dtlFinalScore')+'</strong></div><div class="detail-value"><strong>'+e.FinalScore+'</strong></div></div>';
  h += '</div>';
  h += reasonBlock(e.FinalScore, e.RiskLevel, e.Reasons);
  if (e.SHA256) h += '<div class="detail-section"><h3>VirusTotal</h3><div class="detail-row"><div class="detail-value"><a href="https://www.virustotal.com/gui/file/'+e.SHA256+'" target="_blank">在 VirusTotal 中查看</a></div></div></div>';
  document.getElementById('modalBody').innerHTML = h;
  document.getElementById('modalOverlay').classList.add('show');
}

function showForeDetail(i) {
  const f = filtFore[i]; if (!f) return;
  const srcCN = FS[f.Source] || f.Source;
  document.getElementById('modalTitle').textContent = '取证详情: ' + srcCN + ' - ' + (f.Path||f.Detail);
  let h = '';
  h += sec('基本信息', [['来源',srcCN],['路径',f.Path,1],['详情',f.Detail]]);
  if (f.Source==='Prefetch') h += sec('Prefetch信息', [['可执行文件名',f.ExeName],['最后执行时间',f.LastRunTime],['首次发现',f.FirstSeen],['文件大小',f.FileSize?f.FileSize+' 字节':'']]);
  if (f.Source==='EventLog') h += sec('事件日志', [['事件ID',f.EventID],['事件时间',f.EventTime],['事件源',f.EventSource],['命令行',f.CommandLine,1]]);
  if (f.Source==='RecentFile') h += sec('文件信息', [['修改时间',f.FileModTime],['文件大小',f.FileSize?f.FileSize+' 字节':''],['文件类型',f.FileType]]);
  if (f.Source==='Module') h += sec('模块信息', [['进程PID',f.ProcessPID],['进程名',f.ProcessName],['模块路径',f.ModulePath,1],['签名',f.ModuleSigned?'是':'否'],['签发者',f.ModuleSigner]]);
  h += reasonBlock(f.Score, riskLevelFromScore(f.Score), f.Reasons);
  document.getElementById('modalBody').innerHTML = h;
  document.getElementById('modalOverlay').classList.add('show');
}

function reasonBlock(score, level, reasons) {
  const lv = RL[level]||level;
  let h = '<div class="detail-section"><h3>'+t('dtlRiskAssess')+'</h3>';
  h += '<div class="detail-row"><div class="detail-label">'+t('dtlScore')+'</div><div class="detail-value"><strong>'+score+'</strong></div></div>';
  h += '<div class="detail-row"><div class="detail-label">'+t('dtlLevel')+'</div><div class="detail-value"><span class="tag tag-'+(level==='Critical'?'red':level==='High'?'orange':level==='Medium'?'orange':'blue')+'">'+esc(lv)+'</span></div></div>';
  if ((reasons||[]).length > 0) {
    h += '<div class="detail-row"><div class="detail-label">'+t('dtlReasons')+'</div><div class="detail-value">';
    reasons.forEach(r => { h += '<div class="tag tag-red" style="display:block;margin:2px 0">'+esc(r)+'</div>'; });
    h += '</div></div>';
  }
  h += '</div>';
  return h;
}

function sec(title, rows) {
  let h = '<div class="detail-section"><h3>'+title+'</h3>';
  rows.forEach(([l,v,mono]) => { h += '<div class="detail-row"><div class="detail-label">'+l+'</div><div class="detail-value'+(mono?' mono':'')+'">'+(!v&&v!==0?'-':esc(String(v)))+'</div></div>'; });
  return h + '</div>';
}

function closeModal(e) { if (e.target===document.getElementById('modalOverlay')) document.getElementById('modalOverlay').classList.remove('show'); }
document.addEventListener('keydown', e => { if (e.key==='Escape') { document.getElementById('modalOverlay').classList.remove('show'); document.getElementById('ctxMenu').classList.remove('show'); } });
function esc(s) { if (!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// --- AI Chat Logic ---

const AI_SYSTEM_PROMPT_ZH = '你是资深Windows应急响应专家。用户是安全工程师，使用ProcIR工具排查。回复要求：\n1. 极度精简，不要废话，不要解释基础概念\n2. 直接给结论：有威胁/无威胁/需关注\n3. 用表格或列表呈现，每条一行：进程名+判定+原因\n4. 只报告真正可疑的，正常系统进程不用提\n5. 处置建议只写具体动作，如「kill PID xxx」「删除该计划任务」「排查该外连IP」\n6. 如果没有明显威胁，直接说「未发现明显威胁」，不要凑字数';

const AI_SYSTEM_PROMPT_EN = 'You are a senior Windows incident response expert. The user is a security engineer using ProcIR for investigation. The scan data may contain Chinese-language annotations from the backend detection engine - interpret them and always respond in English. Requirements:\n1. Be extremely concise, no fluff, no basic concept explanations\n2. Give direct conclusions: threat/no threat/needs attention\n3. Use tables or lists, one line per item: process name + verdict + reason\n4. Only report truly suspicious items, skip normal system processes\n5. Remediation advice should be specific actions like "kill PID xxx", "delete scheduled task", "investigate outbound IP"\n6. If no obvious threat, just say "No obvious threats found"';

function getAISystemPrompt() { return curLang === 'en' ? AI_SYSTEM_PROMPT_EN : AI_SYSTEM_PROMPT_ZH; }

let aiChatHistory = [];
let aiTotalTokens = 0;
let aiSending = false;

function updateAIPanel(lang) {
  const titleEl = document.querySelector('#view_ai h3');
  const badgeEl = document.getElementById('aiStatusBadge');
  const keyInput = document.getElementById('aiApiKey');
  const modelSelect = document.getElementById('aiModel');
  const saveLabel = document.querySelector('#aiSaveKey').parentElement;
  const clearBtn = document.querySelector('#view_ai .btn[onclick="clearAIChat()"]');
  const sendDataBtn = document.querySelector('#view_ai .btn[onclick="sendScanData()"]');
  const sendBriefBtn = document.querySelector('#view_ai .btn[onclick="sendScanDataBrief()"]');
  const aiInput = document.getElementById('aiInput');
  const sendBtn = document.getElementById('aiSendBtn');
  const welcome = document.getElementById('aiWelcome');

  if (lang === 'en') {
    titleEl.textContent = 'Claude AI';
    keyInput.placeholder = t('aiKeyPH');
    modelSelect.innerHTML = '<option value="claude-sonnet-4-6" selected>Sonnet 4.6</option><option value="claude-opus-4-6">Opus 4.6</option><option value="claude-haiku-4-5-20251001">Haiku 4.5</option>';
    saveLabel.lastChild.textContent = ' ' + t('aiRememberKey');
  } else {
    titleEl.textContent = 'MiniMax AI';
    keyInput.placeholder = t('aiKeyPH');
    modelSelect.innerHTML = '<option value="MiniMax-M2.5">M2.5</option><option value="MiniMax-M2.5-highspeed">M2.5 高速</option><option value="MiniMax-M2.7" selected>M2.7</option><option value="MiniMax-M2.7-highspeed">M2.7 高速</option>';
    saveLabel.lastChild.textContent = ' ' + t('aiRememberKey');
  }

  badgeEl.textContent = t('aiReady');
  document.querySelector('#view_ai label[style*="white-space:nowrap"][style*="font-size:12px"]').textContent = t('aiModel');
  clearBtn.textContent = t('aiClearChat');
  sendDataBtn.textContent = t('aiSendData');
  sendBriefBtn.textContent = t('aiSendBrief');
  aiInput.placeholder = t('aiInputPH');
  sendBtn.textContent = t('aiSend');

  if (welcome && welcome.style.display !== 'none') {
    welcome.innerHTML = '<div style="font-size:16px;margin-bottom:12px;color:#e94560">'+t('aiWelcomeTitle')+'</div><div style="margin-bottom:8px">'+t('aiWelcomeMsg')+'</div><div style="font-size:11px;color:#555">'+t('aiWelcomeHint')+'</div>';
  }

  // Load saved key for current provider
  const keyName = lang === 'en' ? 'procir_claude_key' : 'procir_minimax_key';
  const saved = localStorage.getItem(keyName);
  keyInput.value = saved || '';
  document.getElementById('aiSaveKey').checked = !!saved;
}

(function() {
  const keyName = curLang === 'en' ? 'procir_claude_key' : 'procir_minimax_key';
  const saved = localStorage.getItem(keyName);
  if (saved) { document.getElementById('aiApiKey').value = saved; document.getElementById('aiSaveKey').checked = true; }
})();

function toggleAISaveKey() {
  const keyName = curLang === 'en' ? 'procir_claude_key' : 'procir_minimax_key';
  if (document.getElementById('aiSaveKey').checked) {
    const key = document.getElementById('aiApiKey').value;
    if (key) localStorage.setItem(keyName, key);
  } else {
    localStorage.removeItem(keyName);
  }
}

function aiInputKeydown(e) {
  if (e.key === 'Enter' && e.ctrlKey) { e.preventDefault(); sendAIMessage(); }
}

function renderAIMd(text) {
  let h = esc(text);
  h = h.replace(/^### (.+)$/gm, '<h4 style="color:#e94560;margin:12px 0 6px 0;font-size:13px">$1</h4>');
  h = h.replace(/^## (.+)$/gm, '<h3 style="color:#e94560;margin:14px 0 8px 0;font-size:14px;border-bottom:1px solid #0f3460;padding-bottom:4px">$1</h3>');
  h = h.replace(/^# (.+)$/gm, '<h2 style="color:#e94560;margin:16px 0 10px 0;font-size:15px">$1</h2>');
  h = h.replace(/\*\*(.+?)\*\*/g, '<strong style="color:#ffd600">$1</strong>');
  h = h.replace(/^(\d+)\. (.+)$/gm, '<div style="padding:1px 0 1px 18px"><span style="color:#e94560">$1.</span> $2</div>');
  h = h.replace(/^- (.+)$/gm, '<div style="padding:1px 0 1px 14px"><span style="color:#64b5f6;margin-right:5px">&#8226;</span>$1</div>');
  h = h.replace(/\n{2,}/g, '<div style="height:8px"></div>');
  h = h.replace(/\n/g, '<br>');
  return h;
}

function appendChatBubble(role, content, isLoading) {
  const area = document.getElementById('aiChatArea');
  const welcome = document.getElementById('aiWelcome');
  if (welcome) welcome.style.display = 'none';

  const bubble = document.createElement('div');
  bubble.style.cssText = 'display:flex;gap:10px;' + (role==='user' ? 'flex-direction:row-reverse' : '');

  const avatar = document.createElement('div');
  avatar.style.cssText = 'width:32px;height:32px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:bold;';
  if (role === 'user') {
    avatar.style.background = '#0f3460'; avatar.textContent = 'U';
  } else {
    avatar.style.background = '#e94560'; avatar.textContent = 'AI';
  }

  const msg = document.createElement('div');
  msg.style.cssText = 'max-width:75%;padding:10px 14px;border-radius:10px;font-size:13px;line-height:1.7;word-break:break-word;';
  if (role === 'user') {
    msg.style.background = '#0f3460'; msg.style.color = '#e0e0e0';
    msg.textContent = content;
  } else {
    msg.style.background = '#1e2a4a'; msg.style.color = '#e0e0e0';
    if (isLoading) {
      msg.innerHTML = '<span style="color:#ffd600">'+t('aiThinking')+'</span>';
      msg.id = 'aiLoadingBubble';
    } else {
      msg.innerHTML = renderAIMd(content);
    }
  }

  bubble.appendChild(avatar);
  bubble.appendChild(msg);
  area.appendChild(bubble);
  area.scrollTop = area.scrollHeight;
  return msg;
}

function buildScanDataFull() {
  let p = t('aiDataIntro') + '\n\n';

  const {c,h,m,s} = countRiskLevels();
  p += '## ' + t('aiOverall') + '\n';
  p += t('aiProcess') + allProc.length + ' (' + t('statCrit')+c+' '+t('statHigh')+h+' '+t('statMed')+m+' '+t('statSusp')+s+') | ' + t('aiTrigger') + allTrig.length + ' | ' + t('aiChain') + allChain.length + ' | IOC:' + allIOC.length + ' | ' + t('statEvt') + allEvt.length + '\n\n';

  const highRisk = [], medRisk = [];
  allProc.forEach(r => {
    if (r.RiskLevel==='Critical' || r.RiskLevel==='High') highRisk.push(r);
    else if (r.RiskLevel==='Medium') medRisk.push(r);
  });
  if (highRisk.length > 0) {
    p += '## ' + t('aiHighProc') + ' (' + highRisk.length + ')\n';
    highRisk.slice(0, 30).forEach(r => {
      p += '- [' + r.RiskLevel + '/' + r.RiskScore + '] ' + r.Name + ' PID:' + r.PID;
      if (r.Path) p += ' ' + r.Path;
      if (r.Signer) p += ' ' + t('aiSigned') + r.Signer; else p += ' ' + t('aiUnsigned');
      if (r.HasPublicIP) p += ' ' + t('aiPublic');
      if (r.IsLOLBin) p += ' [LOLBin]';
      if ((r.Reasons||[]).length) p += ' | ' + r.Reasons.join('; ');
      if (r.CommandLine) p += '\n  CMD: ' + r.CommandLine;
      p += '\n';
    });
    p += '\n';
  }

  if (medRisk.length > 0) {
    p += '## ' + t('aiMedProc') + ' (' + medRisk.length + ')\n';
    medRisk.slice(0, 15).forEach(r => {
      p += '- [' + r.RiskScore + '] ' + r.Name + ' PID:' + r.PID + ' ' + (r.Path||'');
      if ((r.Reasons||[]).length) p += ' | ' + r.Reasons.join('; ');
      p += '\n';
    });
    p += '\n';
  }

  const highTrig = allTrig.filter(tr => tr.Score >= 20).sort((a,b) => b.Score - a.Score);
  if (highTrig.length > 0) {
    p += '## ' + t('aiSuspTrig') + ' (' + highTrig.length + ')\n';
    highTrig.slice(0, 20).forEach(tr => {
      p += '- [' + tr.Score + '][' + (TT[tr.Type]||tr.Type) + '] ' + tr.Name;
      if (tr.Path) p += ' ' + tr.Path;
      if (tr.CommandLine) p += ' CMD:' + tr.CommandLine;
      if ((tr.Reasons||[]).length) p += ' | ' + tr.Reasons.join('; ');
      p += '\n';
    });
    p += '\n';
  }

  if (allChain.length > 0) {
    p += '## ' + t('aiBehavior') + '\n';
    allChain.forEach(c => {
      p += '- [' + c.PatternScore + '] ' + c.PatternName + ': ' + (c.Evidence||[]).join(' -> ');
      p += '\n';
    });
    p += '\n';
  }

  if (allIOC.length > 0) {
    p += '## IOC (' + allIOC.length + ')\n';
    allIOC.slice(0, 30).forEach(i => {
      p += '- [' + (IOT[i.Type]||i.Type) + '] ' + i.Value + (i.SourceObject?' ('+i.SourceObject+')':'') + '\n';
    });
    p += '\n';
  }

  const highExec = allExec.filter(e => e.FinalScore >= 40).sort((a,b) => b.FinalScore - a.FinalScore);
  if (highExec.length > 0) {
    p += '## ' + t('aiHighExec') + ' (' + highExec.length + ')\n';
    highExec.slice(0, 20).forEach(e => {
      p += '- [' + (e.RiskLevel||'?') + '/' + e.FinalScore + '] ' + (e.Path||'?');
      p += ' ' + (e.IsRunning ? t('aiRunning') : t('aiNotRunning'));
      if (e.Signed) p += ' ' + t('aiSigned') + (e.Signer||t('yes')); else p += ' ' + t('aiUnsigned');
      if (e.TriggerCount>0) p += ' ' + t('colTriggers') + ':' + e.TriggerCount + '(' + (e.TriggerTypes||[]).map(tp=>TT[tp]||tp).join('+') + ')';
      if (e.NetworkObserved) p += ' ' + t('aiHasNet');
      if (e.HasPublicIP) p += ' ' + t('aiPublic');
      if (e.YaraMatched) p += ' ' + t('aiYaraHit');
      if (e.HasDLLHijack) p += ' ' + t('aiDLLHijack');
      p += ' ' + t('aiScoreBreak') + t('aiExec') + e.ExecutionScore + '/' + t('aiTrig') + e.TriggerScore + '/' + t('aiForensic') + e.ForensicScore + '/' + t('aiEvent') + e.EventScore + '/' + t('aiModule') + e.DLLHijackScore;
      if ((e.Reasons||[]).length) p += '\n  ' + t('aiReasonLabel') + ' ' + e.Reasons.join('; ');
      p += '\n';
    });
    p += '\n';
  }

  const suspMod = allMod.filter(m => m.Score >= 20 || m.HasDLLHijack).sort((a,b) => b.Score - a.Score);
  if (suspMod.length > 0) {
    p += '## ' + t('aiSuspMod') + ' (' + suspMod.length + ')\n';
    suspMod.slice(0, 15).forEach(m => {
      p += '- [' + m.Score + '] ' + m.ExeName + '(PID:' + m.PID + ') ' + (m.ExePath||'');
      if (m.HasDLLHijack) p += ' ' + t('aiDLLHijack');
      p += ' ' + t('aiSuspDLL') + m.SuspiciousCount + '/' + m.TotalModules;
      if (!m.ExeSigned) p += ' ' + t('aiHostUnsigned');
      if ((m.Reasons||[]).length) p += ' | ' + m.Reasons.join('; ');
      p += '\n';
    });
    p += '\n';
  }

  const suspFore = allFore.filter(f => f.Score >= 20).sort((a,b) => b.Score - a.Score);
  if (suspFore.length > 0) {
    p += '## ' + t('aiSuspFore') + ' (' + suspFore.length + ')\n';
    suspFore.slice(0, 15).forEach(f => {
      const srcLabel = FS[f.Source] || f.Source;
      p += '- [' + f.Score + '][' + srcLabel + '] ' + (f.Path||f.Detail||'');
      const tm = f.EventTime || f.LastRunTime || f.FileModTime || '';
      if (tm) p += ' ' + t('aiTime') + tm;
      if ((f.Reasons||[]).length) p += ' | ' + f.Reasons.join('; ');
      p += '\n';
    });
    p += '\n';
  }

  const highEvt = allEvt.filter(e => e.Score >= 30).sort((a,b) => b.Score - a.Score);
  if (highEvt.length > 0) {
    p += '## ' + t('aiHighEvt') + ' (' + highEvt.length + ')\n';
    highEvt.slice(0, 15).forEach(e => {
      p += '- [' + e.Score + '] EID:' + e.EventID + ' ' + e.Source + ' ' + e.Time + ' ' + (e.Description||'');
      if ((e.Reasons||[]).length) p += ' | ' + e.Reasons.join('; ');
      p += '\n';
    });
  }

  return p;
}

function buildScanDataBrief() {
  const {c,h,m,s} = countRiskLevels();
  let p = t('aiBriefIntro') + ' - ' + t('aiProcess') + allProc.length + '(' + t('statCrit')+c+' '+t('statHigh')+h+' '+t('statMed')+m+' '+t('statSusp')+s+') ' + t('aiTrigger')+allTrig.length+' '+t('aiChain')+allChain.length+' IOC:'+allIOC.length+'\n\n';

  const top = allProc.filter(r => r.RiskLevel==='Critical' || r.RiskLevel==='High').slice(0,10);
  if (top.length) {
    p += t('aiBriefHighProc') + '\n';
    top.forEach(r => { p += '- ' + r.Name + '(PID:'+r.PID+') '+r.RiskLevel+'/'+r.RiskScore + (r.Signer?' '+r.Signer:' '+t('aiUnsigned')) + ' ' + ((r.Reasons||[]).join('; ')) + '\n'; });
  }
  p += '\n' + t('aiBriefQuestion');
  return p;
}

function sendScanData() {
  if (allProc.length === 0) { flash(t('aiNeedScan')); return; }
  document.getElementById('aiInput').value = buildScanDataFull();
  sendAIMessage();
}

function sendScanDataBrief() {
  if (allProc.length === 0) { flash(t('aiNeedScan')); return; }
  document.getElementById('aiInput').value = buildScanDataBrief();
  sendAIMessage();
}

async function sendAIMessage() {
  if (aiSending) return;
  const input = document.getElementById('aiInput');
  const text = input.value.trim();
  if (!text) return;

  const apiKey = document.getElementById('aiApiKey').value.trim();
  if (!apiKey) { flash(t('aiNeedKey')); return; }

  const keyName = curLang === 'en' ? 'procir_claude_key' : 'procir_minimax_key';
  if (document.getElementById('aiSaveKey').checked) {
    localStorage.setItem(keyName, apiKey);
  }

  const model = document.getElementById('aiModel').value;
  aiSending = true;

  aiChatHistory.push({role: 'user', content: text});
  appendChatBubble('user', text);
  input.value = '';
  input.style.height = 'auto';

  appendChatBubble('assistant', '', true);

  const btn = document.getElementById('aiSendBtn');
  const badge = document.getElementById('aiStatusBadge');
  btn.disabled = true; btn.textContent = '...';
  badge.textContent = t('aiRequesting'); badge.style.background = '#4a3000'; badge.style.color = '#ffd600';

  const ctx = aiChatHistory.length > 30 ? aiChatHistory.slice(-30) : aiChatHistory;
  const apiEndpoint = curLang === 'en' ? '/api/ai/claude' : '/api/ai/analyze';
  const systemPrompt = getAISystemPrompt();
  const messages = curLang === 'en' ? ctx : [{role: 'system', content: systemPrompt}, ...ctx];

  try {
    const body = curLang === 'en'
      ? { apiKey: apiKey, model: model, messages: ctx, system: systemPrompt }
      : { apiKey: apiKey, model: model, messages: messages };

    const resp = await fetch(apiEndpoint, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body)
    });
    const data = await resp.json();

    const loading = document.getElementById('aiLoadingBubble');
    if (loading) loading.parentElement.remove();

    if (!data.ok) {
      appendChatBubble('assistant', '(' + t('aiError') + ': ' + (data.error||'') + ')');
      badge.textContent = t('aiFailed'); badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
    } else {
      const content = data.content || t('aiNoReturn');
      aiChatHistory.push({role: 'assistant', content: content});
      appendChatBubble('assistant', content);
      badge.textContent = t('aiReady'); badge.style.background = '#1a3a1a'; badge.style.color = '#a5d6a7';

      const totalTk = data.totalTokens || ((data.promptTokens||0) + (data.completionTokens||0));
      if (totalTk) {
        aiTotalTokens += totalTk;
        document.getElementById('aiTokenCounter').textContent = t('aiRound') + (data.promptTokens||0) + '+' + (data.completionTokens||0) + ' | ' + t('aiTotal') + aiTotalTokens;
      }
    }
  } catch(e) {
    const loading = document.getElementById('aiLoadingBubble');
    if (loading) loading.parentElement.remove();
    appendChatBubble('assistant', '(' + t('aiError') + ': ' + e.message + ')');
    badge.textContent = t('aiError'); badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
  }

  aiSending = false;
  btn.disabled = false; btn.textContent = t('aiSend');
}

function clearAIChat() {
  aiChatHistory = [];
  aiTotalTokens = 0;
  const area = document.getElementById('aiChatArea');
  while (area.firstChild) area.removeChild(area.firstChild);
  const welcome = document.createElement('div');
  welcome.id = 'aiWelcome';
  welcome.style.cssText = 'text-align:center;padding:40px 20px;color:#666';
  welcome.innerHTML = '<div style="font-size:16px;margin-bottom:12px;color:#e94560">'+t('aiWelcomeTitle')+'</div><div style="margin-bottom:8px">'+t('aiWelcomeMsg')+'</div><div style="font-size:11px;color:#555">'+t('aiWelcomeHint')+'</div>';
  area.appendChild(welcome);
  document.getElementById('aiTokenCounter').textContent = '';
  const badge = document.getElementById('aiStatusBadge');
  badge.textContent = t('aiReady'); badge.style.background = '#333'; badge.style.color = '#888';
}
</script>
</body>
</html>`
