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
  <button class="btn" onclick="copySHA256()">复制SHA256</button>
  <button class="btn" onclick="openVT()">查询VT</button>
  <button class="btn" onclick="copyVTLink()">复制VT链接</button>
  <button class="btn" onclick="openDir()">打开目录</button>
  <button class="btn" onclick="showDetail()">详情</button>
  <div class="separator"></div>
  <button class="btn" onclick="exportCSV()">导出CSV</button>
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
  <label>筛选：</label>
  <input id="filterInput" placeholder="搜索进程名、路径、SHA256、签发者、命令行..." oninput="applyFilter()">
  <label>风险：</label>
  <select id="riskFilter" onchange="applyFilter()">
    <option value="">全部</option>
    <option value="Critical">严重</option>
    <option value="High">高危</option>
    <option value="Medium">中危</option>
    <option value="Suspicious">可疑</option>
    <option value="Low">低危</option>
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
        <!-- File upload -->
        <input type="file" id="yaraFileInput" accept=".yar,.yara,.rule" multiple style="display:none" onchange="handleYaraFileUpload(event)">
        <button class="btn btn-primary" onclick="document.getElementById('yaraFileInput').click()">选择规则文件</button>
        <!-- Path input fallback -->
        <span style="color:#666">或</span>
        <input id="yaraPathInput" placeholder="输入规则文件/目录路径" style="flex:1;min-width:200px;padding:5px 10px;background:#1a1a2e;border:1px solid #0f3460;color:#e0e0e0;border-radius:4px;font-size:13px">
        <button class="btn" onclick="loadYaraFromPath()">加载路径</button>
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
  <div class="item" onclick="copySHA256()">复制 SHA256</div>
  <div class="item" onclick="copyMD5()">复制 MD5</div>
  <div class="divider"></div>
  <div class="item" onclick="openVT()">在 VirusTotal 中查询</div>
  <div class="item" onclick="copyVTLink()">复制 VT 链接</div>
  <div class="divider"></div>
  <div class="item" onclick="openDir()">打开所在目录</div>
  <div class="item" onclick="showDetail()">查看详情</div>
  <div class="divider"></div>
  <div class="item" onclick="filterParent()">按父进程筛选</div>
  <div class="item" onclick="copyCmdLine()">复制命令行</div>
  <div class="divider"></div>
  <div class="item" onclick="yaraScan()">YARA 扫描</div>
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
const RL = { Critical:'严重', High:'高危', Medium:'中危', Suspicious:'可疑', Low:'低危' };
const TT = { RunKey:'注册表自启', Startup:'启动文件夹', Task:'计划任务', Service:'系统服务', WMI:'WMI订阅', IFEO:'IFEO劫持', Winlogon:'Winlogon' };
const FS = { Prefetch:'Prefetch', RecentFile:'最近文件', EventLog:'事件日志', Module:'加载模块' };
const TLE = { execution:'执行', trigger:'触发器', file:'文件', network:'网络', module:'模块', eventlog:'日志' };
const IOT = { ip:'IP', domain:'域名', url:'URL', base64:'Base64', filepath:'路径' };

let currentView = 'process';
let allProc=[], allTrig=[], allExec=[], allFore=[], allTL=[], allChain=[], allIOC=[], allEvt=[], allMod=[];
let filtProc=[], filtTrig=[], filtExec=[], filtFore=[], filtTL=[], filtChain=[], filtIOC=[], filtEvt=[], filtMod=[];
let selIdx = -1;

let sortState = { process:{field:'RiskScore',asc:false}, trigger:{field:'Score',asc:false}, execobj:{field:'FinalScore',asc:false}, forensic:{field:'Score',asc:false}, timeline:{field:'Time',asc:false}, chain:{field:'PatternScore',asc:false}, ioc:{field:'Type',asc:true}, event:{field:'Score',asc:false}, module:{field:'Score',asc:false} };

async function startScan() {
  const btn = document.getElementById('scanBtn');
  btn.disabled = true; btn.textContent = '扫描中...';
  document.getElementById('statusText').textContent = '正在扫描进程/触发器/历史痕迹，请稍候...';
  document.getElementById('progressBar').classList.add('scanning');

  try {
    const resp = await fetch('/api/scan', { method: 'POST' });
    const data = await resp.json();
    if (data.status === 'done') await loadAll();
  } catch(e) {
    document.getElementById('statusText').textContent = '扫描出错: ' + e.message;
  }

  btn.disabled = false; btn.textContent = '开始扫描';
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
  document.getElementById('statusText').textContent = '显示 ' + showns[currentView] + ' / ' + totals[currentView] + ' 条记录';
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
    const net = r.HasNetwork ? ((r.RemoteIPs||[]).join(',')||'仅本地') : '';
    const pers = (r.Persistence||[]).length;
    tr.innerHTML =
      '<td>'+esc(RL[r.RiskLevel]||r.RiskLevel)+'</td><td>'+r.RiskScore+'</td>'+
      '<td title="'+esc(r.Name)+'">'+esc(r.Name)+'</td><td>'+r.PID+'</td>'+
      '<td title="'+esc(par)+'">'+esc(par)+'</td>'+
      '<td title="'+esc(r.Path)+'">'+esc(r.Path)+'</td>'+
      '<td title="'+esc(r.CommandLine)+'">'+esc(r.CommandLine)+'</td>'+
      '<td title="'+esc(r.SHA256)+'">'+esc(sha)+'</td>'+
      '<td title="'+esc(r.Signer)+'">'+esc(r.Signer)+'</td>'+
      '<td>'+esc(net)+'</td><td>'+(pers>0?pers+' 项':'')+'</td>'+
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
    const status = e.IsRunning ? '运行中' : '未运行';
    const trigs = (e.TriggerTypes||[]).map(t=>TT[t]||t).join('+');
    const srcs = (e.Sources||[]).join(', ');
    const net = e.NetworkObserved ? ((e.RemoteIPs||[]).join(',')||'是') : '';
    tr.innerHTML =
      '<td>'+esc(RL[e.RiskLevel]||e.RiskLevel)+'</td><td>'+e.FinalScore+'</td>'+
      '<td>'+(e.IsRunning?'<span class="tag tag-red">运行中</span>':'<span class="tag tag-blue">未运行</span>')+'</td>'+
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

function sel(i) { selIdx=i; document.querySelectorAll('.view-panel.active tr').forEach((tr,idx)=>tr.classList.toggle('selected',idx===i)); }
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
    '<span class="critical">严重:'+c+'</span><span class="high">高危:'+h+'</span>'+
    '<span class="medium">中危:'+m+'</span><span class="suspicious">可疑:'+s+'</span>'+
    '<span>低危:'+l+'</span><span>进程:'+allProc.length+' 触发器:'+allTrig.length+' 事件:'+allEvt.length+' 行为链:'+allChain.length+' IOC:'+allIOC.length+'</span>';
}

function ctxMenu(e) { e.preventDefault(); const m=document.getElementById('ctxMenu'); m.classList.add('show'); m.style.left=e.clientX+'px'; m.style.top=e.clientY+'px'; const r=m.getBoundingClientRect(); if(r.right>window.innerWidth)m.style.left=(e.clientX-r.width)+'px'; if(r.bottom>window.innerHeight)m.style.top=(e.clientY-r.height)+'px'; }
document.addEventListener('click', ()=>document.getElementById('ctxMenu').classList.remove('show'));

function copySHA256() { const s=getSelectedPath(); if(s&&s.sha){navigator.clipboard.writeText(s.sha);flash('已复制 SHA256');} }
function copyMD5() { const s=getSelectedPath(); if(s&&s.md5){navigator.clipboard.writeText(s.md5);flash('已复制 MD5');} }
function openVT() { const s=getSelectedPath(); if(s&&s.sha) window.open('https://www.virustotal.com/gui/file/'+s.sha,'_blank'); }
function copyVTLink() { const s=getSelectedPath(); if(s&&s.sha){navigator.clipboard.writeText('https://www.virustotal.com/gui/file/'+s.sha);flash('已复制VT链接');} }
async function openDir() { const s=getSelectedPath(); if(s&&s.path){try{const r=await fetch('/api/opendir',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:s.path})});const d=await r.json();flash(d.ok?'已打开目录':'打开失败: '+(d.error||''));}catch(e){flash('出错: '+e.message);}} }
function copyCmdLine() { const s=getSelectedPath(); if(s&&s.cmd){navigator.clipboard.writeText(s.cmd);flash('已复制命令行');} }
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

async function handleYaraFileUpload(event) {
  const files = event.target.files;
  if (!files || files.length === 0) return;
  const badge = document.getElementById('yaraStatusBadge');
  const msg = document.getElementById('yaraMsg');
  badge.textContent = '加载中...'; badge.style.background = '#4a3000'; badge.style.color = '#ffd600';
  msg.textContent = '正在上传规则文件...'; msg.style.color = '#ffd600';

  // Upload each file
  let totalRules = 0;
  for (const file of files) {
    const form = new FormData();
    form.append('rulefile', file);
    try {
      const resp = await fetch('/api/yara/upload', { method: 'POST', body: form });
      const data = await resp.json();
      if (data.ok) {
        totalRules = data.rules;
      } else {
        msg.textContent = '加载失败: ' + (data.error||''); msg.style.color = '#ff1744';
        badge.textContent = '加载失败'; badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
        return;
      }
    } catch(e) {
      msg.textContent = '上传出错: ' + e.message; msg.style.color = '#ff1744';
      return;
    }
  }
  badge.textContent = totalRules + ' 条规则已加载'; badge.style.background = '#1a3a1a'; badge.style.color = '#a5d6a7';
  msg.textContent = '规则加载成功，可以开始扫描'; msg.style.color = '#4caf50';
  document.getElementById('yaraScanBtn').disabled = false;
  event.target.value = ''; // reset input
}

async function loadYaraFromPath() {
  const path = document.getElementById('yaraPathInput').value.trim();
  if (!path) { flash('请输入路径'); return; }
  const badge = document.getElementById('yaraStatusBadge');
  const msg = document.getElementById('yaraMsg');
  badge.textContent = '加载中...'; badge.style.background = '#4a3000'; badge.style.color = '#ffd600';
  try {
    const resp = await fetch('/api/yara/loadpath', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({path: path})
    });
    const data = await resp.json();
    if (data.ok) {
      badge.textContent = data.rules + ' 条规则已加载'; badge.style.background = '#1a3a1a'; badge.style.color = '#a5d6a7';
      msg.textContent = '从 ' + path + ' 加载成功'; msg.style.color = '#4caf50';
      document.getElementById('yaraScanBtn').disabled = false;
    } else {
      badge.textContent = '加载失败'; badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
      msg.textContent = data.error || '加载失败'; msg.style.color = '#ff1744';
    }
  } catch(e) {
    badge.textContent = '出错'; badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
    msg.textContent = e.message; msg.style.color = '#ff1744';
  }
}

let yaraPolling = null;
async function startYaraScan() {
  const btn = document.getElementById('yaraScanBtn');
  const msg = document.getElementById('yaraMsg');
  const progArea = document.getElementById('yaraProgressArea');
  btn.disabled = true; btn.textContent = '扫描中...';
  progArea.style.display = 'block';
  msg.textContent = '正在扫描所有对象...'; msg.style.color = '#ffd600';

  try {
    const resp = await fetch('/api/yara/scanall', { method: 'POST' });
    const data = await resp.json();
    if (!data.ok) {
      msg.textContent = data.error || '扫描失败'; msg.style.color = '#ff1744';
      btn.disabled = false; btn.textContent = '开始扫描全部对象';
      progArea.style.display = 'none';
      return;
    }
    // Start polling progress
    yaraPolling = setInterval(pollYaraProgress, 500);
  } catch(e) {
    msg.textContent = '出错: ' + e.message; msg.style.color = '#ff1744';
    btn.disabled = false; btn.textContent = '开始扫描全部对象';
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
  btn.disabled = false; btn.textContent = '开始扫描全部对象';

  // Load results
  try {
    const resp = await fetch('/api/yara/results');
    const items = await resp.json();
    renderYaraResults(items || []);
    const cnt = (items||[]).length;
    msg.textContent = '扫描完成！' + (cnt > 0 ? cnt + ' 个对象命中 YARA 规则' : '未发现命中');
    msg.style.color = cnt > 0 ? '#ff9100' : '#4caf50';
    const badge = document.getElementById('yaraStatusBadge');
    if (cnt > 0) {
      badge.textContent = cnt + ' 个命中'; badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
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
  document.getElementById('modalTitle').textContent = '进程详情: ' + r.Name + ' (PID ' + r.PID + ')';
  let h = '';
  h += sec('进程信息', [['进程名',r.Name],['PID',r.PID],['父进程',r.PPID+(r.ParentName?' ('+r.ParentName+')':'')],['路径',r.Path,1],['命令行',r.CommandLine,1],['用户',r.User],['启动时间',r.StartTime]]);
  h += sec('文件信息', [['SHA256',r.SHA256,1],['MD5',r.MD5,1],['文件大小',r.FileSize?r.FileSize+' 字节':''],['修改时间',r.FileModTime]]);
  h += sec('签名信息', [['签名',r.Signed?'✓ 是':'✗ 否'],['有效',r.SignValid?'✓ 是':'✗ 否'],['签发者',r.Signer],['公司',r.Company],['产品',r.Product],['原始文件名',r.OriginalName]]);
  h += sec('上下文分析', [['LOLBin',r.IsLOLBin?'<span class="tag tag-orange">是</span>':'否'],['路径异常',r.PathAbnormal?'<span class="tag tag-red">是</span>':'否'],['文件名伪装',r.IsMasquerade?'<span class="tag tag-red">是</span>':'否'],['异常父进程链',r.AbnormalParentChain?'<span class="tag tag-red">是</span>':'否']]);
  h += sec('网络连接', [['有网络活动',r.HasNetwork?'是':'否'],['远程IP',(r.RemoteIPs||[]).join(', ')],['公网连接',r.HasPublicIP?'<span class="tag tag-red">是</span>':'否']]);
  h += reasonBlock(r.RiskScore, r.RiskLevel, r.Reasons);
  if (r.SHA256) h += '<div class="detail-section"><h3>VirusTotal</h3><div class="detail-row"><div class="detail-value"><a href="https://www.virustotal.com/gui/file/'+r.SHA256+'" target="_blank">在 VirusTotal 中查看</a></div></div></div>';
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
  document.getElementById('modalTitle').textContent = '执行对象详情: ' + (e.Path||e.CommandLine);
  let h = '';
  h += sec('基本信息', [['路径',e.Path,1],['类型',e.ObjType],['位置',e.LocationType],['状态',e.IsRunning?'<span class="tag tag-red">运行中</span>':'<span class="tag tag-blue">未运行</span>'],['PID',(e.PIDs||[]).join(', ')],['来源',(e.Sources||[]).join(', ')]]);
  h += sec('文件信息', [['SHA256',e.SHA256,1],['MD5',e.MD5,1],['文件存在',e.Exists?'是':'否']]);
  h += sec('签名信息', [['签名',e.Signed?'✓ 是':'✗ 否'],['有效',e.SignValid?'✓ 是':'✗ 否'],['签发者',e.Signer],['公司',e.Company]]);
  h += sec('网络', [['有网络活动',e.NetworkObserved?'是':'否'],['远程IP',(e.RemoteIPs||[]).join(', ')],['公网',e.HasPublicIP?'<span class="tag tag-red">是</span>':'否']]);
  if ((e.Triggers||[]).length > 0) {
    h += '<div class="detail-section"><h3>触发器 ('+e.Triggers.length+' 个)</h3>';
    e.Triggers.forEach(t => { h += '<div class="detail-row"><div class="detail-value"><span class="tag tag-orange">['+esc(TT[t.Type]||t.Type)+'] '+esc(t.Name)+'</span> '+esc(t.Detail)+'</div></div>'; });
    h += '</div>';
  }
  h += '<div class="detail-section"><h3>评分构成</h3>';
  h += '<div class="detail-row"><div class="detail-label">进程评分</div><div class="detail-value">'+e.ExecutionScore+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">触发器评分</div><div class="detail-value">'+e.TriggerScore+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">取证评分</div><div class="detail-value">'+e.ForensicScore+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">YARA评分</div><div class="detail-value">'+e.YaraScore+(e.YaraMatched?' <span class="tag tag-red">命中</span>':'')+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">事件评分</div><div class="detail-value">'+e.EventScore+(e.EventCount>0?' ('+e.EventCount+'条事件)':'')+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">模块评分</div><div class="detail-value">'+e.DLLHijackScore+(e.HasDLLHijack?' <span class="tag tag-red">DLL劫持</span>':'')+(e.SuspiciousModuleCount>0?' ('+e.SuspiciousModuleCount+'个可疑)':'')+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">组合加权</div><div class="detail-value">+'+e.SynergyBonus+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label">白特征抵消</div><div class="detail-value">-'+e.WhiteReduction+'</div></div>';
  h += '<div class="detail-row"><div class="detail-label"><strong>最终评分</strong></div><div class="detail-value"><strong>'+e.FinalScore+'</strong></div></div>';
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
  let h = '<div class="detail-section"><h3>风险评估</h3>';
  h += '<div class="detail-row"><div class="detail-label">评分</div><div class="detail-value"><strong>'+score+'</strong></div></div>';
  h += '<div class="detail-row"><div class="detail-label">等级</div><div class="detail-value"><span class="tag tag-'+(level==='Critical'?'red':level==='High'?'orange':level==='Medium'?'orange':'blue')+'">'+esc(lv)+'</span></div></div>';
  if ((reasons||[]).length > 0) {
    h += '<div class="detail-row"><div class="detail-label">风险原因</div><div class="detail-value">';
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

const AI_SYSTEM_PROMPT = '你是资深Windows应急响应专家。用户是安全工程师，使用ProcIR工具排查。回复要求：\n1. 极度精简，不要废话，不要解释基础概念\n2. 直接给结论：有威胁/无威胁/需关注\n3. 用表格或列表呈现，每条一行：进程名+判定+原因\n4. 只报告真正可疑的，正常系统进程不用提\n5. 处置建议只写具体动作，如「kill PID xxx」「删除该计划任务」「排查该外连IP」\n6. 如果没有明显威胁，直接说「未发现明显威胁」，不要凑字数';
let aiChatHistory = []; // {role, content} array for context
let aiTotalTokens = 0;
let aiSending = false;

(function() {
  const saved = localStorage.getItem('procir_minimax_key');
  if (saved) { document.getElementById('aiApiKey').value = saved; document.getElementById('aiSaveKey').checked = true; }
})();

function toggleAISaveKey() {
  if (document.getElementById('aiSaveKey').checked) {
    const key = document.getElementById('aiApiKey').value;
    if (key) localStorage.setItem('procir_minimax_key', key);
  } else {
    localStorage.removeItem('procir_minimax_key');
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
      msg.innerHTML = '<span style="color:#ffd600">思考中...</span>';
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
  let p = '以下是ProcIR扫描结果，请进行全面安全分析：\n\n';

  const {c,h,m,s} = countRiskLevels();
  p += '## 总体统计\n';
  p += '进程:' + allProc.length + ' (严重:'+c+' 高危:'+h+' 中危:'+m+' 可疑:'+s+') | 触发器:' + allTrig.length + ' | 行为链:' + allChain.length + ' | IOC:' + allIOC.length + ' | 事件:' + allEvt.length + '\n\n';

  // Single pass: classify processes into high/medium buckets
  const highRisk = [], medRisk = [];
  allProc.forEach(r => {
    if (r.RiskLevel==='Critical' || r.RiskLevel==='High') highRisk.push(r);
    else if (r.RiskLevel==='Medium') medRisk.push(r);
  });
  if (highRisk.length > 0) {
    p += '## 高风险进程 (' + highRisk.length + '个)\n';
    highRisk.slice(0, 30).forEach(r => {
      p += '- [' + r.RiskLevel + '/' + r.RiskScore + '] ' + r.Name + ' PID:' + r.PID;
      if (r.Path) p += ' ' + r.Path;
      if (r.Signer) p += ' 签名:' + r.Signer; else p += ' [未签名]';
      if (r.HasPublicIP) p += ' [公网]';
      if (r.IsLOLBin) p += ' [LOLBin]';
      if ((r.Reasons||[]).length) p += ' | ' + r.Reasons.join('; ');
      if (r.CommandLine) p += '\n  CMD: ' + r.CommandLine;
      p += '\n';
    });
    p += '\n';
  }

  if (medRisk.length > 0) {
    p += '## 中危进程 (' + medRisk.length + '个)\n';
    medRisk.slice(0, 15).forEach(r => {
      p += '- [' + r.RiskScore + '] ' + r.Name + ' PID:' + r.PID + ' ' + (r.Path||'');
      if ((r.Reasons||[]).length) p += ' | ' + r.Reasons.join('; ');
      p += '\n';
    });
    p += '\n';
  }

  const highTrig = allTrig.filter(t => t.Score >= 20).sort((a,b) => b.Score - a.Score);
  if (highTrig.length > 0) {
    p += '## 可疑触发器 (' + highTrig.length + '个)\n';
    highTrig.slice(0, 20).forEach(t => {
      p += '- [' + t.Score + '][' + (TT[t.Type]||t.Type) + '] ' + t.Name;
      if (t.Path) p += ' ' + t.Path;
      if (t.CommandLine) p += ' CMD:' + t.CommandLine;
      if ((t.Reasons||[]).length) p += ' | ' + t.Reasons.join('; ');
      p += '\n';
    });
    p += '\n';
  }

  if (allChain.length > 0) {
    p += '## 行为链\n';
    allChain.forEach(c => {
      p += '- [' + c.PatternScore + '] ' + c.PatternName + ': ' + (c.Evidence||[]).join(' -> ');
      p += '\n';
    });
    p += '\n';
  }

  if (allIOC.length > 0) {
    p += '## IOC (' + allIOC.length + '个)\n';
    allIOC.slice(0, 30).forEach(i => {
      p += '- [' + (IOT[i.Type]||i.Type) + '] ' + i.Value + (i.SourceObject?' ('+i.SourceObject+')':'') + '\n';
    });
    p += '\n';
  }

  // 执行对象（融合视图，包含多维度评分）
  const highExec = allExec.filter(e => e.FinalScore >= 40).sort((a,b) => b.FinalScore - a.FinalScore);
  if (highExec.length > 0) {
    p += '## 高危执行对象 (' + highExec.length + '个)\n';
    highExec.slice(0, 20).forEach(e => {
      p += '- [' + (e.RiskLevel||'?') + '/' + e.FinalScore + '] ' + (e.Path||'?');
      p += ' ' + (e.IsRunning?'[运行中]':'[未运行]');
      if (e.Signed) p += ' 签名:' + (e.Signer||'是'); else p += ' [未签名]';
      if (e.TriggerCount>0) p += ' 触发器:' + e.TriggerCount + '(' + (e.TriggerTypes||[]).map(t=>TT[t]||t).join('+') + ')';
      if (e.NetworkObserved) p += ' [有网络]';
      if (e.HasPublicIP) p += ' [公网]';
      if (e.YaraMatched) p += ' [YARA命中]';
      if (e.HasDLLHijack) p += ' [DLL劫持]';
      p += ' 评分构成:执行' + e.ExecutionScore + '/触发' + e.TriggerScore + '/取证' + e.ForensicScore + '/事件' + e.EventScore + '/模块' + e.DLLHijackScore;
      if ((e.Reasons||[]).length) p += '\n  原因: ' + e.Reasons.join('; ');
      p += '\n';
    });
    p += '\n';
  }

  // 模块分析（DLL劫持检测）
  const suspMod = allMod.filter(m => m.Score >= 20 || m.HasDLLHijack).sort((a,b) => b.Score - a.Score);
  if (suspMod.length > 0) {
    p += '## 可疑模块/DLL劫持 (' + suspMod.length + '个)\n';
    suspMod.slice(0, 15).forEach(m => {
      p += '- [' + m.Score + '] ' + m.ExeName + '(PID:' + m.PID + ') ' + (m.ExePath||'');
      if (m.HasDLLHijack) p += ' [DLL劫持]';
      p += ' 可疑DLL:' + m.SuspiciousCount + '/' + m.TotalModules;
      if (!m.ExeSigned) p += ' [宿主未签名]';
      if ((m.Reasons||[]).length) p += ' | ' + m.Reasons.join('; ');
      p += '\n';
    });
    p += '\n';
  }

  // 历史取证（Prefetch/最近文件/事件日志/模块）
  const suspFore = allFore.filter(f => f.Score >= 20).sort((a,b) => b.Score - a.Score);
  if (suspFore.length > 0) {
    p += '## 可疑历史取证 (' + suspFore.length + '个)\n';
    suspFore.slice(0, 15).forEach(f => {
      const srcCN = FS[f.Source] || f.Source;
      p += '- [' + f.Score + '][' + srcCN + '] ' + (f.Path||f.Detail||'');
      const t = f.EventTime || f.LastRunTime || f.FileModTime || '';
      if (t) p += ' 时间:' + t;
      if ((f.Reasons||[]).length) p += ' | ' + f.Reasons.join('; ');
      p += '\n';
    });
    p += '\n';
  }

  const highEvt = allEvt.filter(e => e.Score >= 30).sort((a,b) => b.Score - a.Score);
  if (highEvt.length > 0) {
    p += '## 高危事件 (' + highEvt.length + '个)\n';
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
  let p = '扫描摘要 - 进程:' + allProc.length + '(严重:'+c+' 高危:'+h+' 中危:'+m+' 可疑:'+s+') 触发器:'+allTrig.length+' 行为链:'+allChain.length+' IOC:'+allIOC.length+'\n\n';

  const top = allProc.filter(r => r.RiskLevel==='Critical' || r.RiskLevel==='High').slice(0,10);
  if (top.length) {
    p += '高风险进程:\n';
    top.forEach(r => { p += '- ' + r.Name + '(PID:'+r.PID+') '+r.RiskLevel+'/'+r.RiskScore + (r.Signer?' '+r.Signer:' [未签名]') + ' ' + ((r.Reasons||[]).join('; ')) + '\n'; });
  }
  p += '\n请分析这些结果，有什么安全问题？';
  return p;
}

function sendScanData() {
  if (allProc.length === 0) { flash('请先执行系统扫描'); return; }
  document.getElementById('aiInput').value = buildScanDataFull();
  sendAIMessage();
}

function sendScanDataBrief() {
  if (allProc.length === 0) { flash('请先执行系统扫描'); return; }
  document.getElementById('aiInput').value = buildScanDataBrief();
  sendAIMessage();
}

async function sendAIMessage() {
  if (aiSending) return;
  const input = document.getElementById('aiInput');
  const text = input.value.trim();
  if (!text) return;

  const apiKey = document.getElementById('aiApiKey').value.trim();
  if (!apiKey) { flash('请输入MiniMax API Key'); return; }

  if (document.getElementById('aiSaveKey').checked) {
    localStorage.setItem('procir_minimax_key', apiKey);
  }

  const model = document.getElementById('aiModel').value;
  aiSending = true;

  // Add user message
  aiChatHistory.push({role: 'user', content: text});
  appendChatBubble('user', text);
  input.value = '';
  input.style.height = 'auto';

  // Show loading
  appendChatBubble('assistant', '', true);

  const btn = document.getElementById('aiSendBtn');
  const badge = document.getElementById('aiStatusBadge');
  btn.disabled = true; btn.textContent = '...';
  badge.textContent = '请求中'; badge.style.background = '#4a3000'; badge.style.color = '#ffd600';

  // Build messages with system prompt, cap context to last 30 messages
  const ctx = aiChatHistory.length > 30 ? aiChatHistory.slice(-30) : aiChatHistory;
  const messages = [{role: 'system', content: AI_SYSTEM_PROMPT}, ...ctx];

  try {
    const resp = await fetch('/api/ai/analyze', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ apiKey: apiKey, model: model, messages: messages })
    });
    const data = await resp.json();

    // Remove loading bubble
    const loading = document.getElementById('aiLoadingBubble');
    if (loading) loading.parentElement.remove();

    if (!data.ok) {
      appendChatBubble('assistant', '(错误: ' + (data.error||'请求失败') + ')');
      badge.textContent = '失败'; badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
    } else {
      const content = data.content || '(无返回)';
      aiChatHistory.push({role: 'assistant', content: content});
      appendChatBubble('assistant', content);
      badge.textContent = '就绪'; badge.style.background = '#1a3a1a'; badge.style.color = '#a5d6a7';

      if (data.totalTokens) {
        aiTotalTokens += data.totalTokens;
        document.getElementById('aiTokenCounter').textContent = '本轮:' + (data.promptTokens||0) + '+' + (data.completionTokens||0) + ' | 累计:' + aiTotalTokens;
      }
    }
  } catch(e) {
    const loading = document.getElementById('aiLoadingBubble');
    if (loading) loading.parentElement.remove();
    appendChatBubble('assistant', '(网络错误: ' + e.message + ')');
    badge.textContent = '出错'; badge.style.background = '#5c1a1a'; badge.style.color = '#ff8a80';
  }

  aiSending = false;
  btn.disabled = false; btn.textContent = '发送';
}

function clearAIChat() {
  aiChatHistory = [];
  aiTotalTokens = 0;
  const area = document.getElementById('aiChatArea');
  const welcome = document.getElementById('aiWelcome');
  // Remove everything except the welcome element
  while (area.firstChild) area.removeChild(area.firstChild);
  if (welcome) { welcome.style.display = ''; area.appendChild(welcome); }
  document.getElementById('aiTokenCounter').textContent = '';
  const badge = document.getElementById('aiStatusBadge');
  badge.textContent = '就绪'; badge.style.background = '#333'; badge.style.color = '#888';
}
</script>
</body>
</html>`
