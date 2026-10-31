/**
 * app.js - Frontend Controller for CleanPC Master
 * Handles state, responsive user interactions, live polling, and API requests.
 */

// Global State
const state = {
  systemOverview: null,
  memoryStatus: null,
  memoryPollTimer: null,
  disksSmart: [],
  junkCategories: [],
  selectedJunkCategories: new Set(),
  duplicateResults: [],
  selectedDuplicatePaths: new Set(),
  largeFiles: [],
  isScanningDuplicates: false,
  duplicatePollTimer: null
};

// -----------------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------------
function initApp() {
  setupNavigation();
  setupEventListeners();
  loadSystemOverview();
  loadAutostartConfig();
  loadMemoryDaemonConfig();
}

window.addEventListener('pywebviewready', () => {
  console.log('[CleanPC] PyWebView Native API đã kết nối.');
  loadSystemOverview();
  loadAutostartConfig();
  loadMemoryDaemonConfig();
});

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}

// Toast Notifications with Anti-Duplication Protection
const recentToasts = new Map();

function showToast(message, type = 'info') {
  if (!message) return;
  const now = Date.now();
  const key = `${type}:${message.trim()}`;
  
  // Suppress identical notification within 2.5 seconds
  if (recentToasts.has(key) && (now - recentToasts.get(key) < 2500)) {
    return;
  }
  recentToasts.set(key, now);

  const container = document.getElementById('toast-container');
  if (!container) return;

  // Prevent notification flooding - keep maximum 3 visible
  while (container.children.length >= 3) {
    container.removeChild(container.firstChild);
  }
  
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  
  let iconSvg = '';
  if (type === 'success') {
    iconSvg = '<svg style="width:18px;height:18px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>';
  } else if (type === 'danger') {
    iconSvg = '<svg style="width:18px;height:18px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
  } else {
    iconSvg = '<svg style="width:18px;height:18px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>';
  }
  
  toast.innerHTML = `${iconSvg}<span>${message}</span>`;
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// -----------------------------------------------------------------------------
// Navigation & Tabs
// -----------------------------------------------------------------------------
function setupNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  const tabPanes = document.querySelectorAll('.tab-pane');

  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const targetTabId = item.getAttribute('data-tab');
      if (!targetTabId) return;

      navItems.forEach(i => i.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      item.classList.add('active');
      const targetPane = document.getElementById(targetTabId);
      if (targetPane) {
        targetPane.classList.add('active');
      }

      // Proactive loading when entering tabs
      if (targetTabId === 'tab-memory') {
        loadMemoryStatus();
        loadMemoryDaemonConfig();
        if (!state.memoryPollTimer) {
          state.memoryPollTimer = setInterval(loadMemoryStatus, 1500);
        }
      } else {
        if (state.memoryPollTimer) {
          clearInterval(state.memoryPollTimer);
          state.memoryPollTimer = null;
        }
      }

      if (targetTabId === 'tab-optimizer' && state.disksSmart.length === 0) {
        loadDisksSmart();
      }

      if (targetTabId === 'tab-junk' && state.junkCategories.length === 0) {
        scanJunkCategories();
      }
    });
  });

  // Quick path shortcut buttons in Duplicate Tab
  document.querySelectorAll('.quick-path-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const path = btn.getAttribute('data-path');
      document.getElementById('dup-target-dir').value = path;
      showToast(`Đã chọn phạm vi quét: ${path}`, 'info');
    });
  });
}

// -----------------------------------------------------------------------------
// System Overview & Dashboard
// -----------------------------------------------------------------------------
async function loadSystemOverview() {
  try {
    const res = await fetch('/api/system/overview');
    if (!res.ok) throw new Error("Không thể tải thông tin hệ thống");
    const data = await res.json();
    state.systemOverview = data;

    // Render Admin Badge
    const adminBadge = document.getElementById('admin-badge');
    const adminText = document.getElementById('admin-badge-text');
    const btnRestartAdmin = document.getElementById('btn-restart-admin');

    if (data.admin) {
      adminBadge.className = 'badge badge-admin';
      adminText.textContent = 'Quyền: Administrator (Đầy đủ)';
      btnRestartAdmin.style.display = 'none';
    } else {
      adminBadge.className = 'badge badge-user';
      adminText.textContent = 'Quyền: Tiêu chuẩn (Standard)';
      btnRestartAdmin.style.display = 'inline-flex';
    }

    // Render Drives Grid
    renderDrivesGrid(data.drives);

    // Update Quick Clean Estimates
    document.getElementById('quick-recycle-estimate').textContent = data.recycle_bin.total_formatted;
    document.getElementById('quick-junk-estimate').textContent = '2 - 6 GB';

  } catch (err) {
    console.warn(`[CleanPC] Đang chờ kết nối máy chủ (${err.message}), thử lại sau 1.5s...`);
    setTimeout(loadSystemOverview, 1500);
  }
}

function renderDrivesGrid(drives) {
  const container = document.getElementById('drives-grid');
  if (!drives || drives.length === 0) {
    container.innerHTML = '<div class="card">Không tìm thấy ổ đĩa nào.</div>';
    return;
  }

  container.innerHTML = drives.map(drive => {
    const isC = drive.letter === 'C';
    let progressClass = '';
    if (drive.used_percent > 85) progressClass = 'danger';
    else if (drive.used_percent > 70) progressClass = 'warning';

    return `
      <div class="card drive-card ${isC ? 'is-c' : 'is-d'}">
        <div class="drive-card-header">
          <div class="drive-name">
            <span class="drive-letter">Ổ ${drive.letter}:</span>
            <span class="drive-tag">${drive.media_type}</span>
          </div>
          <span style="font-size: 0.82rem; color: var(--text-muted);">${drive.name}</span>
        </div>

        <div class="drive-details">
          <div>
            <div class="drive-used">${drive.used_formatted}</div>
            <div class="drive-total">trên tổng số ${drive.total_formatted}</div>
          </div>
          <div class="drive-free">
            Còn trống: ${drive.free_formatted}
          </div>
        </div>

        <div class="progress-container">
          <div class="progress-bar ${progressClass}" style="width: ${drive.used_percent}%;"></div>
        </div>

        <div class="drive-card-footer">
          <span>Đã sử dụng: <strong>${drive.used_percent}%</strong></span>
          <span>Thùng rác: ${drive.recycle_bin.size_formatted} (${drive.recycle_bin.items} tệp)</span>
        </div>
      </div>
    `;
  }).join('');
}

// -----------------------------------------------------------------------------
// System Junk Cleaner
// -----------------------------------------------------------------------------
async function scanJunkCategories() {
  const listContainer = document.getElementById('junk-categories-list');
  const btnScan = document.getElementById('btn-scan-junk');
  btnScan.disabled = true;
  btnScan.innerHTML = `<span class="pulse-dot"></span> Đang quét hệ thống...`;

  listContainer.innerHTML = `
    <div class="card" style="text-align: center; padding: 40px;">
      <div class="pulse-dot" style="margin: 0 auto 16px auto; width: 14px; height: 14px;"></div>
      <div style="font-weight: 700; font-size: 1.1rem; color: var(--primary);">Đang phân tích các danh mục rác...</div>
      <div style="color: var(--text-muted); font-size: 0.85rem; margin-top: 6px;">Quét bộ nhớ đệm, tệp tạm thời, crash dumps và cache lập trình...</div>
    </div>
  `;

  try {
    const res = await fetch('/api/junk/scan', { method: 'POST' });
    const data = await res.json();
    state.junkCategories = data.categories || [];

    // Reset selection and pre-select default checked items
    state.selectedJunkCategories.clear();
    state.junkCategories.forEach(cat => {
      if (cat.default_checked && cat.total_bytes > 0) {
        state.selectedJunkCategories.add(cat.id);
      }
    });

    renderJunkList();
    updateJunkSelectedSummary();
    showToast(`Quét hoàn tất: Phát hiện ${data.total_formatted} file rác!`, 'success');

  } catch (err) {
    showToast(`Lỗi quét file rác: ${err.message}`, 'danger');
    listContainer.innerHTML = `<div class="card" style="color: var(--danger); text-align: center;">Lỗi phân tích rác: ${err.message}</div>`;
  } finally {
    btnScan.disabled = false;
    btnScan.innerHTML = `<svg style="width:18px;height:18px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Quét Lại Rác`;
  }
}

function renderJunkList() {
  const container = document.getElementById('junk-categories-list');
  if (!state.junkCategories || state.junkCategories.length === 0) {
    container.innerHTML = `<div class="card" style="text-align:center;">Không tìm thấy tệp rác nào. Máy tính của bạn rất sạch!</div>`;
    return;
  }

  container.innerHTML = state.junkCategories.map(cat => {
    const isChecked = state.selectedJunkCategories.has(cat.id);
    const hasFiles = cat.total_files > 0;
    
    let safetyBadge = '';
    if (cat.safety === 'high') {
      safetyBadge = '<span class="badge" style="background:rgba(16,185,129,0.15);color:var(--success);font-size:0.75rem;">An toàn tuyệt đối</span>';
    } else {
      safetyBadge = '<span class="badge" style="background:rgba(59,130,246,0.15);color:var(--secondary);font-size:0.75rem;">An toàn</span>';
    }

    return `
      <div class="junk-item">
        <div class="junk-item-left">
          <input type="checkbox" class="custom-checkbox junk-checkbox" data-id="${cat.id}" ${isChecked ? 'checked' : ''} ${!hasFiles ? 'disabled' : ''}>
          <div class="junk-title-group">
            <div style="display: flex; align-items: center; gap: 8px;">
              <h4>${cat.name}</h4>
              ${safetyBadge}
            </div>
            <p>${cat.description}</p>
          </div>
        </div>

        <div class="junk-item-right">
          <div>
            <div class="junk-size">${cat.total_formatted}</div>
            <div class="junk-files-count">${cat.total_files.toLocaleString()} tệp</div>
          </div>
        </div>
      </div>
    `;
  }).join('');

  // Attach change listeners
  document.querySelectorAll('.junk-checkbox').forEach(chk => {
    chk.addEventListener('change', (e) => {
      const id = e.target.getAttribute('data-id');
      if (e.target.checked) {
        state.selectedJunkCategories.add(id);
      } else {
        state.selectedJunkCategories.delete(id);
      }
      updateJunkSelectedSummary();
    });
  });
}

function updateJunkSelectedSummary() {
  let totalBytes = 0;
  state.junkCategories.forEach(cat => {
    if (state.selectedJunkCategories.has(cat.id)) {
      totalBytes += cat.total_bytes;
    }
  });

  const sizeLabel = document.getElementById('selected-junk-size');
  const btnClean = document.getElementById('btn-clean-selected-junk');

  sizeLabel.textContent = formatBytes(totalBytes);
  btnClean.disabled = (state.selectedJunkCategories.size === 0 || totalBytes === 0);
}

// -----------------------------------------------------------------------------
// Duplicate Files Finder
// -----------------------------------------------------------------------------
async function startDuplicateScan() {
  const targetDir = document.getElementById('dup-target-dir').value.trim();
  const minSizeMb = document.getElementById('dup-min-size').value;
  const fileType = document.getElementById('dup-file-type').value;

  if (!targetDir) {
    showToast("Vui lòng nhập đường dẫn thư mục hoặc ổ đĩa cần quét!", "warning");
    return;
  }

  let fileExts = null;
  if (fileType === 'images') fileExts = ['jpg', 'jpeg', 'png', 'webp', 'gif', 'bmp', 'svg', 'raw', 'cr2', 'nef'];
  else if (fileType === 'videos') fileExts = ['mp4', 'mkv', 'mov', 'avi', 'wmv', 'flv', 'webm'];
  else if (fileType === 'docs') fileExts = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt'];
  else if (fileType === 'archives') fileExts = ['zip', 'rar', '7z', 'tar', 'gz', 'iso'];

  const btnStart = document.getElementById('btn-start-duplicate-scan');
  const btnCancel = document.getElementById('btn-cancel-duplicate-scan');
  const progressCard = document.getElementById('dup-progress-card');
  const resultsBar = document.getElementById('dup-results-bar');
  const container = document.getElementById('duplicate-groups-container');

  btnStart.style.display = 'none';
  btnCancel.style.display = 'inline-flex';
  progressCard.style.display = 'block';
  resultsBar.style.display = 'none';
  container.innerHTML = '';

  state.isScanningDuplicates = true;

  try {
    const res = await fetch('/api/duplicates/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        targets: [targetDir],
        min_size_mb: parseFloat(minSizeMb),
        file_types: fileExts
      })
    });
    const data = await res.json();
    if (!data.started) {
      throw new Error("Không thể khởi động tác vụ quét");
    }

    // Start polling status
    pollDuplicateProgress();

  } catch (err) {
    showToast(`Lỗi quét tệp trùng: ${err.message}`, 'danger');
    btnStart.style.display = 'inline-flex';
    btnCancel.style.display = 'none';
    progressCard.style.display = 'none';
    state.isScanningDuplicates = false;
  }
}

let isLoadingDuplicateResults = false;

function pollDuplicateProgress() {
  if (state.duplicatePollTimer) {
    clearTimeout(state.duplicatePollTimer);
    state.duplicatePollTimer = null;
  }

  let isHandled = false;

  const checkStatus = async () => {
    if (!state.isScanningDuplicates || isHandled) return;

    try {
      const res = await fetch('/api/duplicates/status');
      if (!res.ok) throw new Error("Status check failed");
      const data = await res.json();
      const p = data.progress;

      const phaseEl = document.getElementById('dup-progress-phase');
      if (phaseEl) phaseEl.textContent = p.phase || 'Đang quét...';
      const pctEl = document.getElementById('dup-progress-pct');
      if (pctEl) pctEl.textContent = `${p.percent}%`;
      const barEl = document.getElementById('dup-progress-bar');
      if (barEl) barEl.style.width = `${p.percent}%`;
      const fileEl = document.getElementById('dup-progress-file');
      if (fileEl) fileEl.textContent = p.current_file || '';
      const statsEl = document.getElementById('dup-progress-stats');
      if (statsEl) statsEl.textContent = `${p.scanned_files.toLocaleString()} tệp đã duyệt`;

      if (data.status === 'completed' || data.status === 'cancelled' || data.status === 'error') {
        isHandled = true;
        state.isScanningDuplicates = false;
        if (state.duplicatePollTimer) {
          clearTimeout(state.duplicatePollTimer);
          state.duplicatePollTimer = null;
        }

        const btnStart = document.getElementById('btn-start-duplicate-scan');
        const btnCancel = document.getElementById('btn-cancel-duplicate-scan');
        const progressCard = document.getElementById('dup-progress-card');
        if (btnStart) btnStart.style.display = 'inline-flex';
        if (btnCancel) btnCancel.style.display = 'none';
        if (progressCard) progressCard.style.display = 'none';

        if (data.status === 'completed') {
          await loadDuplicateResults(false);
        } else if (data.status === 'cancelled') {
          showToast("Đã hủy quá trình quét trùng lặp.", "info");
        } else if (data.status === 'error') {
          showToast(`Quét gặp lỗi: ${data.error_message}`, "danger");
        }
        return;
      }
    } catch (e) {
      console.warn("Poll duplicate status error:", e);
    }

    if (state.isScanningDuplicates && !isHandled) {
      state.duplicatePollTimer = setTimeout(checkStatus, 700);
    }
  };

  state.duplicatePollTimer = setTimeout(checkStatus, 300);
}

async function cancelDuplicateScan() {
  try {
    await fetch('/api/duplicates/cancel', { method: 'POST' });
    showToast("Đang dừng quét...", "info");
  } catch (e) {
    console.error(e);
  }
}

async function loadDuplicateResults(silent = false) {
  if (isLoadingDuplicateResults) return;
  isLoadingDuplicateResults = true;

  try {
    const res = await fetch('/api/duplicates/results');
    const data = await res.json();
    state.duplicateResults = data.groups || [];

    // Pre-populate selected paths
    state.selectedDuplicatePaths.clear();
    state.duplicateResults.forEach(grp => {
      grp.files.forEach(f => {
        if (f.selected) {
          state.selectedDuplicatePaths.add(f.path);
        }
      });
    });

    renderDuplicateResults();
    updateDuplicateSelectedSummary();

    if (!silent) {
      const totalWasted = state.duplicateResults.reduce((acc, g) => acc + g.wasted_bytes, 0);
      showToast(`Tìm thấy ${state.duplicateResults.length} nhóm tệp trùng, lãng phí ${formatBytes(totalWasted)}!`, 'success');
    }

  } catch (err) {
    showToast(`Lỗi nạp kết quả trùng: ${err.message}`, 'danger');
  } finally {
    isLoadingDuplicateResults = false;
  }
}

function renderDuplicateResults() {
  const container = document.getElementById('duplicate-groups-container');
  const resultsBar = document.getElementById('dup-results-bar');

  if (!state.duplicateResults || state.duplicateResults.length === 0) {
    resultsBar.style.display = 'none';
    container.innerHTML = `
      <div class="card" style="text-align: center; padding: 40px;">
        <div style="font-size: 1.2rem; font-weight: 700; color: var(--success); margin-bottom: 8px;">Không phát hiện tệp trùng lặp nào!</div>
        <div style="color: var(--text-muted); font-size: 0.9rem;">Thư mục được quét hoàn toàn không có tệp thừa.</div>
      </div>
    `;
    return;
  }

  resultsBar.style.display = 'flex';

  container.innerHTML = state.duplicateResults.map((grp, gIdx) => {
    return `
      <div class="duplicate-group-card" id="dup-card-${grp.id}">
        <div class="duplicate-group-header">
          <div class="duplicate-group-title">
            <span class="dup-badge">Nhóm ${gIdx + 1}</span>
            <span style="font-weight: 700; color: var(--text-main);">${grp.size_formatted} / tệp</span>
            <span style="font-size: 0.82rem; color: var(--text-muted);">(${grp.total_copies} bản sao)</span>
          </div>
          <div style="font-weight: 700; color: var(--warning); font-size: 0.9rem;">
            Lãng phí: ${grp.wasted_formatted}
          </div>
        </div>

        <div class="duplicate-files-list">
          ${grp.files.map(f => {
            const isChecked = state.selectedDuplicatePaths.has(f.path);
            return `
              <div class="duplicate-file-row">
                <div class="dup-file-info">
                  <input type="checkbox" class="custom-checkbox dup-file-checkbox" data-path="${escapeHtml(f.path)}" ${isChecked ? 'checked' : ''}>
                  <div style="overflow: hidden;">
                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 3px;">
                      <span style="font-weight: 600; font-size: 0.92rem; color: var(--text-main);">${escapeHtml(f.name)}</span>
                      ${f.is_oldest ? '<span class="dup-original-badge">Bản gốc (Cũ nhất)</span>' : ''}
                    </div>
                    <div class="dup-file-path" title="${escapeHtml(f.path)}">
                      ${escapeHtml(f.directory)}
                    </div>
                  </div>
                </div>

                <div style="display: flex; align-items: center; gap: 16px;">
                  <span style="font-size: 0.78rem; color: var(--text-dim);">${f.mtime_str}</span>
                  <button class="btn btn-sm btn-outline btn-open-explorer" data-path="${escapeHtml(f.path)}" title="Mở thư mục trong Windows Explorer">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>
                    Mở
                  </button>
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;
  }).join('');

  // Event Listeners for checkboxes and open explorer buttons
  document.querySelectorAll('.dup-file-checkbox').forEach(chk => {
    chk.addEventListener('change', (e) => {
      const p = e.target.getAttribute('data-path');
      if (e.target.checked) {
        state.selectedDuplicatePaths.add(p);
      } else {
        state.selectedDuplicatePaths.delete(p);
      }
      updateDuplicateSelectedSummary();
    });
  });

  document.querySelectorAll('.btn-open-explorer').forEach(btn => {
    btn.addEventListener('click', () => {
      const p = btn.getAttribute('data-path');
      openInExplorer(p);
    });
  });
}

function updateDuplicateSelectedSummary() {
  let freedBytes = 0;
  // Calculate total bytes of selected files
  state.duplicateResults.forEach(grp => {
    grp.files.forEach(f => {
      if (state.selectedDuplicatePaths.has(f.path)) {
        freedBytes += f.size;
      }
    });
  });

  document.getElementById('dup-selected-freed').textContent = formatBytes(freedBytes);
  document.getElementById('btn-delete-duplicates').disabled = (state.selectedDuplicatePaths.size === 0);
}

// -----------------------------------------------------------------------------
// Large Files Scanner
// -----------------------------------------------------------------------------
async function scanLargeFiles() {
  const targetDir = document.getElementById('large-target-dir').value.trim();
  const minSizeMb = document.getElementById('large-min-size').value;
  const limit = document.getElementById('large-limit').value;

  if (!targetDir) {
    showToast("Vui lòng nhập thư mục cần quét tệp lớn!", "warning");
    return;
  }

  const container = document.getElementById('large-files-container');
  const btnScan = document.getElementById('btn-scan-large-files');
  btnScan.disabled = true;
  btnScan.innerHTML = `<span class="pulse-dot"></span> Đang quét...`;

  container.innerHTML = `
    <div style="text-align: center; padding: 40px; color: var(--text-muted);">
      <div class="pulse-dot" style="margin: 0 auto 16px auto; width: 14px; height: 14px;"></div>
      Đang tìm kiếm các tệp lớn hơn ${minSizeMb} MB...
    </div>
  `;

  try {
    const res = await fetch('/api/large_files/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_dir: targetDir,
        min_size_mb: parseFloat(minSizeMb),
        limit: parseInt(limit)
      })
    });
    const data = await res.json();
    state.largeFiles = data.files || [];

    renderLargeFilesTable(data);
    showToast(`Tìm thấy ${state.largeFiles.length} tệp lớn (Tổng ${data.total_formatted})!`, 'success');

  } catch (err) {
    showToast(`Lỗi quét tệp lớn: ${err.message}`, 'danger');
    container.innerHTML = `<div style="text-align:center; padding: 30px; color: var(--danger);">Lỗi: ${err.message}</div>`;
  } finally {
    btnScan.disabled = false;
    btnScan.innerHTML = `<svg style="width:18px;height:18px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Quét Tệp Lớn`;
  }
}

function renderLargeFilesTable(data) {
  const container = document.getElementById('large-files-container');
  const files = data.files || [];

  if (files.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; padding: 40px; color: var(--text-muted);">
        Không tìm thấy tệp nào vượt quá kích thước yêu cầu.
      </div>
    `;
    return;
  }

  const maxFileSize = files[0].size || 1;

  container.innerHTML = `
    <div class="data-table-container">
      <table class="data-table">
        <thead>
          <tr>
            <th>Tên tệp</th>
            <th>Dung lượng</th>
            <th>Tỷ lệ</th>
            <th>Thời gian sửa đổi</th>
            <th>Thao tác</th>
          </tr>
        </thead>
        <tbody>
          ${files.map(f => {
            const pct = Math.round((f.size / maxFileSize) * 100);
            return `
              <tr>
                <td>
                  <div class="file-name-cell">
                    <div class="file-icon">${escapeHtml(f.extension.toUpperCase().slice(0, 4))}</div>
                    <div>
                      <div style="font-weight: 600; color: var(--text-main);">${escapeHtml(f.name)}</div>
                      <div style="font-size: 0.78rem; color: var(--text-dim); max-width: 480px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(f.path)}">
                        ${escapeHtml(f.directory)}
                      </div>
                    </div>
                  </div>
                </td>
                <td style="font-weight: 700; color: var(--primary); white-space: nowrap;">${f.size_formatted}</td>
                <td style="width: 140px;">
                  <div class="progress-container" style="height: 6px; margin-bottom: 0;">
                    <div class="progress-bar" style="width: ${pct}%;"></div>
                  </div>
                </td>
                <td style="color: var(--text-muted); font-size: 0.82rem; white-space: nowrap;">${f.mtime_str}</td>
                <td style="white-space: nowrap;">
                  <button class="btn btn-sm btn-outline btn-open-explorer" data-path="${escapeHtml(f.path)}" title="Mở trong Explorer">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg>
                    Mở
                  </button>
                  <button class="btn btn-sm btn-danger btn-delete-single-file" data-path="${escapeHtml(f.path)}" data-size="${f.size_formatted}" data-name="${escapeHtml(f.name)}" style="margin-left: 6px;" title="Xóa tệp này">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                  </button>
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    </div>
  `;

  // Attach handlers
  container.querySelectorAll('.btn-open-explorer').forEach(btn => {
    btn.addEventListener('click', () => {
      openInExplorer(btn.getAttribute('data-path'));
    });
  });

  container.querySelectorAll('.btn-delete-single-file').forEach(btn => {
    btn.addEventListener('click', () => {
      const p = btn.getAttribute('data-path');
      const sz = btn.getAttribute('data-size');
      const nm = btn.getAttribute('data-name');
      confirmDeleteAction({
        title: "Xác Nhận Xóa Tệp Lớn",
        message: `Bạn có chắc muốn xóa tệp: <strong>${nm}</strong> (${sz})?<br><span style="font-size:0.8rem;color:var(--text-dim);">${p}</span>`,
        paths: [p],
        onSuccess: () => {
          scanLargeFiles();
          loadSystemOverview();
        }
      });
    });
  });
}

// -----------------------------------------------------------------------------
// Drive Optimization & TRIM
// -----------------------------------------------------------------------------
async function runDriveTrim(driveLetter) {
  const terminal = document.getElementById('trim-terminal');
  terminal.textContent = `[${new Date().toLocaleTimeString()}] Đang gửi lệnh TRIM tới ổ đĩa ${driveLetter}:\\...\nVui lòng chờ trong giây lát...\n`;

  try {
    const res = await fetch('/api/optimize/trim', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ drive: driveLetter })
    });
    const data = await res.json();

    terminal.textContent += `\n` + (data.output || data.message || "Hoàn tất.");

    if (data.success) {
      showToast(data.message, 'success');
    } else {
      if (data.need_admin) {
        showToast("Cần quyền Administrator để thực thi lệnh TRIM!", 'warning');
        terminal.textContent += `\n\n[Gợi ý] Hãy nhấn nút 'Nâng quyền Admin' ở góc trên bên phải để khởi động lại ứng dụng với quyền Quản trị viên.`;
      } else {
        showToast(data.message, 'danger');
      }
    }
  } catch (err) {
    terminal.textContent += `\n[Lỗi kết nối]: ${err.message}`;
    showToast(`Lỗi TRIM: ${err.message}`, 'danger');
  }
}

// -----------------------------------------------------------------------------
// Modal & Deletion Actions
// -----------------------------------------------------------------------------
let pendingAction = null;

function confirmDeleteAction({ title, message, paths, onConfirm, onSuccess }) {
  const modal = document.getElementById('confirm-modal');
  document.getElementById('modal-title').textContent = title || "Xác Nhận Dọn Dẹp";
  document.getElementById('modal-body-text').innerHTML = message;
  
  pendingAction = async () => {
    const useRecycleBin = document.getElementById('modal-use-recycle-bin').checked;
    if (onConfirm) {
      await onConfirm(useRecycleBin);
    } else if (paths && paths.length > 0) {
      try {
        const res = await fetch('/api/duplicates/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ paths, use_recycle_bin: useRecycleBin })
        });
        const d = await res.json();
        showToast(`Đã dọn dẹp thành công ${d.deleted_count} tệp, giải phóng ${d.freed_formatted}!`, 'success');
        if (onSuccess) onSuccess(d);
      } catch (err) {
        showToast(`Lỗi khi xóa tệp: ${err.message}`, 'danger');
      }
    }
  };

  modal.classList.add('active');
}

function closeModal() {
  document.getElementById('confirm-modal').classList.remove('active');
  pendingAction = null;
}

// -----------------------------------------------------------------------------
// Global Event Listeners
// -----------------------------------------------------------------------------
function setupEventListeners() {
  // Modal buttons
  document.getElementById('modal-btn-close').addEventListener('click', closeModal);
  document.getElementById('modal-btn-cancel').addEventListener('click', closeModal);
  document.getElementById('modal-btn-confirm').addEventListener('click', async () => {
    if (pendingAction) {
      await pendingAction();
    }
    closeModal();
  });

  // Junk Buttons
  document.getElementById('btn-scan-junk').addEventListener('click', scanJunkCategories);
  document.getElementById('btn-select-all-junk').addEventListener('click', () => {
    state.junkCategories.forEach(c => {
      if (c.total_files > 0) state.selectedJunkCategories.add(c.id);
    });
    renderJunkList();
    updateJunkSelectedSummary();
  });
  document.getElementById('btn-deselect-all-junk').addEventListener('click', () => {
    state.selectedJunkCategories.clear();
    renderJunkList();
    updateJunkSelectedSummary();
  });

  document.getElementById('btn-clean-selected-junk').addEventListener('click', () => {
    const selectedIds = Array.from(state.selectedJunkCategories);
    let totalSize = 0;
    state.junkCategories.forEach(c => {
      if (state.selectedJunkCategories.has(c.id)) totalSize += c.total_bytes;
    });

    confirmDeleteAction({
      title: "Xác Nhận Dọn Rác Hệ Thống",
      message: `Bạn sắp dọn dẹp <strong>${selectedIds.length} danh mục rác</strong> đã chọn, ước tính giải phóng <strong>${formatBytes(totalSize)}</strong> dung lượng.`,
      onConfirm: async (useRecycleBin) => {
        try {
          const res = await fetch('/api/junk/clean', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ category_ids: selectedIds, use_recycle_bin: useRecycleBin })
          });
          const d = await res.json();
          showToast(`Đã dọn dẹp ${d.total_deleted_files} tệp rác, giải phóng ${d.total_freed_formatted}!`, 'success');
          scanJunkCategories();
          loadSystemOverview();
        } catch (e) {
          showToast(`Lỗi dọn rác: ${e.message}`, 'danger');
        }
      }
    });
  });

  // Duplicate Buttons
  document.getElementById('btn-start-duplicate-scan').addEventListener('click', startDuplicateScan);
  document.getElementById('btn-cancel-duplicate-scan').addEventListener('click', cancelDuplicateScan);

  document.getElementById('btn-dup-keep-oldest').addEventListener('click', () => {
    state.selectedDuplicatePaths.clear();
    state.duplicateResults.forEach(grp => {
      grp.files.forEach(f => {
        if (!f.is_oldest) state.selectedDuplicatePaths.add(f.path);
      });
    });
    renderDuplicateResults();
    updateDuplicateSelectedSummary();
    showToast("Đã chọn giữ lại các bản gốc cũ nhất và tích chọn các bản sao.", 'info');
  });

  document.getElementById('btn-dup-keep-newest').addEventListener('click', () => {
    state.selectedDuplicatePaths.clear();
    state.duplicateResults.forEach(grp => {
      const newest = grp.files.reduce((prev, curr) => (curr.mtime > prev.mtime ? curr : prev), grp.files[0]);
      grp.files.forEach(f => {
        if (f.path !== newest.path) state.selectedDuplicatePaths.add(f.path);
      });
    });
    renderDuplicateResults();
    updateDuplicateSelectedSummary();
    showToast("Đã chọn giữ lại các bản mới nhất và tích chọn các bản cũ hơn.", 'info');
  });

  document.getElementById('btn-dup-deselect').addEventListener('click', () => {
    state.selectedDuplicatePaths.clear();
    renderDuplicateResults();
    updateDuplicateSelectedSummary();
  });

  document.getElementById('btn-delete-duplicates').addEventListener('click', () => {
    const paths = Array.from(state.selectedDuplicatePaths);
    confirmDeleteAction({
      title: "Xác Nhận Xóa Tệp Trùng Lặp",
      message: `Bạn đã chọn xóa <strong>${paths.length} tệp trùng lặp</strong>.<br>Hệ thống sẽ giữ lại bản gốc và loại bỏ các bản sao thừa.`,
      paths: paths,
      onSuccess: () => {
        // Refresh duplicate scan results silently to prevent duplicate toast
        loadDuplicateResults(true);
        loadSystemOverview();
      }
    });
  });

  // Large Files Buttons
  document.getElementById('btn-scan-large-files').addEventListener('click', scanLargeFiles);

  // Quick Clean 1-Click
  document.getElementById('btn-quick-clean').addEventListener('click', () => {
    document.querySelector('[data-tab="tab-junk"]').click();
    showToast("Đã chuyển tới bảng Quét Rác Chi Tiết. Bạn có thể xem trước và nhấn Dọn dẹp an toàn!", "info");
  });

  // Empty Recycle Bin
  document.getElementById('btn-empty-recycle').addEventListener('click', () => {
    confirmDeleteAction({
      title: "Dọn Sạch Thùng Rác (Recycle Bin)",
      message: `Bạn có chắc muốn làm trống Thùng rác của toàn bộ các ổ đĩa? Hành động này sẽ giải phóng vĩnh viễn không gian đã xóa.`,
      onConfirm: async () => {
        try {
          const res = await fetch('/api/recycle_bin/empty', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
          });
          const d = await res.json();
          if (d.success) {
            showToast("Đã dọn sạch Thùng rác thành công!", "success");
            loadSystemOverview();
          }
        } catch (e) {
          showToast(`Lỗi dọn thùng rác: ${e.message}`, "danger");
        }
      }
    });
  });

  // TRIM Buttons
  document.querySelectorAll('.btn-run-trim').forEach(btn => {
    btn.addEventListener('click', () => {
      const drive = btn.getAttribute('data-drive');
      runDriveTrim(drive);
    });
  });

  // Restart Admin Button
  document.getElementById('btn-restart-admin').addEventListener('click', async () => {
    try {
      const res = await fetch('/api/system/restart_admin', { method: 'POST' });
      const d = await res.json();
      if (d.success) {
        showToast("Đang kích hoạt hộp thoại UAC để chạy với quyền Admin...", 'info');
      }
    } catch (e) {
      showToast(`Lỗi nâng quyền: ${e.message}`, 'danger');
    }
  });

  // Exit App Button
  const btnExitApp = document.getElementById('btn-exit-app');
  if (btnExitApp) {
    btnExitApp.addEventListener('click', async () => {
      if (confirm("Bạn có chắc chắn muốn thoát hoàn toàn CleanPC Master?")) {
        try {
          if (window.pywebview && window.pywebview.api && window.pywebview.api.exit_app) {
            await window.pywebview.api.exit_app();
          } else {
            await fetch('/api/app/exit', { method: 'POST' });
          }
          document.body.innerHTML = `
            <div style="height: 100vh; display: flex; align-items: center; justify-content: center; text-align: center; font-family: sans-serif; background: #070a13; color: #fff;">
              <div>
                <h2 style="color: #00e5ff; margin-bottom: 12px;">CleanPC Master đã dừng an toàn.</h2>
                <p style="color: #94a3b8;">Hẹn gặp lại bạn lần sau!</p>
              </div>
            </div>
          `;
        } catch (e) {
          window.close();
        }
      }
    });
  }
  // Memory Clean Buttons
  const btnManualCleanRam = document.getElementById('btn-manual-clean-ram');
  if (btnManualCleanRam) {
    btnManualCleanRam.addEventListener('click', cleanMemory);
  }

  const chkAutostartWindows = document.getElementById('chk-autostart-windows');
  if (chkAutostartWindows) {
    chkAutostartWindows.addEventListener('change', updateAutostartConfig);
  }

  const chkAutoCleanRam = document.getElementById('chk-auto-clean-ram');
  if (chkAutoCleanRam) {
    chkAutoCleanRam.addEventListener('change', updateMemoryDaemonConfig);
  }

  const rangeCleanThreshold = document.getElementById('range-clean-threshold');
  const lblThresholdVal = document.getElementById('lbl-threshold-val');
  if (rangeCleanThreshold) {
    rangeCleanThreshold.addEventListener('input', () => {
      if (lblThresholdVal) lblThresholdVal.textContent = `${rangeCleanThreshold.value}%`;
    });
    rangeCleanThreshold.addEventListener('change', updateMemoryDaemonConfig);
  }

  const chkGameGuard = document.getElementById('chk-game-guard');
  if (chkGameGuard) {
    chkGameGuard.addEventListener('change', updateMemoryDaemonConfig);
  }

  const chkOptStandby = document.getElementById('chk-opt-standby');
  if (chkOptStandby) {
    chkOptStandby.addEventListener('change', updateMemoryDaemonConfig);
  }

  const chkOptWorkingsets = document.getElementById('chk-opt-workingsets');
  if (chkOptWorkingsets) {
    chkOptWorkingsets.addEventListener('change', updateMemoryDaemonConfig);
  }

  const chkOptProtectForeground = document.getElementById('chk-opt-protect-foreground');
  if (chkOptProtectForeground) {
    chkOptProtectForeground.addEventListener('change', updateMemoryDaemonConfig);
  }

  // SMART Disk Refresh
  const btnRefreshSmart = document.getElementById('btn-refresh-smart');
  if (btnRefreshSmart) {
    btnRefreshSmart.addEventListener('click', () => loadDisksSmart(true));
  }
}

// -----------------------------------------------------------------------------
// Real-Time Memory Management & Mem Reduct
// -----------------------------------------------------------------------------
async function loadMemoryStatus() {
  try {
    const res = await fetch('/api/memory/status');
    if (!res.ok) return;
    const data = await res.json();
    state.memoryStatus = data;

    const pct = data.used_percent;
    const pctDisp = document.getElementById('ram-percent-display');
    const circleBar = document.getElementById('ram-circle-bar');
    if (pctDisp) pctDisp.textContent = `${pct}%`;
    if (circleBar) {
      const circ = 565.48;
      circleBar.style.strokeDashoffset = circ - (circ * (pct / 100));
    }

    const summaryText = document.getElementById('ram-summary-text');
    if (summaryText) {
      summaryText.textContent = `${data.used_formatted} / ${data.total_formatted} (Trống: ${data.available_formatted})`;
    }

    const inUse = document.getElementById('ram-stat-in-use');
    if (inUse) inUse.textContent = data.used_formatted;

    const standby = document.getElementById('ram-stat-standby');
    if (standby) standby.textContent = data.system_cache_formatted;

    const free = document.getElementById('ram-stat-free');
    if (free) free.textContent = data.available_formatted;

    const pagefile = document.getElementById('ram-stat-pagefile');
    if (pagefile) pagefile.textContent = data.pagefile_used_formatted;

    const pagefileSub = document.getElementById('ram-stat-pagefile-sub');
    if (pagefileSub) pagefileSub.textContent = `Đã dùng ${data.pagefile_percent}% bộ nhớ ảo (${data.pagefile_total_formatted})`;

    const adminInd = document.getElementById('ram-admin-indicator');
    if (adminInd) {
      let gamingText = data.is_gaming ? ' • <span style="color:var(--warning);font-weight:700;">🎮 Đang trong Game Fullscreen (Gaming Guard)</span>' : '';
      let adminText = data.is_admin ? '<span style="color:var(--success);">Administrator (NT Purge Ready)</span>' : '<span style="color:var(--text-muted);">Standard User</span>';
      adminInd.innerHTML = `${adminText}${gamingText}`;
    }
  } catch (e) {
    console.warn('[loadMemoryStatus error]:', e);
  }
}

async function cleanMemory() {
  const btn = document.getElementById('btn-manual-clean-ram');
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="pulse-dot"></span> Đang giải phóng RAM...`;
  }

  const purgeStandby = document.getElementById('chk-opt-standby')?.checked ?? true;
  const emptyWorkingSets = document.getElementById('chk-opt-workingsets')?.checked ?? true;
  const skipForeground = document.getElementById('chk-opt-protect-foreground')?.checked ?? true;

  try {
    const res = await fetch('/api/memory/clean', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        purge_standby: purgeStandby,
        empty_working_sets: emptyWorkingSets,
        flush_modified: true,
        skip_foreground: skipForeground
      })
    });
    const d = await res.json();
    if (d.success) {
      showToast(`Thu hồi thành công ${d.freed_formatted} RAM! (Đã dọn ${d.processes_trimmed} tiến trình nhàn rỗi)`, 'success');
      await loadMemoryStatus();
      await loadMemoryDaemonConfig();
    } else {
      showToast(`Không thể giải phóng RAM: ${d.error || 'Lỗi không xác định'}`, 'danger');
    }
  } catch (e) {
    showToast(`Lỗi dọn RAM: ${e.message}`, 'danger');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg> ⚡ Dọn Dẹp RAM Ngay`;
    }
  }
}

async function loadMemoryDaemonConfig() {
  try {
    const res = await fetch('/api/memory/daemon_config');
    if (!res.ok) return;
    const d = await res.json();

    const chkAuto = document.getElementById('chk-auto-clean-ram');
    if (chkAuto && d.enabled !== undefined) chkAuto.checked = !!d.enabled;

    const rangeThresh = document.getElementById('range-clean-threshold');
    const lblThresh = document.getElementById('lbl-threshold-val');
    if (rangeThresh && d.threshold_pct !== undefined) rangeThresh.value = d.threshold_pct;
    if (lblThresh && d.threshold_pct !== undefined) lblThresh.textContent = `${d.threshold_pct}%`;

    const chkGame = document.getElementById('chk-game-guard');
    if (chkGame && d.pause_in_game !== undefined) chkGame.checked = !!d.pause_in_game;

    const chkStandby = document.getElementById('chk-opt-standby');
    if (chkStandby && d.purge_standby !== undefined) chkStandby.checked = !!d.purge_standby;

    const chkWorkingsets = document.getElementById('chk-opt-workingsets');
    if (chkWorkingsets && d.empty_working_sets !== undefined) chkWorkingsets.checked = !!d.empty_working_sets;

    const chkProtectForeground = document.getElementById('chk-opt-protect-foreground');
    if (chkProtectForeground && d.skip_foreground !== undefined) chkProtectForeground.checked = !!d.skip_foreground;

    const lastTime = document.getElementById('lbl-daemon-last-time');
    if (lastTime && d.last_clean_str) lastTime.textContent = d.last_clean_str;

    const lastFreed = document.getElementById('lbl-daemon-last-freed');
    if (lastFreed && d.last_freed_formatted) lastFreed.textContent = d.last_freed_formatted;

    const cleanCount = document.getElementById('lbl-daemon-clean-count');
    if (cleanCount && d.clean_count !== undefined) cleanCount.textContent = d.clean_count;
  } catch (e) {
    console.warn('[loadMemoryDaemonConfig error]:', e);
  }
}

async function updateMemoryDaemonConfig() {
  try {
    const enabled = document.getElementById('chk-auto-clean-ram')?.checked ?? false;
    const threshold_pct = parseFloat(document.getElementById('range-clean-threshold')?.value ?? 80);
    const pause_in_game = document.getElementById('chk-game-guard')?.checked ?? true;
    const purge_standby = document.getElementById('chk-opt-standby')?.checked ?? true;
    const empty_working_sets = document.getElementById('chk-opt-workingsets')?.checked ?? true;
    const skip_foreground = document.getElementById('chk-opt-protect-foreground')?.checked ?? true;

    const res = await fetch('/api/memory/daemon_config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enabled,
        threshold_pct,
        cooldown_sec: 180,
        pause_in_game,
        purge_standby,
        empty_working_sets,
        skip_foreground
      })
    });
    const d = await res.json();
    if (d.success) {
      showToast(enabled ? `Đã kích hoạt tự động dọn RAM khi vượt ${threshold_pct}% (Zero-Lag Mode)!` : "Đã cập nhật cấu hình dọn dẹp RAM.", 'info');
      await loadMemoryDaemonConfig();
    }
  } catch (e) {
    showToast(`Lỗi lưu cấu hình: ${e.message}`, 'danger');
  }
}

async function loadAutostartConfig() {
  try {
    const res = await fetch('/api/autostart');
    if (!res.ok) return;
    const d = await res.json();
    const chk = document.getElementById('chk-autostart-windows');
    if (chk && d.enabled !== undefined) chk.checked = !!d.enabled;
  } catch (e) {
    console.warn('[loadAutostartConfig error]:', e);
  }
}

async function updateAutostartConfig() {
  try {
    const chk = document.getElementById('chk-autostart-windows');
    const enabled = chk?.checked ?? false;
    const res = await fetch('/api/autostart', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled })
    });
    const d = await res.json();
    if (d.success) {
      showToast(enabled ? "Đã bật: Ứng dụng sẽ tự khởi động ngầm trong khay hệ thống khi bật Windows!" : "Đã tắt khởi động cùng Windows.", 'info');
      await loadAutostartConfig();
    }
  } catch (e) {
    showToast(`Lỗi cài đặt khởi chạy: ${e.message}`, 'danger');
  }
}

// -----------------------------------------------------------------------------
// S.M.A.R.T Disk Health & Optimization
// -----------------------------------------------------------------------------
async function loadDisksSmart(forceRefresh = false) {
  const container = document.getElementById('smart-disks-container');
  if (!container) return;

  if (state.disksSmart.length === 0 || forceRefresh) {
    container.innerHTML = `
      <div class="card" style="text-align: center; color: var(--text-muted); padding: 40px; grid-column: 1 / -1;">
        <div class="pulse-dot" style="margin: 0 auto 16px auto;"></div>
        Đang phân tích sức khỏe phần cứng S.M.A.R.T và cảm biến nhiệt độ...
      </div>
    `;
  }

  try {
    const url = forceRefresh ? '/api/disks/smart?force=1' : '/api/disks/smart';
    const res = await fetch(url);
    if (!res.ok) throw new Error("Không thể tải thông tin S.M.A.R.T");
    const d = await res.json();
    state.disksSmart = d.disks || [];

    if (state.disksSmart.length === 0) {
      container.innerHTML = `<div class="card" style="text-align:center;grid-column: 1 / -1;">Không phát hiện ổ đĩa vật lý hoặc không đủ quyền truy vấn.</div>`;
      return;
    }

    container.innerHTML = state.disksSmart.map(disk => {
      let tempHtml = '';
      if (disk.temperature !== null && disk.temperature !== undefined) {
        let tempClass = disk.temperature_status === 'danger' ? 'temp-badge-danger' : (disk.temperature_status === 'warning' ? 'temp-badge-warning' : 'temp-badge-good');
        let tempHint = disk.temperature < 55 ? 'Mát mẻ' : (disk.temperature < 70 ? 'Ấm' : 'Quá nhiệt');
        tempHtml = `<span class="${tempClass}">🌡️ ${disk.temperature}°C</span> <span class="smart-metric-hint" style="color:var(--text-dim);">(${tempHint})</span>`;
      } else {
        tempHtml = `<span style="font-size:0.85rem;color:var(--text-dim);">Cần quyền Admin</span>`;
      }

      let lifeHtml = '';
      if (disk.remaining_life_percent !== null && disk.remaining_life_percent !== undefined) {
        lifeHtml = `<span style="color:var(--success);">${disk.remaining_life_percent}%</span> <span class="smart-metric-hint" style="color:var(--text-dim);">(Hao mòn: ${disk.wear_percent}%)</span>`;
      } else {
        lifeHtml = `<span style="font-size:0.85rem;color:var(--text-dim);">Hoạt động tốt</span>`;
      }

      let trimButtons = '';
      if (disk.drives && disk.drives.length > 0) {
        trimButtons = disk.drives.map(letter => `
          <button class="btn btn-sm btn-primary btn-run-trim" data-drive="${letter}">
            ⚡ Chạy TRIM Ổ ${letter}:
          </button>
        `).join('');
      }

      return `
        <div class="smart-disk-card">
          <div class="smart-disk-header">
            <div class="smart-disk-info">
              <div class="smart-disk-title" title="${escapeHtml(disk.name)}">
                <svg style="width:19px;height:19px;color:var(--primary);flex-shrink:0;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                <span>${escapeHtml(disk.name)}</span>
              </div>
              <div class="smart-disk-subtitle">
                Phân vùng: <strong>${disk.drives.join(', ') || 'N/A'}</strong> • Dung lượng: <strong>${disk.size_formatted}</strong>
              </div>
            </div>
            <div class="smart-badges">
              <span class="badge" style="background:rgba(59,130,246,0.15);color:var(--secondary);">${escapeHtml(disk.full_type)}</span>
              <span class="badge" style="background:rgba(16,185,129,0.15);color:var(--success);">${escapeHtml(disk.health_status)}</span>
            </div>
          </div>

          <div class="smart-metrics-grid">
            <div class="smart-metric-box">
              <div class="smart-metric-label">Nhiệt Độ Ổ Cứng</div>
              <div class="smart-metric-val">${tempHtml}</div>
            </div>
            <div class="smart-metric-box">
              <div class="smart-metric-label">Tuổi Thọ Còn Lại</div>
              <div class="smart-metric-val">${lifeHtml}</div>
            </div>
            <div class="smart-metric-box">
              <div class="smart-metric-label">Thời Gian Hoạt Động</div>
              <div class="smart-metric-val">
                <span>${disk.power_on_hours ? disk.power_on_hours + ' Giờ' : 'Sẵn sàng'}</span>
              </div>
            </div>
            <div class="smart-metric-box">
              <div class="smart-metric-label">Lỗi Đọc Ghi (Read Errors)</div>
              <div class="smart-metric-val">
                <span style="color:${disk.read_errors ? 'var(--warning)' : 'var(--success)'};">${disk.read_errors ? disk.read_errors + ' Lỗi' : '0 (An toàn)'}</span>
              </div>
            </div>
          </div>

          <div class="smart-disk-actions">
            ${trimButtons}
          </div>
        </div>
      `;
    }).join('');

    // Re-bind TRIM buttons
    container.querySelectorAll('.btn-run-trim').forEach(btn => {
      btn.addEventListener('click', () => {
        const drive = btn.getAttribute('data-drive');
        runDriveTrim(drive, btn);
      });
    });

  } catch (e) {
    container.innerHTML = `<div class="card" style="color:var(--danger);text-align:center;grid-column: 1 / -1;">Lỗi tải dữ liệu S.M.A.R.T: ${e.message}</div>`;
  }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------
async function openInExplorer(path) {
  try {
    const res = await fetch('/api/system/open_explorer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path })
    });
    const d = await res.json();
    if (d.success) {
      showToast("Đã mở thư mục trong Windows Explorer", 'info');
    } else {
      showToast("Không thể mở đường dẫn này", 'warning');
    }
  } catch (e) {
    showToast(`Lỗi: ${e.message}`, 'danger');
  }
}

function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) {
    bytes /= 1024;
    i++;
  }
  return `${bytes.toFixed(2)} ${units[i]}`;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// -----------------------------------------------------------------------------
// Power & Idle Optimization: Zero Resource Mode when Minimized / Hidden to Tray
// -----------------------------------------------------------------------------
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    // Window minimized or sent to system tray: completely freeze polling
    if (state.memoryPollTimer) {
      clearInterval(state.memoryPollTimer);
      state.memoryPollTimer = null;
    }
    if (state.duplicatePollTimer) {
      clearInterval(state.duplicatePollTimer);
      state.duplicatePollTimer = null;
    }
  } else {
    // Window restored to foreground: resume live polling if memory tab is active
    const activeTab = document.querySelector('.nav-item.active');
    if (activeTab && activeTab.getAttribute('data-tab') === 'tab-memory') {
      loadMemoryStatus();
      if (!state.memoryPollTimer) {
        state.memoryPollTimer = setInterval(loadMemoryStatus, 2000);
      }
    }
  }
});

