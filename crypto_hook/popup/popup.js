/**
 * 稻草人安全团队密钥获取工具 - Popup Script v1.0
 * 精简版：专注于 Key/IV/Secret 展示
 */

// 过滤底层捕获来源
const FILTER_SOURCES = ['String.fromCharCode', 'Uint8Array.set', 'btoa', 'atob'];

// 当前标签页 ID
let currentTabId = null;

// HTML 转义
function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

document.addEventListener('DOMContentLoaded', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTabId = tab.id;
  
  loadCaptures(tab.id);
  
  document.getElementById('refreshBtn').addEventListener('click', () => loadCaptures(tab.id));
  document.getElementById('exportBtn').addEventListener('click', () => exportCaptures(tab.id));
  document.getElementById('clearBtn').addEventListener('click', () => clearCaptures(tab.id));
});

// 加载捕获数据
async function loadCaptures(tabId) {
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'GET_TAB_CAPTURES',
      tabId: tabId
    });
    
    const keyStore = response.keyStore || { keys: [], ivs: [], secrets: [] };
    
    // 过滤底层来源
    const keys = filterBySource(keyStore.keys);
    const ivs = filterBySource(keyStore.ivs);
    const secrets = keyStore.secrets || [];
    
    // 更新统计
    document.getElementById('keyCount').textContent = keys.length;
    document.getElementById('ivCount').textContent = ivs.length;
    document.getElementById('secretCount').textContent = secrets.length;
    
    // 渲染列表
    renderCaptureList(keys, ivs, secrets);
    
  } catch (e) {
    console.error('加载失败:', e);
  }
}

// 过滤底层来源
function filterBySource(items) {
  if (!items || !Array.isArray(items)) return [];
  return items.filter(item => {
    const source = item.source || '';
    return !FILTER_SOURCES.some(f => source.includes(f));
  });
}

// 渲染捕获列表
function renderCaptureList(keys, ivs, secrets) {
  const listEl = document.getElementById('captureList');
  
  // 合并所有数据
  const allItems = [
    ...keys.map(k => ({ ...k, type: 'key' })),
    ...ivs.map(k => ({ ...k, type: 'iv' })),
    ...secrets.map(s => ({ ...s, type: 'secret' }))
  ];
  
  if (allItems.length === 0) {
    listEl.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🎯</div>
        <p>等待捕获...</p>
        <p class="empty-hint">触发页面加解密操作后自动显示</p>
      </div>
    `;
    return;
  }
  
  listEl.innerHTML = allItems.slice(0, 20).map((item, idx) => {
    const type = item.type;
    const typeLabel = type === 'key' ? 'KEY' : type === 'iv' ? 'IV' : 'SECRET';
    
    if (type === 'secret') {
      const value = escapeHtml(item.value || '');
      const usage = escapeHtml(item.usage || '');
      const displayValue = value.length > 50 ? value.substring(0, 50) + '...' : value;
      
      return `
        <div class="capture-item">
          <div class="capture-header">
            <span class="capture-type ${type}">${usage || typeLabel}</span>
            <button class="capture-copy" data-copy="${value}" title="复制">📋</button>
          </div>
          <div class="capture-value" data-value="${value}">${displayValue}</div>
        </div>
      `;
    }
    
    const ascii = escapeHtml(item.ascii || item.original || '');
    const hex = escapeHtml(item.hex || '');
    const algo = escapeHtml(item.algorithm || '');
    const mode = item.mode ? escapeHtml(item.mode) : '';
    const padding = item.padding ? '/' + escapeHtml(item.padding) : '';
    const length = item.length || (hex.length / 2);
    
    return `
      <div class="capture-item">
        <div class="capture-header">
          <span class="capture-type ${type}">${typeLabel}</span>
          <span class="capture-algo">${algo} ${length}字节</span>
          ${mode ? `<span class="capture-mode">${mode}${padding}</span>` : ''}
          <button class="capture-copy" data-copy="${ascii}" title="复制">📋</button>
        </div>
        <div class="capture-value" data-value="${ascii}">${ascii}</div>
        ${hex ? `<div class="capture-hex">Hex: ${hex}</div>` : ''}
      </div>
    `;
  }).join('');
  
  // 绑定复制事件
  listEl.querySelectorAll('.capture-copy').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      copyToClipboard(btn.dataset.copy);
      btn.textContent = '✅';
      setTimeout(() => btn.textContent = '📋', 800);
    });
  });
  
  listEl.querySelectorAll('.capture-value').forEach(el => {
    el.addEventListener('click', () => {
      copyToClipboard(el.dataset.value || el.textContent);
      el.style.background = '#c8e6c9';
      setTimeout(() => el.style.background = '', 300);
    });
  });
}

// 复制到剪贴板
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
  }
}

// 导出
async function exportCaptures(tabId) {
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'GET_TAB_CAPTURES',
      tabId: tabId
    });
    
    const data = {
      keyStore: response.keyStore,
      exportTime: new Date().toISOString()
    };
    
    const ks = data.keyStore;
    if (!ks.keys?.length && !ks.ivs?.length && !ks.secrets?.length) {
      alert('没有可导出的数据');
      return;
    }
    
    const json = JSON.stringify(data, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `crypto-keys-${Date.now()}.json`;
    a.click();
    
    URL.revokeObjectURL(url);
  } catch (e) {
    alert('导出失败: ' + e.message);
  }
}

// 清空
async function clearCaptures(tabId) {
  if (!confirm('确定清空所有捕获数据？')) return;
  
  try {
    await chrome.runtime.sendMessage({
      type: 'CLEAR_TAB_CAPTURES',
      tabId: tabId
    });
    
    try {
      await chrome.tabs.sendMessage(tabId, { type: 'CLEAR_CAPTURES' });
    } catch (e) {}
    
    loadCaptures(tabId);
  } catch (e) {
    console.error('清空失败:', e);
  }
}
