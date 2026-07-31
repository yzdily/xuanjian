/**
 * 稻草人安全团队密钥获取工具 - Background Service Worker v1.0
 * 负责管理捕获数据和标签页状态
 */

// 存储所有标签页的捕获数据
const tabCaptures = new Map();

// 存储所有标签页的 Key/IV/Secret
const tabKeyStore = new Map();

// 存储所有标签页的加密请求记录
const tabRequests = new Map();

// 需要过滤掉的底层捕获来源（与 popup.js 保持一致）
const FILTER_SOURCES = [
  'String.fromCharCode',
  'Uint8Array.set',
  'btoa',
  'atob'
];

// 过滤掉底层捕获来源的数据
function filterBySource(items) {
  if (!items || !Array.isArray(items)) return [];
  return items.filter(item => {
    const source = item.source || '';
    return !FILTER_SOURCES.some(filterSource => source.includes(filterSource));
  });
}

// 监听来自 content script 的消息
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id;
  
  console.log('[CryptoHook Background] 收到消息:', message.type, 'tabId:', tabId);
  
  if (message.type === 'CRYPTO_CAPTURE') {
    if (tabId) {
      if (!tabCaptures.has(tabId)) {
        tabCaptures.set(tabId, []);
      }
      tabCaptures.get(tabId).push(message.payload);
      updateBadge(tabId);
    }
    return false;
  } 
  else if (message.type === 'KEY_CAPTURE') {
    if (tabId) {
      if (!tabKeyStore.has(tabId)) {
        tabKeyStore.set(tabId, { keys: [], ivs: [], secrets: [] });
      }
      const store = tabKeyStore.get(tabId);
      const { keyType, data } = message.payload;
      
      console.log('[CryptoHook Background] KEY_CAPTURE:', keyType, data);
      
      if (keyType === 'KEY') {
        if (!store.keys.find(k => k.hex === data.hex)) {
          store.keys.unshift(data);
          if (store.keys.length > 50) store.keys.pop();
          console.log('[CryptoHook Background] 添加 Key, 当前数量:', store.keys.length);
        }
      } else if (keyType === 'IV') {
        if (!store.ivs.find(k => k.hex === data.hex)) {
          store.ivs.unshift(data);
          if (store.ivs.length > 30) store.ivs.pop();
          console.log('[CryptoHook Background] 添加 IV, 当前数量:', store.ivs.length);
        }
      } else if (keyType === 'SECRET') {
        if (!store.secrets.find(s => s.value === data.value)) {
          store.secrets.unshift(data);
          if (store.secrets.length > 30) store.secrets.pop();
          console.log('[CryptoHook Background] 添加 Secret, 当前数量:', store.secrets.length);
        }
      }
      
      updateBadge(tabId);
    }
    return false;
  }
  else if (message.type === 'REQUEST_CAPTURE') {
    // 新增：存储加密请求记录
    if (tabId) {
      tabRequests.set(tabId, message.payload || []);
      console.log('[CryptoHook Background] 更新请求记录, 数量:', (message.payload || []).length);
    }
    return false;
  }
  else if (message.type === 'GET_TAB_CAPTURES') {
    const tid = message.tabId;
    const result = { 
      captures: tabCaptures.get(tid) || [],
      keyStore: tabKeyStore.get(tid) || { keys: [], ivs: [], secrets: [] },
      requests: tabRequests.get(tid) || []
    };
    console.log('[CryptoHook Background] GET_TAB_CAPTURES 返回:', result.keyStore.keys.length, 'keys,', result.requests.length, 'requests');
    sendResponse(result);
    return true;
  } 
  else if (message.type === 'CLEAR_TAB_CAPTURES') {
    const tid = message.tabId;
    tabCaptures.set(tid, []);
    tabKeyStore.set(tid, { keys: [], ivs: [], secrets: [] });
    tabRequests.set(tid, []);
    updateBadge(tid);
    sendResponse({ success: true });
    return true;
  } 
  else if (message.type === 'EXPORT_ALL_CAPTURES') {
    const allCaptures = {};
    const allKeyStore = {};
    const allRequests = {};
    tabCaptures.forEach((captures, tid) => {
      allCaptures[tid] = captures;
    });
    tabKeyStore.forEach((store, tid) => {
      allKeyStore[tid] = store;
    });
    tabRequests.forEach((requests, tid) => {
      allRequests[tid] = requests;
    });
    sendResponse({ captures: allCaptures, keyStore: allKeyStore, requests: allRequests });
    return true;
  }
  
  return false;
});

// 更新扩展图标上的 badge
async function updateBadge(tabId) {
  if (!tabId) return;
  
  try {
    // 先检查标签页是否存在
    await chrome.tabs.get(tabId);
    
    const captures = tabCaptures.get(tabId) || [];
    const keyStore = tabKeyStore.get(tabId) || { keys: [], ivs: [], secrets: [] };
    
    // 使用过滤后的 Key 数量（与 popup 保持一致）
    const filteredKeys = filterBySource(keyStore.keys);
    const keyCount = filteredKeys.length;
    const count = keyCount > 0 ? keyCount : captures.length;
    
    await chrome.action.setBadgeText({
      text: count > 0 ? String(count) : '',
      tabId: tabId
    });
    
    await chrome.action.setBadgeBackgroundColor({
      color: keyCount > 0 ? '#FF5722' : '#667eea',  // 有 Key 显示橙色
      tabId: tabId
    });
  } catch (e) {
    // 标签页不存在，清理数据
    tabCaptures.delete(tabId);
    tabKeyStore.delete(tabId);
  }
}

// 标签页关闭时清理数据
chrome.tabs.onRemoved.addListener((tabId) => {
  tabCaptures.delete(tabId);
  tabKeyStore.delete(tabId);
  tabRequests.delete(tabId);
});

// 标签页导航时清理数据
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    tabCaptures.set(tabId, []);
    tabKeyStore.set(tabId, { keys: [], ivs: [], secrets: [] });
    tabRequests.set(tabId, []);
    updateBadge(tabId);
  }
});

console.log('[稻草人安全团队密钥获取工具] Background service worker v1.0 已启动');
