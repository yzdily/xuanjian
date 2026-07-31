/**
 * 稻草人安全团队密钥获取工具 - Content Script v1.0
 * inject.js 已通过 manifest 直接注入到 MAIN world
 * 本脚本负责与 inject.js 和 background.js 通信
 */

(function() {
  'use strict';

  // 防止重复注入
  if (window.__CRYPTO_HOOK_CONTENT_INJECTED__) return;
  window.__CRYPTO_HOOK_CONTENT_INJECTED__ = true;

  // 存储从注入脚本接收的捕获数据
  let capturedData = {
    captures: [],
    keyStore: {
      keys: [],
      ivs: [],
      secrets: [],
      signParams: []
    },
    requests: [] // 新增：加密请求记录
  };
  
  // 等待 inject.js 响应的 Promise 回调
  let pendingCallbacks = new Map();
  let callbackId = 0;

  // 安全发送消息到 background（不等待响应）
  function safeSendMessage(message) {
    try {
      chrome.runtime.sendMessage(message).catch(() => {});
    } catch (e) {}
  }

  // 监听来自注入脚本的消息
  window.addEventListener('message', function(event) {
    if (event.source !== window) return;
    
    const data = event.data;
    if (!data || data.source !== 'CRYPTO_HOOK_INJECT') return;
    
    if (data.type === 'CAPTURE_UPDATE') {
      // v5.2: 只同步新增的数据，避免重复发送
      const oldKeyCount = capturedData.keyStore.keys.length;
      const oldIVCount = capturedData.keyStore.ivs.length;
      const oldSecretCount = capturedData.keyStore.secrets.length;
      
      capturedData.captures = data.captures || [];
      capturedData.keyStore = data.keyStore || capturedData.keyStore;
      capturedData.requests = data.requests || capturedData.requests;
      
      // 只同步新增的 Key（比较数量，只发送新增的部分）
      if (data.keyStore && data.keyStore.keys) {
        const newKeys = data.keyStore.keys.slice(0, data.keyStore.keys.length - oldKeyCount);
        newKeys.forEach(key => {
          safeSendMessage({ type: 'KEY_CAPTURE', payload: { keyType: 'KEY', data: key } });
        });
      }
      // 只同步新增的 IV
      if (data.keyStore && data.keyStore.ivs) {
        const newIVs = data.keyStore.ivs.slice(0, data.keyStore.ivs.length - oldIVCount);
        newIVs.forEach(iv => {
          safeSendMessage({ type: 'KEY_CAPTURE', payload: { keyType: 'IV', data: iv } });
        });
      }
      // 只同步新增的 Secret
      if (data.keyStore && data.keyStore.secrets) {
        const newSecrets = data.keyStore.secrets.slice(0, data.keyStore.secrets.length - oldSecretCount);
        newSecrets.forEach(secret => {
          safeSendMessage({ type: 'KEY_CAPTURE', payload: { keyType: 'SECRET', data: secret } });
        });
      }
      // 同步请求记录（整体替换）
      if (data.requests) {
        safeSendMessage({ type: 'REQUEST_CAPTURE', payload: data.requests });
      }
      
    } else if (data.type === 'NEW_CAPTURE') {
      capturedData.captures.push(data.entry);
      safeSendMessage({ type: 'CRYPTO_CAPTURE', payload: data.entry });
      
    } else if (data.type === 'KEY_CAPTURE') {
      safeSendMessage({ type: 'KEY_CAPTURE', payload: { keyType: data.keyType, data: data.data } });
      
    } else if (data.type === 'REQUEST_CAPTURE') {
      // 新增：加密请求捕获
      if (!capturedData.requests) capturedData.requests = [];
      capturedData.requests.unshift(data.request);
      if (capturedData.requests.length > 50) capturedData.requests.pop();
      safeSendMessage({ type: 'REQUEST_CAPTURE', payload: capturedData.requests });
      
    } else if (data.type === 'CRYPTO_RESULT') {
      // 处理加解密结果回调
      const callback = pendingCallbacks.get(data.callbackId);
      if (callback) {
        pendingCallbacks.delete(data.callbackId);
        callback(data);
      }
    }
  });

  // 请求注入脚本发送当前数据
  function requestCaptureData() {
    window.postMessage({ source: 'CRYPTO_HOOK_CONTENT', type: 'REQUEST_CAPTURES' }, '*');
  }

  // 请求清空数据
  function requestClearCaptures() {
    window.postMessage({ source: 'CRYPTO_HOOK_CONTENT', type: 'CLEAR_CAPTURES' }, '*');
  }
  
  // 发送加解密请求到 inject.js 并等待结果
  function performCryptoInPage(action, data, algorithm, keyIndex) {
    return new Promise((resolve) => {
      const id = ++callbackId;
      pendingCallbacks.set(id, resolve);
      
      window.postMessage({
        source: 'CRYPTO_HOOK_CONTENT',
        type: 'PERFORM_CRYPTO',
        callbackId: id,
        action: action,
        data: data,
        algorithm: algorithm,
        keyIndex: keyIndex
      }, '*');
      
      // 超时处理
      setTimeout(() => {
        if (pendingCallbacks.has(id)) {
          pendingCallbacks.delete(id);
          resolve({ success: false, error: '操作超时' });
        }
      }, 10000);
    });
  }
  
  // 发送请求重放到 inject.js
  function replayRequestInPage(request) {
    return new Promise((resolve) => {
      const id = ++callbackId;
      pendingCallbacks.set(id, resolve);
      
      window.postMessage({
        source: 'CRYPTO_HOOK_CONTENT',
        type: 'REPLAY_REQUEST',
        callbackId: id,
        request: request
      }, '*');
      
      // 超时处理
      setTimeout(() => {
        if (pendingCallbacks.has(id)) {
          pendingCallbacks.delete(id);
          resolve({ success: false, error: '请求超时' });
        }
      }, 30000);
    });
  }
  
  // 监听来自 popup 的消息
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_CAPTURES') {
      requestCaptureData();
      setTimeout(() => {
        sendResponse({
          success: true,
          captures: capturedData.captures,
          keyStore: capturedData.keyStore,
          requests: capturedData.requests,
          count: capturedData.captures.length
        });
      }, 100);
      return true;
      
    } else if (message.type === 'CLEAR_CAPTURES') {
      requestClearCaptures();
      capturedData.captures = [];
      capturedData.keyStore = { keys: [], ivs: [], secrets: [], signParams: [] };
      capturedData.requests = [];
      sendResponse({ success: true });
      return true;
      
    } else if (message.type === 'PERFORM_CRYPTO') {
      // 新增：执行加解密
      performCryptoInPage(message.action, message.data, message.algorithm, message.keyIndex)
        .then(result => sendResponse(result));
      return true;
      
    } else if (message.type === 'REPLAY_REQUEST') {
      // 新增：重放请求
      replayRequestInPage(message.request)
        .then(result => sendResponse(result));
      return true;
    }
    return true;
  });
  
  // 定期同步数据
  setInterval(requestCaptureData, 2000);
  
  // 延迟请求数据
  setTimeout(requestCaptureData, 500);
  
})();
