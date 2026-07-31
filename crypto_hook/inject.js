/**
 * 稻草人安全团队密钥获取工具 - 注入脚本 v1.0
 * 行业最强前端加解密 Hook 工具
 * 核心能力：精准捕获 Key/IV/Secret、自动识别加密模式、明密文关联、自主加解密
 * 支持：CryptoJS、JSEncrypt、SM2/SM4、WebCrypto、Forge、SJCL
 * 通过 manifest.json 的 world: "MAIN" 直接注入到页面主世界
 */
(function(targetWindow) {
  'use strict';
  
  if (targetWindow.__CRYPTO_HOOK_INITIALIZED__) return;
  targetWindow.__CRYPTO_HOOK_INITIALIZED__ = true;
  
  var VERSION = '1.0';
  var LOG_PREFIX = '[🔐 稻草人安全]';
  var DEBUG_MODE = false;  // 设为 true 可开启详细日志
  
  // 保存原始 console 方法，防止被网站重写影响
  var originalConsole = {
    log: console.log.bind(console),
    warn: console.warn.bind(console),
    error: console.error.bind(console),
    group: console.group ? console.group.bind(console) : function() {},
    groupCollapsed: console.groupCollapsed ? console.groupCollapsed.bind(console) : function() {},
    groupEnd: console.groupEnd ? console.groupEnd.bind(console) : function() {}
  };
  
  // ==================== 核心数据存储 ====================
  
  var keyStore = {
    keys: [],
    ivs: [],
    secrets: [],
    signParams: [],
    // v5.0 新增：明密文记录
    cryptoRecords: []
  };
  
  var captures = [];
  var capturedData = {
    CryptoJS: [], RSA: [], SM2: [], SM4: [], WebCrypto: [],
    Encoders: [], Hash: [], Sign: [], KeyCapture: [],
    // v5.0 新增
    Forge: [], SJCL: []
  };
  
  var config = { maxCaptures: 500, enableConsoleLog: true, autoAnalyze: true };
  var lastEncryptStack = '';
  var lastDecryptStack = '';
  
  // v6.4: 防止重复输出的标记
  var cryptoOutputState = {
    lastOutputTime: 0,
    lastKeyHex: '',
    lastPlaintext: '',
    interval: 100  // 100ms 内相同的操作不重复输出
  };
  
  function shouldOutputCrypto(keyHex, plaintext) {
    var now = Date.now();
    if (now - cryptoOutputState.lastOutputTime < cryptoOutputState.interval &&
        cryptoOutputState.lastKeyHex === keyHex &&
        cryptoOutputState.lastPlaintext === plaintext) {
      return false;
    }
    cryptoOutputState.lastOutputTime = now;
    cryptoOutputState.lastKeyHex = keyHex;
    cryptoOutputState.lastPlaintext = plaintext;
    return true;
  }
  
  // ==================== v6.0 请求追踪系统 ====================
  
  var requestTracker = {
    // 待关联的加密操作（时间窗口内）
    pendingCrypto: [],
    // 请求追踪记录
    traces: [],
    // 当前活跃的请求上下文
    activeRequests: {},
    // 配置
    config: {
      timeWindow: 100,        // 关联时间窗口(ms)
      maxTraces: 50,          // 最大追踪记录数
      maxPending: 20          // 最大待关联数
    }
  };
  
  // 生成唯一请求ID
  function generateRequestId() {
    return 'req_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
  }
  
  // 添加待关联的加密操作
  function addPendingCrypto(cryptoInfo) {
    cryptoInfo.timestamp = Date.now();
    cryptoInfo.id = 'crypto_' + Date.now() + '_' + Math.random().toString(36).substr(2, 4);
    requestTracker.pendingCrypto.unshift(cryptoInfo);
    
    // 限制数量
    if (requestTracker.pendingCrypto.length > requestTracker.config.maxPending) {
      requestTracker.pendingCrypto.pop();
    }
    
    // 清理过期的（超过1秒）
    var now = Date.now();
    requestTracker.pendingCrypto = requestTracker.pendingCrypto.filter(function(c) {
      return now - c.timestamp < 1000;
    });
    
    return cryptoInfo;
  }
  
  // 关联加密操作到请求
  function associateCryptoToRequest(requestId, url, method) {
    var now = Date.now();
    var timeWindow = requestTracker.config.timeWindow;
    
    // 查找时间窗口内的加密操作
    var associated = requestTracker.pendingCrypto.filter(function(c) {
      return now - c.timestamp < timeWindow && !c.associated;
    });
    
    // 标记为已关联
    associated.forEach(function(c) { c.associated = true; });
    
    if (associated.length > 0 || true) {  // 始终创建追踪记录
      var trace = {
        id: requestId,
        request: {
          method: method,
          url: url,
          timestamp: now
        },
        encryptions: associated,
        response: null
      };
      
      requestTracker.traces.unshift(trace);
      requestTracker.activeRequests[requestId] = trace;
      
      // 限制数量
      if (requestTracker.traces.length > requestTracker.config.maxTraces) {
        var removed = requestTracker.traces.pop();
        delete requestTracker.activeRequests[removed.id];
      }
      
      return trace;
    }
    return null;
  }
  
  // 关联解密操作到响应
  function associateDecryptToResponse(url, decryptInfo) {
    // 查找匹配的请求追踪
    var trace = requestTracker.traces.find(function(t) {
      return t.request.url === url || url.indexOf(t.request.url) !== -1 || t.request.url.indexOf(url) !== -1;
    });
    
    if (trace) {
      trace.response = {
        decrypted: decryptInfo.plaintext,
        algorithm: decryptInfo.algorithm,
        keyHex: decryptInfo.keyHex,
        ivHex: decryptInfo.ivHex,
        timestamp: Date.now()
      };
      
      // 检查是否使用相同的Key
      if (trace.encryptions && trace.encryptions.length > 0) {
        var sameKey = trace.encryptions.some(function(e) {
          return e.keyHex === decryptInfo.keyHex;
        });
        if (sameKey) {
          trace.response.sameKeyAsRequest = true;
        }
      }
    }
    
    return trace;
  }
  
  // 格式化时间
  function formatTime(timestamp) {
    var d = new Date(timestamp);
    return d.getHours().toString().padStart(2, '0') + ':' +
           d.getMinutes().toString().padStart(2, '0') + ':' +
           d.getSeconds().toString().padStart(2, '0') + '.' +
           d.getMilliseconds().toString().padStart(3, '0');
  }
  
  // 获取请求追踪记录
  function getRequestTraces() {
    console.log('%c' + LOG_PREFIX + ' 📊 请求追踪记录 (' + requestTracker.traces.length + '条)', 'color: #9C27B0; font-weight: bold; font-size: 14px;');
    console.log('%c' + '═'.repeat(60), 'color: #9C27B0;');
    
    if (requestTracker.traces.length === 0) {
      console.log('%c  暂无追踪记录，请先触发一些加密请求', 'color: #999;');
      return [];
    }
    
    requestTracker.traces.forEach(function(trace, index) {
      var hasEncrypt = trace.encryptions && trace.encryptions.length > 0;
      var hasDecrypt = trace.response !== null;
      
      console.log('%c┌─ 请求 #' + (index + 1) + ' ' + '─'.repeat(50), 'color: #2196F3;');
      console.log('%c│ ' + trace.request.method + ' ' + trace.request.url + ' @ ' + formatTime(trace.request.timestamp), 'color: #2196F3; font-weight: bold;');
      
      if (hasEncrypt) {
        console.log('%c├───────────────────────────────────────────────────────', 'color: #4CAF50;');
        console.log('%c│ 📤 请求加密 (' + trace.encryptions.length + '个):', 'color: #4CAF50; font-weight: bold;');
        trace.encryptions.forEach(function(enc, i) {
          console.log('%c│   [' + (i + 1) + '] ' + enc.algorithm + '-' + enc.mode + '-' + enc.padding, 'color: #4CAF50;');
          console.log('%c│       Key: ' + enc.keyHex, 'color: #666;');
          if (enc.ivHex) console.log('%c│       IV: ' + enc.ivHex, 'color: #666;');
          console.log('%c│       明文: ' + (enc.plaintext || '').substring(0, 80) + ((enc.plaintext || '').length > 80 ? '...' : ''), 'color: #666;');
          if (enc.callStack) {
            var stackLine = enc.callStack.split('\n')[0] || '';
            console.log('%c│       调用: ' + stackLine.trim(), 'color: #FF9800;');
          }
        });
      }
      
      if (hasDecrypt) {
        console.log('%c├───────────────────────────────────────────────────────', 'color: #E91E63;');
        console.log('%c│ 📥 响应解密:', 'color: #E91E63; font-weight: bold;');
        console.log('%c│   算法: ' + trace.response.algorithm + (trace.response.sameKeyAsRequest ? ' (同Key)' : ''), 'color: #E91E63;');
        console.log('%c│   Key: ' + trace.response.keyHex, 'color: #666;');
        if (trace.response.ivHex) console.log('%c│   IV: ' + trace.response.ivHex, 'color: #666;');
        console.log('%c│   明文: ' + (trace.response.decrypted || '').substring(0, 80) + ((trace.response.decrypted || '').length > 80 ? '...' : ''), 'color: #666;');
      }
      
      if (!hasEncrypt && !hasDecrypt) {
        console.log('%c│ (无加解密操作)', 'color: #999;');
      }
      
      console.log('%c└' + '─'.repeat(59), 'color: #2196F3;');
      console.log('');
    });
    
    return requestTracker.traces;
  }
  
  // 查看某个Key的所有使用记录
  function getKeyUsage(keyHex) {
    // 支持数字类型参数，自动转为字符串
    if (keyHex !== undefined && keyHex !== null) {
      keyHex = String(keyHex);
    }
    
    if (!keyHex) {
      console.log('%c' + LOG_PREFIX + ' ⚠️ 请提供 keyHex 参数', 'color: #FF9800;');
      console.log('%c  用法: getKeyUsage("abc123...") 或 getKeyUsage(getKeys()[0].hex)', 'color: #999;');
      return [];
    }
    
    var usages = [];
    
    // 从 cryptoRecords 中查找
    keyStore.cryptoRecords.forEach(function(r) {
      if (r.keyHex === keyHex || (r.keyHex && r.keyHex.indexOf(keyHex) !== -1)) {
        usages.push({
          type: r.type,
          algorithm: r.algorithm,
          mode: r.mode,
          url: r.url || '未知',
          plaintext: r.plaintext,
          ciphertext: r.ciphertext,
          timestamp: r.timestamp,
          callStack: r.callStack
        });
      }
    });
    
    var displayKey = keyHex.length > 16 ? keyHex.substring(0, 16) + '...' : keyHex;
    console.log('%c' + LOG_PREFIX + ' 🔑 Key 使用记录: ' + displayKey, 'color: #9C27B0; font-weight: bold;');
    console.log('%c  共 ' + usages.length + ' 条记录', 'color: #666;');
    
    if (usages.length === 0) {
      console.log('%c  暂无使用记录。提示: 请先触发加解密操作（如登录、提交表单）', 'color: #999;');
    }
    
    usages.forEach(function(u, i) {
      console.log('%c[' + (i + 1) + '] ' + u.type.toUpperCase() + ' - ' + u.algorithm + ' @ ' + formatTime(u.timestamp), 'color: #2196F3;');
      if (u.url !== '未知') console.log('    URL: ' + u.url);
      console.log('    明文: ' + (u.plaintext || '').substring(0, 60));
    });
    
    return usages;
  }
  
  // ==================== 加密模式检测 ====================
  
  function detectCryptoMode(cfg, CryptoJS) {
    if (!cfg) return { mode: 'ECB', padding: 'PKCS7' };
    
    var mode = 'CBC';
    var padding = 'PKCS7';
    
    if (cfg.mode) {
      if (CryptoJS && CryptoJS.mode) {
        if (cfg.mode === CryptoJS.mode.CBC) mode = 'CBC';
        else if (cfg.mode === CryptoJS.mode.ECB) mode = 'ECB';
        else if (cfg.mode === CryptoJS.mode.CFB) mode = 'CFB';
        else if (cfg.mode === CryptoJS.mode.OFB) mode = 'OFB';
        else if (cfg.mode === CryptoJS.mode.CTR) mode = 'CTR';
        else if (cfg.mode.name) mode = cfg.mode.name;
      } else if (typeof cfg.mode === 'string') {
        mode = cfg.mode.toUpperCase();
      } else if (cfg.mode.name) {
        mode = cfg.mode.name;
      }
    }
    
    if (!cfg.iv) mode = 'ECB';
    
    if (cfg.padding) {
      if (CryptoJS && CryptoJS.pad) {
        if (cfg.padding === CryptoJS.pad.Pkcs7) padding = 'PKCS7';
        else if (cfg.padding === CryptoJS.pad.ZeroPadding) padding = 'ZeroPadding';
        else if (cfg.padding === CryptoJS.pad.NoPadding) padding = 'NoPadding';
        else if (cfg.padding === CryptoJS.pad.Iso10126) padding = 'ISO10126';
        else if (cfg.padding.name) padding = cfg.padding.name;
      } else if (typeof cfg.padding === 'string') {
        padding = cfg.padding;
      }
    }
    
    return { mode: mode, padding: padding };
  }
  
  // ==================== 明密文记录 ====================
  
  function addCryptoRecord(record) {
    var isDuplicate = keyStore.cryptoRecords.some(function(r) {
      return r.keyHex === record.keyHex && 
             r.plaintext === record.plaintext && 
             r.ciphertext === record.ciphertext;
    });
    
    if (!isDuplicate) {
      keyStore.cryptoRecords.unshift(record);
      if (keyStore.cryptoRecords.length > 100) keyStore.cryptoRecords.pop();
      
      try {
        targetWindow.postMessage({
          source: 'CRYPTO_HOOK_INJECT',
          type: 'CRYPTO_RECORD',
          data: record
        }, '*');
      } catch (e) {}
    }
    
    return record;
  }
  
  // ==================== 基础工具函数（提前定义）====================
  
  function getCallStack() {
    try {
      var stack = new Error().stack || '';
      return stack.split('\n').slice(3).filter(function(line) {
        return line.indexOf('__CRYPTO_HOOK__') === -1 && line.indexOf('inject.js') === -1;
      }).slice(0, 10).join('\n');
    } catch (e) { return ''; }
  }
  
  // v6.3: 简化版调用栈，只保留关键帧（文件名+行号）
  function getSimplifiedCallStack(stack) {
    if (!stack) return '';
    try {
      var lines = stack.split('\n');
      var simplified = [];
      for (var i = 0; i < Math.min(lines.length, 5); i++) {
        var line = lines[i].trim();
        // 提取文件名和行号，格式如: "at functionName (file.js:123:45)" 或 "at file.js:123:45"
        var match = line.match(/at\s+(?:(\S+)\s+)?\(?([^:]+):(\d+):\d+\)?/);
        if (match) {
          var funcName = match[1] || 'anonymous';
          var fileName = match[2].split('/').pop().split('?')[0]; // 只保留文件名
          var lineNum = match[3];
          simplified.push(funcName + ' @ ' + fileName + ':' + lineNum);
        }
      }
      return simplified.join(' → ');
    } catch (e) {
      return stack.split('\n')[0] || '';
    }
  }
  
  // v6.3: 格式化时间戳
  function formatTimestamp(timestamp) {
    if (!timestamp) timestamp = Date.now();
    var d = new Date(timestamp);
    return d.getHours().toString().padStart(2, '0') + ':' +
           d.getMinutes().toString().padStart(2, '0') + ':' +
           d.getSeconds().toString().padStart(2, '0') + '.' +
           d.getMilliseconds().toString().padStart(3, '0');
  }
  
  // v6.3: 尝试美化 JSON 输出
  function tryPrettifyJSON(str, maxLen) {
    maxLen = maxLen || 200;
    if (!str || typeof str !== 'string') return str;
    try {
      // 尝试解析 JSON
      if ((str.charAt(0) === '{' || str.charAt(0) === '[') && str.length < 2000) {
        var obj = JSON.parse(str);
        var pretty = JSON.stringify(obj, null, 2);
        return pretty.length > maxLen ? pretty.substring(0, maxLen) + '...' : pretty;
      }
    } catch (e) {}
    return str.length > maxLen ? str.substring(0, maxLen) + '...' : str;
  }
  
  function hexToAscii(hex) {
    if (!hex || hex.length % 2 !== 0) return '';
    var str = '';
    var printableCount = 0;
    for (var i = 0; i < hex.length; i += 2) {
      var code = parseInt(hex.substr(i, 2), 16);
      if (code >= 32 && code < 127) {
        str += String.fromCharCode(code);
        printableCount++;
      } else {
        str += '.';
      }
    }
    // v6.3: 如果可打印字符少于 50%，说明是随机二进制数据，返回提示信息
    var totalChars = hex.length / 2;
    if (printableCount < totalChars * 0.5) {
      return '[二进制数据，非文本密钥]';
    }
    return str;
  }
  
  // v6.1: 将 Hex 转换为原始二进制字符串（用于正确的 Base64 编码）
  function hexToRaw(hex) {
    if (!hex || hex.length % 2 !== 0) return '';
    var str = '';
    for (var i = 0; i < hex.length; i += 2) {
      str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
  }
  
  // v6.1: 将 Hex 直接转换为 Base64（正确处理二进制数据）
  function hexToBase64(hex) {
    if (!hex || hex.length % 2 !== 0) return '';
    try {
      return btoa(hexToRaw(hex));
    } catch (e) {
      return '';
    }
  }
  
  function isValidKeyLength(len) {
    return len === 8 || len === 16 || len === 24 || len === 32 || len === 64;
  }
  
  function guessAlgorithm(byteLength) {
    switch (byteLength) {
      case 8: return 'DES';
      case 16: return 'AES-128 / SM4';
      case 24: return 'AES-192 / 3DES';
      case 32: return 'AES-256';
      case 64: return 'SHA-512 / Custom';
      default: return 'Unknown';
    }
  }
  
  // WordArray 转 Hex（CryptoJS 专用）
  function wordArrayToHex(wordArray) {
    if (!wordArray || !wordArray.words || wordArray.sigBytes === undefined) return '';
    var hex = '';
    var words = wordArray.words;
    var sigBytes = wordArray.sigBytes;
    
    for (var i = 0; i < sigBytes; i++) {
      var byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
      hex += byte.toString(16).padStart(2, '0');
    }
    return hex;
  }
  
  // 简化版 addKey（用于早期 Hook）- 静默模式，不输出日志
  // v5.0: 支持 extraInfo 参数（mode/padding）
  // 返回值: { entry, isNew } 用于判断是否需要输出日志
  function addKeyEarly(hex, source, algorithm, originalValue, extraInfo) {
    if (!hex || !isValidKeyLength(hex.length / 2)) return { entry: null, isNew: false };
    hex = hex.toLowerCase();
    
    var existing = keyStore.keys.find(function(k) { return k.hex === hex; });
    if (existing) {
      existing.count++;
      // v5.0: 更新模式信息
      if (extraInfo) {
        if (extraInfo.mode && !existing.mode) existing.mode = extraInfo.mode;
        if (extraInfo.padding && !existing.padding) existing.padding = extraInfo.padding;
      }
      return { entry: existing, isNew: false };  // 已存在，不是新的
    }
    
    var ascii = hexToAscii(hex);
    var entry = {
      hex: hex,
      original: originalValue || ascii,
      ascii: ascii,
      length: hex.length / 2,
      algorithm: algorithm || guessAlgorithm(hex.length / 2),
      source: source,
      sources: [source],
      timestamp: Date.now(),
      count: 1,
      // v5.0 新增：加密模式和填充方式
      mode: extraInfo && extraInfo.mode || null,
      padding: extraInfo && extraInfo.padding || null
    };
    
    keyStore.keys.unshift(entry);
    if (keyStore.keys.length > 50) keyStore.keys.pop();
    
    // 静默模式：不输出日志，由调用方 captureKeyFromContext 统一输出
    
    // 通知
    try {
      targetWindow.postMessage({
        source: 'CRYPTO_HOOK_INJECT', type: 'KEY_CAPTURE', keyType: 'KEY', data: entry
      }, '*');
    } catch (e) {}
    
    return { entry: entry, isNew: true };  // 新增的 key
  }
  
  function addIVEarly(hex, source, originalValue, silent) {
    // IV 长度检查：支持 8字节(16 hex)、16字节(32 hex)、24字节(48 hex)、32字节(64 hex)
    if (!hex || hex.length < 16) return null;
    hex = hex.toLowerCase();
    
    var existing = keyStore.ivs.find(function(k) { return k.hex === hex; });
    if (existing) { existing.count++; return { entry: existing, isNew: false }; }
    
    var ascii = hexToAscii(hex);
    var entry = {
      hex: hex, original: originalValue || ascii, ascii: ascii,
      length: hex.length / 2, source: source, timestamp: Date.now(), count: 1
    };
    
    keyStore.ivs.unshift(entry);
    if (keyStore.ivs.length > 30) keyStore.ivs.pop();
    
    // v6.5: 只在非静默模式下发送通知
    if (!silent) {
      try {
        targetWindow.postMessage({
          source: 'CRYPTO_HOOK_INJECT', type: 'KEY_CAPTURE', keyType: 'IV', data: entry
        }, '*');
      } catch (e) {}
    }
    
    return { entry: entry, isNew: true };
  }
  
  // ==================== 最早期 Hook（关键！）====================
  // 在 CryptoJS 加载前，Hook 多种方式来拦截 reset 方法的定义
  
  var origDefineProperty = Object.defineProperty;
  var origDefineProperties = Object.defineProperties;
  var origAssign = Object.assign;
  var origCreate = Object.create;
  var hookedResetFunctions = new WeakSet();
  var hookedObjects = new WeakSet();
  
  // 核心：检测并 Hook 任何带有 _key 属性的函数调用
  // v5.0: 增强版 captureKeyFromContext，支持加密模式检测
  function captureKeyFromContext(context, source) {
    if (!context) return;
    
    try {
      // 检测是加密还是解密
      var stack = getCallStack();
      var isEncrypt = /encrypt/i.test(stack);
      var isDecrypt = /decrypt/i.test(stack);
      var operation = isEncrypt ? '加密' : (isDecrypt ? '解密' : '加密');
      
      // 检查 _key
      if (context._key && context._key.words && context._key.sigBytes !== undefined) {
        var keyHex = wordArrayToHex(context._key);
        if (keyHex && isValidKeyLength(keyHex.length / 2)) {
          var keyOriginal = hexToAscii(keyHex);
          
          // v5.0: 检测加密模式
          var modeInfo = {};
          if (context.cfg) {
            modeInfo = detectCryptoMode(context.cfg, targetWindow.CryptoJS);
          }
          
          if (isEncrypt) {
            lastEncryptStack = stack;
          } else if (isDecrypt) {
            lastDecryptStack = stack;
          }
          
          var result = addKeyEarly(keyHex, source, null, keyOriginal, modeInfo);
          
          // 只有新增的 key 才输出日志，避免重复输出
          if (result.isNew) {
            // v6.3: 统一输出格式，使用颜色主题（加密绿色系，解密蓝色系）
            var colorTheme = isEncrypt ? '#4CAF50' : '#2196F3';  // 加密绿色，解密蓝色
            var opIcon = isEncrypt ? '🔒' : '🔓';
            
            console.log('%c' + LOG_PREFIX + ' ' + opIcon + ' AES/DES ' + operation + ' [' + formatTimestamp() + ']', 'color: ' + colorTheme + '; font-weight: bold;');
            console.log('%c  📍 调用位置: ' + getSimplifiedCallStack(stack), 'color: #FF9800; font-size: 11px;');
            console.log('%c  🔑 Key(Hex): ' + keyHex, 'color: ' + colorTheme + ';');
            console.log('%c  🔑 Key(Base64): ' + hexToBase64(keyHex), 'color: ' + colorTheme + ';');
            console.log('%c  🔑 Key(明文): ' + keyOriginal, 'color: #E91E63;');
            
            // 紧跟 Key 输出 IV（如果有的话）- 修复：无论 IV 是否新增都输出
            var ivHex = null;
            var ivOriginal = '';
            if (context._iv && context._iv.words && context._iv.sigBytes !== undefined) {
              ivHex = wordArrayToHex(context._iv);
              ivOriginal = hexToAscii(ivHex);
            } else if (context.cfg && context.cfg.iv && context.cfg.iv.words) {
              ivHex = wordArrayToHex(context.cfg.iv);
              ivOriginal = hexToAscii(ivHex);
            }
            if (ivHex) {
              addIVEarly(ivHex, source, ivOriginal);  // 存储 IV
              console.log('%c  🔐 IV(Hex): ' + ivHex, 'color: ' + colorTheme + ';');
              console.log('%c  🔐 IV(Base64): ' + hexToBase64(ivHex), 'color: ' + colorTheme + ';');
              console.log('%c  🔐 IV(明文): ' + ivOriginal, 'color: #E91E63;');
            }
            
            // v5.0: 显示加密模式
            if (modeInfo.mode) {
              console.log('%c  ⚙️ 模式: ' + modeInfo.mode + '/' + (modeInfo.padding || 'PKCS7'), 'color: #9C27B0;');
            }
            console.log('%c  ────────────────────────────────────────', 'color: #DDD;');
          }
        }
      }
      
      // 检查 _iv - 如果 Key 没有被捕获，单独捕获 IV
      if (context._iv && context._iv.words && context._iv.sigBytes !== undefined) {
        var ivHex = wordArrayToHex(context._iv);
        if (ivHex) {
          var ivOriginal = hexToAscii(ivHex);
          addIVEarly(ivHex, source, ivOriginal);  // 静默存储
        }
      }
      // 也检查 cfg.iv
      if (context.cfg && context.cfg.iv && context.cfg.iv.words) {
        var ivHex = wordArrayToHex(context.cfg.iv);
        if (ivHex) {
          var ivOriginal = hexToAscii(ivHex);
          addIVEarly(ivHex, source, ivOriginal);  // 静默存储
        }
      }
    } catch (e) {}
  }
  
  // 核心：Hook reset 函数
  var resetHookCount = 0;  // 计数器
  function hookResetFunctionEarly(obj, origFn, propName) {
    if (!origFn || typeof origFn !== 'function') return;
    if (origFn.__CRYPTO_HOOKED__) return;
    
    try {
      hookedResetFunctions.add(origFn);
      
      var hookedReset = function() {
        var result = origFn.apply(this, arguments);
        captureKeyFromContext(this, 'CryptoJS.BlockCipher.reset');
        return result;
      };
      
      hookedReset.__CRYPTO_HOOKED__ = true;
      origFn.__CRYPTO_HOOKED__ = true;
      
      // 复制原函数的属性
      Object.keys(origFn).forEach(function(key) {
        try { hookedReset[key] = origFn[key]; } catch (e) {}
      });
      
      // 使用原始的 defineProperty 重新设置
      try {
        origDefineProperty.call(Object, obj, propName || 'reset', {
          value: hookedReset,
          writable: true,
          configurable: true,
          enumerable: true
        });
      } catch (e) {
        try { obj[propName || 'reset'] = hookedReset; } catch (e2) {}
      }
      
      resetHookCount++;
      // 不再每次都输出，改为在初始化完成时汇总输出
      
    } catch (e) {
      if (DEBUG_MODE) console.error(LOG_PREFIX + ' hookResetFunctionEarly 失败:', e);
    }
  }
  
  // 检查对象是否有 reset 方法需要 hook
  function checkAndHookReset(obj) {
    if (!obj || typeof obj !== 'object') return;
    if (hookedObjects.has(obj)) return;
    
    try {
      // 检查 reset 方法
      if (typeof obj.reset === 'function' && !obj.reset.__CRYPTO_HOOKED__) {
        hookResetFunctionEarly(obj, obj.reset, 'reset');
        hookedObjects.add(obj);
      }
    } catch (e) {}
  }
  
  // Hook Object.defineProperty
  Object.defineProperty = function(obj, prop, descriptor) {
    var result = origDefineProperty.call(Object, obj, prop, descriptor);
    
    try {
      if (descriptor && descriptor.value && typeof descriptor.value === 'function') {
        // 检测 reset 方法 - CryptoJS BlockCipher 的核心
        if (prop === 'reset' && !hookedResetFunctions.has(descriptor.value)) {
          hookResetFunctionEarly(obj, descriptor.value, 'reset');
        }
      }
    } catch (e) {}
    
    return result;
  };
  
  // Hook Object.defineProperties
  Object.defineProperties = function(obj, props) {
    var result = origDefineProperties.call(Object, obj, props);
    
    try {
      if (props && props.reset && props.reset.value && typeof props.reset.value === 'function') {
        if (!hookedResetFunctions.has(props.reset.value)) {
          hookResetFunctionEarly(obj, props.reset.value, 'reset');
        }
      }
    } catch (e) {}
    
    return result;
  };
  
  // Hook Object.assign - 很多库用这个来扩展原型
  Object.assign = function(target) {
    var result = origAssign.apply(Object, arguments);
    
    try {
      // 检查所有源对象中是否有 reset
      for (var i = 1; i < arguments.length; i++) {
        var source = arguments[i];
        if (source && typeof source.reset === 'function' && !source.reset.__CRYPTO_HOOKED__) {
          // 源对象有 reset，检查目标对象
          if (target && typeof target.reset === 'function' && !target.reset.__CRYPTO_HOOKED__) {
            hookResetFunctionEarly(target, target.reset, 'reset');
          }
        }
      }
    } catch (e) {}
    
    return result;
  };
  
  // Hook Object.create - CryptoJS 使用这个创建原型链
  Object.create = function(proto, propertiesObject) {
    var result = origCreate.call(Object, proto, propertiesObject);
    
    try {
      // 检查 propertiesObject 中是否有 reset
      if (propertiesObject && propertiesObject.reset && propertiesObject.reset.value) {
        if (typeof propertiesObject.reset.value === 'function' && !propertiesObject.reset.value.__CRYPTO_HOOKED__) {
          hookResetFunctionEarly(result, propertiesObject.reset.value, 'reset');
        }
      }
      // 检查原型链上是否有 reset
      if (proto && typeof proto.reset === 'function' && !proto.reset.__CRYPTO_HOOKED__) {
        hookResetFunctionEarly(proto, proto.reset, 'reset');
      }
    } catch (e) {}
    
    return result;
  };
  
  // ==================== 关键：监控 _key 属性的设置 ====================
  // 当 CryptoJS 设置 _key 时捕获
  
  var capturedKeyHexSet = new Set(); // 防止重复捕获
  
  // 监控所有对象的 _key 属性设置
  function monitorKeyProperty(obj) {
    if (!obj || typeof obj !== 'object') return;
    if (obj.__KEY_MONITORED__) return;
    
    try {
      var _keyValue = obj._key;
      
      origDefineProperty.call(Object, obj, '_key', {
        get: function() { return _keyValue; },
        set: function(val) {
          _keyValue = val;
          // 当 _key 被设置时，尝试捕获
          if (val && val.words && val.sigBytes !== undefined) {
            var keyHex = wordArrayToHex(val);
            if (keyHex && isValidKeyLength(keyHex.length / 2) && !capturedKeyHexSet.has(keyHex)) {
              capturedKeyHexSet.add(keyHex);
              var keyOriginal = hexToAscii(keyHex);
              var stack = getCallStack();
              
              addKeyEarly(keyHex, 'CryptoJS._key.set', null, keyOriginal);
              
              console.log('%c' + LOG_PREFIX + ' aes/des捕获，下面是调用堆栈', 'color: #FF5722;');
              console.log('%c' + stack, 'color: #666; font-family: monospace;');
              console.log('%c(AES/DES)加密Hex key: ' + keyHex, 'color: #4CAF50;');
              console.log('%c(AES/DES)加密Base64 key: ' + hexToBase64(keyHex), 'color: #2196F3;');
              console.log('%c(AES/DES)加密明文key: ' + keyOriginal, 'color: #E91E63;');
            }
          }
        },
        configurable: true,
        enumerable: false
      });
      
      obj.__KEY_MONITORED__ = true;
    } catch (e) {}
  }

  // 定期扫描全局对象中的 CryptoJS
  var cryptoJSScanInterval = setInterval(function() {
    try {
      // 检查常见的 CryptoJS 位置
      var locations = [
        targetWindow.CryptoJS,
        targetWindow.crypto,
        targetWindow.Crypto,
        targetWindow.aes,
        targetWindow.AES
      ];
      
      locations.forEach(function(cryptoObj) {
        if (cryptoObj && cryptoObj.lib && cryptoObj.lib.BlockCipher) {
          var BlockCipher = cryptoObj.lib.BlockCipher;
          if (BlockCipher.prototype && BlockCipher.prototype.reset) {
            checkAndHookReset(BlockCipher.prototype);
          }
        }
      });
    } catch (e) {}
  }, 50);
  
  // 5秒后停止扫描
  setTimeout(function() { clearInterval(cryptoJSScanInterval); }, 5000);
  
  // ==================== 其他工具函数 ====================
  
  function toHex(data) {
    if (!data) return '';
    if (typeof data === 'string') {
      return Array.from(data).map(function(c) {
        return c.charCodeAt(0).toString(16).padStart(2, '0');
      }).join('');
    }
    if (data instanceof ArrayBuffer) data = new Uint8Array(data);
    if (ArrayBuffer.isView(data)) {
      return Array.from(new Uint8Array(data.buffer || data)).map(function(b) {
        return b.toString(16).padStart(2, '0');
      }).join('');
    }
    if (Array.isArray(data)) {
      return data.map(function(b) {
        return (b & 0xff).toString(16).padStart(2, '0');
      }).join('');
    }
    return String(data);
  }
  
  function safeStringify(obj, maxLen) {
    maxLen = maxLen || 200;
    try {
      if (obj === null) return 'null';
      if (obj === undefined) return 'undefined';
      if (typeof obj === 'string') return obj.length > maxLen ? obj.slice(0, maxLen) + '...' : obj;
      if (typeof obj === 'number' || typeof obj === 'boolean') return String(obj);
      if (typeof obj === 'function') return '[Function]';
      if (obj && obj.toString && obj.sigBytes !== undefined) {
        return obj.toString();
      }
      if (ArrayBuffer.isView(obj) || obj instanceof ArrayBuffer) {
        return toHex(obj);
      }
      var str = JSON.stringify(obj);
      return str.length > maxLen ? str.slice(0, maxLen) + '...' : str;
    } catch (e) { return '[Object]'; }
  }
  
  // 判断字符串是否是 hex 格式
  function isHexString(str) {
    return typeof str === 'string' && /^[0-9a-fA-F]+$/.test(str) && str.length % 2 === 0;
  }
  
  // 智能获取原始值和 hex 值
  function getKeyValues(data) {
    var original = '';
    var hex = '';
    
    if (!data) return { original: '', hex: '' };
    
    if (typeof data === 'string') {
      original = data;
      if (isHexString(data)) {
        hex = data.toLowerCase();
      } else {
        hex = toHex(data);
      }
    } else if (data && data.sigBytes !== undefined) {
      // CryptoJS WordArray
      hex = data.toString();
      original = hexToAscii(hex);
    } else if (ArrayBuffer.isView(data) || data instanceof ArrayBuffer) {
      hex = toHex(data);
      original = hexToAscii(hex);
    } else {
      original = String(data);
      hex = toHex(original);
    }
    
    return { original: original, hex: hex.toLowerCase() };
  }
  
  // 判断数据是否像密钥（高熵值）
  function looksLikeKey(data) {
    if (!data) return false;
    var hex = typeof data === 'string' && /^[0-9a-fA-F]+$/.test(data) ? data : toHex(data);
    if (!hex || !isValidKeyLength(hex.length / 2)) return false;
    
    // 检查熵值（不是全0或重复模式）
    var bytes = {};
    for (var i = 0; i < hex.length; i += 2) {
      var b = hex.substr(i, 2);
      bytes[b] = (bytes[b] || 0) + 1;
    }
    var uniqueBytes = Object.keys(bytes).length;
    return uniqueBytes > hex.length / 8; // 至少 1/4 的字节是不同的
  }
  
  // ==================== 密钥存储管理 ====================
  
  // silent: 静默模式，不输出到控制台（用于底层捕获如 String.fromCharCode）
  // v5.0: 新增 extraInfo 参数支持 mode/padding
  function addKey(hex, source, algorithm, originalValue, silent, extraInfo) {
    if (!hex || !isValidKeyLength(hex.length / 2)) return null;
    hex = hex.toLowerCase();
    
    // 检查是否已存在
    var existing = keyStore.keys.find(function(k) { return k.hex === hex; });
    if (existing) {
      existing.count++;
      existing.sources = existing.sources || [];
      if (existing.sources.indexOf(source) === -1) {
        existing.sources.push(source);
      }
      // v5.0: 更新模式信息
      if (extraInfo) {
        if (extraInfo.mode && !existing.mode) existing.mode = extraInfo.mode;
        if (extraInfo.padding && !existing.padding) existing.padding = extraInfo.padding;
      }
      existing.isNew = false;  // v6.1: 标记不是新的
      return existing;
    }
    
    var ascii = hexToAscii(hex);
    var entry = {
      hex: hex,
      original: originalValue || ascii,  // 保存原始值
      ascii: ascii,
      length: hex.length / 2,
      algorithm: algorithm || guessAlgorithm(hex.length / 2),
      source: source,
      sources: [source],
      timestamp: Date.now(),
      count: 1,
      // v5.0 新增
      mode: extraInfo && extraInfo.mode || null,
      padding: extraInfo && extraInfo.padding || null,
      isNew: true  // v6.1: 标记是新的
    };
    
    keyStore.keys.unshift(entry);
    if (keyStore.keys.length > 50) keyStore.keys.pop();
    
    // 只在非静默模式下输出和通知（String.fromCharCode 等底层捕获使用静默模式）
    if (!silent) {
      // v6.4: 使用 groupCollapsed 折叠日志，减少刷屏
      var isDecrypt = source && (source.indexOf('decrypt') !== -1 || source.indexOf('Decrypt') !== -1);
      var opIcon = isDecrypt ? '🔓' : '🔒';
      var opColor = isDecrypt ? '#2196F3' : '#4CAF50';
      var base64Key = hexToBase64(hex);
      
      console.groupCollapsed(
        '%c' + LOG_PREFIX + ' ' + opIcon + ' Key [' + entry.algorithm + '] %c' + hex.substring(0, 16) + '...',
        'color: ' + opColor + '; font-weight: bold;',
        'color: #666; font-family: monospace;'
      );
      console.log('%cHex: %c' + hex, 'color: #888;', 'color: #4CAF50; font-family: monospace;');
      if (base64Key) {
        console.log('%cBase64: %c' + base64Key, 'color: #888;', 'color: #2196F3; font-family: monospace;');
      }
      console.log('%c原始值: %c' + (originalValue || ascii), 'color: #888;', 'color: #E91E63;');
      if (entry.mode) {
        console.log('%c模式: %c' + entry.mode + '/' + (entry.padding || 'PKCS7'), 'color: #888;', 'color: #9C27B0;');
      }
      console.log('%c来源: %c' + source, 'color: #888;', 'color: #FF9800;');
      console.groupEnd();
      
      notifyCapture('KEY', entry);
    }
    
    return entry;
  }
  
  function addIV(hex, source, originalValue, silent) {
    // v6.3: 修复 IV 长度检查，与 addIVEarly 保持一致
    // 支持 8字节(16 hex)、16字节(32 hex)、24字节(48 hex)、32字节(64 hex)
    if (!hex || hex.length < 16) return null;
    hex = hex.toLowerCase();
    
    var existing = keyStore.ivs.find(function(k) { return k.hex === hex; });
    if (existing) {
      existing.count++;
      return existing;
    }
    
    var ascii = hexToAscii(hex);
    var entry = {
      hex: hex,
      original: originalValue || ascii,
      ascii: ascii,
      length: hex.length / 2,
      source: source,
      timestamp: Date.now(),
      count: 1
    };
    
    keyStore.ivs.unshift(entry);
    if (keyStore.ivs.length > 30) keyStore.ivs.pop();
    
    if (!silent) {
      // v6.4: 使用 groupCollapsed 折叠日志
      var isDecrypt = source && (source.indexOf('decrypt') !== -1 || source.indexOf('Decrypt') !== -1);
      var opIcon = isDecrypt ? '🔓' : '🔒';
      var opColor = isDecrypt ? '#2196F3' : '#4CAF50';
      var base64IV = hexToBase64(hex);
      
      console.groupCollapsed(
        '%c' + LOG_PREFIX + ' ' + opIcon + ' IV [' + entry.length + '字节] %c' + hex.substring(0, 16) + '...',
        'color: ' + opColor + '; font-weight: bold;',
        'color: #666; font-family: monospace;'
      );
      console.log('%cHex: %c' + hex, 'color: #888;', 'color: #4CAF50; font-family: monospace;');
      if (base64IV) {
        console.log('%cBase64: %c' + base64IV, 'color: #888;', 'color: #2196F3; font-family: monospace;');
      }
      console.log('%c原始值: %c' + (originalValue || ascii), 'color: #888;', 'color: #E91E63;');
      console.groupEnd();
      
      notifyCapture('IV', entry);
    }
    
    return entry;
  }
  
  function addSecret(value, source, usage) {
    if (!value || value.length < 6) return;
    
    var existing = keyStore.secrets.find(function(s) { return s.value === value; });
    if (existing) {
      existing.count++;
      return existing;
    }
    
    var entry = {
      value: value,
      source: source,
      usage: usage || 'unknown',
      timestamp: Date.now(),
      count: 1
    };
    
    keyStore.secrets.unshift(entry);
    if (keyStore.secrets.length > 30) keyStore.secrets.pop();
    
    // v6.4: 使用 groupCollapsed 折叠日志，并检查是否与 Key 重复
    // 如果 value 已经作为 Key 存在，则不重复输出
    var isAlreadyKey = keyStore.keys.some(function(k) { 
      return k.hex === value || k.original === value || k.ascii === value; 
    });
    
    if (!isAlreadyKey) {
      console.groupCollapsed(
        '%c' + LOG_PREFIX + ' 🔑 Secret [' + usage + '] %c' + (value.length > 20 ? value.substring(0, 20) + '...' : value),
        'color: #E91E63; font-weight: bold;',
        'color: #666; font-family: monospace;'
      );
      console.log('%c值: %c' + value, 'color: #888;', 'color: #4CAF50;');
      console.log('%c来源: %c' + source, 'color: #888;', 'color: #FF9800;');
      console.groupEnd();
    }
    
    notifyCapture('SECRET', entry);
    return entry;
  }
  
  // ==================== 签名分析 ====================
  
  function analyzeSignature(input, output, source) {
    // 尝试解析签名参数
    var params = {};
    var template = '';
    
    if (typeof input === 'string') {
      // URL 参数格式: a=1&b=2&sign=xxx
      if (input.indexOf('&') !== -1 || input.indexOf('=') !== -1) {
        input.split('&').forEach(function(pair) {
          var kv = pair.split('=');
          if (kv.length === 2) {
            params[kv[0]] = kv[1];
          }
        });
        template = 'URL_PARAMS';
      }
      // JSON 格式
      else if (input.charAt(0) === '{') {
        try {
          params = JSON.parse(input);
          template = 'JSON';
        } catch (e) {}
      }
      // 纯字符串拼接
      else {
        template = 'STRING_CONCAT';
        // 尝试识别固定部分（可能是 secret）
        var parts = input.match(/[a-zA-Z0-9]{16,}/g) || [];
        parts.forEach(function(part, i) {
          if (part.length >= 16 && part.length <= 64) {
            addSecret(part, source, 'sign_secret_' + i);
          }
        });
      }
    }
    
    var entry = {
      input: safeStringify(input, 500),
      output: safeStringify(output),
      template: template,
      params: params,
      source: source,
      timestamp: Date.now()
    };
    
    keyStore.signParams.unshift(entry);
    if (keyStore.signParams.length > 20) keyStore.signParams.pop();
    
    return entry;
  }
  
  // ==================== 通知机制 ====================
  
  // v6.5: 优化日志输出策略
  // 1. 内部函数（InlineFunc、底层实现）完全静默
  // 2. Hash/HMAC 只在首次和每5秒输出一次摘要
  // 3. 加解密操作整合输出（Key+IV+明密文一起）
  
  var logFilter = {
    // 需要完全静默的类型（底层实现细节）
    silentPatterns: [
      /^InlineFunc\./,
      /\.createDecryptor$/,
      /\.createEncryptor$/,
      /\.decryptBlock$/,
      /\.encryptBlock$/,
      /SerializableCipher\./,
      /BlockCipherMode\./,
      /lib\.Cipher\./
    ],
    
    // Hash/HMAC 特殊处理
    hashState: {
      lastOutputTime: 0,
      totalCount: 0,
      interval: 5000  // 5秒输出一次摘要
    },
    
    shouldOutput: function(category, subType) {
      var fullType = category + '.' + subType;
      
      // 检查是否匹配静默模式
      for (var i = 0; i < this.silentPatterns.length; i++) {
        if (this.silentPatterns[i].test(fullType)) {
          return false;
        }
      }
      
      // Hash/HMAC 特殊处理
      if (category === 'Hash') {
        this.hashState.totalCount++;
        var now = Date.now();
        
        // 首次调用或超过间隔才输出
        if (this.hashState.lastOutputTime === 0) {
          this.hashState.lastOutputTime = now;
          return { type: 'first' };
        }
        
        if (now - this.hashState.lastOutputTime >= this.hashState.interval) {
          var count = this.hashState.totalCount;
          this.hashState.totalCount = 0;
          this.hashState.lastOutputTime = now;
          return { type: 'summary', count: count };
        }
        
        return false;
      }
      
      return true;
    }
  };

  function notifyCapture(type, data) {
    try {
      // 静默发送，不输出日志
      targetWindow.postMessage({
        source: 'CRYPTO_HOOK_INJECT',
        type: 'KEY_CAPTURE',
        keyType: type,
        data: data
      }, '*');
    } catch (e) {
      console.error(LOG_PREFIX + ' postMessage 失败:', e);
    }
  }

  function logCapture(category, subType, data) {
    var entry = {
      id: captures.length + 1,
      timestamp: new Date().toISOString(),
      category: category,
      subType: subType,
      data: data,
      callStack: getCallStack()
    };
    
    captures.push(entry);
    if (capturedData[category]) capturedData[category].push(entry);
    if (captures.length > config.maxCaptures) captures.shift();
    
    if (config.enableConsoleLog) {
      // v6.5: 使用新的日志过滤器
      var shouldOutput = logFilter.shouldOutput(category, subType);
      
      if (shouldOutput) {
        // Hash 类型特殊处理
        if (shouldOutput.type === 'first') {
          // 首次调用，简洁输出
          console.log('%c' + LOG_PREFIX + ' 🔑 ' + subType + ' 首次调用', 
            'color: #9C27B0; font-weight: bold;');
        } else if (shouldOutput.type === 'summary') {
          // 摘要输出
          console.log('%c' + LOG_PREFIX + ' 🔑 ' + category + ' 累计 ' + shouldOutput.count + ' 次调用', 
            'color: #9C27B0;');
        } else {
          // 普通输出（非 Hash 类型）
          console.groupCollapsed('%c' + LOG_PREFIX + ' %c' + category + '.' + subType, 
            'color: #4CAF50; font-weight: bold;', 'color: #2196F3;');
          Object.keys(data).forEach(function(key) {
            console.log('%c' + key + ':', 'color: #FF9800;', data[key]);
          });
          console.groupEnd();
        }
      }
    }
    
    try {
      targetWindow.postMessage({
        source: 'CRYPTO_HOOK_INJECT',
        type: 'NEW_CAPTURE',
        entry: entry
      }, '*');
    } catch (e) {}
    
    return entry;
  }
  
  // ==================== CryptoJS Hook ====================
  
  function hookCryptoJS(CryptoJS) {
    if (!CryptoJS || CryptoJS.__HOOKED__) return;
    if (DEBUG_MODE) console.log(LOG_PREFIX + ' 检测到 CryptoJS，正在 Hook...');
    
    // ============ 深度 Hook: BlockCipher 底层 ============
    // v6.5: 底层 Hook 全部静默，只捕获数据，由高层 Hook 统一输出日志
    
    function hookCipherCore(CryptoJS) {
      try {
        // Hook lib.BlockCipher 的原型
        if (CryptoJS.lib && CryptoJS.lib.BlockCipher) {
          var BlockCipher = CryptoJS.lib.BlockCipher;
          
          // Hook reset 函数 - 这是密钥初始化的核心
          if (BlockCipher.prototype && BlockCipher.prototype.reset && !BlockCipher.prototype.reset.__HOOKED__) {
            var origReset = BlockCipher.prototype.reset;
            BlockCipher.prototype.reset = function() {
              var result = origReset.apply(this, arguments);
              
              // 静默捕获 Key
              if (this._key && this._key.words) {
                try {
                  var keyHex = wordArrayToHex(this._key);
                  var stack = getCallStack();
                  
                  if (/encrypt/i.test(stack)) lastEncryptStack = stack;
                  else if (/decrypt/i.test(stack)) lastDecryptStack = stack;
                  
                  if (keyHex && isValidKeyLength(keyHex.length / 2)) {
                    addKey(keyHex, 'CryptoJS.BlockCipher.reset', null, hexToAscii(keyHex), true);
                  }
                } catch (e) {}
              }
              
              // 静默捕获 IV
              if (this._iv && this._iv.words) {
                try {
                  var ivHex = wordArrayToHex(this._iv);
                  if (ivHex) addIVEarly(ivHex, 'CryptoJS.BlockCipher.reset', hexToAscii(ivHex), true);
                } catch (e) {}
              }
              if (this.cfg && this.cfg.iv && this.cfg.iv.words) {
                try {
                  var ivHex = wordArrayToHex(this.cfg.iv);
                  if (ivHex) addIVEarly(ivHex, 'CryptoJS.BlockCipher.reset.cfg', hexToAscii(ivHex), true);
                } catch (e) {}
              }
              
              return result;
            };
            BlockCipher.prototype.reset.__HOOKED__ = true;
          }
          
          // Hook init 函数
          if (BlockCipher.prototype && BlockCipher.prototype.init && !BlockCipher.prototype.init.__HOOKED__) {
            var origInit = BlockCipher.prototype.init;
            BlockCipher.prototype.init = function(xformMode, key, cfg) {
              var result = origInit.apply(this, arguments);
              
              // 静默捕获 Key
              if (key && key.words) {
                try {
                  var keyHex = wordArrayToHex(key);
                  if (keyHex && isValidKeyLength(keyHex.length / 2)) {
                    addKey(keyHex, 'CryptoJS.BlockCipher.init', null, hexToAscii(keyHex), true);
                  }
                } catch (e) {}
              }
              
              // 静默捕获 IV
              if (cfg && cfg.iv && cfg.iv.words) {
                try {
                  var ivHex = wordArrayToHex(cfg.iv);
                  if (ivHex) addIVEarly(ivHex, 'CryptoJS.BlockCipher.init', hexToAscii(ivHex), true);
                } catch (e) {}
              }
              
              return result;
            };
            BlockCipher.prototype.init.__HOOKED__ = true;
          }
        }
        
        // Hook Cipher.createEncryptor/createDecryptor
        if (CryptoJS.lib && CryptoJS.lib.Cipher) {
          var Cipher = CryptoJS.lib.Cipher;
          
          if (Cipher.createEncryptor) {
            var origCreateEnc = Cipher.createEncryptor;
            Cipher.createEncryptor = function(key, cfg) {
              lastEncryptStack = getCallStack();
              
              // v6.5: 静默捕获，不输出日志（由高层 Hook 统一输出）
              if (key && key.words) {
                try {
                  var keyHex = key.toString();
                  var keyOriginal = hexToAscii(keyHex);
                  if (keyHex && isValidKeyLength(keyHex.length / 2)) {
                    addKey(keyHex, 'CryptoJS.Cipher.createEncryptor', null, keyOriginal, true);  // silent
                  }
                } catch (e) {}
              }
              
              if (cfg && cfg.iv && cfg.iv.words) {
                try {
                  var ivHex = wordArrayToHex(cfg.iv);
                  if (ivHex) {
                    addIVEarly(ivHex, 'CryptoJS.Cipher.createEncryptor', hexToAscii(ivHex), true);  // silent
                  }
                } catch (e) {}
              }
              
              return origCreateEnc.apply(this, arguments);
            };
          }
          
          if (Cipher.createDecryptor) {
            var origCreateDec = Cipher.createDecryptor;
            Cipher.createDecryptor = function(key, cfg) {
              lastDecryptStack = getCallStack();
              
              // v6.5: 静默捕获，不输出日志（由高层 Hook 统一输出）
              if (key && key.words) {
                try {
                  var keyHex = key.toString();
                  var keyOriginal = hexToAscii(keyHex);
                  if (keyHex && isValidKeyLength(keyHex.length / 2)) {
                    addKey(keyHex, 'CryptoJS.Cipher.createDecryptor', null, keyOriginal, true);  // silent
                  }
                } catch (e) {}
              }
              
              if (cfg && cfg.iv && cfg.iv.words) {
                try {
                  var ivHex = wordArrayToHex(cfg.iv);
                  if (ivHex) {
                    addIVEarly(ivHex, 'CryptoJS.Cipher.createDecryptor', hexToAscii(ivHex), true);  // silent
                  }
                } catch (e) {}
              }
              
              return origCreateDec.apply(this, arguments);
            };
          }
        }
        
        // Hook SerializableCipher.encrypt/decrypt - 这是最常用的入口
        // v6.5: 静默捕获，由高层 Hook 统一输出日志
        if (CryptoJS.lib && CryptoJS.lib.SerializableCipher) {
          var SerializableCipher = CryptoJS.lib.SerializableCipher;
          
          if (SerializableCipher.encrypt) {
            var origSerEnc = SerializableCipher.encrypt;
            SerializableCipher.encrypt = function(cipher, message, key, cfg) {
              lastEncryptStack = getCallStack();
              cfg = cfg || {};
              
              // 静默捕获 Key/IV
              if (key && key.words) {
                try {
                  var keyHex = key.toString();
                  if (keyHex && isValidKeyLength(keyHex.length / 2)) {
                    addKey(keyHex, 'CryptoJS.SerializableCipher.encrypt', null, hexToAscii(keyHex), true);
                  }
                } catch (e) {}
              }
              
              if (cfg && cfg.iv && cfg.iv.words) {
                try {
                  var ivHex = wordArrayToHex(cfg.iv);
                  if (ivHex) {
                    addIVEarly(ivHex, 'CryptoJS.SerializableCipher.encrypt', hexToAscii(ivHex), true);
                  }
                } catch (e) {}
              }
              
              return origSerEnc.apply(this, arguments);
            };
          }
          
          if (SerializableCipher.decrypt) {
            var origSerDec = SerializableCipher.decrypt;
            SerializableCipher.decrypt = function(cipher, ciphertext, key, cfg) {
              lastDecryptStack = getCallStack();
              cfg = cfg || {};
              
              // 静默捕获 Key/IV
              if (key && key.words) {
                try {
                  var keyHex = key.toString();
                  if (keyHex && isValidKeyLength(keyHex.length / 2)) {
                    addKey(keyHex, 'CryptoJS.SerializableCipher.decrypt', null, hexToAscii(keyHex), true);
                  }
                } catch (e) {}
              }
              
              if (cfg && cfg.iv && cfg.iv.words) {
                try {
                  var ivHex = wordArrayToHex(cfg.iv);
                  if (ivHex) {
                    addIVEarly(ivHex, 'CryptoJS.SerializableCipher.decrypt', hexToAscii(ivHex), true);
                  }
                } catch (e) {}
              }
              
              return origSerDec.apply(this, arguments);
            };
          }
        }
        
        // Hook PasswordBasedCipher - 处理密码派生密钥的情况
        if (CryptoJS.lib && CryptoJS.lib.PasswordBasedCipher) {
          var PasswordBasedCipher = CryptoJS.lib.PasswordBasedCipher;
          
          if (PasswordBasedCipher.encrypt) {
            var origPwdEnc = PasswordBasedCipher.encrypt;
            PasswordBasedCipher.encrypt = function(cipher, message, password, cfg) {
              lastEncryptStack = getCallStack();
              
              // 密码也是重要信息
              if (typeof password === 'string') {
                addSecret(password, 'CryptoJS.PasswordBasedCipher.encrypt', 'PASSWORD');
              }
              
              return origPwdEnc.apply(this, arguments);
            };
          }
        }
        
      } catch (e) {
        if (DEBUG_MODE) console.log(LOG_PREFIX + ' 深度 Hook 出错:', e);
      }
    }
    
    // 执行深度 Hook
    hookCipherCore(CryptoJS);
    
    // ============ 原有的高层 Hook ============
    // 对称加密算法
    var algorithms = ['AES', 'DES', 'TripleDES', 'Rabbit', 'RC4', 'Blowfish'];
    
    algorithms.forEach(function(algo) {
      if (!CryptoJS[algo]) return;
      var original = CryptoJS[algo];
      
      if (original.encrypt) {
        var origEncrypt = original.encrypt;
        original.encrypt = function(message, key, cfg) {
          lastEncryptStack = getCallStack();
          
          var result = origEncrypt.apply(this, arguments);
          cfg = cfg || {};
          
          var modeInfo = detectCryptoMode(cfg, CryptoJS);
          
          // 提取 Key
          var keyHex = '';
          var keyOriginal = '';
          if (key && key.sigBytes) {
            keyHex = key.toString();
            keyOriginal = hexToAscii(keyHex);
          } else if (typeof key === 'string') {
            keyOriginal = key;
            keyHex = isHexString(key) ? key : toHex(key);
          }
          
          // 提取 IV
          var ivHex = '';
          var ivOriginal = '';
          if (cfg.iv) {
            ivHex = cfg.iv.sigBytes ? cfg.iv.toString() : (isHexString(cfg.iv) ? cfg.iv : toHex(cfg.iv));
            ivOriginal = cfg.iv.sigBytes ? hexToAscii(ivHex) : (typeof cfg.iv === 'string' ? cfg.iv : '');
          }
          
          // 静默存储 Key/IV
          if (keyHex) addKey(keyHex, 'CryptoJS.' + algo + '.encrypt', algo, keyOriginal, true, modeInfo);
          if (ivHex) addIVEarly(ivHex, 'CryptoJS.' + algo + '.encrypt', ivOriginal, true);
          
          // 记录明密文
          var plaintextStr = safeStringify(message, 500);
          var ciphertextStr = safeStringify(result, 500);
          var cryptoRecord = {
            type: 'encrypt',
            algorithm: algo,
            keyHex: keyHex,
            ivHex: ivHex,
            mode: modeInfo.mode,
            padding: modeInfo.padding,
            plaintext: plaintextStr,
            ciphertext: ciphertextStr,
            callStack: lastEncryptStack,
            timestamp: Date.now()
          };
          addCryptoRecord(cryptoRecord);
          addPendingCrypto(cryptoRecord);
          
          // v6.5.2: 平铺输出，不使用 groupCollapsed
          if (shouldOutputCrypto(keyHex, plaintextStr)) {
            var modeStr = modeInfo.mode ? '/' + modeInfo.mode : '/ECB';
            var paddingStr = modeInfo.padding || 'PKCS7';
            console.log('%c' + LOG_PREFIX + ' 🔒 AES/DES 加密 [' + formatTimestamp() + ']', 'color: #4CAF50; font-weight: bold;');
            console.log('  🔑 Key(Hex): ' + keyHex);
            console.log('  🔑 Key(Base64): ' + hexToBase64(keyHex));
            if (keyOriginal) console.log('  🔑 Key(明文): ' + keyOriginal);
            if (ivHex) {
              console.log('  🔐 IV(Hex): ' + ivHex);
              console.log('  🔐 IV(Base64): ' + hexToBase64(ivHex));
            }
            console.log('  ⚙️ 模式: ' + modeStr.substring(1) + '/' + paddingStr);
            console.log('  📝 明文: ' + (plaintextStr.length > 200 ? plaintextStr.substring(0, 200) + '...' : plaintextStr));
            console.log('  🔒 密文: ' + (ciphertextStr.length > 200 ? ciphertextStr.substring(0, 200) + '...' : ciphertextStr));
            console.log('  ────────────────────────────────────────');
          }
          
          return result;
        };
      }
      
      if (original.decrypt) {
        var origDecrypt = original.decrypt;
        original.decrypt = function(ciphertext, key, cfg) {
          lastDecryptStack = getCallStack();
          
          var result = origDecrypt.apply(this, arguments);
          cfg = cfg || {};
          
          var modeInfo = detectCryptoMode(cfg, CryptoJS);
          
          // 提取 Key
          var keyHex = '';
          var keyOriginal = '';
          if (key && key.sigBytes) {
            keyHex = key.toString();
            keyOriginal = hexToAscii(keyHex);
          } else if (typeof key === 'string') {
            keyOriginal = key;
            keyHex = isHexString(key) ? key : toHex(key);
          }
          
          // 提取 IV
          var ivHex = '';
          var ivOriginal = '';
          if (cfg.iv) {
            ivHex = cfg.iv.sigBytes ? cfg.iv.toString() : toHex(cfg.iv);
            ivOriginal = cfg.iv.sigBytes ? hexToAscii(ivHex) : (typeof cfg.iv === 'string' ? cfg.iv : '');
          }
          
          // 静默存储 Key/IV
          if (keyHex) addKey(keyHex, 'CryptoJS.' + algo + '.decrypt', algo, keyOriginal, true, modeInfo);
          if (ivHex) addIVEarly(ivHex, 'CryptoJS.' + algo + '.decrypt', ivOriginal, true);
          
          // 记录明密文
          var ciphertextStr = safeStringify(ciphertext, 500);
          var plaintext = '';
          try {
            plaintext = result.toString(CryptoJS.enc.Utf8);
          } catch (e) {
            plaintext = safeStringify(result, 500);
          }
          
          var cryptoRecord = {
            type: 'decrypt',
            algorithm: algo,
            keyHex: keyHex,
            ivHex: ivHex,
            mode: modeInfo.mode,
            padding: modeInfo.padding,
            plaintext: plaintext,
            ciphertext: ciphertextStr,
            callStack: lastDecryptStack,
            timestamp: Date.now()
          };
          addCryptoRecord(cryptoRecord);
          
          // v6.5.2: 平铺输出，不使用 groupCollapsed
          if (shouldOutputCrypto(keyHex, ciphertextStr)) {
            var modeStr = modeInfo.mode ? '/' + modeInfo.mode : '/ECB';
            var paddingStr = modeInfo.padding || 'PKCS7';
            console.log('%c' + LOG_PREFIX + ' 🔓 AES/DES 解密 [' + formatTimestamp() + ']', 'color: #2196F3; font-weight: bold;');
            console.log('  🔑 Key(Hex): ' + keyHex);
            console.log('  🔑 Key(Base64): ' + hexToBase64(keyHex));
            if (keyOriginal) console.log('  🔑 Key(明文): ' + keyOriginal);
            if (ivHex) {
              console.log('  🔐 IV(Hex): ' + ivHex);
              console.log('  🔐 IV(Base64): ' + hexToBase64(ivHex));
            }
            console.log('  ⚙️ 模式: ' + modeStr.substring(1) + '/' + paddingStr);
            console.log('  🔒 密文: ' + (ciphertextStr.length > 200 ? ciphertextStr.substring(0, 200) + '...' : ciphertextStr));
            console.log('  📝 明文: ' + tryPrettifyJSON(plaintext, 300));
            console.log('  ────────────────────────────────────────');
          }
          
          return result;
        };
      }
    });
    
    // Hash 算法 - 重点捕获签名
    var hashAlgos = ['MD5', 'SHA1', 'SHA256', 'SHA512', 'SHA3', 'RIPEMD160'];
    hashAlgos.forEach(function(algo) {
      if (!CryptoJS[algo] || CryptoJS[algo].__HOOKED__) return;  // v6.3: 避免重复 Hook
      var origHash = CryptoJS[algo];
      CryptoJS[algo] = function(message) {
        var result = origHash.apply(this, arguments);
        var msgStr = safeStringify(message, 1000);
        var hashStr = result.toString();
        
        // 分析是否是签名
        analyzeSignature(msgStr, hashStr, 'CryptoJS.' + algo);
        
        logCapture('Hash', algo, {
          input: msgStr,
          output: hashStr
        });
        
        return result;
      };
      CryptoJS[algo].__HOOKED__ = true;  // v6.3: 标记已 Hook
      Object.setPrototypeOf(CryptoJS[algo], origHash);
      Object.assign(CryptoJS[algo], origHash);
    });
    
    // HMAC - 重点捕获 Secret
    var hmacAlgos = ['HmacMD5', 'HmacSHA1', 'HmacSHA256', 'HmacSHA512'];
    hmacAlgos.forEach(function(algo) {
      if (!CryptoJS[algo] || CryptoJS[algo].__HOOKED__) return;  // v6.3: 避免重复 Hook
      var origHmac = CryptoJS[algo];
      CryptoJS[algo] = function(message, key) {
        var result = origHmac.apply(this, arguments);
        
        // HMAC 的 key 就是 secret
        var keyStr = safeStringify(key);
        addSecret(keyStr, 'CryptoJS.' + algo, 'HMAC');
        
        logCapture('Hash', algo, {
          message: safeStringify(message),
          secret: keyStr,
          hmac: result.toString()
        });
        
        return result;
      };
      CryptoJS[algo].__HOOKED__ = true;  // v6.3: 标记已 Hook
      Object.setPrototypeOf(CryptoJS[algo], origHmac);
      Object.assign(CryptoJS[algo], origHmac);
    });
    
    // PBKDF2 - 密钥派生
    if (CryptoJS.PBKDF2) {
      var origPBKDF2 = CryptoJS.PBKDF2;
      CryptoJS.PBKDF2 = function(password, salt, cfg) {
        var result = origPBKDF2.apply(this, arguments);
        cfg = cfg || {};
        
        var derivedKey = result.toString();
        addKey(derivedKey, 'CryptoJS.PBKDF2', 'PBKDF2');
        
        logCapture('CryptoJS', 'PBKDF2', {
          password: safeStringify(password),
          salt: safeStringify(salt),
          iterations: cfg.iterations,
          keySize: cfg.keySize,
          derivedKey: derivedKey
        });
        
        return result;
      };
    }
    
    // enc.parse - 常用于构造 Key/IV
    if (CryptoJS.enc) {
      ['Hex', 'Utf8', 'Base64', 'Latin1'].forEach(function(enc) {
        if (!CryptoJS.enc[enc] || !CryptoJS.enc[enc].parse) return;
        var origParse = CryptoJS.enc[enc].parse;
        CryptoJS.enc[enc].parse = function(str) {
          var result = origParse.apply(this, arguments);
          
          // 检查是否可能是 Key/IV
          // v6.5.1: 底层 enc.parse 全部静默捕获，由高层 AES.encrypt/decrypt 整合输出
          if (str && isValidKeyLength(str.length / (enc === 'Hex' ? 2 : 1))) {
            var hex = enc === 'Hex' ? str : toHex(str);
            var stack = getCallStack();
            
            if (/key|secret/i.test(stack)) {
              addKey(hex, 'CryptoJS.enc.' + enc + '.parse', null, str, true);  // silent
            } else if (/iv|vector/i.test(stack)) {
              addIV(hex, 'CryptoJS.enc.' + enc + '.parse', str, true);  // silent
            } else if (looksLikeKey(hex)) {
              // 根据长度猜测
              if (hex.length === 32) {
                addIV(hex, 'CryptoJS.enc.' + enc + '.parse (猜测)', str, true);  // silent
              } else {
                addKey(hex, 'CryptoJS.enc.' + enc + '.parse (猜测)', null, str, true);  // silent
              }
            }
          }
          
          return result;
        };
      });
    }
    
    CryptoJS.__HOOKED__ = true;
    if (DEBUG_MODE) console.log(LOG_PREFIX + ' CryptoJS Hook 完成 ✓');
  }
  
  // ==================== JSEncrypt (RSA) Hook ====================
  
  // RSA 相关的全局存储
  var rsaInstances = [];
  var lastRsaPublicKey = null;
  var lastRsaPrivateKey = null;
  
  function hookJSEncrypt(JSEncrypt) {
    if (!JSEncrypt || JSEncrypt.__HOOKED__ || !JSEncrypt.prototype) return;
    if (DEBUG_MODE) console.log(LOG_PREFIX + ' 检测到 JSEncrypt，正在 Hook...');
    
    // Hook 构造函数
    var OrigJSEncrypt = JSEncrypt;
    var newJSEncrypt = function() {
      var instance = new OrigJSEncrypt();
      rsaInstances.push(instance);
      
      // 输出 RSA 识别信息（模仿 FakeCryptoJS 的格式）
      console.log('%c' + LOG_PREFIX + ' 识别到RSA算法', 'color: #9C27B0; font-weight: bold;');
      console.log('执行代码获取密钥(获取私钥报错则说明不存在私钥):');
      console.log('私钥: customerRsa.getPrivateKey()');
      console.log('公钥：customerRsa.getPublicKey()');
      console.log('加密：customerRsa.encrypt');
      console.log('解密：customerRsa.decrypt');
      
      return instance;
    };
    newJSEncrypt.prototype = OrigJSEncrypt.prototype;
    Object.assign(newJSEncrypt, OrigJSEncrypt);
    
    var origSetPublicKey = JSEncrypt.prototype.setPublicKey;
    var origSetPrivateKey = JSEncrypt.prototype.setPrivateKey;
    var origSetKey = JSEncrypt.prototype.setKey;
    var origEncrypt = JSEncrypt.prototype.encrypt;
    var origDecrypt = JSEncrypt.prototype.decrypt;
    var origGetPublicKey = JSEncrypt.prototype.getPublicKey;
    var origGetPrivateKey = JSEncrypt.prototype.getPrivateKey;
    
    if (origSetPublicKey) {
      JSEncrypt.prototype.setPublicKey = function(key) {
        lastRsaPublicKey = key;
        addSecret(key.substring(0, 100) + '...', 'JSEncrypt.setPublicKey', 'RSA_PUBLIC_KEY');
        return origSetPublicKey.apply(this, arguments);
      };
    }
    
    if (origSetKey) {
      JSEncrypt.prototype.setKey = function(key) {
        if (key && key.indexOf('PRIVATE') !== -1) {
          lastRsaPrivateKey = key;
          addSecret(key.substring(0, 100) + '...', 'JSEncrypt.setKey', 'RSA_PRIVATE_KEY');
        } else {
          lastRsaPublicKey = key;
          addSecret(key.substring(0, 100) + '...', 'JSEncrypt.setKey', 'RSA_PUBLIC_KEY');
        }
        return origSetKey.apply(this, arguments);
      };
    }
    
    if (origSetPrivateKey) {
      JSEncrypt.prototype.setPrivateKey = function(key) {
        lastRsaPrivateKey = key;
        addSecret(key.substring(0, 100) + '...', 'JSEncrypt.setPrivateKey', 'RSA_PRIVATE_KEY');
        return origSetPrivateKey.apply(this, arguments);
      };
    }
    
    if (origEncrypt) {
      JSEncrypt.prototype.encrypt = function(data) {
        lastRsaEncStack = getCallStack();  // 记录调用栈
        var result = origEncrypt.apply(this, arguments);
        logCapture('RSA', 'encrypt', {
          plaintext: safeStringify(data),
          ciphertext: safeStringify(result)
        });
        return result;
      };
    }
    
    if (origDecrypt) {
      JSEncrypt.prototype.decrypt = function(data) {
        lastRsaDecStack = getCallStack();  // 记录调用栈
        var result = origDecrypt.apply(this, arguments);
        
        // RSA 解密的结果可能是对称加密的 Key！
        if (result && isValidKeyLength(result.length)) {
          addKey(toHex(result), 'JSEncrypt.decrypt (RSA解密得到)', null, result);
        }
        
        logCapture('RSA', 'decrypt', {
          ciphertext: safeStringify(data),
          plaintext: safeStringify(result)
        });
        return result;
      };
    }
    
    JSEncrypt.__HOOKED__ = true;
    if (DEBUG_MODE) console.log(LOG_PREFIX + ' JSEncrypt Hook 完成 ✓');
  }
  
  // ==================== SM2/SM4 Hook ====================
  
  function hookSMCrypto() {
    // SM4
    if (targetWindow.sm4 && !targetWindow.sm4.__HOOKED__) {
      if (DEBUG_MODE) console.log(LOG_PREFIX + ' 检测到 sm4，正在 Hook...');
      
      var origSm4Encrypt = targetWindow.sm4.encrypt;
      var origSm4Decrypt = targetWindow.sm4.decrypt;
      
      if (origSm4Encrypt) {
        targetWindow.sm4.encrypt = function(data, key) {
          lastSm4EncStack = getCallStack();  // 记录调用栈
          var result = origSm4Encrypt.apply(this, arguments);
          var keyOriginal = typeof key === 'string' ? key : '';
          var keyHex = isHexString(key) ? key : toHex(key);
          addKey(keyHex, 'sm4.encrypt', 'SM4', keyOriginal);
          logCapture('SM4', 'encrypt', { plaintext: safeStringify(data), key: keyHex, keyOriginal: keyOriginal, ciphertext: safeStringify(result) });
          return result;
        };
      }
      
      if (origSm4Decrypt) {
        targetWindow.sm4.decrypt = function(data, key) {
          lastSm4DecStack = getCallStack();  // 记录调用栈
          var result = origSm4Decrypt.apply(this, arguments);
          var keyOriginal = typeof key === 'string' ? key : '';
          var keyHex = isHexString(key) ? key : toHex(key);
          addKey(keyHex, 'sm4.decrypt', 'SM4', keyOriginal);
          logCapture('SM4', 'decrypt', { ciphertext: safeStringify(data), key: keyHex, keyOriginal: keyOriginal, plaintext: safeStringify(result) });
          return result;
        };
      }
      
      targetWindow.sm4.__HOOKED__ = true;
      if (DEBUG_MODE) console.log(LOG_PREFIX + ' sm4 Hook 完成 ✓');
    }
    
    // SM2
    if (targetWindow.sm2 && !targetWindow.sm2.__HOOKED__) {
      if (DEBUG_MODE) console.log(LOG_PREFIX + ' 检测到 sm2，正在 Hook...');
      
      var origSm2Encrypt = targetWindow.sm2.doEncrypt;
      var origSm2Decrypt = targetWindow.sm2.doDecrypt;
      
      if (origSm2Encrypt) {
        targetWindow.sm2.doEncrypt = function(msg, publicKey, cipherMode) {
          lastSm2EncStack = getCallStack();  // 记录调用栈
          var result = origSm2Encrypt.apply(this, arguments);
          addSecret(publicKey, 'sm2.doEncrypt', 'SM2_PUBLIC_KEY');
          logCapture('SM2', 'encrypt', { plaintext: safeStringify(msg), publicKey: safeStringify(publicKey), ciphertext: safeStringify(result) });
          return result;
        };
      }
      
      if (origSm2Decrypt) {
        targetWindow.sm2.doDecrypt = function(encryptData, privateKey, cipherMode) {
          lastSm2DecStack = getCallStack();  // 记录调用栈
          var result = origSm2Decrypt.apply(this, arguments);
          addSecret(privateKey, 'sm2.doDecrypt', 'SM2_PRIVATE_KEY');
          
          // SM2 解密结果可能是对称密钥
          if (result && isValidKeyLength(result.length)) {
            addKey(toHex(result), 'sm2.doDecrypt (解密得到)', null, result);
          }
          
          logCapture('SM2', 'decrypt', { ciphertext: safeStringify(encryptData), plaintext: safeStringify(result) });
          return result;
        };
      }
      
      targetWindow.sm2.__HOOKED__ = true;
      if (DEBUG_MODE) console.log(LOG_PREFIX + ' sm2 Hook 完成 ✓');
    }
  }
  
  // ==================== 内联 SM4 深度 Hook ====================
  // 针对打包在模块内部的 SM4 实现（如 functions.js 中的 SM4Decrypt）
  
  var inlineSm4HookCount = 0;
  var sm4KeyCandidates = new Set();  // 存储 SM4 key 候选
  var lastSm4InlineStack = null;
  
  // SM4 特征检测：SM4 使用的 S-Box 常量
  var SM4_SBOX_SIGNATURE = [0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7];
  
  // Hook 函数调用，检测 SM4 特征
  function hookInlineSM4() {
    // 1. Hook Function.prototype.apply - 捕获所有函数调用
    var origApply = Function.prototype.apply;
    var origCall = Function.prototype.call;
    
    // 检测是否是 SM4 相关的函数调用
    function checkSM4Context(args, source) {
      if (!args || args.length === 0) return;
      
      for (var i = 0; i < args.length; i++) {
        var arg = args[i];
        
        // 检测 16 字节的数组/Uint8Array（SM4 key 长度）
        if (arg && (Array.isArray(arg) || ArrayBuffer.isView(arg))) {
          var len = arg.length || (arg.byteLength);
          if (len === 16) {
            var hex = toHex(arg);
            if (hex && looksLikeKey(hex) && !sm4KeyCandidates.has(hex)) {
              sm4KeyCandidates.add(hex);
              var stack = getCallStack();
              
              // 检查调用栈是否包含 SM4 相关关键字
              if (/sm4|decrypt|encrypt|cipher/i.test(stack)) {
                lastSm4InlineStack = stack;
                addKey(hex, 'InlineSM4 (' + source + ')', 'SM4', hexToAscii(hex));
                
                console.log('%c' + LOG_PREFIX + ' 🔐 检测到内联 SM4 Key!', 'color: #E91E63; font-weight: bold;');
                console.log('%c  Hex: ' + hex, 'color: #4CAF50;');
                console.log('%c  来源: ' + source, 'color: #FF9800;');
                console.log('%c  调用栈:', 'color: #666;');
                console.log(stack);
              }
            }
          }
        }
        
        // 检测字符串形式的 key（16 字符）
        if (typeof arg === 'string' && arg.length === 16) {
          var hex = toHex(arg);
          if (hex && looksLikeKey(hex) && !sm4KeyCandidates.has(hex)) {
            var stack = getCallStack();
            if (/sm4|decrypt|encrypt|cipher/i.test(stack)) {
              sm4KeyCandidates.add(hex);
              lastSm4InlineStack = stack;
              addKey(hex, 'InlineSM4 (' + source + ')', 'SM4', arg);
            }
          }
        }
        
        // 检测 32 字符的 hex 字符串（SM4 key 的 hex 表示）
        if (typeof arg === 'string' && arg.length === 32 && /^[0-9a-fA-F]+$/.test(arg)) {
          var stack = getCallStack();
          if (/sm4|decrypt|encrypt|cipher/i.test(stack) && !sm4KeyCandidates.has(arg.toLowerCase())) {
            sm4KeyCandidates.add(arg.toLowerCase());
            lastSm4InlineStack = stack;
            addKey(arg, 'InlineSM4.Hex (' + source + ')', 'SM4', hexToAscii(arg));
          }
        }
      }
    }
    
    // 2. 深度 Hook：监控所有可能的 SM4 函数名
    function hookSM4Functions(obj, path, depth) {
      if (!obj || typeof obj !== 'object' || depth > 5) return;
      
      // 排除自己的对象
      if (obj === targetWindow.__cryptoHook__ || path === '__cryptoHook__') return;
      
      var keys;
      try { keys = Object.keys(obj); } catch (e) { return; }
      
      for (var i = 0; i < keys.length; i++) {
        var key = keys[i];
        var fullPath = path ? path + '.' + key : key;
        
        // 排除自己导出的函数（包括路径中包含这些函数名的情况）
        if (/^(sm4Enc|sm4Dec|locateInlineSm4|customerSm4Enc|customerSm4Dec|__cryptoHook__)$/.test(key)) continue;
        if (/locateInlineSm4|customerSm4|sm4Enc|sm4Dec/.test(fullPath)) continue;
        
        // 检测 SM4 相关函数名
        if (/sm4|SM4|Sm4/i.test(key)) {
          try {
            var val = obj[key];
            
            if (typeof val === 'function' && !val.__SM4_HOOKED__) {
              var origFn = val;
              
              obj[key] = (function(original, funcPath) {
                var wrapped = function() {
                  var args = Array.from(arguments);
                  lastSm4InlineStack = getCallStack();
                  
                  // 检查参数中的 key
                  checkSM4Context(args, funcPath);
                  
                  var result = original.apply(this, args);
                  
                  console.log('%c' + LOG_PREFIX + ' 🔐 SM4 函数调用: ' + funcPath, 'color: #9C27B0;');
                  console.log('  参数:', args.map(function(a) { return safeStringify(a, 100); }));
                  console.log('  结果:', safeStringify(result, 100));
                  
                  logCapture('SM4', funcPath, {
                    arguments: args.map(function(a) { return safeStringify(a); }),
                    result: safeStringify(result)
                  });
                  
                  return result;
                };
                wrapped.__SM4_HOOKED__ = true;
                wrapped.toString = function() { return original.toString(); };
                return wrapped;
              })(origFn, fullPath);
              
              inlineSm4HookCount++;
              if (DEBUG_MODE) console.log(LOG_PREFIX + ' Hook SM4 函数: ' + fullPath);
            }
            
            // 递归检查对象
            if (typeof val === 'object' && val !== null) {
              hookSM4Functions(val, fullPath, depth + 1);
            }
          } catch (e) {}
        }
      }
    }
    
    // 3. 监控 eval 和 new Function - 动态代码中可能包含 SM4
    var origEval = targetWindow.eval;
    targetWindow.eval = function(code) {
      if (typeof code === 'string' && /sm4|SM4/i.test(code)) {
        console.log('%c' + LOG_PREFIX + ' ⚠️ 检测到 eval 中包含 SM4 代码', 'color: #FF5722;');
      }
      return origEval.apply(this, arguments);
    };
    
    // 4. 扫描全局对象中的 SM4 函数
    setTimeout(function() {
      hookSM4Functions(targetWindow, '', 0);
      
      // 特别检查常见的模块化位置
      var moduleLocations = ['__WEBPACK_MODULES__', 'webpackChunk', '__modules__', 'require', 'define'];
      moduleLocations.forEach(function(loc) {
        try {
          if (targetWindow[loc]) {
            hookSM4Functions(targetWindow[loc], loc, 0);
          }
        } catch (e) {}
      });
      
      if (inlineSm4HookCount > 0) {
        if (DEBUG_MODE) console.log(LOG_PREFIX + ' 内联 SM4 Hook 完成，共 Hook ' + inlineSm4HookCount + ' 个函数');
      }
    }, 500);
    
    // 5. 定期扫描新加载的模块
    var sm4ScanCount = 0;
    var sm4ScanInterval = setInterval(function() {
      sm4ScanCount++;
      hookSM4Functions(targetWindow, '', 0);
      if (sm4ScanCount > 10) clearInterval(sm4ScanInterval);
    }, 1000);
  }
  
  // 内联 SM4 定位函数
  function locateInlineSm4() {
    if (!lastSm4InlineStack) {
      console.log('%c' + LOG_PREFIX + ' ⚠️ 还没有捕获到内联 SM4 调用', 'color: #FF9800;');
      return;
    }
    console.log('%c' + LOG_PREFIX + ' 📍 最后一次内联 SM4 调用位置:', 'color: #4CAF50; font-weight: bold;');
    console.log('%c' + lastSm4InlineStack, 'color: #666; font-family: monospace;');
  }
  
  // ==================== v5.0: Forge.js Hook ====================
  
  function hookForge(forge) {
    if (!forge || forge.__HOOKED__) return;
    if (DEBUG_MODE) console.log(LOG_PREFIX + ' 检测到 forge，正在 Hook...');
    
    // Hook forge.cipher.createCipher
    if (forge.cipher && forge.cipher.createCipher) {
      var origCreateCipher = forge.cipher.createCipher;
      forge.cipher.createCipher = function(algorithm, key) {
        var keyHex = toHex(key);
        if (keyHex && isValidKeyLength(keyHex.length / 2)) {
          addKey(keyHex, 'forge.cipher.createCipher', algorithm, null, true);  // v6.5.1: silent
        }
        
        var cipher = origCreateCipher.apply(this, arguments);
        
        if (cipher && cipher.start) {
          var origStart = cipher.start;
          cipher.start = function(options) {
            if (options && options.iv) {
              var ivHex = toHex(options.iv);
              if (ivHex) addIV(ivHex, 'forge.cipher.start', null, true);  // v6.5.1: silent
            }
            return origStart.apply(this, arguments);
          };
        }
        
        return cipher;
      };
    }
    
    // Hook forge.cipher.createDecipher
    if (forge.cipher && forge.cipher.createDecipher) {
      var origCreateDecipher = forge.cipher.createDecipher;
      forge.cipher.createDecipher = function(algorithm, key) {
        var keyHex = toHex(key);
        if (keyHex && isValidKeyLength(keyHex.length / 2)) {
          addKey(keyHex, 'forge.cipher.createDecipher', algorithm, null, true);  // v6.5.1: silent
        }
        
        var decipher = origCreateDecipher.apply(this, arguments);
        
        if (decipher && decipher.start) {
          var origStart = decipher.start;
          decipher.start = function(options) {
            if (options && options.iv) {
              var ivHex = toHex(options.iv);
              if (ivHex) addIV(ivHex, 'forge.decipher.start', null, true);  // v6.5.1: silent
            }
            return origStart.apply(this, arguments);
          };
        }
        
        return decipher;
      };
    }
    
    // Hook forge.pki (RSA)
    if (forge.pki) {
      if (forge.pki.publicKeyFromPem) {
        var origPubFromPem = forge.pki.publicKeyFromPem;
        forge.pki.publicKeyFromPem = function(pem) {
          addSecret(pem.substring(0, 100) + '...', 'forge.pki.publicKeyFromPem', 'RSA_PUBLIC_KEY');
          return origPubFromPem.apply(this, arguments);
        };
      }
      
      if (forge.pki.privateKeyFromPem) {
        var origPrivFromPem = forge.pki.privateKeyFromPem;
        forge.pki.privateKeyFromPem = function(pem) {
          addSecret(pem.substring(0, 100) + '...', 'forge.pki.privateKeyFromPem', 'RSA_PRIVATE_KEY');
          return origPrivFromPem.apply(this, arguments);
        };
      }
    }
    
    // Hook forge.hmac
    if (forge.hmac && forge.hmac.create) {
      var origHmacCreate = forge.hmac.create;
      forge.hmac.create = function() {
        var hmac = origHmacCreate.apply(this, arguments);
        
        if (hmac && hmac.start) {
          var origStart = hmac.start;
          hmac.start = function(md, key) {
            if (key) {
              addSecret(safeStringify(key), 'forge.hmac.start', 'HMAC');
            }
            return origStart.apply(this, arguments);
          };
        }
        
        return hmac;
      };
    }
    
    forge.__HOOKED__ = true;
    if (DEBUG_MODE) console.log(LOG_PREFIX + ' forge Hook 完成 ✓');
  }
  
  // ==================== v5.0: SJCL Hook ====================
  
  function hookSJCL(sjcl) {
    if (!sjcl || sjcl.__HOOKED__) return;
    if (DEBUG_MODE) console.log(LOG_PREFIX + ' 检测到 sjcl，正在 Hook...');
    
    // Hook sjcl.encrypt
    if (sjcl.encrypt) {
      var origEncrypt = sjcl.encrypt;
      sjcl.encrypt = function(password, plaintext, params) {
        lastEncryptStack = getCallStack();
        
        if (typeof password === 'string') {
          addSecret(password, 'sjcl.encrypt', 'PASSWORD');
        }
        
        var result = origEncrypt.apply(this, arguments);
        
        addCryptoRecord({
          type: 'encrypt',
          algorithm: 'SJCL-AES',
          plaintext: safeStringify(plaintext, 500),
          ciphertext: safeStringify(result, 500),
          timestamp: Date.now()
        });
        
        logCapture('SJCL', 'encrypt', {
          plaintext: safeStringify(plaintext),
          ciphertext: safeStringify(result)
        });
        
        return result;
      };
    }
    
    // Hook sjcl.decrypt
    if (sjcl.decrypt) {
      var origDecrypt = sjcl.decrypt;
      sjcl.decrypt = function(password, ciphertext, params) {
        lastDecryptStack = getCallStack();
        
        if (typeof password === 'string') {
          addSecret(password, 'sjcl.decrypt', 'PASSWORD');
        }
        
        var result = origDecrypt.apply(this, arguments);
        
        addCryptoRecord({
          type: 'decrypt',
          algorithm: 'SJCL-AES',
          plaintext: safeStringify(result, 500),
          ciphertext: safeStringify(ciphertext, 500),
          timestamp: Date.now()
        });
        
        logCapture('SJCL', 'decrypt', {
          ciphertext: safeStringify(ciphertext),
          plaintext: safeStringify(result)
        });
        
        return result;
      };
    }
    
    sjcl.__HOOKED__ = true;
    if (DEBUG_MODE) console.log(LOG_PREFIX + ' sjcl Hook 完成 ✓');
  }
  
  // ==================== WebCrypto Hook ====================

  function hookWebCrypto() {
    if (!targetWindow.crypto || !targetWindow.crypto.subtle) return;
    if (targetWindow.crypto.subtle.__HOOKED__) return;
    if (DEBUG_MODE) console.log(LOG_PREFIX + ' 检测到 WebCrypto，正在 Hook...');
    
    var subtle = targetWindow.crypto.subtle;
    
    // importKey - 最重要的 Key 捕获点
    var origImportKey = subtle.importKey;
    subtle.importKey = function(format, keyData, algorithm, extractable, keyUsages) {
      // 捕获导入的密钥
      var keyHex = toHex(keyData);
      if (keyHex && isValidKeyLength(keyHex.length / 2)) {
        var algoName = typeof algorithm === 'string' ? algorithm : (algorithm.name || 'Unknown');
        addKey(keyHex, 'WebCrypto.importKey', algoName, null, true);  // v6.5.1: silent
      }
      
      return origImportKey.apply(this, arguments).then(function(result) {
        logCapture('WebCrypto', 'importKey', {
          format: format,
          algorithm: safeStringify(algorithm),
          keyData: keyHex,
          extractable: extractable
        });
        return result;
      });
    };
    
    // encrypt
    var origEncrypt = subtle.encrypt;
    subtle.encrypt = function(algorithm, key, data) {
      // 尝试提取 IV
      if (algorithm && algorithm.iv) {
        var ivHex = toHex(algorithm.iv);
        if (ivHex) addIV(ivHex, 'WebCrypto.encrypt', null, true);  // v6.5.1: silent
      }
      
      return origEncrypt.apply(this, arguments).then(function(result) {
        logCapture('WebCrypto', 'encrypt', {
          algorithm: safeStringify(algorithm),
          plaintext: toHex(data),
          ciphertext: toHex(result)
        });
        return result;
      });
    };
    
    // decrypt
    var origDecrypt = subtle.decrypt;
    subtle.decrypt = function(algorithm, key, data) {
      if (algorithm && algorithm.iv) {
        var ivHex = toHex(algorithm.iv);
        if (ivHex) addIV(ivHex, 'WebCrypto.decrypt', null, true);  // v6.5.1: silent
      }
      
      return origDecrypt.apply(this, arguments).then(function(result) {
        logCapture('WebCrypto', 'decrypt', {
          algorithm: safeStringify(algorithm),
          ciphertext: toHex(data),
          plaintext: toHex(result)
        });
        return result;
      });
    };
    
    // digest - Hash
    var origDigest = subtle.digest;
    subtle.digest = function(algorithm, data) {
      return origDigest.apply(this, arguments).then(function(result) {
        var inputStr = '';
        try {
          inputStr = new TextDecoder().decode(data);
        } catch (e) {
          inputStr = toHex(data);
        }
        
        analyzeSignature(inputStr, toHex(result), 'WebCrypto.digest');
        
        logCapture('Hash', 'WebCrypto.' + (algorithm.name || algorithm), {
          input: inputStr,
          output: toHex(result)
        });
        return result;
      });
    };
    
    subtle.__HOOKED__ = true;
    if (DEBUG_MODE) console.log(LOG_PREFIX + ' WebCrypto Hook 完成 ✓');
  }
  
  // ==================== v5.0: 请求/响应自动解密 ====================
  
  var autoDecryptConfig = {
    enabled: true,
    logRequests: true,
    logResponses: true,
    autoDecrypt: true,
    maxBodyLength: 10000,  // 最大处理的响应体长度
    decryptedResponses: []  // 存储解密后的响应
  };
  
  // 检测字符串是否像加密数据
  function looksLikeEncrypted(str) {
    if (!str || typeof str !== 'string') return false;
    str = str.trim();
    
    // Base64 编码的密文特征
    if (/^[A-Za-z0-9+/=]{20,}$/.test(str) && str.length % 4 === 0) {
      return { type: 'base64', data: str };
    }
    
    // Hex 编码的密文特征
    if (/^[0-9a-fA-F]{32,}$/.test(str) && str.length % 2 === 0) {
      return { type: 'hex', data: str };
    }
    
    // JSON 中包含加密字段
    if (str.charAt(0) === '{') {
      try {
        var obj = JSON.parse(str);
        var encryptedFields = [];
        
        function findEncryptedFields(o, path) {
          if (!o || typeof o !== 'object') return;
          for (var key in o) {
            var val = o[key];
            var currentPath = path ? path + '.' + key : key;
            
            // 检测可能的加密字段名
            if (/encrypt|cipher|secret|data|content|body|result|payload/i.test(key)) {
              if (typeof val === 'string' && val.length > 20) {
                var encrypted = looksLikeEncrypted(val);
                if (encrypted) {
                  encryptedFields.push({ path: currentPath, ...encrypted });
                }
              }
            }
            
            // 递归检查
            if (typeof val === 'object' && val !== null) {
              findEncryptedFields(val, currentPath);
            }
          }
        }
        
        findEncryptedFields(obj, '');
        
        if (encryptedFields.length > 0) {
          return { type: 'json', data: str, fields: encryptedFields, parsed: obj };
        }
      } catch (e) {}
    }
    
    return false;
  }
  
  // 尝试使用捕获的 Key 解密数据
  function tryAutoDecrypt(encryptedData, url) {
    if (!autoDecryptConfig.autoDecrypt) return null;
    if (keyStore.keys.length === 0) return null;
    
    var results = [];
    
    // 遍历所有捕获的 Key 尝试解密
    for (var i = 0; i < Math.min(keyStore.keys.length, 5); i++) {
      var keyEntry = keyStore.keys[i];
      var keyHex = keyEntry.hex;
      var ivHex = keyStore.ivs.length > 0 ? keyStore.ivs[0].hex : null;
      
      // 尝试 AES 解密
      if (targetWindow.CryptoJS) {
        try {
          var CryptoJS = targetWindow.CryptoJS;
          var key = CryptoJS.enc.Hex.parse(keyHex);
          var cfg = { padding: CryptoJS.pad.Pkcs7 };
          
          // 尝试 CBC 模式（如果有 IV）
          if (ivHex) {
            cfg.iv = CryptoJS.enc.Hex.parse(ivHex);
            cfg.mode = CryptoJS.mode.CBC;
            
            try {
              var decrypted = CryptoJS.AES.decrypt(encryptedData, key, cfg);
              var plaintext = decrypted.toString(CryptoJS.enc.Utf8);
              
              if (plaintext && plaintext.length > 0 && isValidPlaintext(plaintext)) {
                results.push({
                  success: true,
                  algorithm: 'AES-CBC',
                  keyHex: keyHex,
                  ivHex: ivHex,
                  plaintext: plaintext,
                  url: url
                });
              }
            } catch (e) {}
          }
          
          // 尝试 ECB 模式
          cfg = { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 };
          try {
            var decrypted = CryptoJS.AES.decrypt(encryptedData, key, cfg);
            var plaintext = decrypted.toString(CryptoJS.enc.Utf8);
            
            if (plaintext && plaintext.length > 0 && isValidPlaintext(plaintext)) {
              results.push({
                success: true,
                algorithm: 'AES-ECB',
                keyHex: keyHex,
                ivHex: null,
                plaintext: plaintext,
                url: url
              });
            }
          } catch (e) {}
          
        } catch (e) {}
      }
      
      // 尝试 SM4 解密
      if (targetWindow.sm4 && keyHex.length === 32) {
        try {
          var plaintext = targetWindow.sm4.decrypt(encryptedData, keyHex);
          if (plaintext && plaintext.length > 0 && isValidPlaintext(plaintext)) {
            results.push({
              success: true,
              algorithm: 'SM4',
              keyHex: keyHex,
              plaintext: plaintext,
              url: url
            });
          }
        } catch (e) {}
      }
    }
    
    return results.length > 0 ? results : null;
  }
  
  // 检测解密结果是否是有效的明文
  function isValidPlaintext(text) {
    if (!text || text.length === 0) return false;
    
    // 检查是否包含大量不可打印字符
    var printableCount = 0;
    for (var i = 0; i < Math.min(text.length, 100); i++) {
      var code = text.charCodeAt(i);
      if ((code >= 32 && code < 127) || code === 10 || code === 13 || code === 9) {
        printableCount++;
      }
    }
    
    // 至少 80% 是可打印字符
    return printableCount / Math.min(text.length, 100) > 0.8;
  }
  
  // 处理响应数据
  function processResponseData(url, responseText, method) {
    if (!autoDecryptConfig.enabled) return;
    if (!responseText || responseText.length > autoDecryptConfig.maxBodyLength) return;
    
    var encrypted = looksLikeEncrypted(responseText);
    if (!encrypted) return;
    
    if (autoDecryptConfig.logResponses) {
      console.log('%c' + LOG_PREFIX + ' 🔍 检测到可能的加密响应', 'color: #FF9800; font-weight: bold;');
      console.log('  URL:', url);
      console.log('  类型:', encrypted.type);
      if (encrypted.fields) {
        console.log('  加密字段:', encrypted.fields.map(function(f) { return f.path; }).join(', '));
      }
    }
    
    // 尝试自动解密
    var dataToDecrypt = encrypted.type === 'json' && encrypted.fields 
      ? encrypted.fields[0].data 
      : encrypted.data;
    
    var decryptResults = tryAutoDecrypt(dataToDecrypt, url);
    
    if (decryptResults && decryptResults.length > 0) {
      var best = decryptResults[0];
      
      console.log('%c' + LOG_PREFIX + ' ✅ 自动解密成功!', 'color: #4CAF50; font-weight: bold;');
      console.log('  算法:', best.algorithm);
      console.log('  Key:', best.keyHex);
      if (best.ivHex) console.log('  IV:', best.ivHex);
      console.log('  明文:', best.plaintext.substring(0, 200) + (best.plaintext.length > 200 ? '...' : ''));
      
      // 存储解密结果
      autoDecryptConfig.decryptedResponses.unshift({
        url: url,
        method: method,
        encrypted: dataToDecrypt.substring(0, 100),
        decrypted: best.plaintext,
        algorithm: best.algorithm,
        keyHex: best.keyHex,
        ivHex: best.ivHex,
        timestamp: Date.now()
      });
      
      if (autoDecryptConfig.decryptedResponses.length > 50) {
        autoDecryptConfig.decryptedResponses.pop();
      }
      
      // 通知 Popup
      try {
        targetWindow.postMessage({
          source: 'CRYPTO_HOOK_INJECT',
          type: 'AUTO_DECRYPT',
          data: {
            url: url,
            plaintext: best.plaintext,
            algorithm: best.algorithm
          }
        }, '*');
      } catch (e) {}
      
      // 记录到明密文对
      addCryptoRecord({
        type: 'auto-decrypt',
        algorithm: best.algorithm,
        keyHex: best.keyHex,
        ivHex: best.ivHex,
        mode: best.algorithm.includes('CBC') ? 'CBC' : 'ECB',
        padding: 'PKCS7',
        plaintext: best.plaintext,
        ciphertext: dataToDecrypt.substring(0, 500),
        url: url,
        timestamp: Date.now()
      });
      
      // v6.0: 关联到请求追踪
      associateDecryptToResponse(url, {
        plaintext: best.plaintext,
        algorithm: best.algorithm,
        keyHex: best.keyHex,
        ivHex: best.ivHex
      });
    }
  }
  
  // Hook fetch
  function hookFetch() {
    if (!targetWindow.fetch || targetWindow.fetch.__HOOKED__) return;
    
    var origFetch = targetWindow.fetch;
    
    targetWindow.fetch = function(input, init) {
      var url = typeof input === 'string' ? input : (input.url || '');
      var method = (init && init.method) || 'GET';
      
      // v6.0: 生成请求ID并关联加密操作
      var requestId = generateRequestId();
      associateCryptoToRequest(requestId, url, method);
      
      // 记录请求
      if (autoDecryptConfig.logRequests && init && init.body) {
        var requestEncrypted = looksLikeEncrypted(init.body);
        if (requestEncrypted) {
          console.log('%c' + LOG_PREFIX + ' 📤 检测到加密请求', 'color: #2196F3;');
          console.log('  URL:', url);
          console.log('  Method:', method);
        }
      }
      
      return origFetch.apply(this, arguments).then(function(response) {
        // 克隆响应以便读取
        var clonedResponse = response.clone();
        
        clonedResponse.text().then(function(text) {
          processResponseData(url, text, method);
        }).catch(function() {});
        
        return response;
      });
    };
    
    targetWindow.fetch.__HOOKED__ = true;
  }
  
  // Hook XMLHttpRequest - 使用被动监听模式，不干扰原始请求
  function hookXHR() {
    if (targetWindow.XMLHttpRequest.__HOOKED__) return;
    
    var origOpen = targetWindow.XMLHttpRequest.prototype.open;
    var origSend = targetWindow.XMLHttpRequest.prototype.send;
    var origSetRequestHeader = targetWindow.XMLHttpRequest.prototype.setRequestHeader;
    
    targetWindow.XMLHttpRequest.prototype.open = function(method, url) {
      this.__cryptoHook_url__ = url;
      this.__cryptoHook_method__ = method;
      this.__cryptoHook_headers__ = {};
      return origOpen.apply(this, arguments);
    };
    
    // Hook setRequestHeader 来记录请求头
    targetWindow.XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
      if (this.__cryptoHook_headers__) {
        this.__cryptoHook_headers__[name] = value;
      }
      return origSetRequestHeader.apply(this, arguments);
    };
    
    targetWindow.XMLHttpRequest.prototype.send = function(body) {
      var xhr = this;
      var url = xhr.__cryptoHook_url__ || '';
      var method = xhr.__cryptoHook_method__ || 'GET';
      var headers = xhr.__cryptoHook_headers__ || {};
      
      // v6.0: 生成请求ID并关联加密操作
      var requestId = generateRequestId();
      xhr.__cryptoHook_requestId__ = requestId;
      associateCryptoToRequest(requestId, url, method);
      
      // 先调用原始 send，确保请求正常发出
      var result = origSend.apply(this, arguments);
      
      // 异步处理，完全不阻塞原始请求流程
      setTimeout(function() {
        try {
          // 记录加密请求
          if (body && typeof body === 'string') {
            var requestEncrypted = looksLikeEncrypted(body);
            if (requestEncrypted) {
              // 记录到请求列表
              recordEncryptedRequest(method, url, body, headers);
              
              if (autoDecryptConfig.logRequests) {
                console.log('%c' + LOG_PREFIX + ' 📤 检测到加密请求 (XHR)', 'color: #2196F3;');
                console.log('  URL:', url);
                console.log('  Method:', method);
              }
            }
          }
        } catch (e) {}
        
        // 使用 readystatechange 监听，但只读取数据，不修改任何回调
        var checkResponse = function() {
          try {
            if (xhr.readyState === 4 && xhr.status === 200) {
              var responseText = '';
              try { responseText = xhr.responseText; } catch (e) {}
              if (responseText) {
                processResponseData(url, responseText, method);
              }
            }
          } catch (e) {}
        };
        
        // 延迟检查响应，避免干扰正常流程
        var checkInterval = setInterval(function() {
          if (xhr.readyState === 4) {
            clearInterval(checkInterval);
            checkResponse();
          }
        }, 50);
        
        // 最多检查 30 秒
        setTimeout(function() { clearInterval(checkInterval); }, 30000);
      }, 0);
      
      return result;
    };
    
    targetWindow.XMLHttpRequest.__HOOKED__ = true;
  }
  
  // 初始化网络 Hook
  function hookNetwork() {
    try { hookFetch(); } catch (e) { if (DEBUG_MODE) console.error(LOG_PREFIX + ' hookFetch error:', e); }
    try { hookXHR(); } catch (e) { if (DEBUG_MODE) console.error(LOG_PREFIX + ' hookXHR error:', e); }
  }
  
  // 获取解密后的响应
  function getDecryptedResponses() {
    console.log('%c' + LOG_PREFIX + ' 📥 自动解密的响应 (' + autoDecryptConfig.decryptedResponses.length + '条)', 'color: #4CAF50; font-weight: bold;');
    autoDecryptConfig.decryptedResponses.forEach(function(r, i) {
      console.log('%c[' + (i + 1) + '] ' + r.method + ' ' + r.url, 'color: #2196F3;');
      console.log('  算法:', r.algorithm);
      console.log('  明文:', r.decrypted.substring(0, 150) + (r.decrypted.length > 150 ? '...' : ''));
    });
    return autoDecryptConfig.decryptedResponses;
  }
  
  // 设置自动解密配置
  function setAutoDecrypt(enabled) {
    autoDecryptConfig.enabled = enabled;
    autoDecryptConfig.autoDecrypt = enabled;
    console.log(LOG_PREFIX + ' 自动解密已' + (enabled ? '开启' : '关闭'));
  }
  
  // ==================== 底层 Hook ====================
  
  // Hook String.fromCharCode - 捕获密钥构造
  function setupStringHook() {
    var originalFromCharCode = String.fromCharCode;
    
    String.fromCharCode = function() {
      var result = originalFromCharCode.apply(this, arguments);
      var len = arguments.length;
      
      // 只关注可能是 Key/IV 的长度
      if (isValidKeyLength(len)) {
        var stack = getCallStack();
        
        // 只在加密相关调用栈中捕获
        if (/encrypt|decrypt|cipher|key|iv|aes|des|sm4|sm2|crypto/i.test(stack)) {
          var args = Array.prototype.slice.call(arguments);
          var hex = args.map(function(c) { return (c & 0xff).toString(16).padStart(2, '0'); }).join('');
          
          if (looksLikeKey(hex)) {
            if (len === 8 || (len === 16 && /iv|vector/i.test(stack))) {
              addIV(hex, 'String.fromCharCode', null, true);  // 静默模式
            } else {
              addKey(hex, 'String.fromCharCode', null, null, true);  // 静默模式
            }
          }
        }
      }
      
      return result;
    };
    
    // 不再输出日志
  }
  
  // Hook Uint8Array - 捕获二进制密钥
  function setupTypedArrayHook() {
    var OrigUint8Array = targetWindow.Uint8Array;
    var origSet = OrigUint8Array.prototype.set;
    
    OrigUint8Array.prototype.set = function(source, offset) {
      var result = origSet.apply(this, arguments);
      
      if (source && isValidKeyLength(source.length)) {
        var stack = getCallStack();
        if (/encrypt|decrypt|cipher|key|iv|aes|des|sm4|crypto/i.test(stack)) {
          var hex = toHex(source);
          if (looksLikeKey(hex)) {
            if (source.length === 16 && /iv/i.test(stack)) {
              addIV(hex, 'Uint8Array.set', null, true);  // v6.5.1: silent
            } else {
              addKey(hex, 'Uint8Array.set', null, null, true);  // v6.5.1: silent
            }
          }
        }
      }
      
      return result;
    };
  }
  
  // Hook btoa - 捕获 Base64 编码的密钥
  function setupBase64Hook() {
    var originalBtoa = targetWindow.btoa;
    var originalAtob = targetWindow.atob;
    
    targetWindow.btoa = function(str) {
      var result = originalBtoa.apply(this, arguments);
      
      if (str && isValidKeyLength(str.length)) {
        var stack = getCallStack();
        if (/encrypt|decrypt|key|iv|cipher|crypto/i.test(stack)) {
          var hex = toHex(str);
          if (looksLikeKey(hex)) {
            addKey(hex, 'btoa (Base64编码前)', null, null, true);  // v6.5.1: silent
          }
        }
      }
      
      return result;
    };
    
    targetWindow.atob = function(str) {
      var result = originalAtob.apply(this, arguments);
      
      if (result && isValidKeyLength(result.length)) {
        var stack = getCallStack();
        if (/encrypt|decrypt|key|iv|cipher|crypto/i.test(stack)) {
          var hex = toHex(result);
          if (looksLikeKey(hex)) {
            addKey(hex, 'atob (Base64解码后)', null, null, true);  // v6.5.1: silent
          }
        }
      }
      
      return result;
    };
  }
  
  // ==================== 全局扫描 ====================
  
  function scanGlobalCryptoFunctions() {
    var patterns = [/encrypt/i, /decrypt/i, /cipher/i, /sign/i, /hash/i, /md5/i, /sha/i, /aes/i, /des/i, /sm4/i, /sm2/i];
    var scanned = new WeakSet();
    var hookedCount = 0;
    
    // v6.3: 排除已被 CryptoJS Hook 处理的函数名（避免重复日志）
    var cryptoJSHookedNames = [
      'HmacMD5', 'HmacSHA1', 'HmacSHA256', 'HmacSHA512',  // HMAC
      'MD5', 'SHA1', 'SHA256', 'SHA512', 'SHA3', 'RIPEMD160',  // Hash
      'PBKDF2',  // KDF
      'AES', 'DES', 'TripleDES', 'Rabbit', 'RC4', 'RC4Drop'  // Ciphers
    ];
    
    // 深度扫描检测 CryptoJS 结构
    function detectAndHookCryptoJS(obj, path) {
      if (!obj || typeof obj !== 'object') return;
      
      try {
        // 检测 CryptoJS 特征：lib.BlockCipher
        if (obj.lib && obj.lib.BlockCipher) {
          if (DEBUG_MODE) console.log(LOG_PREFIX + ' 在 ' + path + ' 检测到 CryptoJS 结构');
          hookCryptoJS(obj);
        }
        
        // 检测 BlockCipher.prototype.reset
        if (obj.prototype && typeof obj.prototype.reset === 'function') {
          if (!obj.prototype.reset.__HOOKED__) {
            if (DEBUG_MODE) console.log(LOG_PREFIX + ' 在 ' + path + '.prototype 检测到 reset 方法');
            checkAndHookReset(obj.prototype);
          }
        }
        
        // 检测 AES/DES 对象
        if (obj.AES || obj.DES || obj.TripleDES) {
          if (DEBUG_MODE) console.log(LOG_PREFIX + ' 在 ' + path + ' 检测到 AES/DES 对象');
          hookCryptoJS(obj);
        }
      } catch (e) {}
    }
    
    function scanObject(obj, path, depth) {
      if (depth > 4 || !obj || scanned.has(obj)) return;
      try { scanned.add(obj); } catch (e) { return; }
      
      // 首先检测是否是 CryptoJS
      detectAndHookCryptoJS(obj, path);
      
      var keys;
      try { keys = Object.keys(obj); } catch (e) { return; }
      
      for (var i = 0; i < keys.length; i++) {
        var key = keys[i];
        var fullPath = path ? path + '.' + key : key;
        
        // 排除自己导出的函数
        if (/^(sm4Enc|sm4Dec|locateInlineSm4|customerSm4Enc|customerSm4Dec|CJSencrypt|CJSdecrypt|locateSm2Enc|locateSm2Dec|locateRsaEnc|locateRsaDec|customerEnc|customerDec|__cryptoHook__|help|getKeys|getIVs|getCaptures|setConfig|getRequestTraces|getKeyUsage|getDecryptedResponses|setAutoDecrypt|getCryptoRecords|getSecrets|getSignParams)$/.test(key)) continue;
        
        var isMatch = patterns.some(function(p) { return p.test(key); });
        
        // v6.3: 跳过已被 CryptoJS Hook 处理的函数（避免重复日志）
        if (cryptoJSHookedNames.indexOf(key) !== -1) {
          isMatch = false;
        }
        
        if (isMatch) {
          try {
            var val = obj[key];
            if (typeof val === 'function' && !val.__HOOKED__) {
              var origFn = val;
              var fnPath = fullPath;
              
              obj[key] = (function(original, funcPath) {
                var wrapped = function() {
                  var args = Array.from(arguments);
                  var result = original.apply(this, args);
                  
                  // v6.5.1: 全局扫描的函数也静默捕获
                  // 分析参数，查找可能的 Key/IV
                  args.forEach(function(arg, idx) {
                    if (arg && typeof arg === 'string' && isValidKeyLength(arg.length)) {
                      var hex = toHex(arg);
                      if (looksLikeKey(hex)) {
                        addKey(hex, funcPath + ' (参数' + idx + ')', null, null, true);  // silent
                      }
                    }
                  });
                  
                  // 分析返回值
                  if (result && typeof result === 'string' && isValidKeyLength(result.length)) {
                    var hex = toHex(result);
                    if (looksLikeKey(hex)) {
                      addKey(hex, funcPath + ' (返回值)', null, null, true);  // silent
                    }
                  }
                  
                  logCapture('InlineFunc', funcPath, {
                    arguments: args.map(function(a) { return safeStringify(a); }),
                    result: safeStringify(result)
                  });
                  
                  return result;
                };
                wrapped.__HOOKED__ = true;
                wrapped.toString = function() { return original.toString(); };
                return wrapped;
              })(origFn, fnPath);
              
              hookedCount++;
            }
          } catch (e) {}
        }
        
        try {
          var childVal = obj[key];
          if (childVal && typeof childVal === 'object' && !Array.isArray(childVal)) {
            scanObject(childVal, fullPath, depth + 1);
          }
        } catch (e) {}
      }
    }
    
    scanObject(targetWindow, '', 0);
    
    if (hookedCount > 0) {
      if (DEBUG_MODE) console.log(LOG_PREFIX + ' 全局扫描完成，Hook了 ' + hookedCount + ' 个函数');
    }
  }
  
  // ==================== 属性拦截 ====================
  
  function setupPropertyInterceptor(propName, hookFn) {
    var _value = targetWindow[propName];
    if (_value) { hookFn(_value); return; }
    try {
      Object.defineProperty(targetWindow, propName, {
        get: function() { return _value; },
        set: function(newValue) {
          _value = newValue;
          if (newValue && !newValue.__HOOKED__) {
            setTimeout(function() { hookFn(newValue); }, 0);
          }
        },
        configurable: true,
        enumerable: true
      });
    } catch (e) {}
  }
  
  // ==================== 消息监听 ====================
  
  // 加密请求记录
  var encryptedRequests = [];
  
  targetWindow.addEventListener('message', function(event) {
    if (event.source !== targetWindow) return;
    var data = event.data;
    if (!data || data.source !== 'CRYPTO_HOOK_CONTENT') return;
    
    if (data.type === 'REQUEST_CAPTURES') {
      targetWindow.postMessage({
        source: 'CRYPTO_HOOK_INJECT',
        type: 'CAPTURE_UPDATE',
        captures: captures.slice(),
        keyStore: JSON.parse(JSON.stringify(keyStore)),
        requests: encryptedRequests.slice()
      }, '*');
    } else if (data.type === 'CLEAR_CAPTURES') {
      captures.length = 0;
      Object.keys(capturedData).forEach(function(k) { capturedData[k] = []; });
      keyStore.keys = [];
      keyStore.ivs = [];
      keyStore.secrets = [];
      keyStore.signParams = [];
      encryptedRequests = [];
    } else if (data.type === 'PERFORM_CRYPTO') {
      // 工作台加解密请求
      if (!getCryptoJS()) {
        loadCryptoJS().then(function() {
          var result = performCryptoFromPopup(data.action, data.data, data.algorithm, data.keyIndex);
          targetWindow.postMessage({
            source: 'CRYPTO_HOOK_INJECT',
            type: 'CRYPTO_RESULT',
            callbackId: data.callbackId,
            success: result.success,
            result: result.result,
            error: result.error
          }, '*');
        }).catch(function(err) {
          targetWindow.postMessage({
            source: 'CRYPTO_HOOK_INJECT',
            type: 'CRYPTO_RESULT',
            callbackId: data.callbackId,
            success: false,
            error: '无法加载 CryptoJS: ' + err.message
          }, '*');
        });
      } else {
        var result = performCryptoFromPopup(data.action, data.data, data.algorithm, data.keyIndex);
        targetWindow.postMessage({
          source: 'CRYPTO_HOOK_INJECT',
          type: 'CRYPTO_RESULT',
          callbackId: data.callbackId,
          success: result.success,
          result: result.result,
          error: result.error
        }, '*');
      }
    } else if (data.type === 'REPLAY_REQUEST') {
      // 请求重放
      replayRequest(data.request, data.callbackId);
    }
  });
  
  // 从 popup 工作台执行加解密
  function performCryptoFromPopup(action, inputData, algorithm, keyIndex) {
    try {
      var result;
      var selectedKey = null;
      var selectedSecret = null;
      
      // 解析 keyIndex 获取选中的密钥
      if (keyIndex && keyIndex !== 'auto') {
        var colonIdx = keyIndex.indexOf(':');
        if (colonIdx > -1) {
          var keyType = keyIndex.substring(0, colonIdx);
          var keyValue = keyIndex.substring(colonIdx + 1);
          
          if (keyType === 'key') {
            selectedKey = keyStore.keys.find(function(k) { return k.hex === keyValue; });
          } else if (keyType === 'secret') {
            var decodedValue = decodeURIComponent(keyValue);
            selectedSecret = keyStore.secrets.find(function(s) { return s.value === decodedValue; });
          }
        }
      }
      
      // 如果没有选中或找不到，使用最后捕获的 key
      if (!selectedKey && !selectedSecret) {
        selectedKey = keyStore.keys[0];
      }
      
      // 确定实际使用的算法
      var actualAlgo = algorithm;
      if (algorithm === 'auto' && selectedKey) {
        actualAlgo = selectedKey.algorithm || 'AES';
      }
      
      // 获取 key 和 iv
      var keyHex = selectedKey ? selectedKey.hex : null;
      var ivHex = keyStore.ivs[0] ? keyStore.ivs[0].hex : null;
      
      // ECB 模式不需要 IV
      if (selectedKey && selectedKey.mode === 'ECB') {
        ivHex = null;
      }
      
      if (!keyHex) {
        return { success: false, error: '没有可用的密钥。请先在页面上触发加密操作以捕获密钥。' };
      }
      
      // 根据算法选择加解密方法
      if (actualAlgo === 'AES' || actualAlgo === 'DES' || actualAlgo === '3DES' || actualAlgo === 'TripleDES') {
        var cryptoAlgo = actualAlgo === '3DES' ? 'TripleDES' : actualAlgo;
        if (action === 'encrypt') {
          result = customerEnc(inputData, keyHex, ivHex, cryptoAlgo);
        } else {
          result = customerDec(inputData, keyHex, ivHex, cryptoAlgo);
        }
      } else if (actualAlgo === 'RSA') {
        var publicKey = selectedSecret ? selectedSecret.value : null;
        if (action === 'encrypt') {
          result = customerRsaEnc(inputData, publicKey);
        } else {
          result = customerRsaDec(inputData);
        }
      } else if (actualAlgo === 'SM4') {
        if (action === 'encrypt') {
          result = customerSm4Enc(inputData);
        } else {
          result = customerSm4Dec(inputData);
        }
      } else if (actualAlgo === 'SM2') {
        if (action === 'encrypt') {
          result = customerSm2Enc(inputData);
        } else {
          result = customerSm2Dec(inputData);
        }
      } else {
        // 尝试自动检测 - 优先使用捕获的配置
        if (selectedKey) {
          var algo = selectedKey.algorithm || 'AES';
          var cryptoAlgo2 = algo === '3DES' ? 'TripleDES' : algo;
          if (action === 'encrypt') {
            result = customerEnc(inputData, keyHex, ivHex, cryptoAlgo2);
          } else {
            result = customerDec(inputData, keyHex, ivHex, cryptoAlgo2);
          }
        } else {
          // 没有捕获的 key，尝试 RSA
          if (action === 'encrypt') {
            result = customerRsaEnc(inputData);
          } else {
            result = customerRsaDec(inputData);
          }
        }
      }
      
      if (result !== null && result !== undefined && result !== '') {
        return { success: true, result: result };
      } else {
        return { success: false, error: '加解密失败，请检查密钥和数据格式' };
      }
    } catch (e) {
      return { success: false, error: '执行异常: ' + e.message };
    }
  }
  
  // 重放请求
  function replayRequest(request, callbackId) {
    try {
      var xhr = new targetWindow.XMLHttpRequest();
      xhr.open(request.method || 'GET', request.url, true);
      
      // 设置请求头
      if (request.headers) {
        Object.keys(request.headers).forEach(function(key) {
          try {
            xhr.setRequestHeader(key, request.headers[key]);
          } catch (e) {}
        });
      }
      
      xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
          targetWindow.postMessage({
            source: 'CRYPTO_HOOK_INJECT',
            type: 'CRYPTO_RESULT',
            callbackId: callbackId,
            success: true,
            result: xhr.responseText,
            status: xhr.status
          }, '*');
        }
      };
      
      xhr.onerror = function() {
        targetWindow.postMessage({
          source: 'CRYPTO_HOOK_INJECT',
          type: 'CRYPTO_RESULT',
          callbackId: callbackId,
          success: false,
          error: '请求失败'
        }, '*');
      };
      
      xhr.send(request.body || null);
    } catch (e) {
      targetWindow.postMessage({
        source: 'CRYPTO_HOOK_INJECT',
        type: 'CRYPTO_RESULT',
        callbackId: callbackId,
        success: false,
        error: e.message
      }, '*');
    }
  }
  
  // 记录加密请求
  function recordEncryptedRequest(method, url, body, headers) {
    var req = {
      method: method,
      url: url,
      body: body,
      headers: headers,
      timestamp: Date.now()
    };
    encryptedRequests.unshift(req);
    if (encryptedRequests.length > 50) encryptedRequests.pop();
    
    // 通知 content script
    targetWindow.postMessage({
      source: 'CRYPTO_HOOK_INJECT',
      type: 'REQUEST_CAPTURE',
      request: req
    }, '*');
  }
  
  // ==================== 定位函数（用于调试定位加密调用位置）====================
  
  // 存储最后一次加解密的调用栈
  var lastEncryptStack = null;
  var lastDecryptStack = null;
  var lastSm4EncStack = null;
  var lastSm4DecStack = null;
  var lastSm2EncStack = null;
  var lastSm2DecStack = null;
  var lastRsaEncStack = null;
  var lastRsaDecStack = null;
  
  // CryptoJS AES/DES 加密定位函数
  function CJSencrypt() {
    if (!lastEncryptStack) {
      console.log('%c' + LOG_PREFIX + ' ⚠️ 还没有捕获到加密调用，请先触发加密操作', 'color: #FF9800;');
      return;
    }
    console.log('%c' + LOG_PREFIX + ' 📍 最后一次 AES/DES 加密调用位置:', 'color: #4CAF50; font-weight: bold;');
    console.log('%c' + lastEncryptStack, 'color: #666; font-family: monospace;');
    console.log('%c💡 提示: 点击上方链接可跳转到代码位置', 'color: #2196F3;');
  }
  
  // CryptoJS AES/DES 解密定位函数
  function CJSdecrypt() {
    if (!lastDecryptStack) {
      console.log('%c' + LOG_PREFIX + ' ⚠️ 还没有捕获到解密调用，请先触发解密操作', 'color: #FF9800;');
      return;
    }
    console.log('%c' + LOG_PREFIX + ' 📍 最后一次 AES/DES 解密调用位置:', 'color: #4CAF50; font-weight: bold;');
    console.log('%c' + lastDecryptStack, 'color: #666; font-family: monospace;');
    console.log('%c💡 提示: 点击上方链接可跳转到代码位置', 'color: #2196F3;');
  }
  
  // SM4 加密定位函数
  function sm4Enc() {
    if (!lastSm4EncStack) {
      console.log('%c' + LOG_PREFIX + ' ⚠️ 还没有捕获到 SM4 加密调用', 'color: #FF9800;');
      return;
    }
    console.log('%c' + LOG_PREFIX + ' 📍 最后一次 SM4 加密调用位置:', 'color: #4CAF50; font-weight: bold;');
    console.log('%c' + lastSm4EncStack, 'color: #666; font-family: monospace;');
  }
  
  // SM4 解密定位函数
  function sm4Dec() {
    if (!lastSm4DecStack) {
      console.log('%c' + LOG_PREFIX + ' ⚠️ 还没有捕获到 SM4 解密调用', 'color: #FF9800;');
      return;
    }
    console.log('%c' + LOG_PREFIX + ' 📍 最后一次 SM4 解密调用位置:', 'color: #4CAF50; font-weight: bold;');
    console.log('%c' + lastSm4DecStack, 'color: #666; font-family: monospace;');
  }
  
  // SM2 加密定位函数  
  function locateSm2Enc() {
    if (!lastSm2EncStack) {
      console.log('%c' + LOG_PREFIX + ' ⚠️ 还没有捕获到 SM2 加密调用', 'color: #FF9800;');
      return;
    }
    console.log('%c' + LOG_PREFIX + ' 📍 最后一次 SM2 加密调用位置:', 'color: #4CAF50; font-weight: bold;');
    console.log('%c' + lastSm2EncStack, 'color: #666; font-family: monospace;');
  }
  
  // SM2 解密定位函数
  function locateSm2Dec() {
    if (!lastSm2DecStack) {
      console.log('%c' + LOG_PREFIX + ' ⚠️ 还没有捕获到 SM2 解密调用', 'color: #FF9800;');
      return;
    }
    console.log('%c' + LOG_PREFIX + ' 📍 最后一次 SM2 解密调用位置:', 'color: #4CAF50; font-weight: bold;');
    console.log('%c' + lastSm2DecStack, 'color: #666; font-family: monospace;');
  }
  
  // RSA 加密定位函数
  function locateRsaEnc() {
    if (!lastRsaEncStack) {
      console.log('%c' + LOG_PREFIX + ' ⚠️ 还没有捕获到 RSA 加密调用', 'color: #FF9800;');
      return;
    }
    console.log('%c' + LOG_PREFIX + ' 📍 最后一次 RSA 加密调用位置:', 'color: #4CAF50; font-weight: bold;');
    console.log('%c' + lastRsaEncStack, 'color: #666; font-family: monospace;');
  }
  
  // RSA 解密定位函数
  function locateRsaDec() {
    if (!lastRsaDecStack) {
      console.log('%c' + LOG_PREFIX + ' ⚠️ 还没有捕获到 RSA 解密调用', 'color: #FF9800;');
      return;
    }
    console.log('%c' + LOG_PREFIX + ' 📍 最后一次 RSA 解密调用位置:', 'color: #4CAF50; font-weight: bold;');
    console.log('%c' + lastRsaDecStack, 'color: #666; font-family: monospace;');
  }
  
  // ==================== 自主加解密函数 ====================
  
  // 获取最后捕获的 Key 和 IV
  function getLastKey() {
    return keyStore.keys[0] || null;
  }
  
  function getLastIV() {
    return keyStore.ivs[0] || null;
  }
  
  // 获取或加载 CryptoJS
  function getCryptoJS() {
    // 优先使用页面已有的 CryptoJS
    if (targetWindow.CryptoJS) {
      return targetWindow.CryptoJS;
    }
    // 检查是否有其他命名空间
    if (targetWindow.crypto && targetWindow.crypto.CryptoJS) {
      return targetWindow.crypto.CryptoJS;
    }
    return null;
  }
  
  // 动态加载 CryptoJS（如果页面没有）
  var cryptoJSLoading = null;
  function loadCryptoJS() {
    if (cryptoJSLoading) return cryptoJSLoading;
    if (getCryptoJS()) return Promise.resolve(getCryptoJS());
    
    cryptoJSLoading = new Promise(function(resolve, reject) {
      var script = document.createElement('script');
      script.src = 'https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js';
      script.onload = function() {
        console.log(LOG_PREFIX + ' ✅ CryptoJS 动态加载成功');
        resolve(targetWindow.CryptoJS);
      };
      script.onerror = function() {
        console.error(LOG_PREFIX + ' ❌ CryptoJS 加载失败');
        reject(new Error('CryptoJS 加载失败'));
      };
      document.head.appendChild(script);
    });
    return cryptoJSLoading;
  }
  
  // 通用 AES/DES 加密（使用 CryptoJS）
  function customerEnc(data, keyHex, ivHex, algorithm) {
    var CryptoJS = getCryptoJS();
    if (!CryptoJS) return null;
    
    keyHex = keyHex || (getLastKey() && getLastKey().hex);
    ivHex = ivHex || (getLastIV() && getLastIV().hex);
    algorithm = algorithm || 'AES';
    
    if (!keyHex) return null;
    
    try {
      var key = CryptoJS.enc.Hex.parse(keyHex);
      var cfg = {
        mode: ivHex ? CryptoJS.mode.CBC : CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
      };
      if (ivHex) cfg.iv = CryptoJS.enc.Hex.parse(ivHex);
      
      var algo = CryptoJS[algorithm] || CryptoJS.AES;
      return algo.encrypt(data, key, cfg).toString();
    } catch (e) {
      return null;
    }
  }
  
  // 通用 AES/DES 解密（使用 CryptoJS）
  function customerDec(ciphertext, keyHex, ivHex, algorithm) {
    var CryptoJS = getCryptoJS();
    if (!CryptoJS) return null;
    
    keyHex = keyHex || (getLastKey() && getLastKey().hex);
    ivHex = ivHex || (getLastIV() && getLastIV().hex);
    algorithm = algorithm || 'AES';
    
    if (!keyHex) return null;
    
    try {
      var key = CryptoJS.enc.Hex.parse(keyHex);
      var cfg = {
        mode: ivHex ? CryptoJS.mode.CBC : CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
      };
      if (ivHex) cfg.iv = CryptoJS.enc.Hex.parse(ivHex);
      
      var algo = CryptoJS[algorithm] || CryptoJS.AES;
      
      // 自动检测密文格式：Hex 或 Base64
      var cipherInput = ciphertext;
      if (/^[0-9a-fA-F]+$/.test(ciphertext)) {
        var cipherBytes = CryptoJS.enc.Hex.parse(ciphertext);
        cipherInput = CryptoJS.lib.CipherParams.create({ ciphertext: cipherBytes });
      }
      
      var decrypted = algo.decrypt(cipherInput, key, cfg);
      return decrypted.toString(CryptoJS.enc.Utf8) || null;
    } catch (e) {
      return null;
    }
  }
  
  // SM4 加密
  function customerSm4Enc(data, keyHex) {
    keyHex = keyHex || (getLastKey() && getLastKey().hex);
    
    if (!keyHex) {
      console.error(LOG_PREFIX + ' 没有可用的 Key');
      return null;
    }
    
    // 尝试使用 sm-crypto 库
    if (targetWindow.sm4) {
      try {
        var result = targetWindow.sm4.encrypt(data, keyHex);
        console.log(LOG_PREFIX + ' 🔐 SM4 加密完成:', result);
        return result;
      } catch (e) {
        console.error(LOG_PREFIX + ' SM4 加密失败:', e.message);
      }
    }
    
    // 尝试使用 GMCrypto
    if (targetWindow.GMCrypto && targetWindow.GMCrypto.SM4) {
      try {
        var result = targetWindow.GMCrypto.SM4.encrypt(data, keyHex);
        console.log(LOG_PREFIX + ' 🔐 GMCrypto SM4 加密完成:', result);
        return result;
      } catch (e) {
        console.error(LOG_PREFIX + ' GMCrypto SM4 加密失败:', e.message);
      }
    }
    
    console.error(LOG_PREFIX + ' 未找到 SM4 加密库 (sm4 或 GMCrypto)');
    return null;
  }
  
  // SM4 解密
  function customerSm4Dec(ciphertext, keyHex) {
    keyHex = keyHex || (getLastKey() && getLastKey().hex);
    
    if (!keyHex) {
      console.error(LOG_PREFIX + ' 没有可用的 Key');
      return null;
    }
    
    if (targetWindow.sm4) {
      try {
        var result = targetWindow.sm4.decrypt(ciphertext, keyHex);
        console.log(LOG_PREFIX + ' 🔓 SM4 解密完成:', result);
        return result;
      } catch (e) {
        console.error(LOG_PREFIX + ' SM4 解密失败:', e.message);
      }
    }
    
    if (targetWindow.GMCrypto && targetWindow.GMCrypto.SM4) {
      try {
        var result = targetWindow.GMCrypto.SM4.decrypt(ciphertext, keyHex);
        console.log(LOG_PREFIX + ' 🔓 GMCrypto SM4 解密完成:', result);
        return result;
      } catch (e) {
        console.error(LOG_PREFIX + ' GMCrypto SM4 解密失败:', e.message);
      }
    }
    
    console.error(LOG_PREFIX + ' 未找到 SM4 解密库');
    return null;
  }
  
  // SM2 加密
  function customerSm2Enc(data, publicKey) {
    publicKey = publicKey || (keyStore.secrets.find(function(s) { return s.usage === 'SM2_PUBLIC_KEY'; }) || {}).value;
    
    if (!publicKey) {
      console.error(LOG_PREFIX + ' 没有可用的 SM2 公钥');
      return null;
    }
    
    if (targetWindow.sm2) {
      try {
        var result = targetWindow.sm2.doEncrypt(data, publicKey, 1);
        console.log(LOG_PREFIX + ' 🔐 SM2 加密完成');
        return result;
      } catch (e) {
        console.error(LOG_PREFIX + ' SM2 加密失败:', e.message);
      }
    }
    
    if (targetWindow.GMCrypto && targetWindow.GMCrypto.SM2) {
      try {
        var result = targetWindow.GMCrypto.SM2.encrypt(data, publicKey);
        console.log(LOG_PREFIX + ' 🔐 GMCrypto SM2 加密完成');
        return result;
      } catch (e) {
        console.error(LOG_PREFIX + ' GMCrypto SM2 加密失败:', e.message);
      }
    }
    
    console.error(LOG_PREFIX + ' 未找到 SM2 加密库');
    return null;
  }
  
  // SM2 解密
  function customerSm2Dec(ciphertext, privateKey) {
    privateKey = privateKey || (keyStore.secrets.find(function(s) { return s.usage === 'SM2_PRIVATE_KEY'; }) || {}).value;
    
    if (!privateKey) {
      console.error(LOG_PREFIX + ' 没有可用的 SM2 私钥');
      return null;
    }
    
    if (targetWindow.sm2) {
      try {
        var result = targetWindow.sm2.doDecrypt(ciphertext, privateKey, 1);
        console.log(LOG_PREFIX + ' 🔓 SM2 解密完成:', result);
        return result;
      } catch (e) {
        console.error(LOG_PREFIX + ' SM2 解密失败:', e.message);
      }
    }
    
    if (targetWindow.GMCrypto && targetWindow.GMCrypto.SM2) {
      try {
        var result = targetWindow.GMCrypto.SM2.decrypt(ciphertext, privateKey);
        console.log(LOG_PREFIX + ' 🔓 GMCrypto SM2 解密完成:', result);
        return result;
      } catch (e) {
        console.error(LOG_PREFIX + ' GMCrypto SM2 解密失败:', e.message);
      }
    }
    
    console.error(LOG_PREFIX + ' 未找到 SM2 解密库');
    return null;
  }
  
  // RSA 加密
  function customerRsaEnc(data, publicKey) {
    publicKey = publicKey || (keyStore.secrets.find(function(s) { return s.usage === 'RSA_PUBLIC_KEY'; }) || {}).value;
    
    if (!publicKey) {
      console.error(LOG_PREFIX + ' 没有可用的 RSA 公钥');
      return null;
    }
    
    if (targetWindow.JSEncrypt) {
      try {
        var encrypt = new targetWindow.JSEncrypt();
        encrypt.setPublicKey(publicKey);
        var result = encrypt.encrypt(data);
        console.log(LOG_PREFIX + ' 🔐 RSA 加密完成');
        return result;
      } catch (e) {
        console.error(LOG_PREFIX + ' RSA 加密失败:', e.message);
      }
    }
    
    console.error(LOG_PREFIX + ' 未找到 JSEncrypt 库');
    return null;
  }
  
  // RSA 解密
  function customerRsaDec(ciphertext, privateKey) {
    privateKey = privateKey || (keyStore.secrets.find(function(s) { return s.usage === 'RSA_PRIVATE_KEY'; }) || {}).value;
    
    if (!privateKey) {
      console.error(LOG_PREFIX + ' 没有可用的 RSA 私钥');
      return null;
    }
    
    if (targetWindow.JSEncrypt) {
      try {
        var decrypt = new targetWindow.JSEncrypt();
        decrypt.setPrivateKey(privateKey);
        var result = decrypt.decrypt(ciphertext);
        console.log(LOG_PREFIX + ' 🔓 RSA 解密完成:', result);
        return result;
      } catch (e) {
        console.error(LOG_PREFIX + ' RSA 解密失败:', e.message);
      }
    }
    
    console.error(LOG_PREFIX + ' 未找到 JSEncrypt 库');
    return null;
  }
  
  // ==================== customerRsa 对象（兼容 FakeCryptoJS API）====================
  
  var customerRsa = {
    encrypt: function(data) {
      return customerRsaEnc(data);
    },
    decrypt: function(ciphertext) {
      return customerRsaDec(ciphertext);
    },
    getPublicKey: function() {
      var pk = lastRsaPublicKey || (keyStore.secrets.find(function(s) { return s.usage === 'RSA_PUBLIC_KEY'; }) || {}).value;
      if (pk) {
        console.log(LOG_PREFIX + ' RSA 公钥:');
        console.log(pk);
        return pk;
      }
      console.log(LOG_PREFIX + ' 未捕获到 RSA 公钥');
      return null;
    },
    getPrivateKey: function() {
      var pk = lastRsaPrivateKey || (keyStore.secrets.find(function(s) { return s.usage === 'RSA_PRIVATE_KEY'; }) || {}).value;
      if (pk) {
        console.log(LOG_PREFIX + ' RSA 私钥:');
        console.log(pk);
        return pk;
      }
      console.log(LOG_PREFIX + ' 未捕获到 RSA 私钥');
      return null;
    }
  };
  
// ==================== 导出 API ====================

  function init() {
    var log = originalConsole.log;
    
    // v1.0: 简洁启动提示
    log('%c[🔐 稻草人安全] v' + VERSION + ' 已启动', 'color: #4CAF50; font-weight: bold; font-size: 14px;');
    log('%c查询: getKeys() | getCryptoRecords() | summary()  定位: CJSencrypt()  导出: exportToFile()  帮助: help()', 'color: #666;');
    
    try { setupBase64Hook(); } catch (e) {}
    try { setupStringHook(); } catch (e) {}
    try { setupTypedArrayHook(); } catch (e) {}
    
    setupPropertyInterceptor('CryptoJS', hookCryptoJS);
    setupPropertyInterceptor('JSEncrypt', hookJSEncrypt);
    setupPropertyInterceptor('sm2', hookSMCrypto);
    setupPropertyInterceptor('sm4', hookSMCrypto);
    
    // v5.0: 新增 Forge 和 SJCL 拦截
    setupPropertyInterceptor('forge', hookForge);
    setupPropertyInterceptor('sjcl', hookSJCL);
    
    hookWebCrypto();
    
    // v5.0: 网络请求/响应 Hook（自动解密）
    hookNetwork();
    
    // 内联 SM4 Hook
    try { hookInlineSM4(); } catch (e) { if (DEBUG_MODE) console.error(LOG_PREFIX + ' hookInlineSM4 error:', e); }
    
    setTimeout(function() {
      try { scanGlobalCryptoFunctions(); } catch (e) {}
    }, 1000);
    
    // 轮询检测
    var pollCount = 0;
    var pollInterval = setInterval(function() {
      pollCount++;
      if (targetWindow.CryptoJS && !targetWindow.CryptoJS.__HOOKED__) hookCryptoJS(targetWindow.CryptoJS);
      if (targetWindow.JSEncrypt && !targetWindow.JSEncrypt.__HOOKED__) hookJSEncrypt(targetWindow.JSEncrypt);
      hookSMCrypto();
      // v5.0: 检测 Forge 和 SJCL
      if (targetWindow.forge && !targetWindow.forge.__HOOKED__) hookForge(targetWindow.forge);
      if (targetWindow.sjcl && !targetWindow.sjcl.__HOOKED__) hookSJCL(targetWindow.sjcl);
      if (pollCount % 10 === 0) {
        try { scanGlobalCryptoFunctions(); } catch (e) {}
      }
      if (pollCount > 30) clearInterval(pollInterval);
    }, 500);
    
    // ==================== 导出 API ====================
    
    targetWindow.__cryptoHook__ = {
      version: VERSION,
      
      // 获取所有捕获的 Key（增强版：显示用途和使用示例）
      getKeys: function(showDetail) {
        var log = originalConsole.log;
        
        if (keyStore.keys.length === 0) {
          log('%c' + LOG_PREFIX + ' ⚠️ 还没有捕获到任何 Key', 'color: #FF9800;');
          log('%c  请先触发页面上的加解密操作（如登录、提交表单等）', 'color: #999;');
          return [];
        }
        
        log('%c' + LOG_PREFIX + ' 🔑 捕获的密钥列表 (' + keyStore.keys.length + '个)', 'color: #4CAF50; font-weight: bold; font-size: 14px;');
        log('%c' + '═'.repeat(70), 'color: #4CAF50;');
        
        keyStore.keys.forEach(function(k, index) {
          // 查找这个 Key 的使用记录
          var usages = keyStore.cryptoRecords.filter(function(r) {
            return r.keyHex === k.hex;
          });
          
          // 查找关联的 IV
          var relatedIV = null;
          if (usages.length > 0 && usages[0].ivHex) {
            relatedIV = usages[0].ivHex;
          } else if (keyStore.ivs.length > 0) {
            // 尝试找时间最接近的 IV
            var keyTime = k.timestamp;
            keyStore.ivs.forEach(function(iv) {
              if (!relatedIV && Math.abs(iv.timestamp - keyTime) < 1000) {
                relatedIV = iv.hex;
              }
            });
          }
          
          // 获取加密模式信息
          var mode = k.mode || (usages.length > 0 ? usages[0].mode : null) || 'CBC';
          var padding = k.padding || (usages.length > 0 ? usages[0].padding : null) || 'Pkcs7';
          var algorithm = k.algorithm || 'AES';
          
          log('%c┌─ Key #' + (index + 1) + ' ' + '─'.repeat(60), 'color: #2196F3;');
          log('%c│ 原始值: %c' + (k.original || k.ascii || '(二进制)'), 'color: #2196F3;', 'color: #E91E63; font-family: monospace;');
          log('%c│ Hex:    %c' + k.hex, 'color: #2196F3;', 'color: #4CAF50; font-family: monospace;');
          log('%c│ 长度:   %c' + k.length + ' 字节 (' + algorithm + ')', 'color: #2196F3;', 'color: #9C27B0;');
          log('%c│ 模式:   %c' + mode + '/' + padding, 'color: #2196F3;', 'color: #00BCD4;');
          log('%c│ 来源:   %c' + k.source, 'color: #2196F3;', 'color: #FF9800;');
          
          // 显示用途（关联的请求）
          if (usages.length > 0) {
            log('%c├───────────────────────────────────────────────────────────────────', 'color: #4CAF50;');
            log('%c│ 📍 用途 (' + usages.length + '次使用):', 'color: #4CAF50; font-weight: bold;');
            usages.slice(0, 3).forEach(function(u, i) {
              var typeIcon = u.type === 'encrypt' ? '🔒加密' : '🔓解密';
              log('%c│   [' + (i + 1) + '] ' + typeIcon + ' @ ' + (u.url || '本地操作'), 'color: #4CAF50;');
              if (u.plaintext) {
                log('%c│       明文: ' + (u.plaintext || '').substring(0, 60) + ((u.plaintext || '').length > 60 ? '...' : ''), 'color: #666;');
              }
            });
            if (usages.length > 3) {
              log('%c│   ... 还有 ' + (usages.length - 3) + ' 条记录', 'color: #999;');
            }
          }
          
          // 显示使用示例
          log('%c├───────────────────────────────────────────────────────────────────', 'color: #E91E63;');
          log('%c│ 💡 使用示例:', 'color: #E91E63; font-weight: bold;');
          
          if (algorithm === 'SM4') {
            log('%c│   // SM4 加密', 'color: #666;');
            log('%c│   customerSm4Enc("你的明文", "' + k.hex + '")', 'color: #4CAF50; font-family: monospace;');
            log('%c│   // SM4 解密', 'color: #666;');
            log('%c│   customerSm4Dec("密文", "' + k.hex + '")', 'color: #4CAF50; font-family: monospace;');
          } else if (algorithm === 'RSA' || k.source.indexOf('RSA') !== -1) {
            log('%c│   // RSA 加密', 'color: #666;');
            log('%c│   customerRsaEnc("你的明文")', 'color: #4CAF50; font-family: monospace;');
            log('%c│   // RSA 解密', 'color: #666;');
            log('%c│   customerRsaDec("密文")', 'color: #4CAF50; font-family: monospace;');
          } else {
            // AES/DES
            var ivPart = relatedIV ? ', "' + relatedIV + '"' : '';
            log('%c│   // ' + algorithm + ' 加密 (' + mode + ')', 'color: #666;');
            log('%c│   customerEnc("你的明文", "' + k.hex + '"' + ivPart + ', "' + algorithm + '")', 'color: #4CAF50; font-family: monospace;');
            log('%c│   // ' + algorithm + ' 解密', 'color: #666;');
            log('%c│   customerDec("密文", "' + k.hex + '"' + ivPart + ', "' + algorithm + '")', 'color: #4CAF50; font-family: monospace;');
            
            if (relatedIV) {
              log('%c│   // 关联的 IV: ' + relatedIV, 'color: #999;');
            }
          }
          
          log('%c└' + '─'.repeat(70), 'color: #2196F3;');
          log('');
        });
        
        // 快速复制提示
        log('%c💡 提示: 可以直接复制上面的代码到控制台执行', 'color: #FF9800;');
        log('%c   getKeys()[0].hex  - 获取第一个 Key 的 Hex 值', 'color: #999;');
        log('%c   getIVs()[0].hex   - 获取第一个 IV 的 Hex 值', 'color: #999;');
        
        return keyStore.keys;
      },
      
      // 获取所有捕获的 IV
      getIVs: function() {
        console.table(keyStore.ivs.map(function(k) {
          return { Original: k.original || k.ascii, Hex: k.hex, Length: k.length + '字节', Source: k.source, Count: k.count };
        }));
        return keyStore.ivs;
      },
      
      // 获取所有捕获的 Secret
      getSecrets: function() {
        console.table(keyStore.secrets.map(function(s) {
          return { Value: s.value.substring(0, 50), Usage: s.usage, Source: s.source, Count: s.count };
        }));
        return keyStore.secrets;
      },
      
      // 获取签名参数
      getSignParams: function() {
        console.table(keyStore.signParams.map(function(s) {
          return { Input: s.input.substring(0, 80), Output: s.output, Template: s.template };
        }));
        return keyStore.signParams;
      },
      
      // v6.0: 获取明密文记录（增强版，显示调用栈）
      getCryptoRecords: function() {
        console.log('%c' + LOG_PREFIX + ' 📝 明密文记录 (' + keyStore.cryptoRecords.length + '条)', 'color: #9C27B0; font-weight: bold;');
        keyStore.cryptoRecords.forEach(function(r, i) {
          var timeStr = r.timestamp ? formatTime(r.timestamp) : '';
          console.log('%c[' + (i + 1) + '] ' + r.type.toUpperCase() + ' - ' + r.algorithm + ' (' + (r.mode || '?') + '/' + (r.padding || '?') + ') @ ' + timeStr, 'color: #FF5722;');
          console.log('  Key: ' + (r.keyHex || ''));
          if (r.ivHex) console.log('  IV: ' + r.ivHex);
          if (r.url) console.log('  URL: ' + r.url);
          console.log('  明文: ' + (r.plaintext || '').substring(0, 100));
          console.log('  密文: ' + (r.ciphertext || '').substring(0, 100));
          if (r.callStack) {
            var stackLine = r.callStack.split('\n')[0] || '';
            console.log('%c  调用: ' + stackLine.trim(), 'color: #FF9800;');
          }
        });
        return keyStore.cryptoRecords;
      },
      
      // v6.0: 请求追踪
      getRequestTraces: getRequestTraces,
      
      // v6.0: Key 使用记录
      getKeyUsage: getKeyUsage,
      
      // v5.0: 获取自动解密的响应
      getDecryptedResponses: getDecryptedResponses,
      
      // v5.0: 设置自动解密开关
      setAutoDecrypt: setAutoDecrypt,
      
      // 获取所有捕获
      getCaptures: function() { return captures.slice(); },
      
      // 清空
      clear: function() {
        captures.length = 0;
        Object.keys(capturedData).forEach(function(k) { capturedData[k] = []; });
        keyStore.keys = [];
        keyStore.ivs = [];
        keyStore.secrets = [];
        keyStore.signParams = [];
        keyStore.cryptoRecords = [];
        autoDecryptConfig.decryptedResponses = [];
        // v6.0: 清空请求追踪
        requestTracker.pendingCrypto = [];
        requestTracker.traces = [];
        requestTracker.activeRequests = {};
        console.log(LOG_PREFIX + ' 已清空所有数据');
      },
      
      // 导出
      export: function() {
        var data = {
          keys: keyStore.keys,
          ivs: keyStore.ivs,
          secrets: keyStore.secrets,
          signParams: keyStore.signParams,
          cryptoRecords: keyStore.cryptoRecords,
          decryptedResponses: autoDecryptConfig.decryptedResponses,
          requestTraces: requestTracker.traces,  // v6.0: 添加请求追踪
          captures: captures
        };
        console.log(JSON.stringify(data, null, 2));
        return data;
      },
      
      // v6.3: 一键导出到文件
      exportToFile: function(filename) {
        var data = {
          exportTime: new Date().toISOString(),
          version: VERSION,
          url: targetWindow.location.href,
          keys: keyStore.keys,
          ivs: keyStore.ivs,
          secrets: keyStore.secrets,
          cryptoRecords: keyStore.cryptoRecords,
          requestTraces: requestTracker.traces,
          summary: {
            keyCount: keyStore.keys.length,
            ivCount: keyStore.ivs.length,
            secretCount: keyStore.secrets.length,
            recordCount: keyStore.cryptoRecords.length
          }
        };
        
        var jsonStr = JSON.stringify(data, null, 2);
        var blob = new Blob([jsonStr], { type: 'application/json' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = filename || 'crypto-capture-' + Date.now() + '.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        console.log('%c' + LOG_PREFIX + ' ✅ 已导出到文件: ' + a.download, 'color: #4CAF50; font-weight: bold;');
        console.log('%c  包含: ' + data.summary.keyCount + ' Keys, ' + data.summary.ivCount + ' IVs, ' + data.summary.recordCount + ' 条加解密记录', 'color: #666;');
        return data;
      },
      
      // v6.3: 快速查看当前捕获摘要
      summary: function() {
        var log = originalConsole.log;
        log('%c' + LOG_PREFIX + ' 📊 捕获摘要 [' + formatTimestamp() + ']', 'color: #9C27B0; font-weight: bold; font-size: 14px;');
        log('%c' + '═'.repeat(50), 'color: #9C27B0;');
        log('%c  🔑 Keys: ' + keyStore.keys.length + ' 个', 'color: #4CAF50;');
        log('%c  🔐 IVs: ' + keyStore.ivs.length + ' 个', 'color: #2196F3;');
        log('%c  🔒 Secrets: ' + keyStore.secrets.length + ' 个', 'color: #E91E63;');
        log('%c  📝 加解密记录: ' + keyStore.cryptoRecords.length + ' 条', 'color: #FF9800;');
        log('%c  🌐 请求追踪: ' + requestTracker.traces.length + ' 条', 'color: #00BCD4;');
        log('%c' + '═'.repeat(50), 'color: #9C27B0;');
        log('%c  💡 使用 getKeys() 查看详细密钥信息', 'color: #999;');
        log('%c  💡 使用 exportToFile() 导出所有数据', 'color: #999;');
        return {
          keys: keyStore.keys.length,
          ivs: keyStore.ivs.length,
          secrets: keyStore.secrets.length,
          records: keyStore.cryptoRecords.length,
          traces: requestTracker.traces.length
        };
      },
      
      // ==================== 定位函数 ====================
      
      // AES/DES 加密定位
      CJSencrypt: CJSencrypt,
      
      // AES/DES 解密定位
      CJSdecrypt: CJSdecrypt,
      
      // SM4 加密定位
      sm4Enc: sm4Enc,
      
      // SM4 解密定位
      sm4Dec: sm4Dec,
      
      // 内联 SM4 定位
      locateInlineSm4: locateInlineSm4,
      
      // SM2 加密定位
      locateSm2Enc: locateSm2Enc,
      
      // SM2 解密定位
      locateSm2Dec: locateSm2Dec,
      
      // RSA 加密定位
      locateRsaEnc: locateRsaEnc,
      
      // RSA 解密定位
      locateRsaDec: locateRsaDec,
      
      // ==================== 自主加解密函数 ====================
      
      // AES/DES 加密
      customerEnc: customerEnc,
      
      // AES/DES 解密
      customerDec: customerDec,
      
      // SM4 加密
      customerSm4Enc: customerSm4Enc,
      
      // SM4 解密
      customerSm4Dec: customerSm4Dec,
      
      // SM2 加密
      customerSm2Enc: customerSm2Enc,
      
      // SM2 解密
      customerSm2Dec: customerSm2Dec,
      
      // RSA 加密
      customerRsaEnc: customerRsaEnc,
      
      // RSA 解密
      customerRsaDec: customerRsaDec,
      
      // RSA 对象（兼容 FakeCryptoJS API）
      customerRsa: customerRsa,
      
      // 帮助 - 使用原始 console 防止被网站重写影响
      help: function() {
        var log = originalConsole.log;
        log('%c[🔐 稻草人安全] v' + VERSION + ' 帮助', 'color: #4CAF50; font-weight: bold; font-size: 14px;');
        log('%c支持: CryptoJS | JSEncrypt | SM2/SM4 | WebCrypto | Forge', 'color: #666;');
        log('');
        log('%c【查询】', 'color: #FF5722; font-weight: bold;');
        log('  getKeys()           查看捕获的 Key (含模式/Hex)');
        log('  getIVs()            查看捕获的 IV');
        log('  getSecrets()        查看 RSA公钥/SM2密钥等');
        log('  getCryptoRecords()  查看明密文对 (含调用栈)');
        log('  getRequestTraces()  按请求查看加解密关联');
        log('  summary()           快速查看捕获摘要');
        log('');
        log('%c【定位】断点定位加密调用位置', 'color: #9C27B0; font-weight: bold;');
        log('  CJSencrypt() / CJSdecrypt()   AES/DES');
        log('  sm4Enc() / sm4Dec()           SM4');
        log('  locateSm2Enc() / locateSm2Dec()   SM2');
        log('  locateRsaEnc() / locateRsaDec()   RSA');
        log('');
        log('%c【加解密】使用捕获的密钥', 'color: #E91E63; font-weight: bold;');
        log('  customerEnc(data) / customerDec(cipher)     AES/DES');
        log('  customerSm4Enc(data) / customerSm4Dec(cipher)   SM4');
        log('  customerSm2Enc(data) / customerSm2Dec(cipher)   SM2');
        log('  customerRsa.encrypt(data) / .decrypt(cipher)   RSA');
        log('');
        log('%c【导出】', 'color: #2196F3; font-weight: bold;');
        log('  exportToFile()      一键导出所有数据到文件');
        log('');
      }
    };
    
    // 快捷方式 - 直接在控制台使用
    targetWindow.getKeys = targetWindow.__cryptoHook__.getKeys;
    targetWindow.getIVs = targetWindow.__cryptoHook__.getIVs;
    targetWindow.getSecrets = targetWindow.__cryptoHook__.getSecrets;
    targetWindow.getSignParams = targetWindow.__cryptoHook__.getSignParams;
    targetWindow.getCaptures = targetWindow.__cryptoHook__.getCaptures;
    targetWindow.getCryptoRecords = targetWindow.__cryptoHook__.getCryptoRecords;
    targetWindow.getDecryptedResponses = getDecryptedResponses;
    targetWindow.setAutoDecrypt = setAutoDecrypt;
    
    // v6.0: 请求追踪快捷方式
    targetWindow.getRequestTraces = getRequestTraces;
    targetWindow.getKeyUsage = getKeyUsage;
    
    // 定位函数快捷方式
    targetWindow.CJSencrypt = CJSencrypt;
    targetWindow.CJSdecrypt = CJSdecrypt;
    targetWindow.sm4Enc = sm4Enc;
    targetWindow.sm4Dec = sm4Dec;
    targetWindow.locateInlineSm4 = locateInlineSm4;
    targetWindow.locateSm2Enc = locateSm2Enc;
    targetWindow.locateSm2Dec = locateSm2Dec;
    targetWindow.locateRsaEnc = locateRsaEnc;
    targetWindow.locateRsaDec = locateRsaDec;
    
    // 自主加解密快捷方式
    targetWindow.customerEnc = customerEnc;
    targetWindow.customerDec = customerDec;
    targetWindow.customerSm4Enc = customerSm4Enc;
    targetWindow.customerSm4Dec = customerSm4Dec;
    targetWindow.customerSm2Enc = customerSm2Enc;
    targetWindow.customerSm2Dec = customerSm2Dec;
    targetWindow.customerRsaEnc = customerRsaEnc;
    targetWindow.customerRsaDec = customerRsaDec;
    targetWindow.customerRsa = customerRsa;
    
    // help 快捷方式
    targetWindow.help = targetWindow.__cryptoHook__.help;
  }
  
  init();
})(window);
