"""
core/crypto_replay — 加密接口自动测试

## 价值
国内大量 API 用 SM2/SM4/AES 包了一层，传统漏扫工具直接放弃。
本模块在已有 `core/crypto_engine` + `crypto_hook` 浏览器扩展的基础上，再往前一步：

1. **录制**：监听 `crypto.captured` 事件，从浏览器/mitmproxy 捕获到的加密流量学习模板
2. **模板化**：把"哪个 host 的哪些字段被加密、用什么算法/密钥"沉淀成 YAML 模板
3. **应用**：在漏洞测试注入 payload 时，自动按模板加密 payload 后发出去
4. **可视化**：UI 展示每个 host 学到的加密接口，可手动测试

## 模块结构
- models.py     — Template / Field 数据模型
- store.py      — 模板持久化 (data/crypto_templates/<host>.yaml)
- learner.py    — 监听事件学习模板
- applier.py    — 注入时调用：apply(host, plaintext) → ciphertext
- algorithms/   — 算法适配（复用 core.crypto_engine）
- register.py   — 挂载到事件总线

## 零侵入接入
- learner 通过 `crypto.captured` 事件订阅，旧代码完全无感知
- applier 是工具函数，主流程"愿意调就调，不调就跳过"，不强制依赖
"""

from core.crypto_replay.models import (
    AlgorithmType,
    EncryptedField,
    CryptoTemplate,
)
from core.crypto_replay.store import (
    save_template,
    load_template,
    list_templates,
    delete_template,
)
from core.crypto_replay.applier import (
    has_template,
    apply_template,
    encrypt_field,
)
from core.crypto_replay.learner import learn_from_capture

__all__ = [
    "AlgorithmType",
    "EncryptedField",
    "CryptoTemplate",
    "save_template",
    "load_template",
    "list_templates",
    "delete_template",
    "has_template",
    "apply_template",
    "encrypt_field",
    "learn_from_capture",
]
