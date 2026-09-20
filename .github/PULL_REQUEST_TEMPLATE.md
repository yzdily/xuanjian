## 改动说明

<!-- 这个 PR 做了什么？为什么？关联 Issue：Fixes #xxx -->

## 改动类型

- [ ] Bug 修复（不破坏现有行为）
- [ ] 新功能
- [ ] 重构（无行为变更）
- [ ] 文档
- [ ] SKILL 方法论
- [ ] 安全加固

## 检查清单

<!-- 提交前确认以下项 -->

- [ ] 单文件新增 `.py` ≤800 行（CI 行数闸门 `scripts/check_giant_files.py`）
- [ ] 未新增 `global` 声明（D7 holder 模式，见 `tests/unit/test_global_count_gate.py`）
- [ ] 新增/修改逻辑有配套单元测试（零网络、零真实 LLM）
- [ ] `pytest -m "not slow and not e2e and not llm"` 全绿
- [ ] 敏感信息（API Key / Cookie / Token / 内网地址）已脱敏
- [ ] 公开 API 改动已确认不破坏调用方（巨文件拆分见契约草案）

## 测试

<!-- 如何验证本次改动 -->

```bash
# 本地验证命令
pytest -m "not slow and not e2e and not llm" -p no:cacheprovider -o addopts=""
```

## 许可证

提交即表示你同意以 [MIT License](../LICENSE) 授权你的贡献。
NC 许可证内容（如 wooyun-legacy）不得混入主代码库。
