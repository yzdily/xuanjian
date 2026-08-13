"""LLM 连接池：多模型管理、故障转移、运行时热更新（供 WebUI 使用）。

从 core.llm 拆分而来。
"""
from __future__ import annotations

from core.log import get_logger
from core.llm._client import LLMClient
from core.llm._config import LLMConfig, Message, load_llm_configs, save_llm_configs

log = get_logger("llm")

class LLMPool:
    def __init__(self):
        self.configs = load_llm_configs()
        self.clients = {cfg.name: LLMClient(cfg) for cfg in self.configs}
        # 无有效配置时创建占位项目，提示用户在 WebUI 中配置
        if not self.configs:
            placeholder = LLMConfig(
                name="_unconfigured",
                provider="",
                base_url="",
                api_key="",
                model="(请先在 WebUI 设置中添加模型)",
            )
            self.configs = [placeholder]
            self.clients = {}

    @property
    def primary(self) -> LLMClient | None:
        # ★ 未配置任何 LLM 时返回 None，让 fast/无 LLM 模式可以创建会话；
        # 真正需要 LLM 的代码路径自行检查 None 并给出友好提示。
        if not self.clients:
            return None
        # 返回 is_primary=True 的模型；没有则用第一个
        for cfg in self.configs:
            if cfg.is_primary and cfg.name in self.clients:
                return self.clients[cfg.name]
        return self.clients[self.configs[0].name]

    def get(self, name: str) -> LLMClient:
        return self.clients[name]

    def all(self) -> list[LLMClient]:
        return list(self.clients.values())

    def chat_with_fallback(
        self,
        messages: list[Message],
        tools: list[dict] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 4096,
        caller: str = "",
        exclude: set[str] | None = None,
        use_cache: bool = True,
    ) -> tuple[Message, str]:
        """带故障转移的 LLM 调用：主模型失败时自动切换备用模型。

        Returns:
            (response_message, model_name_used)
        Raises:
            RuntimeError: 所有模型都失败时抛出
        """
        exclude = exclude or set()
        # 候选顺序：primary 优先，然后其余按配置顺序
        candidates: list[LLMClient] = []
        primary = self.primary  # 未配置时为 None
        if primary is not None and primary.config.name not in exclude:
            candidates.append(primary)
        for client in self.clients.values():
            if client not in candidates and client.config.name not in exclude:
                candidates.append(client)

        if not candidates:
            raise RuntimeError("未配置任何可用的 LLM 模型")

        errors: list[str] = []
        for client in candidates:
            try:
                resp = client.chat(
                    messages=messages, tools=tools,
                    temperature=temperature, max_tokens=max_tokens,
                    caller=caller, use_cache=use_cache,
                )
                return resp, client.config.name
            except Exception as exc:
                err_msg = f"[{client.config.name}] {type(exc).__name__}: {str(exc)[:200]}"
                errors.append(err_msg)
                log.warning("LLM fallback: 模型 %s 失败，尝试下一个: %s",
                            client.config.name, str(exc)[:150])
                # 把这个模型加入 exclude，避免在同一轮里重复尝试
                exclude.add(client.config.name)

        all_errors = "; ".join(errors)
        raise RuntimeError(f"所有 LLM 模型均调用失败: {all_errors}")

    @property
    def count(self) -> int:
        return len(self.clients)

    # ============== 运行时管理（供 WebUI 使用）==============

    def reload(self) -> dict:
        """从 data/llm_configs.json 重新加载配置，并热更新现有 clients。
        策略：
        - 同名 client 复用对象，只更新其 config（已被 session 引用的连接不断链）
        - 新增 name：创建新 client
        - 消失 name：从 self.clients 删除（如果还有 session 持有引用，对象本身仍有效）
        返回 {added, updated, removed}。
        """
        new_configs = load_llm_configs()
        # 无有效配置时用占位符，提示用户配置
        if not new_configs:
            placeholder = LLMConfig(
                name="_unconfigured",
                provider="",
                base_url="",
                api_key="",
                model="(请先在 WebUI 设置中添加模型)",
            )
            new_configs = [placeholder]
        new_names = {c.name for c in new_configs}

        added, updated, removed = [], [], []

        # 更新或新增
        for cfg in new_configs:
            if cfg.name in self.clients:
                old_cfg = self.clients[cfg.name].config
                if (old_cfg.provider != cfg.provider or old_cfg.base_url != cfg.base_url
                        or old_cfg.api_key != cfg.api_key or old_cfg.model != cfg.model):
                    # 重置内部底层 client（base_url/key 变了必须重建）
                    self.clients[cfg.name].config = cfg
                    self.clients[cfg.name]._client = None
                    updated.append(cfg.name)
            else:
                self.clients[cfg.name] = LLMClient(cfg)
                added.append(cfg.name)

        # 删除
        for name in list(self.clients.keys()):
            if name not in new_names:
                del self.clients[name]
                removed.append(name)

        self.configs = new_configs
        return {"added": added, "updated": updated, "removed": removed,
                "total": len(self.configs)}

    def add_or_update(self, name: str, provider: str, base_url: str,
                      api_key: str, model: str,
                      is_primary: bool | None = None) -> tuple[bool, str]:
        """新增或更新一个模型配置，并落盘。
        返回 (success, message)。
        - api_key 传空字符串表示"保留原值"（仅在更新已有 name 时生效）。
        - is_primary=None 表示保留原值；True 会把此模型设为主要，其他模型取消。
        """
        name = (name or "").strip()
        if not name:
            return False, "name 不能为空"
        if not provider or provider.lower() not in ("openai", "anthropic"):
            return False, "provider 只支持 openai / anthropic"
        if not base_url:
            return False, "base_url 不能为空"
        if not model:
            return False, "model 不能为空"

        # 空 api_key + 已有 name → 保留原值
        existing = next((c for c in self.configs if c.name == name), None)
        if not api_key:
            if existing:
                api_key = existing.api_key
            else:
                return False, "新增模型必须填写 api_key"

        # 决定 is_primary 值
        if is_primary is None:
            is_primary_val = existing.is_primary if existing else False
        else:
            is_primary_val = is_primary

        new_cfg = LLMConfig(
            provider=provider.lower(),
            base_url=base_url.strip(),
            api_key=api_key.strip(),
            model=model.strip(),
            name=name,
            is_primary=is_primary_val,
        )

        if existing:
            # 替换原配置，同时移除占位符
            new_list = [new_cfg if c.name == name else c for c in self.configs
                        if c.name != "_unconfigured"]
        else:
            # 新增时排除占位符
            new_list = [c for c in self.configs if c.name != "_unconfigured"] + [new_cfg]

        # 如果设为 primary，取消其他模型的标记
        if is_primary_val:
            new_list = [
                LLMConfig(**{**c.__dict__, "is_primary": False})
                if c.name != name else c
                for c in new_list
            ]

        save_llm_configs(new_list)
        result = self.reload()
        return True, f"已保存（{result['added'] and '新增' or '更新'} {name}）"

    def delete(self, name: str, current_active: str = "") -> tuple[bool, str]:
        """删除一个模型配置。
        - 不允许删除当前正在使用的模型
        - 不允许删除最后一个模型
        """
        if name == current_active:
            return False, f"模型 {name} 正在使用中，请先切换到其他模型再删除"
        if name not in self.clients:
            return False, "模型不存在"
        if len(self.configs) <= 1:
            return False, "至少保留一个模型"

        removed_primary = any(c.name == name and c.is_primary for c in self.configs)
        new_list = [c for c in self.configs if c.name != name]
        # 删掉的是主模型→把剩余第一个设为 primary
        if removed_primary and new_list:
            new_list = [
                LLMConfig(**{**c.__dict__, "is_primary": True})
                if i == 0 else LLMConfig(**{**c.__dict__, "is_primary": False})
                for i, c in enumerate(new_list)
            ]
        save_llm_configs(new_list)
        self.reload()
        return True, f"已删除 {name}"

    def test_connection(self, name: str) -> tuple[bool, str]:
        """对指定模型发一个 ping 请求验证连通性。"""
        if name not in self.clients:
            return False, "模型不存在"
        client = self.clients[name]
        try:
            resp = client.chat(
                messages=[Message(role="user", content="ping")],
                temperature=0.0,
                max_tokens=16,
                caller="connection_test",
            )
            tail = (resp.content or "")[:40].strip() or "(空响应)"
            return True, f"连通正常 · 模型回复: {tail}"
        except Exception as ex:
            return False, f"{type(ex).__name__}: {str(ex)[:200]}"
