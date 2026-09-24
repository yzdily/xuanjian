"""
ScopeMixin — 域名作用域判定 + 关联域推断。

包含的方法（全部是类方法，期望 self 持有 target/target_domain/extra_scope/_THIRD_PARTY_BLACKLIST）：
- _is_in_scope            : 判断 URL 是否在爬取范围内
- _is_third_party         : 判断是否第三方 SDK / 基础设施域
- _shares_brand_with_target : 判断是否与目标共享品牌词
- _infer_scope_incremental : 增量推断关联域（每页爬完调用）
- infer_extra_scope       : 启动期 + 登录后调用一次的全量关联域推断
"""

from __future__ import annotations

from urllib.parse import urlparse


class ScopeMixin:
    """域名作用域判定 mixin（必须由持有 target_domain/extra_scope/_THIRD_PARTY_BLACKLIST 的类继承）。"""

    def _is_in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False
            domain = parsed.netloc
            # 主域 + 子域
            if domain == self.target_domain or domain.endswith("." + self.target_domain):
                return True
            # ★ 同 hostname 不同端口也视为 in scope（同一台主机的不同服务）
            # 例如 target=sz-nextpark.com:35351，URL=https://sz-nextpark.com/... 也应放行
            domain_hostname = domain.split(":")[0] if ":" in domain else domain
            target_hostname = self.target_domain.split(":")[0] if ":" in self.target_domain else self.target_domain
            if domain_hostname == target_hostname:
                return True
            # 关联域白名单（精确匹配 + 子域名匹配）
            # 例：extra_scope 含 api.example.com → v2.api.example.com 也放行
            if domain in self.extra_scope:
                return True
            for scope_domain in self.extra_scope:
                if domain.endswith("." + scope_domain):
                    return True
            return False
        except Exception:
            return False

    def _is_third_party(self, domain: str) -> bool:
        """判断是否是已知第三方 SDK / 基础设施域。"""
        domain = domain.lower().lstrip(".")
        for blocked in self._THIRD_PARTY_BLACKLIST:
            if domain == blocked or domain.endswith("." + blocked):
                return True
        # 通用特征过滤：纯 CDN / 静态资源域
        cdn_keywords = ("cdn.", "static.", "assets.", "media.", "img.", "images.",
                        "fonts.", "analytics.", "tracking.", "ads.", "pixel.")
        for kw in cdn_keywords:
            if domain.startswith(kw):
                return True
        return False

    def _shares_brand_with_target(self, domain: str) -> bool:
        """判断给定域名是否与 target 同公司体系（共享品牌词或租户前缀）。

        判定策略（任一命中即认定为同公司）：
        1. SLD 相同（同主品牌）：如 a.foo.com vs b.foo.com → True
        2. 租户前缀相同（同租户跨产品）：如 nsua.freshservice.com vs nsua.myfreshworks.com → True
        3. SLD 包含目标 SLD 关键词（如 freshservice / myfreshworks 都含 'fresh'）

        排除：
        - 已知第三方域（黑名单优先）
        - SLD/前缀长度 < 4 字符（避免误伤 ccTLD 多段域名 / 通用短词）
        """
        if not domain:
            return False
        domain = domain.lower().lstrip(".")
        # 第三方黑名单优先级最高
        if self._is_third_party(domain):
            return False

        target_parts = self.target_domain.lower().split(".")
        domain_parts = domain.split(".")
        if len(target_parts) < 2 or len(domain_parts) < 2:
            return False

        target_sld = target_parts[-2]
        domain_sld = domain_parts[-2]

        # 规则 1：SLD 完全相同（最强信号）
        # 长度 ≥3 防止 "co" / "ne" 这种 ccTLD 二段误伤
        if len(target_sld) >= 3 and target_sld == domain_sld:
            return True

        # 规则 2：租户前缀相同（如 nsua.x.com / nsua.y.com）
        # 长度 ≥4 防止 "www" / "api" 等通用前缀误伤
        if len(target_parts[0]) >= 4 and target_parts[0] == domain_parts[0]:
            return True

        # 规则 3：SLD 互相包含品牌关键词（如 freshservice ⊃ fresh ⊂ myfreshworks）
        # 取目标 SLD 的"主词根"（去掉常见前后缀），看 domain SLD 是否包含
        if len(target_sld) >= 5 and len(domain_sld) >= 5:
            # 提取双方共同的子串（最长公共前缀 ≥4）
            min_len = min(len(target_sld), len(domain_sld))
            common = 0
            for i in range(min_len):
                if target_sld[i] == domain_sld[i]:
                    common += 1
                else:
                    break
            if common >= 5:  # 至少 5 字符前缀相同（如 'fresh'）
                return True
            # 互相子串包含（如 'freshservice' 含 'fresh'，'myfreshworks' 含 'fresh'）
            # 提取至少 5 字符的最长公共子串
            for i in range(len(target_sld) - 4):
                substr = target_sld[i:i+5]
                if substr in domain_sld:
                    return True

        return False

    def _infer_scope_incremental(self, captured: list[dict]) -> set[str]:
        """每页爬完调用一次，从最近流量中增量发现新关联域。

        相比 infer_extra_scope（启动期 + 登录后调用一次）：
        - 不依赖 Cookie 域，靠流量统计 + 品牌识别
        - 已知关联域已经在 self.extra_scope 中，会被跳过 → 只返回"新增"
        - 命中策略与 infer_extra_scope 一致（★ 924 修复：仅同公司体系晋升，≥3 次不再无差别通行）
        """
        from collections import Counter
        api_domain_count: Counter = Counter()
        # ★ 提取 target 的纯 hostname（不含端口），用于同主机不同端口的判断
        _target_hostname = self.target_domain.split(":")[0] if ":" in self.target_domain else self.target_domain
        for req in captured:
            req_url = req.get("url", "")
            rt = req.get("resource_type", "")
            if not req_url:
                continue
            try:
                d = urlparse(req_url).netloc.lower()
            except Exception:
                continue
            if (not d or d == self.target_domain
                or d.endswith("." + self.target_domain)
                or d in self.extra_scope
                or any(d.endswith("." + sd) for sd in self.extra_scope)):
                continue  # 跳过 target 主域、已知关联域及其子域
            # ★ 同 hostname 不同端口也视为同一主机，不应作为"新关联域"
            # 例如 target=sz-nextpark.com:35351，流量中出现 sz-nextpark.com（443）应跳过
            d_hostname = d.split(":")[0] if ":" in d else d
            if d_hostname == _target_hostname:
                continue
            if self._is_third_party(d):
                continue
            if rt in ("xhr", "fetch") or "/api/" in req_url:
                api_domain_count[d] += 1

        new_scope: set[str] = set()
        # ★ AuthorizedScope 契约统一（924 §4.2）：逃生门模式判定单一来源
        from core.scope_contract import is_extended_mode
        _auto_promote = is_extended_mode()
        for domain, count in api_domain_count.items():
            if count >= 1 and self._shares_brand_with_target(domain):
                # ★ 924 修复：仅同公司体系才晋升；原 "count >= 3 无差别通行" 已删除
                new_scope.add(domain)
            elif count >= 3 and _auto_promote:
                # 逃生门：显式设 XUANJIAN_SCOPE_AUTO_PROMOTE=1 才恢复旧行为
                new_scope.add(domain)
        return new_scope

    def infer_extra_scope(self, captured: list[dict], cookies: list[dict] | None = None) -> set[str]:
        """从爬取流量和 Cookie 自动推断业务关联域名。

        规则（★ 924 复盘收紧：泄漏①修复）：
        1. Cookie 域覆盖：用户提供的 Cookie 里 domain=.xxx.com，且与目标共享品牌词
        2. 低频/高频但同公司体系：≥1 次调用 + 与目标共享 SLD 或租户前缀
        3. ~~高频 API 域无差别晋升~~ 已删除："任何域 API≥3 次即认定为业务关联"
           会把跟链越界资产（如 r.aibank.com → nginx.com → f5.com）整包拉进作用域
           （task_1790219173 案例：729 条 f5.com 流量 → f5.com 晋升 → 31/32 功能点越界）。

        逃生门：设 XUANJIAN_SCOPE_AUTO_PROMOTE=1 可临时恢复旧行为（不推荐）。

        排除：已知第三方黑名单、只有静态资源请求的域、和目标域完全无关的域
        """
        from collections import Counter
        # ★ AuthorizedScope 契约统一（924 §4.2）：逃生门模式判定单一来源
        from core.scope_contract import is_extended_mode
        discovered: set[str] = set()

        # ★ 提取 target 的纯 hostname（不含端口），用于同主机不同端口的判断
        _target_hostname = self.target_domain.split(":")[0] if ":" in self.target_domain else self.target_domain

        # 1. Cookie 域推断（用 _shares_brand_with_target 统一判定）
        for ck in (cookies or []):
            ck_domain = (ck.get("domain") or "").lstrip(".").lower()
            if not ck_domain or ck_domain == self.target_domain:
                continue
            # ★ 同 hostname 不同端口不算关联域
            ck_hostname = ck_domain.split(":")[0] if ":" in ck_domain else ck_domain
            if ck_hostname == _target_hostname:
                continue
            if self._shares_brand_with_target(ck_domain):
                discovered.add(ck_domain)

        # 2. 仅"同公司体系"策略（原"≥3 次 API 无差别晋升"已删除）
        api_domain_count: Counter = Counter()
        rejected_high_freq: list[str] = []
        for req in captured:
            req_url = req.get("url", "")
            resource_type = req.get("resource_type", "")
            if not req_url:
                continue
            try:
                d = urlparse(req_url).netloc.lower()
            except Exception:
                continue
            if not d or d == self.target_domain or d.endswith("." + self.target_domain):
                continue
            # ★ 同 hostname 不同端口也视为同一主机，跳过
            d_hostname = d.split(":")[0] if ":" in d else d
            if d_hostname == _target_hostname:
                continue
            if self._is_third_party(d):
                continue
            # 只统计 API 请求（xhr/fetch）或路径含 /api/
            if resource_type in ("xhr", "fetch") or "/api/" in req_url:
                api_domain_count[d] += 1

        _auto_promote = is_extended_mode()
        for domain, count in api_domain_count.items():
            if count >= 1 and self._shares_brand_with_target(domain):
                # 同公司体系（同 SLD 或同租户前缀）才认定业务关联
                discovered.add(domain)
            elif count >= 3 and _auto_promote:
                # 逃生门：显式设 XUANJIAN_SCOPE_AUTO_PROMOTE=1 才恢复旧的"高频晋升"
                discovered.add(domain)
            elif count >= 3:
                # ★ 高频但非同品牌：记录但不晋升 —— 正是 924 案例的污染入口
                rejected_high_freq.append(f"{domain}({count})")

        if rejected_high_freq:
            self._report(
                f"  🔒 作用域保护: {len(rejected_high_freq)} 个高频非同品牌域未自动晋升"
                f"（如需纳入请在界面上显式授权）: {', '.join(rejected_high_freq[:5])}"
            )

        if discovered:
            self._report(f"  🔗 推断关联域: {', '.join(sorted(discovered))}")

        self.extra_scope.update(discovered)
        return discovered
