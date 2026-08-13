"""fast_scanner YAML 规则加载（从原 fast_scanner.py 机械拆分，内容逐字保留）。"""

from __future__ import annotations

from pathlib import Path

from core.log import get_logger

log = get_logger("fast_scanner")


# ============================================================
# 从 YAML 规则文件加载
# ============================================================

def load_rules_from_yaml(rules_dir: str = "rules") -> list[dict]:
    """从 rules/ 目录加载 YAML 格式的规则文件。

    ★ 已激活使用：FastScanner 初始化时会调用此函数加载 YAML 规则，
      并与硬编码规则合并，实现规则的热更新和扩展。

    规则格式：
        name: SQL注入检测
        type: sql_injection
        severity: critical
        match:
          - pattern: "SQL syntax.*MySQL"
            in: body
          - pattern: "ORA-\\d{5}"
            in: body
        payloads:
          - "'"
          - "' OR '1'='1"

    支持的规则类型：
        - sql_injection: SQL 注入 payloads
        - xss: XSS 检测 probes
        - info_disclosure: 敏感路径列表
        - unauthorized: 未授权访问路径
        - weak_password: 弱口令凭据列表
    """
    rules = []
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        return rules

    try:
        import yaml
    except ImportError:
        log.warning("PyYAML 未安装，跳过 YAML 规则加载")
        return rules

    for yml_file in rules_path.glob("*.yaml"):
        try:
            data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                rules.extend(data)
            elif isinstance(data, dict):
                rules.append(data)
        except Exception as e:
            log.warning("加载规则文件 %s 失败: %s", yml_file, e)

    log.info("从 %s 加载了 %d 条规则", rules_dir, len(rules))
    return rules
