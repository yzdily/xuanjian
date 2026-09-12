"""scripts/update_knowledge.py — 知识库月增量更新（中期 M4 配套）。

按 XUANJIAN_ROADMAP_MID_TERM §5.3 Step 4 落地。
- 先 backup_current() 把现有 data/knowledge 备份到 .backups/{YYYYMM}/
- 再 update_owasp() 拉 OWASP 官网 Top 10（断网 fallback 到内置 SNAPSHOT）
- rotate_backups(keep=12) 只保留最近 12 个月

零外部依赖（urllib + regex）。
"""
from __future__ import annotations

import datetime
import pathlib
import re
import shutil
import urllib.error
import urllib.request

ROOT = pathlib.Path("data/knowledge")
BACKUP = pathlib.Path("data/knowledge/.backups")

# 2024 快照（断网 fallback）
SNAPSHOT: dict[str, str] = {
    "A01": "Broken Access Control：访问控制缺陷，含 IDOR / 越权 / 路径遍历。",
    "A02": "Cryptographic Failures：加密失效。",
    "A03": "Injection：注入类（SQLi / XSS / SSTI / 命令注入）。",
    "A04": "Insecure Design：不安全设计。",
    "A05": "Security Misconfiguration：配置错误。",
    "A06": "Vulnerable Components：组件漏洞。",
    "A07": "Authentication Failures：认证失败。",
    "A08": "Software & Data Integrity：完整性失效。",
    "A09": "Logging Failures：日志不足。",
    "A10": "SSRF：服务端请求伪造。",
}


def backup_current() -> pathlib.Path | None:
    """更新前先备份当前知识库。返回备份目录路径。"""
    if not ROOT.exists():
        return None
    BACKUP.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m")
    dest = BACKUP / ts
    if dest.exists():
        return dest  # 同月不重复备份
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(".backups"))
    return dest


def fetch_owasp_top10() -> dict[str, str]:
    """从 OWASP 官网快照 Top 10（无外网时用内置 SNAPSHOT）。"""
    try:
        req = urllib.request.Request(
            "https://owasp.org/Top10/",
            headers={"User-Agent": "xuanjian/1.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            html = r.read().decode("utf-8", errors="ignore")[:50000]
        out: dict[str, str] = {}
        for m in re.finditer(r'<h2[^>]*id="(A\d{2})"[^>]*>(.*?)</h2>', html, re.DOTALL):
            out[m.group(1)] = re.sub(r"<[^>]+>", "", m.group(2)).strip()[:200]
        return out if out else SNAPSHOT
    except (urllib.error.URLError, TimeoutError, OSError):
        return SNAPSHOT


def update_owasp() -> list[str]:
    """增量更新：仅写差异项。返回变更项列表。"""
    fresh = fetch_owasp_top10()
    changed: list[str] = []
    for k, v in fresh.items():
        p = ROOT / "owasp" / f"{k}.md"
        old = p.read_text(encoding="utf-8") if p.exists() else ""
        new_body = f"# {k}\n\n{v}\n\n修复建议请参考本地 remediation/ 模板。\n"
        if new_body.strip() != old.strip():
            p.write_text(new_body, encoding="utf-8")
            changed.append(k)
    return changed


def rotate_backups(keep: int = 12) -> list[str]:
    """仅保留最近 N 个月备份。返回被删除的目录名列表。"""
    if not BACKUP.exists():
        return []
    dirs = sorted([d for d in BACKUP.iterdir() if d.is_dir()], key=lambda d: d.name)
    removed: list[str] = []
    for d in dirs[:-keep] if len(dirs) > keep else []:
        shutil.rmtree(d)
        removed.append(d.name)
    return removed


if __name__ == "__main__":
    import json

    bk = backup_current()
    changed = update_owasp()
    removed = rotate_backups()
    out = {
        "backup": str(bk) if bk else None,
        "updated": changed,
        "rotated_old": removed,
        "ts": datetime.datetime.now().isoformat(),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
