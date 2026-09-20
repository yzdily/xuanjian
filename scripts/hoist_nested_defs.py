"""工厂化提升 A 档纯嵌套 def 到模块级（行为保持）。

策略（零风险 P2-1 同款）：
1. 复用 analyze_pure_nested 的 symtable 纯度判定，取 hoistable 集合。
2. 去重：若某 def 的父函数也是 hoistable（如 _canon_type 父是 _dedupe_verdicts），
   则跳过它——提升父函数时会整体带走其内部嵌套 def。
3. 对每个 outer hoistable：
   - 按缩进切出整个 def 块（含其内部更深层嵌套）。
   - 整体去缩进 `parent_indent` 格 → 模块级（0 缩进）。
   - 从原位置删除，追加到文件末尾（带 `# hoisted from <parent>` 注释）。
   - 调用点不变（名字解析回退到模块全局，行为一致）。
4. 安全检查：模块级已存在同名 → 跳过；父函数体内对该名有赋值（会遮蔽）→ 跳过。

--dry 仅预览，不落盘。
"""
import os, re, sys, json
from analyze_pure_nested import analyze, ROOT, SKIP

def module_level_def_names(src):
    return set(re.findall(r'^(?:async def|def)\s+(\w+)', src, re.M))

def parent_reassigns(src, file, parent_func, name):
    """粗判：父函数体内是否有 `name =` 赋值（会遮蔽模块级同名）。"""
    lines = src.splitlines()
    # 找父函数起始行
    start = None
    for i, ln in enumerate(lines):
        if re.search(r'(?:async def|def)\s+' + re.escape(parent_func) + r'\b', ln):
            start = i; break
    if start is None:
        return False
    # 父函数缩进
    pind = len(lines[start]) - len(lines[start].lstrip())
    # 扫描父函数体
    for ln in lines[start+1:]:
        if ln.strip() == "":
            continue
        cind = len(ln) - len(ln.lstrip())
        if cind <= pind:
            break  # 离开父函数
        if re.search(r'\b' + re.escape(name) + r'\s*=[^=]', ln):
            return True
    return False

def extract_block(lines, start_idx, indent):
    block = [lines[start_idx]]
    i = start_idx + 1
    while i < len(lines):
        ln = lines[i]
        if ln.strip() == "":
            block.append(ln); i += 1; continue
        cind = len(ln) - len(ln.lstrip())
        if cind > indent:
            block.append(ln); i += 1; continue
        break
    # 去掉尾部空行
    while block and block[-1].strip() == "":
        block.pop()
    return block, i

def hoist_file(path, entries, dry):
    """entries: list of (name, parent_func, lineno_str). 返回 (changed_bool, note)."""
    src = open(path, encoding="utf-8").read()
    lines = src.splitlines()
    if not lines or lines[-1] != "":
        lines.append("")  # 保证末尾有换行
    mod_defs = module_level_def_names(src)
    actions = []
    for (name, parent, _) in entries:
        if name in mod_defs:
            actions.append(f"SKIP {name}: 模块级已存在同名")
            continue
        if parent_reassigns(src, path, parent, name):
            actions.append(f"SKIP {name}: 父函数 {parent} 体内有 `{name} =` 赋值，会遮蔽")
            continue
        # 定位 def 行
        found = None
        for i, ln in enumerate(lines):
            if re.search(r'(?:async def|def)\s+' + re.escape(name) + r'\b', ln):
                # 确认它属于 parent（在 parent 之后且缩进更深）
                found = i; break
        if found is None:
            actions.append(f"SKIP {name}: 未找到 def 行")
            continue
        ind = len(lines[found]) - len(lines[found].lstrip())
        block, after = extract_block(lines, found, ind)
        # 去缩进 ind 格
        dedented = []
        for ln in block:
            if ln.strip() == "":
                dedented.append(ln)
            else:
                dedented.append(ln[ind:] if ln.startswith(" " * ind) else ln)
        # 从原位置删除
        del lines[found:after]
        # 追加到末尾
        lines.append(f"# --- hoisted from {parent} (A-grade, no local capture) ---")
        lines.extend(dedented)
        lines.append("")
        actions.append(f"HOIST {name} (was L{found+1}, parent={parent})")
    if dry:
        return False, actions
    new_src = "\n".join(lines)
    open(path, "w", encoding="utf-8").write(new_src)
    return True, actions

def main():
    dry = "--dry" in sys.argv
    all_hits = {}
    for p in _iter_py():
        for h in analyze(p):
            if "_error" in h:
                continue
            all_hits.setdefault(p, []).append(h)
    # 取 hoistable 集合（按 file+name）
    hoistable = {}
    for p, hs in all_hits.items():
        for h in hs:
            if h["hoistable"]:
                hoistable.setdefault(p, {})[h["name"]] = h
    # 去重：父函数也是 hoistable 的跳过
    plan = {}  # file -> list of (name, parent)
    for p, names in hoistable.items():
        for name, h in names.items():
            parent = h["parent_func"]
            if parent in names:  # 父也在 hoistable → 随父带走
                continue
            plan.setdefault(p, []).append((name, parent, h.get("lineno")))
    total = sum(len(v) for v in plan.values())
    print(f"[DRY={dry}] 计划提升 {total} 个 outer A 档嵌套 def，跨 {len(plan)} 文件")
    for p, entries in sorted(plan.items()):
        print(f"\n## {p}  ({len(entries)}个)")
        changed, acts = hoist_file(p, entries, dry)
        for a in acts:
            print("   ", a)
    if not dry:
        print("\n已落盘。请运行：py_compile + import + 测试验证。")

def _iter_py():
    for dirpath, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(dirpath, f)

if __name__ == "__main__":
    main()
