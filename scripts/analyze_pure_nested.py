"""精确识别 core/ 内「真正纯」的方法内嵌套 def —— symtable 闭包捕获分析（修正版）。

排除 symtable 把 genexpr / lambda 也算作 Function 符号的噪声；用每个函数**自身**的
get_frees()（非递归）判断它是否捕获了直接父函数的局部变量。

判定：嵌套 def D（父 P 为函数）可安全提升到模块级  iff
    set(D.get_frees()) ∩ set(P.get_locals()) == ∅
  - 捕获模块级全局 / import / builtin 安全（模块级函数仍可见）。
  - 捕获 self 或父函数局部 → 禁止 P2-1 式提升（留 B/C 档）。
  - D 内部的更深层嵌套 def 随 D 一并搬移，不单独处理。

输出 JSON：file / lineno / name / parent_func / free_vars / captured_locals / hoistable。
"""
import os, json, sys, symtable

ROOT = "core"
SKIP = {"__pycache__", "venv", ".venv"}
NOISE = {"genexpr", "lambda"}  # 非真实 def，不计入可提升

def iter_py(root):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(dirpath, f)

def analyze(path):
    try:
        src = open(path, encoding="utf-8").read()
        mod = symtable.symtable(src, path, "exec")
    except Exception as e:
        return [{"file": path, "_error": str(e)[:120]}]
    res = []
    def walk(st, parent):
        if isinstance(st, symtable.Function) and st.get_name() not in NOISE:
            if parent is not None and isinstance(parent, symtable.Function):
                free = set(st.get_frees())
                encl = set(parent.get_locals())
                captured = sorted(free & encl)
                res.append({
                    "file": path,
                    "name": st.get_name(),
                    "parent_func": parent.get_name(),
                    "free_vars": sorted(free),
                    "captured_locals": captured,
                    "hoistable": len(captured) == 0,
                })
            for ch in st.get_children():
                walk(ch, st)
        else:
            for ch in st.get_children():
                walk(ch, st)
    walk(mod, None)
    return res

def _lineno_of(path, name, after_func):
    """粗定位：返回文件内名为 name 的 def 行号（best-effort）。"""
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except Exception:
        return None
    for i, ln in enumerate(lines, 1):
        if f"def {name}" in ln or f"async def {name}" in ln:
            return i
    return None

def main():
    all_hits = []
    for p in iter_py(ROOT):
        all_hits.extend(analyze(p))
    # 补全 lineno（浅层）
    seen = {}
    for h in all_hits:
        if "_error" in h:
            continue
        key = (h["file"], h["parent_func"], h["name"])
        if key not in seen:
            seen[key] = _lineno_of(h["file"], h["name"], h["parent_func"])
        h["lineno"] = seen[key]
    if "--json" in sys.argv:
        json.dump(all_hits, sys.stdout, ensure_ascii=False)
        return
    pure = [h for h in all_hits if "_error" not in h and h["hoistable"]]
    impure = [h for h in all_hits if "_error" not in h and not h["hoistable"]]
    print(f"TOTAL real nested defs (excl genexpr/lambda): {len([h for h in all_hits if '_error' not in h])}")
    print(f"  HOISTABLE (pure, no local capture): {len(pure)}")
    print(f"  NOT hoistable (captures local/self): {len(impure)}")
    from collections import Counter
    c = Counter(h["file"] for h in pure)
    print("\nPer-file hoistable counts (>=1):")
    for f, n in sorted(c.items(), key=lambda x: (-x[1], x[0])):
        print(f"  {n:>2}  {f}")

if __name__ == "__main__":
    main()
