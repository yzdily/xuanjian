"""`core/attachments.py` 附件抽取测试（零依赖 docx/xlsx 解析 + 预算 + 安全）。

覆盖三件容易出事的事：
1. **路径穿越防线** —— 前端传来的路径必须落在 `data/uploads/` 内（`../`、URL 编码绕过都要挡）；
2. **OOXML 零依赖抽取** —— docx/xlsx 是 zip + XML，用 stdlib 抽文本；
3. **预算保护** —— 附件文本会拼进 chat message，必须有上限（下游 context.py 有 token 硬拦截）。
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from core import attachments as A


@pytest.fixture()
def upload_root(tmp_path, monkeypatch):
    """把白名单根目录指到临时目录，避免污染真实 data/uploads/。"""
    root = tmp_path / "uploads"
    root.mkdir()
    monkeypatch.setattr(A, "UPLOAD_DIR", root)
    return root


def _make_docx(path: Path, text: str = "Hello 世界 docx") -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("word/document.xml",
                    f"<w:document><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>")
        zf.writestr("[Content_Types].xml", "<Types/>")
    return path


def _make_xlsx(path: Path, text: str = "SheetOne 报表") -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("xl/worksheets/sheet1.xml", f"<root><t>{text}</t></root>")
    return path


# ---------------------------------------------------------------- 安全：路径白名单

@pytest.mark.parametrize("bad", [
    "../../../etc/passwd",
    "..%2F..%2Fetc%2Fpasswd",          # URL 编码绕过
    "data/reports/secret.md",          # 白名单目录之外
    "/etc/hosts",
])
def test_resolve_rejects_paths_outside_uploads(bad, upload_root):
    path, err = A.resolve_upload_path(bad)
    assert path is None, f"{bad!r} 不该被解析为可读路径"
    assert err


def test_resolve_accepts_file_inside_uploads(upload_root):
    f = upload_root / "note.txt"
    f.write_text("hi", encoding="utf-8")
    path, err = A.resolve_upload_path(str(f))
    assert path == f.resolve() and err == ""


def test_resolve_rejects_directory(upload_root):
    path, err = A.resolve_upload_path(str(upload_root))
    assert path is None and "不存在" in err


# ---------------------------------------------------------------- 各类型抽取

def test_extract_txt_and_json(upload_root):
    t = upload_root / "a.txt"
    t.write_text("普通文本", encoding="utf-8")
    info = A.extract_attachment(t)
    assert info["kind"] == "document" and "普通文本" in info["text"]

    j = upload_root / "b.json"
    j.write_text('{"a":1,"b":[2]}', encoding="utf-8")
    info = A.extract_attachment(j)
    assert json.loads(info["text"])["a"] == 1          # 已格式化，仍是合法 JSON


def test_extract_html_strips_tags_and_scripts(upload_root):
    h = upload_root / "c.html"
    h.write_text("<html><head><style>p{}</style><script>evil()</script></head>"
                 "<body><h1>标题</h1><p>正文</p></body></html>", encoding="utf-8")
    info = A.extract_attachment(h)
    assert "标题" in info["text"] and "正文" in info["text"]
    assert "evil" not in info["text"] and "p{}" not in info["text"]


def test_extract_docx_zero_dependency(upload_root):
    d = _make_docx(upload_root / "report.docx", "Spring 配置泄漏")
    info = A.extract_attachment(d)
    assert info["kind"] == "document"
    assert "Spring" in info["text"] and "配置泄漏" in info["text"]


def test_extract_xlsx_zero_dependency(upload_root):
    x = _make_xlsx(upload_root / "data.xlsx", "用户ID 越权")
    info = A.extract_attachment(x)
    assert info["kind"] == "document" and "越权" in info["text"]


def test_legacy_doc_gives_actionable_error(upload_root):
    d = upload_root / "old.doc"
    d.write_bytes(b"\xd0\xcf\x11\xe0 binary junk")
    info = A.extract_attachment(d)
    assert info["kind"] == "unsupported"
    assert "docx" in info["error"]                    # 提示转存，而不是静默空


def test_image_is_not_text_attachment(upload_root):
    p = upload_root / "shot.png"
    p.write_bytes(b"\x89PNG\r\n\x1a\n")
    info = A.extract_attachment(p)
    assert info["kind"] == "image" and "screenshot_paths" in info["error"]


def test_unknown_ext_rejected(upload_root):
    e = upload_root / "evil.exe"
    e.write_bytes(b"MZ")
    info = A.extract_attachment(e)
    assert info["kind"] == "unsupported"


def test_corrupt_docx_degrades(upload_root):
    d = upload_root / "broken.docx"
    d.write_bytes(b"not a zip")
    info = A.extract_attachment(d)
    assert info["kind"] == "document" and info["error"]   # 不抛异常，给原因


# ---------------------------------------------------------------- 预算与汇总

def test_build_block_truncates_and_reports(upload_root):
    big = upload_root / "big.txt"
    big.write_text("A" * (A.MAX_PER_FILE_CHARS + 5000), encoding="utf-8")
    block, meta = A.build_attachment_block([str(big)])
    assert "附件内容结束" in block
    assert meta[0]["truncated"] is True
    assert len(block) < A.MAX_PER_FILE_CHARS + 2000


def test_build_block_enforces_total_budget(upload_root):
    files = []
    for i in range(4):
        f = upload_root / f"p{i}.txt"
        f.write_text("B" * A.MAX_PER_FILE_CHARS, encoding="utf-8")
        files.append(str(f))
    block, meta = A.build_attachment_block(files)
    assert block.count("### 附件：") <= 2                     # 总量 20k 只装得下 1-2 个
    assert any(m.get("error") for m in meta)                  # 被忽略的要有说明


def test_build_block_mixed_and_rejected(upload_root):
    good = upload_root / "ok.txt"
    good.write_text("有效内容", encoding="utf-8")
    block, meta = A.build_attachment_block([str(good), "/etc/hosts", ""])
    assert "有效内容" in block
    kinds = {m.get("kind") for m in meta}
    assert "rejected" in kinds
    assert sum(1 for m in meta if m.get("chars")) == 1


def test_build_block_empty_input(upload_root):
    block, meta = A.build_attachment_block([])
    assert block == "" and meta == []
