"""阶段 2 端到端：上传附件 → 抽取 → 可拼进 chat message 的完整闭环。

这条链路横跨三个模块（upload_api → attachments → server.chat），且**其中任意一环
断开都不会报错、只会静默失效**（上传成功但内容没进上下文），所以必须端到端测。

覆盖：
1. 图片 + 文档混合上传后，各自的 `channel` 正确（图片走视觉通道，不进文本块）；
2. 文档抽取内容真的出现在最终的上下文块里（不是"上传成功但内容丢失"）；
3. 越权路径（`data/uploads/../…`）被拒 —— 前端传路径属于不可信输入。
"""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core import attachments as A
from web.api import upload_api


@pytest.fixture()
def wired(tmp_path, monkeypatch):
    """让上传端点与抽取器使用同一个临时上传目录。"""
    root = tmp_path / "uploads"
    root.mkdir()
    monkeypatch.setattr(upload_api, "UPLOAD_DIR", root)
    monkeypatch.setattr(A, "UPLOAD_DIR", root)
    app = FastAPI()
    app.include_router(upload_api.router)
    return TestClient(app), root


def _docx(text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", f"<w:document><w:t>{text}</w:t></w:document>")
    return buf.getvalue()


def test_upload_then_extract_end_to_end(wired):
    client, root = wired
    res = client.post("/api/upload/attachment", files=[
        ("file", ("配置说明.docx", _docx("spring.datasource.password 明文存储"), "application/octet-stream")),
        ("file", ("shot.png", b"\x89PNG\r\n\x1a\n" + b"0" * 32, "image/png")),
    ])
    files = res.json()["files"]
    assert len(files) == 2

    doc = next(f for f in files if f["channel"] == "file_paths")
    img = next(f for f in files if f["channel"] == "screenshot_paths")

    # ① 只有文档进文本上下文；图片明确走视觉通道
    block, meta = A.build_attachment_block([doc["path"]])
    assert "spring.datasource.password" in block
    assert "【用户上传的附件内容】" in block and "【附件内容结束】" in block
    assert meta[0]["kind"] == "document" and meta[0]["chars"] > 0

    # ② 把图片也丢进来 → 不进 block，但有可解释原因（前端已按 channel 分派）
    block2, meta2 = A.build_attachment_block([doc["path"], img["path"]])
    assert block2.count("### 附件：") == 1
    assert any(m.get("kind") == "image" and m.get("error") for m in meta2)

    # ③ 落盘都在上传目录内
    for f in files:
        assert root in Path(f["path"]).parents


def test_escaped_path_rejected_at_extraction(wired):
    """即便前端被篡改传来越权路径，抽取层也必须挡住。"""
    client, root = wired
    (root.parent / "reports").mkdir(exist_ok=True)
    outside = root.parent / "reports" / "leak.md"
    outside.write_text("sensitive", encoding="utf-8")

    block, meta = A.build_attachment_block([str(outside)])
    assert block == ""
    assert meta[0]["kind"] == "rejected"
    assert "上传目录" in meta[0]["error"]


def test_rejected_file_does_not_silently_disappear(wired):
    """不支持的类型必须回显原因 —— 用户不能"上传了但什么都没发生"。"""
    client, _ = wired
    res = client.post("/api/upload/attachment",
                      files={"file": ("payload.exe", b"MZ", "application/octet-stream")})
    body = res.json()
    assert body["files"] == []
    assert body["rejected"][0]["filename"] == "payload.exe"
    assert "allowed" in body["rejected"][0]        # 顺带告诉用户支持什么
