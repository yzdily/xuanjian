"""`/api/upload/attachment` 上传端点测试（阶段 2 · 断线能力接线）。

关注点：
1. 白名单（用户 0919 指定）：json/txt/word/html/burp/xlsx/excel + 图片；
2. **通道分派**：图片 → `screenshot_paths`，文档 → `file_paths`（前端据此组装 chat payload）；
3. **文件名净化**：`../../evil.txt` 不能落出 `data/uploads/`；
4. 空文件 / 超大 / 非法类型一律**显式拒绝并给原因**（不静默丢弃）。
"""
from __future__ import annotations

import io
import zipfile

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from web.api import upload_api


@pytest.fixture()
def client(tmp_path, monkeypatch):
    root = tmp_path / "uploads"
    root.mkdir()
    monkeypatch.setattr(upload_api, "UPLOAD_DIR", root)
    app = FastAPI()
    app.include_router(upload_api.router)
    c = TestClient(app)
    c._upload_root = root              # 便于断言落盘位置
    return c


def _docx_bytes(text: str = "配置泄漏") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", f"<w:document><w:t>{text}</w:t></w:document>")
    return buf.getvalue()


def test_upload_document_goes_to_file_paths_channel(client):
    res = client.post("/api/upload/attachment",
                      files={"file": ("报告.docx", _docx_bytes(), "application/octet-stream")})
    assert res.status_code == 200
    body = res.json()
    assert len(body["files"]) == 1 and not body["rejected"]
    f = body["files"][0]
    assert f["kind"] == "document" and f["channel"] == "file_paths"
    assert f["ext"] == ".docx"
    # 落盘必须在上传目录内，且中文名被保留
    assert client._upload_root in __import__("pathlib").Path(f["path"]).parents
    assert "报告" in f["filename"]


def test_upload_image_goes_to_screenshot_channel(client):
    png = b"\x89PNG\r\n\x1a\n" + b"0" * 64
    res = client.post("/api/upload/attachment",
                      files={"file": ("shot.png", png, "image/png")})
    f = res.json()["files"][0]
    assert f["kind"] == "image" and f["channel"] == "screenshot_paths"


def test_upload_accepts_json_txt_html_burp_xlsx(client):
    cases = [("a.json", b'{"k":1}'), ("b.txt", b"hello"),
             ("c.html", b"<p>x</p>"), ("d.burp", b"<items/>"),
             ("e.xlsx", _docx_bytes())]
    for name, data in cases:
        res = client.post("/api/upload/attachment",
                          files={"file": (name, data, "application/octet-stream")})
        assert res.status_code == 200, name
        assert res.json()["files"], f"{name} 应被接受"


@pytest.mark.parametrize("name", ["evil.exe", "shell.sh", "a.js", "noext"])
def test_reject_disallowed_extensions(client, name):
    res = client.post("/api/upload/attachment",
                      files={"file": (name, b"x", "application/octet-stream")})
    body = res.json()
    assert body["files"] == []
    assert body["rejected"] and "不支持的文件类型" in body["rejected"][0]["reason"]


def test_path_traversal_in_filename_is_neutralized(client):
    res = client.post("/api/upload/attachment",
                      files={"file": ("../../../etc/passwd.txt", b"root:x:0", "text/plain")})
    f = res.json()["files"][0]
    # 落盘路径必须仍在上传目录内
    assert client._upload_root in __import__("pathlib").Path(f["path"]).parents
    assert ".." not in f["filename"]


def test_empty_file_rejected(client):
    res = client.post("/api/upload/attachment",
                      files={"file": ("empty.txt", b"", "text/plain")})
    assert res.json()["files"] == []
    assert "为空" in res.json()["rejected"][0]["reason"]


def test_oversize_file_rejected(client, monkeypatch):
    monkeypatch.setattr(upload_api, "MAX_UPLOAD_BYTES", 1024)
    res = client.post("/api/upload/attachment",
                      files={"file": ("big.txt", b"A" * 4096, "text/plain")})
    body = res.json()
    assert body["files"] == [] and "10MB" in body["rejected"][0]["reason"]


def test_multi_file_partial_acceptance(client):
    res = client.post("/api/upload/attachment", files=[
        ("file", ("ok.txt", b"fine", "text/plain")),
        ("file", ("bad.exe", b"MZ", "application/octet-stream")),
    ])
    body = res.json()
    assert len(body["files"]) == 1 and len(body["rejected"]) == 1


def test_missing_file_field(client):
    res = client.post("/api/upload/attachment", data={"x": "1"})
    assert res.status_code == 400


def test_allowed_types_endpoint_matches_whitelist(client):
    body = client.get("/api/upload/allowed").json()
    assert ".docx" in body["allowed"] and ".xlsx" in body["allowed"]
    assert ".json" in body["allowed"] and ".burp" in body["allowed"]
    assert ".png" in body["image"] and ".png" not in body["document"]
    assert body["max_mb"] == 10
