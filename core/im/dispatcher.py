"""core.im.dispatcher — IM 入口 ↔ 启动器 ↔ 报告回传（中期 M3）。

按 XUANJIAN_ROADMAP_MID_TERM §4.3 Step 3 落地（精简版）。

行为：
- handle_message(connector_name, raw_msg) 解析 → 异步触发 cli.main run
- 不用真的起线程：返回 plan dict（同步），由调用方决定何时执行
- 真实运行由 cli.main 跑；这里只做协议层

零外部依赖。
"""
from __future__ import annotations

import os
import sys
import threading
from typing import Any

from core.im.base import IMConnector


class IMDispatcher:
    """IM 消息 → cli.main run 调度。"""

    def __init__(self, connectors: list[IMConnector]):
        self.connectors = {c.name: c for c in connectors}

    def handle_message(self, connector_name: str, raw_msg: dict) -> dict:
        """处理一条 IM 消息。返回 plan 或 {"ignored": ...}。"""
        if os.environ.get("XUANJIAN_IM_DISABLED") == "1":
            return {"ignored": "XUANJIAN_IM_DISABLED=1"}

        c = self.connectors.get(connector_name)
        if not c:
            return {"ignored": f"unknown connector: {connector_name}"}

        cmd = c.parse_command(raw_msg)
        if not cmd or cmd.get("cmd") != "scan":
            return {"ignored": "not a /scan command"}

        args = cmd["args"]
        url = args.get("url")
        if not url:
            c.send(
                raw_msg.get("sender", "?"),
                "用法: /scan url=... mode=fast|standard|deep [tenant=...]",
            )
            return {"error": "missing url"}

        mode = args.get("mode", "standard")
        if mode not in ("fast", "standard", "deep"):
            mode = "standard"
        tenant = args.get("tenant") or os.environ.get("XUANJIAN_TENANT", "default")

        plan = {
            "argv": ["xuanjian", "run", "--url", url, "--mode", mode, "--tenant", tenant],
            "url": url,
            "mode": mode,
            "tenant": tenant,
            "sender": raw_msg.get("sender"),
            "connector": connector_name,
        }

        # 异步起扫描（daemon 线程，不阻塞 dispatcher）
        t = threading.Thread(
            target=self._run_scan,
            args=(connector_name, plan),
            daemon=True,
        )
        t.start()
        plan["thread"] = t.name
        return plan

    def _run_scan(self, connector_name: str, plan: dict) -> None:
        """在子线程里跑 cli.main run，回传报告链接。"""
        c = self.connectors.get(connector_name)
        if not c:
            return
        try:
            old_argv = sys.argv
            sys.argv = plan["argv"]
            from cli.main import main as cli_main  # 延迟 import 避循环

            cli_main()
            # 真实报告回传（精简版：给个固定提示，cli.main 内部已落 report.html）
            c.send(
                plan.get("sender", "?"),
                f"扫描完成：tenant={plan['tenant']} 报告请查 data/tenants/{plan['tenant']}/output/report.html",
            )
        except SystemExit:
            pass
        except Exception as e:  # pragma: no cover
            c.send(plan.get("sender", "?"), f"扫描失败: {str(e)[:200]}")
        finally:
            sys.argv = old_argv


__all__ = ["IMDispatcher"]
