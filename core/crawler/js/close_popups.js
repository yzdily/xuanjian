() => {
                                const closeSelectors = [
                                    '.el-dialog__close', '.ant-modal-close',
                                    '.el-drawer__close-btn', '.ant-drawer-close',
                                    '.modal-header .close', '[aria-label="Close"]',
                                    '[aria-label="关闭"]', '.layui-layer-close',
                                ];
                                for (const sel of closeSelectors) {
                                    const btn = document.querySelector(sel);
                                    if (btn) { btn.click(); return true; }
                                }
                                return false;
                            }
