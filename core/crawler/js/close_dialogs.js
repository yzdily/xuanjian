() => {
                        const dialogSelectors = [
                            '.el-dialog__wrapper:not([style*="display: none"]) .el-dialog',
                            '.el-drawer__wrapper:not([style*="display: none"]) .el-drawer',
                            '.ant-modal-wrap:not([style*="display: none"]) .ant-modal',
                            '.ant-drawer-open .ant-drawer',
                            '.modal.show, .modal[style*="display: block"]',
                            'dialog[open]',
                            '[role="dialog"]:not([aria-hidden="true"])',
                            '.v-dialog--active',
                            '.layui-layer',
                        ];
                        for (const sel of dialogSelectors) {
                            const dlg = document.querySelector(sel);
                            if (dlg) {
                                const rect = dlg.getBoundingClientRect();
                                if (rect.width < 50 || rect.height < 50) continue;
                                // 提取弹窗内的可交互元素
                                const inputs = Array.from(dlg.querySelectorAll('input:not([type="hidden"]), textarea, select'))
                                    .map(e => ({
                                        type: e.type || e.tagName.toLowerCase(),
                                        name: e.name || '',
                                        placeholder: e.placeholder || '',
                                        required: e.required || false,
                                    }));
                                const buttons = Array.from(dlg.querySelectorAll('button, [role="button"], .el-button, .ant-btn'))
                                    .map(b => ({
                                        text: (b.textContent || '').trim().slice(0, 30),
                                        type: b.type || '',
                                    }))
                                    .filter(b => b.text);
                                const links = Array.from(dlg.querySelectorAll('a[href]'))
                                    .map(a => a.href)
                                    .filter(h => h && !h.startsWith('javascript:'));
                                const title = (dlg.querySelector('.el-dialog__title, .ant-modal-title, .modal-title, h1, h2')?.textContent || '').trim();
                                return {
                                    title: title,
                                    selector: sel,
                                    inputs: inputs.slice(0, 30),
                                    buttons: buttons.slice(0, 20),
                                    links: links.slice(0, 20),
                                };
                            }
                        }
                        return null;
                    }
