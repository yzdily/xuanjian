() => {
                    // 通用遮挡检测：取侧边栏/菜单区域的中心点，检查是否被其他元素遮盖
                    const navContainers = document.querySelectorAll(
                        'nav, aside, [role="navigation"], .sidebar, .side-bar, ' +
                        '.menu, .nav, #sidebar, #nav, #menu, ' +
                        '[class*="sidebar"], [class*="side-bar"], [class*="menu"], [class*="nav-"]'
                    );
                    for (const nav of navContainers) {
                        if (nav.offsetParent === null || nav.children.length === 0) continue;
                        const rect = nav.getBoundingClientRect();
                        if (rect.width < 30 || rect.height < 30) continue;
                        // 检查导航区域中心点是否被遮挡
                        const cx = rect.left + rect.width / 2;
                        const cy = rect.top + rect.height / 2;
                        const topEl = document.elementFromPoint(cx, cy);
                        if (topEl && topEl !== nav && !nav.contains(topEl)) {
                            // 导航区域被其他元素遮挡了
                            // 尝试找遮挡元素（高 z-index 的遮罩层/弹窗）
                            let overlay = topEl;
                            // 向上找到最顶层的遮罩容器
                            for (let i = 0; i < 5; i++) {
                                if (overlay.parentElement && overlay.parentElement !== document.body) {
                                    const parentRect = overlay.parentElement.getBoundingClientRect();
                                    // 父元素几乎覆盖全屏 → 这就是遮罩容器
                                    if (parentRect.width > window.innerWidth * 0.5 &&
                                        parentRect.height > window.innerHeight * 0.3) {
                                        overlay = overlay.parentElement;
                                        continue;
                                    }
                                }
                                break;
                            }
                            // 提取遮挡元素信息
                            const overlayRect = overlay.getBoundingClientRect();
                            const inputs = Array.from(overlay.querySelectorAll(
                                'input:not([type="hidden"]), textarea, select'
                            )).map(e => ({
                                type: e.type || e.tagName.toLowerCase(),
                                name: e.name || '',
                                placeholder: e.placeholder || '',
                                required: e.required || false,
                            }));
                            const buttons = Array.from(overlay.querySelectorAll(
                                'button, [role="button"], .el-button, .ant-btn'
                            )).map(b => ({
                                text: (b.textContent || '').trim().slice(0, 30),
                                type: b.type || '',
                            })).filter(b => b.text);
                            const links = Array.from(overlay.querySelectorAll('a[href]'))
                                .map(a => a.href)
                                .filter(h => h && !h.startsWith('javascript:'));
                            const title = (overlay.querySelector(
                                '.el-dialog__title, .ant-modal-title, .modal-title, ' +
                                'h1, h2, h3, [class*="title"], [class*="header"]'
                            )?.textContent || '').trim().slice(0, 60);
                            // 检测关闭按钮
                            const closeSelectors = [
                                '.el-dialog__close', '.ant-modal-close',
                                '.el-drawer__close-btn', '.ant-drawer-close',
                                '.modal-header .close', '[aria-label="Close"]',
                                '[aria-label="关闭"]', '.layui-layer-close',
                                '[class*="close"]', '[class*="Close"]',
                                'button[class*="cancel"]',
                            ];
                            let closeButton = null;
                            for (const sel of closeSelectors) {
                                const btn = overlay.querySelector(sel);
                                if (btn) { closeButton = sel; break; }
                            }
                            // 检测是否可以点击遮罩空白区关闭（遮罩覆盖导航区但弹窗在中间）
                            const isBackdrop = overlayRect.width > window.innerWidth * 0.7 &&
                                               overlayRect.height > window.innerHeight * 0.5;
                            return {
                                blocked: true,
                                title: title,
                                selector: overlay.tagName.toLowerCase() +
                                    (overlay.className ? '.' + overlay.className.split(' ')[0] : ''),
                                inputs: inputs.slice(0, 30),
                                buttons: buttons.slice(0, 20),
                                links: links.slice(0, 20),
                                closeButton: closeButton,
                                isBackdrop: isBackdrop,
                                overlayRect: {
                                    x: overlayRect.x, y: overlayRect.y,
                                    w: overlayRect.width, h: overlayRect.height
                                },
                            };
                        }
                    }
                    return { blocked: false };
                }
