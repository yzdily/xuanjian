() => {
                    const result = [];
                    const existingTexts = new Set();
                    // 收集已识别的菜单项文本，避免重复
                    document.querySelectorAll('[data-crawl-idx]').forEach(el => {
                        const t = (el.textContent || '').trim().slice(0, 50);
                        if (t) existingTexts.add(t);
                    });

                    // 策略1：查找页面侧边栏/顶部区域中的短文本可点击元素
                    // 这些元素通常是导航菜单但使用了自定义组件
                    const candidates = [];
                    document.querySelectorAll('div, span, li, a, p').forEach(el => {
                        const text = (el.textContent || '').trim();
                        // 菜单项特征：短文本（2-15字符）、无子元素或子元素很少、可见
                        if (!text || text.length < 2 || text.length > 15) return;
                        // 排除包含换行的（说明是容器而非叶子节点）
                        if (text.includes('\\n') && text.split('\\n').filter(s => s.trim()).length > 1) return;
                        // 排除已识别的
                        if (existingTexts.has(text)) return;
                        // 排除不可见元素
                        const rect = el.getBoundingClientRect();
                        if (rect.width <= 0 || rect.height <= 0) return;
                        const style = window.getComputedStyle(el);
                        if (style.display === 'none' || style.visibility === 'hidden') return;
                        if (parseFloat(style.opacity) === 0) return;
                        // 排除有太多子元素的容器（不是叶子节点）
                        if (el.querySelectorAll('div, span, li, a, p').length > 3) return;
                        // 排除纯数字/符号
                        if (/^[^a-zA-Z\\u4e00-\\u9fff]+$/.test(text)) return;
                        // 排除 CSS/SVG 垃圾
                        if (/[{}]/.test(text)) return;
                        candidates.push({
                            el: el, text: text,
                            rect: rect, tag: el.tagName.toLowerCase(),
                        });
                    });

                    if (candidates.length < 3) return result;

                    // 策略2：找到"成群出现"的短文本元素（同一父容器下多个相似元素）
                    // 这是导航菜单的典型特征
                    const parentGroups = new Map();
                    candidates.forEach(c => {
                        const parent = c.el.parentElement;
                        if (!parent) return;
                        // 用父元素的 DOM 路径作为分组 key
                        const key = parent.tagName + '#' + (parent.id || '') + '.' + (parent.className || '').toString().slice(0, 50);
                        if (!parentGroups.has(key)) parentGroups.set(key, []);
                        parentGroups.get(key).push(c);
                    });

                    // 找到包含 ≥3 个候选项的父容器组（很可能是导航菜单）
                    let bestGroup = null;
                    let bestSize = 0;
                    for (const [key, group] of parentGroups) {
                        if (group.length >= 3 && group.length > bestSize) {
                            bestGroup = group;
                            bestSize = group.length;
                        }
                    }

                    if (!bestGroup || bestGroup.length < 3) return result;

                    // 为这些元素生成选择器并标记
                    let fallbackIdx = 9000;  // 用高索引避免与已有的冲突
                    bestGroup.forEach(c => {
                        c.el.setAttribute('data-crawl-idx', String(fallbackIdx));
                        result.push({
                            tag: c.tag, text: c.text,
                            type: '', id: c.el.id || '',
                            selector: c.el.id ? '#' + c.el.id : '[data-crawl-idx="' + fallbackIdx + '"]',
                            isMenu: true,
                            isFallback: true,
                        });
                        fallbackIdx++;
                    });
                    return result;
                }
