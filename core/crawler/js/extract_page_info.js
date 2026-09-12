() => {
            const result = {links: [], forms: [], clickables: [], menus: []};

            document.querySelectorAll('a[href]').forEach(a => {
                if (a.href && a.href.startsWith('http')) result.links.push(a.href);
            });
            result.links = [...new Set(result.links)];

            document.querySelectorAll('form').forEach((f, i) => {
                result.forms.push({
                    action: f.action, method: (f.method || 'GET').toUpperCase(),
                    inputs: Array.from(f.elements).map(e => ({
                        tag: e.tagName.toLowerCase(), type: e.type || '', name: e.name || '',
                        id: e.id || '', placeholder: e.placeholder || '', required: e.required,
                    })).filter(e => e.name),
                    selector: f.id ? `#${f.id}` : `form:nth-of-type(${i+1})`,
                });
            });

            // 全量可点击元素（不限数量）
            // 补充更多 UI 框架的可点击元素选择器
            const sels = 'button, input[type=submit], input[type=button], [role=button], [onclick], [role=tab], .nav-link, .menu-item, [data-toggle], [aria-haspopup], [role=menuitem], .el-menu-item, .ant-menu-item, .sidebar-item, .nav-item a, .el-submenu__title, .ant-menu-submenu-title, .MuiListItem-root, .MuiMenuItem-root, .MuiButton-root, .v-list-item, .v-btn, .n-menu-item, .arco-menu-item, .t-menu__item, .ivu-menu-item, [class*="menu-item"], [class*="nav-item"], [data-menu-item]';
            // 导航容器判断：覆盖主流框架 + Web Component + 通用属性特征
            const NAV_CTX = 'nav, [role=navigation], .sidebar, .el-menu, .ant-menu, .nav-menu, ' +
                '.ant-layout-sider, .el-aside, ' +
                // Web Component 自定义导航（Freshworks/各类 SaaS）
                '[class*="sidebar"], [class*="nav-"], [class*="-nav"], [id*="sidebar"], [id*="nav-menu"], ' +
                '[class*="NavigationMenu"], [class*="SideNav"], [class*="AppNav"], ' +
                // 更多 UI 框架
                // Material UI / MUI
                '.MuiDrawer-root, .MuiList-root, [class*="MuiNav"], [class*="MuiDrawer"], ' +
                // Chakra UI
                '[class*="chakra-sidebar"], [class*="chakra-nav"], ' +
                // Vuetify
                '.v-navigation-drawer, .v-list, [class*="v-navigation"], ' +
                // Naive UI / Arco Design
                '.n-menu, .n-layout-sider, .arco-menu, .arco-layout-sider, ' +
                // TDesign / iView / View Design
                '.t-menu, .t-aside, .ivu-menu, .ivu-layout-sider, ' +
                // Bootstrap
                '.navbar-nav, .nav-sidebar, .offcanvas, ' +
                // Tailwind UI / Headless UI
                '[class*="Sidebar"], [class*="sidebar-nav"], [class*="side-nav"], ' +
                // 通用属性特征
                '[data-sidebar], [data-nav], [aria-label*="navigation" i], [aria-label*="sidebar" i], ' +
                '[aria-label*="menu" i], [data-testid*="nav" i], [data-testid*="sidebar" i], [data-testid*="menu" i]';
            // 底部固定导航 / TabBar 检测函数
            // 覆盖移动端 H5 底部 TabBar、管理后台底部固定操作栏
            function isInFixedBottomNav(el) {
                let node = el;
                for (let i = 0; i < 8; i++) {
                    if (!node || node === document.body || node === document.documentElement) break;
                    const style = window.getComputedStyle(node);
                    const pos = style.position;
                    // fixed/sticky 且贴近底部的容器
                    if ((pos === 'fixed' || pos === 'sticky') && 
                        (style.bottom === '0px' || parseInt(style.bottom) <= 10)) {
                        return true;
                    }
                    // 常见 TabBar class 名
                    const cls = (node.className || '').toString().toLowerCase();
                    if (cls.includes('tabbar') || cls.includes('tab-bar') || 
                        cls.includes('bottom-nav') || cls.includes('footer-nav') ||
                        cls.includes('dock') || cls.includes('bottom-menu')) {
                        return true;
                    }
                    node = node.parentElement;
                }
                return false;
            }

            let idx = 0;
            document.querySelectorAll(sels).forEach((el) => {
                const text = (el.textContent || el.value || '').trim().slice(0, 50);
                if (!text) return;
                // 过滤不可见元素（解决标记了隐藏菜单导致选择器失效的问题）
                const rect = el.getBoundingClientRect();
                const style = window.getComputedStyle(el);
                if (el.offsetParent === null && style.position !== 'fixed' && style.position !== 'sticky') return;
                if (style.display === 'none' || style.visibility === 'hidden') return;
                if (rect.width <= 0 || rect.height <= 0) return;
                if (parseFloat(style.opacity) === 0) return;
                // 过滤 CSS/SVG 垃圾文本（如 "#eQCu9oBhsxn1{pointer-ev"）
                if (/[{}]/.test(text) || /^[#.][a-zA-Z0-9_-]+\{/.test(text)) return;
                // 过滤纯符号/数字文本（不太可能是菜单项）
                if (/^[^a-zA-Z\u4e00-\u9fff]+$/.test(text) && text.length < 3) return;
                el.setAttribute('data-crawl-idx', String(idx));
                result.clickables.push({
                    tag: el.tagName.toLowerCase(), text: text,
                    type: el.type || '', id: el.id || '',
                    selector: el.id ? `#${el.id}` : `[data-crawl-idx="${idx}"]`,
                    isMenu: !!(el.closest(NAV_CTX)) || isInFixedBottomNav(el),
                });
                idx++;
            });

            // 专门提取底部固定导航栏（TabBar）中的菜单项
            // 移动端 H5 / 混合 App 常见底部 TabBar，不在 NAV_CTX 覆盖范围内
            const fixedBottomEls = document.querySelectorAll(
                '[class*="tabbar"], [class*="tab-bar"], [class*="bottom-nav"], ' +
                '[class*="footer-nav"], [class*="dock"], [class*="bottom-menu"], ' +
                '.van-tabbar, .nut-tabbar, .weui-tabbar, .mint-tabbar, ' +
                '.uni-tabbar, .taro-tabbar'
            );
            fixedBottomEls.forEach((container) => {
                // 也检查 position:fixed + bottom:0 的通用容器
                const style = window.getComputedStyle(container);
                const isFixed = (style.position === 'fixed' || style.position === 'sticky') &&
                    (style.bottom === '0px' || parseInt(style.bottom) <= 10);
                const clsMatch = (container.className || '').toString().toLowerCase();
                const isTabBar = clsMatch.includes('tabbar') || clsMatch.includes('tab-bar') ||
                    clsMatch.includes('bottom-nav') || clsMatch.includes('dock');
                if (!isFixed && !isTabBar) return;
                // 提取 TabBar 内的可点击项
                const items = container.querySelectorAll('a, [role=tab], [role=button], button, .van-tabbar-item, .nut-tabbar-item, [class*="tab-item"], [class*="tabbar-item"]');
                items.forEach((item, i) => {
                    const text = (item.textContent || '').trim().slice(0, 40);
                    if (!text || text.length < 1) return;
                    item.setAttribute('data-tabbar-idx', String(i));
                    // 避免重复添加（已被 sels 选中的跳过）
                    if (item.hasAttribute('data-crawl-idx')) return;
                    result.clickables.push({
                        tag: item.tagName.toLowerCase(), text: text,
                        type: item.type || '', id: item.id || '',
                        selector: item.id ? `#${item.id}` : `[data-tabbar-idx="${i}"]`,
                        isMenu: true,  // TabBar 项视为菜单
                        isTabBar: true,
                    });
                });
            });

            // position:fixed + bottom 的通用容器也作为菜单容器
            document.querySelectorAll('*').forEach((el) => {
                if (el.children.length < 2 || el.children.length > 12) return;
                const style = window.getComputedStyle(el);
                if ((style.position === 'fixed' || style.position === 'sticky') &&
                    (style.bottom === '0px' || parseInt(style.bottom) <= 10) &&
                    el.offsetHeight > 30 && el.offsetHeight < 120) {
                    // 这是一个底部固定导航栏，提取其中的菜单项
                    const items = [];
                    el.querySelectorAll('a, button, [role=tab], [role=button], span, div').forEach((child, i) => {
                        const text = (child.textContent || '').trim().slice(0, 40);
                        if (!text || text.length < 1 || child.children.length > 3) return;
                        // 只取叶子节点或浅层节点
                        if (child.querySelector('a, button, [role=tab]') && child.tagName !== 'A' && child.tagName !== 'BUTTON') return;
                        items.push({
                            text: text, tag: child.tagName.toLowerCase(),
                            selector: child.id ? `#${child.id}` : `[data-crawl-idx="${child.getAttribute('data-crawl-idx') || ''}"]`,
                            hasChildren: false,
                        });
                    });
                    if (items.length >= 2) {
                        result.menus.push({container: 'FIXED_BOTTOM_NAV', items: items});
                    }
                }
            });

            // 识别导航菜单容器（用于二三级菜单展开）
            // 与 NAV_CTX 保持同步，覆盖更多 UI 框架
            const menuSels = 'nav, [role=navigation], .sidebar, .el-menu, .ant-menu, .nav-menu, ' +
                '.ant-layout-sider, .el-aside, ' +
                '[class*="sidebar"], [class*="nav-"], [class*="-nav"], [id*="sidebar"], [id*="nav-menu"], ' +
                '[class*="NavigationMenu"], [class*="SideNav"], [class*="AppNav"], ' +
                // Material UI / MUI
                '.MuiDrawer-root, .MuiList-root, [class*="MuiNav"], [class*="MuiDrawer"], ' +
                // Vuetify / Naive UI / Arco Design
                '.v-navigation-drawer, .v-list, .n-menu, .n-layout-sider, .arco-menu, .arco-layout-sider, ' +
                // TDesign / iView / Bootstrap
                '.t-menu, .t-aside, .ivu-menu, .ivu-layout-sider, .navbar-nav, .nav-sidebar, ' +
                // Tailwind / Headless UI
                '[class*="Sidebar"], [class*="sidebar-nav"], [class*="side-nav"], ' +
                '[data-sidebar], [data-nav], [aria-label*="navigation" i], [aria-label*="sidebar" i], ' +
                '[aria-label*="menu" i], [data-testid*="nav" i], [data-testid*="sidebar" i], [data-testid*="menu" i]';
            // 过滤掉内容像用户名/邮箱/纯数字ID的误识别文本
            const EMAIL_RE = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
            const NUMERIC_RE = /^[0-9\\-_]{4,}$/;
            const SKIP_TEXT_RE = /^(loading|spinner|tooltip|placeholder)$/i;
            document.querySelectorAll(menuSels).forEach((m) => {
                const items = m.querySelectorAll('a, [role=menuitem], .el-menu-item, .ant-menu-item, .el-submenu__title, .ant-menu-submenu-title, li > span, li > div, .MuiListItem-root, .MuiMenuItem-root, .v-list-item, .n-menu-item, .arco-menu-item, .t-menu__item, .ivu-menu-item, .nav-link, .navbar-nav .nav-item');
                const menuItems = [];
                items.forEach((item, i) => {
                    const text = (item.textContent || '').trim().slice(0, 40);
                    if (!text || text.length < 2) return;
                    // 过滤邮箱、纯数字ID、无意义占位文本
                    if (EMAIL_RE.test(text) || NUMERIC_RE.test(text) || SKIP_TEXT_RE.test(text)) return;
                    // 过滤包含邮箱的混合文本（如 "Andreaandrea@freshse..."）
                    if (text.includes('@') && text.includes('.')) return;
                    item.setAttribute('data-menu-idx', String(i));
                    menuItems.push({
                        text: text, tag: item.tagName.toLowerCase(),
                        selector: item.id ? `#${item.id}` : `[data-menu-idx="${i}"]`,
                        hasChildren: !!(item.querySelector('ul, .el-submenu, .ant-menu-sub, .v-list-group, .n-submenu, .arco-menu-inline, .MuiCollapse-root, [aria-haspopup], [aria-expanded]')),
                    });
                });
                if (menuItems.length > 0) {
                    result.menus.push({container: m.tagName, items: menuItems});
                }
            });

            // Shadow DOM 穿透：递归遍历所有 Shadow Root，提取其中的导航/链接/表单
            // 覆盖 Salesforce、ServiceNow、Workday、各类 Web Component 框架
            function extractFromShadowRoot(root, depth) {
                if (depth > 5) return;  // 最多 5 层，防止无限递归
                root.querySelectorAll('*').forEach(el => {
                    // 递归进入子 Shadow Root
                    if (el.shadowRoot) extractFromShadowRoot(el.shadowRoot, depth + 1);

                    // 提取链接
                    if (el.tagName === 'A' && el.href && el.href.startsWith('http')) {
                        result.links.push(el.href);
                    }

                    // 提取表单
                    if (el.tagName === 'FORM') {
                        result.forms.push({
                            action: el.action || '', method: (el.method || 'GET').toUpperCase(),
                            inputs: Array.from(el.elements || []).map(e => ({
                                tag: e.tagName.toLowerCase(), type: e.type || '',
                                name: e.name || '', id: e.id || '',
                                placeholder: e.placeholder || '', required: e.required,
                            })).filter(e => e.name),
                            selector: el.id ? `#${el.id}` : 'shadow-form',
                        });
                    }

                    // 提取可点击元素
                    const tag = el.tagName.toLowerCase();
                    const isClickable = (
                        tag === 'button' || tag === 'a' ||
                        el.getAttribute('role') === 'button' ||
                        el.getAttribute('role') === 'menuitem' ||
                        el.getAttribute('role') === 'tab' ||
                        el.hasAttribute('onclick') ||
                        (el.className && typeof el.className === 'string' && (
                            el.className.includes('menu-item') ||
                            el.className.includes('nav-item') ||
                            el.className.includes('sidebar-item')
                        ))
                    );
                    if (isClickable) {
                        const text = (el.textContent || el.value || '').trim().slice(0, 50);
                        if (text && text.length >= 2 && !EMAIL_RE.test(text) && !NUMERIC_RE.test(text)) {
                            // Shadow DOM 内元素无法用普通选择器定位，记录为特殊标记
                            result.clickables.push({
                                tag: tag, text: text, type: el.type || '', id: el.id || '',
                                selector: el.id ? `#${el.id}` : `shadow::${tag}[text="${text.slice(0,20)}"]`,
                                isMenu: true,  // Shadow DOM 内的导航项优先视为菜单
                                isShadow: true,
                            });
                        }
                    }
                });
            }
            // 遍历所有顶层 Shadow Host
            document.querySelectorAll('*').forEach(el => {
                if (el.shadowRoot) extractFromShadowRoot(el.shadowRoot, 0);
            });
            // links 去重
            result.links = [...new Set(result.links)];

            return result;
        }
