() => {
            const items = [];
            const sels = '[role=menuitem], .el-menu-item, .ant-menu-item, a[href], .el-submenu .el-menu-item, .ant-menu-sub .ant-menu-item, .sidebar a, .nav-item a, .menu-item a';
            let idx = 10000;
            document.querySelectorAll(sels).forEach((el) => {
                if (el.getAttribute('data-crawl-idx')) return;
                const text = (el.textContent || '').trim().slice(0, 50);
                if (!text || text.length < 2) return;
                // 跳过不可见元素
                const rect = el.getBoundingClientRect();
                if (rect.width === 0 && rect.height === 0) return;
                el.setAttribute('data-crawl-idx', String(idx));
                // 一并采集 href（任务级菜单去重需要）
                let href = '';
                try {
                    if (el.tagName === 'A' && el.href) {
                        href = el.href;
                    } else {
                        const a = el.closest('a[href]') || el.querySelector('a[href]');
                        if (a && a.href) href = a.href;
                    }
                } catch (e) {}
                items.push({
                    tag: el.tagName.toLowerCase(), text: text,
                    selector: `[data-crawl-idx="${idx}"]`,
                    href: href,
                    isMenu: true,
                });
                idx++;
            });
            return items;
        }
