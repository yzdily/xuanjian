() => {
                    const results = [];
                    const sels = '.el-submenu.is-opened .el-submenu__title, ' +
                        '.ant-menu-submenu-open .ant-menu-submenu-title, ' +
                        '[aria-expanded="true"] [aria-haspopup], ' +
                        '.el-submenu.is-opened .el-submenu .el-submenu__title, ' +
                        '.ant-menu-submenu-open .ant-menu-submenu .ant-menu-submenu-title';
                    document.querySelectorAll(sels).forEach((el) => {
                        const text = (el.textContent || '').trim().slice(0, 40);
                        if (!text || text.length < 2) return;
                        const hasKids = !!(el.querySelector('ul, .el-submenu, .ant-menu-sub') ||
                            el.closest('[aria-haspopup]'));
                        if (hasKids) {
                            const idx = 20000 + results.length;
                            el.setAttribute('data-expand-idx', String(idx));
                            results.push({
                                text: text,
                                selector: `[data-expand-idx="${idx}"]`,
                                hasChildren: true,
                            });
                        }
                    });
                    return [{items: results}];
                }
