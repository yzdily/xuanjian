() => {
                    const texts = ['加载更多', '查看更多', '更多', '下一页', 'Load more', 'More', 'Next'];
                    const btns = document.querySelectorAll('button, a, [role="button"]');
                    for (const btn of btns) {
                        const t = (btn.textContent || '').trim();
                        if (texts.some(x => t === x || t.includes(x)) && btn.offsetParent !== null) {
                            btn.click();
                            return true;
                        }
                    }
                    return false;
                }
