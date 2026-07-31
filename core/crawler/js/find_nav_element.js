() => {
                                const nav = document.querySelector(
                                    'nav, aside, [role="navigation"], .sidebar, .menu'
                                );
                                if (!nav || nav.offsetParent === null) return false;
                                const rect = nav.getBoundingClientRect();
                                const topEl = document.elementFromPoint(
                                    rect.left + rect.width / 2,
                                    rect.top + rect.height / 2
                                );
                                return topEl && topEl !== nav && !nav.contains(topEl);
                            }
