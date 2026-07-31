() => {
                        const result = {routes: [], mode: 'hash'};
                        try {
                            // Vue 3
                            const app = document.querySelector('#app');
                            if (app && app.__vue_app__) {
                                const router = app.__vue_app__.config.globalProperties.$router;
                                if (router) {
                                    result.routes = router.getRoutes().map(r => r.path).filter(p => p && p !== '/');
                                    // 检测 history 模式：vue-router 4.x
                                    const opt = router.options || {};
                                    const hist = opt.history;
                                    if (hist) {
                                        // createWebHashHistory → base 含 #；createWebHistory → 不含
                                        const histStr = String(hist.createCurrentLocation || hist.location || '');
                                        if (location.hash && location.hash.startsWith('#/')) {
                                            result.mode = 'hash';
                                        } else {
                                            result.mode = 'history';
                                        }
                                    }
                                    return result;
                                }
                            }
                            // Vue 2
                            if (app && app.__vue__ && app.__vue__.$router) {
                                const router = app.__vue__.$router;
                                result.routes = router.options.routes.map(r => r.path).filter(p => p && p !== '/');
                                result.mode = router.mode || (location.hash.startsWith('#/') ? 'hash' : 'history');
                                return result;
                            }
                            // React Router (v6 没有公开 API，但 history 对象常被挂在 window)
                            // 试着从 window.__REACT_ROUTER_HISTORY__ 或 window.history.state.routes 读取
                            if (window.__reactRouterHistory__) {
                                // 这个 API 不稳定，留空
                            }
                            // 兜底：根据当前 URL 判断模式
                            result.mode = location.hash && location.hash.startsWith('#/') ? 'hash' : 'history';
                        } catch(e) {}
                        return result;
                    }
