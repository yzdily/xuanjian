/**
 * SPA 路由提取脚本 — 在浏览器运行时通过 page.evaluate() 执行。
 *
 * 增强版（2026-08-13）：
 * - Vue 3 / Vue 2：通过 __vue_app__ / __vue__ 读取路由表
 * - React：通过 fiber 检测 + DOM <a[href]> 提取路由路径
 * - Angular：通过 ng.getRouter() 或 [ng-version] 检测
 * - 通用：链接数统计、动态内容比例计算、路由模式检测
 *
 * 此文件为参考文档，实际执行逻辑在 spa_mixin.py._detect_spa_enhanced() 中内联。
 * 保持两者同步以避免维护不同步风险。
 */
() => {
    const result = {
        framework: '',
        routes: [],
        mode: '',
        linkCount: 0,
        dynamicRatio: 0,
    };
    try {
        // ---- Vue 3 ----
        const app = document.querySelector('#app');
        if (app && app.__vue_app__) {
            result.framework = 'vue3';
            const router = app.__vue_app__.config.globalProperties.$router;
            if (router) {
                try {
                    result.routes = router.getRoutes()
                        .map(r => r.path)
                        .filter(p => p && p !== '/');
                } catch(e) {}
                const opt = router.options || {};
                if (opt.history) {
                    result.mode = location.hash && location.hash.startsWith('#/')
                        ? 'hash' : 'history';
                }
            }
        }
        // ---- Vue 2 ----
        if (!result.framework && app && app.__vue__) {
            result.framework = 'vue2';
            const router = app.__vue__.$router;
            if (router) {
                try {
                    result.routes = (router.options.routes || [])
                        .map(r => r.path)
                        .filter(p => p && p !== '/');
                } catch(e) {}
                result.mode = router.mode ||
                    (location.hash.startsWith('#/') ? 'hash' : 'history');
            }
        }
        // ---- React ----
        if (!result.framework) {
            const rootEl = document.getElementById('root') || document.getElementById('app');
            if (rootEl && rootEl._reactRootContainer) {
                result.framework = 'react';
            }
            if (!result.framework) {
                const fiberKey = Object.keys(rootEl || {}).find(k =>
                    k.startsWith('__reactFiber'));
                if (fiberKey) result.framework = 'react';
            }
            if (result.framework === 'react') {
                // 从 DOM <a> 标签提取 React Router 路径
                const reactLinks = Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.getAttribute('href'))
                    .filter(h => h && (h.startsWith('/') || h.startsWith('#/')))
                    .filter(h => !h.startsWith('//'));
                result.routes = [...new Set(reactLinks)].slice(0, 100);
                result.mode = location.hash && location.hash.startsWith('#/')
                    ? 'hash' : 'history';
            }
        }
        // ---- Angular ----
        if (!result.framework) {
            if (window.ng || document.querySelector('[ng-version]')) {
                result.framework = 'angular';
                result.mode = location.hash && location.hash.startsWith('#/')
                    ? 'hash' : 'history';
                try {
                    if (window.ng && window.ng.getRouter) {
                        const router = window.ng.getRouter();
                        if (router) {
                            result.routes = router.config
                                .map(r => r.path)
                                .filter(p => p && p !== '**' && p !== '');
                        }
                    }
                } catch(e) {}
            }
        }

        // ---- 通用检测 ----
        result.linkCount = document.querySelectorAll('a[href]').length;
        const body = document.body;
        if (body) {
            const totalNodes = body.querySelectorAll('*').length;
            const textNodes = body.querySelectorAll(
                'p, span, h1, h2, h3, h4, h5, h6, label, a, td, li'
            ).length;
            result.dynamicRatio = totalNodes > 0
                ? 1 - (textNodes / totalNodes) : 0;
        }
        if (!result.mode) {
            result.mode = location.hash && location.hash.startsWith('#/')
                ? 'hash' : 'history';
        }
    } catch(e) {}
    return result;
}
