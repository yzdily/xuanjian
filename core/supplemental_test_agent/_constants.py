"""SupplementalTestAgent — 配置常量与第三方域名黑名单。

从原 core/supplemental_test_agent.py 抽取，行为不变。
"""

from __future__ import annotations

# ============================================================
# 配置
# ============================================================

# 每个新 API 的单测试预算（秒）
PER_API_TIMEOUT_S = 60.0

# 整个 Phase 2.55 的总预算（秒）
TOTAL_BUDGET_S = 30 * 60.0

# 单个 worker 同时测多少个新 feature
FEATURES_PER_WORKER = 5

# 已知第三方 SDK / 监控 / 基础设施域黑名单（绝不补测）
_THIRD_PARTY_BLACKLIST = {
    # ================================================================
    # Google 系
    # ================================================================
    "google-analytics.com", "googletagmanager.com", "googleapis.com",
    "doubleclick.net", "google.com", "recaptcha.net", "gstatic.com",
    "android.clients.google.com", "content-autofill.googleapis.com",
    "googleadservices.com", "googlesyndication.com",
    "firebase.google.com", "firebase.io", "firebaseapp.com",
    # ================================================================
    # 社交/登录 CDN
    # ================================================================
    "facebook.com", "facebook.net", "fbcdn.net",
    "twitter.com", "twimg.com",                    # Twitter 图片 CDN
    "linkedin.com", "licdn.com",                   # LinkedIn CDN
    "instagram.com",
    # ================================================================
    # 国际分析/埋点/热力图
    # ================================================================
    "mixpanel.com", "amplitude.com",
    "segment.com", "segment.io", "segment.build",
    "heap.io",                                     # Heap 分析
    "pendo.io",                                    # Pendo 产品分析
    "posthog.com",                                 # PostHog 开源分析
    "plausible.io",                                # Plausible 隐私分析
    "matomo.org", "matomo.cloud", "piwik.pro",     # Matomo/Piwik 分析
    "hotjar.com",
    "fullstory.com",
    "clarity.ms",                                  # Microsoft Clarity 热力图
    "inspectlet.com",                              # Inspectlet 会话录制
    "crazyegg.com",                                # Crazy Egg 热力图
    "luckyorange.com",                             # Lucky Orange 热力图
    "mouseflow.com",                               # Mouseflow 会话录制
    "quantummetric.com",                           # Quantum Metric 体验分析
    "contentsquare.com",                           # Contentsquare 体验分析
    "optimizely.com",                              # Optimizely A/B 测试
    "vwo.com",                                     # VWO A/B 测试
    "abtasty.com",                                 # ABTasty A/B 测试
    # ================================================================
    # 国际监控/APM
    # ================================================================
    "sentry.io", "datadoghq.com", "newrelic.com",
    "bugsnag.com", "raygun.io", "logrocket.com",
    "rollbar.com",                                 # Rollbar 错误监控
    "honeybadger.io",                              # Honeybadger 错误监控
    "elastic.co", "elastic.io",                    # Elastic APM
    "grafana.net",                                 # Grafana Cloud
    "vercel-insights.com",                         # Vercel Analytics
    "speedcurve.com",                              # SpeedCurve 性能监控
    "pingdom.net", "pingdom.com",                  # Pingdom 监控
    "uptimerobot.com",                             # UptimeRobot 监控
    "statuspage.io",                               # StatusPage 状态页
    # ================================================================
    # 国际归因/广告/推送
    # ================================================================
    "appsflyer.com",
    "adjust.com",                                  # Adjust 归因
    "branch.io",                                   # Branch 深度链接/归因
    "kochava.com",                                 # Kochava 归因
    "singular.net",                                # Singular 归因
    "tenjin.com",                                  # Tenjin 归因
    "onesignal.com",                               # OneSignal 推送
    "pushwoosh.com",                               # Pushwoosh 推送
    "braze.com", "appboy.com",                     # Braze 推送/营销 (旧名 Appboy)
    "iterable.com",                                # Iterable 推送/营销
    "clevertap.com",                               # CleverTap 推送/分析
    "leanplum.com",                                # Leanplum 推送/营销
    # ================================================================
    # 国际 CDN / 静态资源
    # ================================================================
    "cloudflare.com", "cloudflare-dns.com",
    "akamai.net", "akamaihd.net", "akamaized.net",
    "fastly.net", "fastlylb.net",
    "amazonaws.com", "azureedge.net", "cloudfront.net",
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "bootstrapcdn.com",
    "stackpathcdn.com",                            # StackPath CDN
    "edgecastcdn.net",                             # Edgecast CDN (Verizon)
    "bunny.net", "b-cdn.net",                      # Bunny CDN
    "cdn77.org",                                   # CDN77
    "keycdn.com",                                   # KeyCDN
    "sucuri.net",                                   # Sucuri WAF/CDN
    "incapdns.net", "impervadns.net",              # Imperva/Incapsula WAF
    "cdnetworks.com", "cdngc.net",                 # CDNetworks
    # ================================================================
    # 用户引导/帮助/产品引导
    # ================================================================
    "intercom.io", "intercomcdn.com",
    "userpilot.io", "userpilot.com",
    "beamercontent.com", "beamer.io", "getbeamer.com",
    "appcues.com", "appcues.net",
    "pendo.io",                                    # Pendo 引导 (也做分析)
    "walkme.com",                                  # WalkMe 引导
    "whatfix.com",                                 # WhatFix 引导
    # ================================================================
    # 支付
    # ================================================================
    "stripe.com", "paypal.com",
    # ================================================================
    # 监控 (Freshworks 等)
    # ================================================================
    "freshmarketer.com", "freshping.io", "haystack.es",
    # ================================================================
    # 字节跳动系 (纯 SDK/埋点/CDN，非客户业务)
    # ================================================================
    "snssdk.com",          # 抖音 SDK 日志/监控/接口
    "zijieapi.com",        # 字节内部服务网关（广告/AB/SDK/埋点 mcs/mon）
    "pstatp.com",          # 图片/视频 CDN
    "byteimg.com", "ibyteimg.com",  # 图片 CDN
    "bytecdn.cn", "bytefcdn.com", "bytefcdn-oversea.com",  # CDN
    "volceapplog.com",     # 火山引擎埋点上报 (mcs.volceapplog.com)
    "ixiguavideo.com",     # 西瓜视频 CDN
    "amemv.com",           # 抖音旧域名 SDK
    "bytegoofy.com",       # 字节 A/B 测试
    "ibytedtos.com",       # 字节 CDN/分发
    "i18n-pglstatp.com",   # 海外埋点/统计
    # ================================================================
    # 国内分析/埋点/热力图
    # ================================================================
    "growingio.com",       # GrowingIO 埋点 (api.growingio.com / assets.growingio.com)
    "sensorsdata.cn",      # 神策数据 SDK 上报
    "zhugeio.com",         # 诸葛io 埋点
    "talkingdata.com",     # TalkingData 统计
    "umeng.com",           # 友盟统计
    "cnzz.com",            # CNZZ 统计
    "hm.baidu.com",        # 百度统计埋点 JS
    "51.la",               # 51la 统计
    "ptengine.cn", "ptengine.com",  # Ptengine 热力图
    "appadhoc.com",        # AppAdhoc A/B 测试
    # ================================================================
    # 国内推送 SDK
    # ================================================================
    "jpush.cn",            # 极光推送
    "getui.net",           # 个推
    "xg.qq.com",           # 信鸽推送
    # ================================================================
    # 国内 CDN / 静态资源
    # ================================================================
    "gtimg.cn",            # 腾讯图片 CDN
    "idqqimg.com",         # QQ 图片 CDN
    "qpic.cn",             # QQ 图片 CDN
    "tencdns.net",         # 腾讯 DNS
    "dnsv1.com",           # 腾讯 CDN DNS
    "alicdn.com",          # 阿里 CDN
    "alikunlun.com",       # 阿里 CDN (旧)
    "taobaocdn.com",       # 淘宝 CDN (旧)
    "mmcdn.cn",            # 阿里多媒体 CDN
    "bdimg.com",           # 百度图片 CDN
    "bdstatic.com",        # 百度静态资源
    "bcebos.com",          # 百度云 CDN
    "qbox.me", "qiniudn.com", "qiniucdn.com",  # 七牛 CDN
    "aicdn.com", "jiashule.com",  # 又拍云 CDN
    "wscdns.com", "wscngs.com",   # 网宿 CDN
    "lxdns.com",                   # 蓝讯 CDN (旧)
    "chinanetcenter.com",          # 网宿
    "kspkg.com",           # 快手 CDN
    "hdslb.com",           # B站 CDN
    "bilivideo.com",       # B站视频 CDN
    # ================================================================
    # 京东系 (监控 SDK)
    # ================================================================
    "sgm-m.jd.com",
    # ================================================================
    # 其他常见 SDK/监控
    # ================================================================
    "algolia.net", "algolianet.com",  # Algolia 搜索 SDK
    "launchdarkly.com",               # LaunchDarkly Feature Flag
    "io1.app",                        # io.1 分析
    "go-mpulse.net",                  # Akamai mPulse 性能监控
    "rum.haystack.es",                # Haystack RUM
}
