# 国产组件指纹 + 默认凭据 + 高危路径知识库

> 来源：src-hunter-skill chinese-srcfingerprints.md + default-credentials-cn.md + WooYun 统计
> 加载方式：`knowledge_load_skill("china-specific/fingerprints")`
> 
> 本知识库覆盖：国产 OA/CMS/中间件指纹识别、默认凭据、高危路径、高频参数字典

---

## 1. 国产 OA 指纹 + 高危路径

### 1.1 致远 OA（Seeyon）

```
指纹：
  Server: SEEYON-OA / X-Powered-By: SEEYON
  <title>致远协同管理软件</title>
  Cookie: JSESSIONID

关键路径：
  /seeyon/                      默认根路径
  /seeyon/main.do                登录后主页
  /seeyon/management/index.jsp   管理控制台
  /seeyon/htmlofficeservlet      A8 RCE 端点 ⚠️
  /seeyon/thirdpartyController.do  SSRF / 信息泄露 ⚠️

日志泄露：
  /ctp.log（23 例命中）
  /seeyon/logs/ctp.log
```

### 1.2 通达 OA（Tongda）

```
指纹：
  <title>通达OA</title>
  Cookie: PHPSESSID

关键路径：
  /general/login.php         登录入口
  /mobile/auth_mobi.php      移动端鉴权（任意用户登录）⚠️
  /ispirit/interface/gateway.php  RCE ⚠️
  /Pda/                      移动 PDA 接口
```

### 1.3 泛微 e-cology / e-office（Weaver）

```
指纹：
  e-cology 字样
  Cookie: ecology_JSessionId

关键路径：
  /login/Login.jsp                       登录
  /weaver/bsh.servlet.BshServlet         BeanShell RCE ⚠️
  /mobile/                               移动端
  /api/                                  API 网关
```

### 1.4 用友 / 金蝶 / 蓝凌

```
用友 NC：
  /nc/ /nc/servlet/ /portal/
  指纹: <title>用友NC</title>
  /oaerp/ui/sync/excelUpload.jsp  任意上传 ⚠️

金蝶 GSiS / EAS：
  /kdgs/ /kdgs/core/upload/  上传点 ⚠️
  /eas/  指纹: KingdeeApp / kdgs

蓝凌 LandrayOA：
  /sys/login/login.do /sys/web/index.jsp
  指纹: 蓝凌
```

---

## 2. 国产中间件指纹

```
Druid（阿里）：
  /druid/index.html  /druid/sql.html  /druid/weburi.html
  指纹: <title>Druid</title>
  ⚠️ 默认无密码或 admin/admin

Nacos：
  /nacos/  /nacos/v1/auth/users
  指纹: <title>Nacos</title>
  ⚠️ 默认 nacos/nacos

XXL-JOB：
  /xxl-job-admin/
  指纹: <title>任务调度中心</title>
  ⚠️ 默认 admin/123456

Apollo：
  /portal/  /eureka/apps
  指纹: apollo / Apollo

RuoYi / JeecgBoot：
  /system/user  /jeecg-boot/
  指纹: ruoyi / jeecg-boot
  ⚠️ RuoYi 默认 admin/admin123，MyBatis ${} 拼接 → SQL 注入高频
```

---

## 3. 默认凭据字典

| 系统 | 用户名 | 密码 |
|------|--------|------|
| 致远 OA | admin | 123456 / admin |
| 通达 OA | admin | 空 |
| 泛微 e-cology | sysadmin | 1 |
| 用友 NC | admin | admin / ncadmin |
| 金蝶 EAS | admin | admin |
| Nacos | nacos | nacos |
| XXL-JOB | admin | 123456 |
| Druid | admin | admin |
| RuoYi | admin | admin123 |
| JeecgBoot | admin | 123456 |
| Grafana | admin | admin |
| Zabbix | Admin | zabbix |
| Redis | - | 无密码（6379 默认未授权） |

---

## 4. 信息泄露专用路径（WooYun 命中率）

### 4.1 版本控制泄露（560 例）

```
/.git/config    /.git/HEAD    /.git/index
/.svn/entries   /.svn/wc.db
```

### 4.2 备份压缩包（530 例）

```
/wwwroot.rar  /wwwroot.zip  /www.zip  /web.rar
/web.zip      /backup.zip   /site.tar.gz
/{域名}.zip   /{域名}.rar
```

### 4.3 SQL 备份（136 例）

```
/backup.sql   /database.sql  /db.sql  /dump.sql
```

### 4.4 配置备份（101 例）

```
/config.php.bak  /web.config.bak  /.env.bak
```

### 4.5 PHP 探针（47 例）

```
/phpinfo.php  /info.php  /test.php  /1.php  /t.php
```

---

## 5. 高频参数字典（WooYun 27,732 案例）

### 5.1 SQL 注入高频参数

```
id action aid typeid typeId username act m y a method bid mid
out_trade_no fileName siteId dir systemID PARENTTYPEID Channel
```

### 5.2 业务逻辑高频参数

```
密码重置：phone/mobile/username/code/smsCode/verifyCode/token/step
越权/IDOR：id/uid/userId/user_id/oid/orderId/file_id/msg_id/account_id/tenant_id
支付/订单：amount/price/total/fee/quantity/count/productId/status/sign
授权篡改：role/role_id/isAdmin/is_admin/level/permissions/authorities
回调/重定向：url/redirect/redirect_uri/callback/jumpurl/next/returnUrl
文件操作：fileName/file/path/dir/filepath/fileLocation
```

### 5.3 任意 X 子授权高频字段

```
role=admin  is_admin=true  admin=1  level=9  role_id=1
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Original-URL: /admin
```

---

## 6. 高频后台路径

```
/admin/  /manage/  /houtai/  /admincp/  /system/login
/console/  /web-console/  /jmx-console/
中文常见但易忽略：
/houtai  /guanli  /backstage  /bgmanage  /control
/portal/admin  /agent/  /shop/admin  /merchant/  /dealer/  /partner/login
```

---

## 7. API 文档/调试路径

```
/swagger-ui.html  /swagger-ui/  /v2/api-docs  /v3/api-docs
/openapi.json     /swagger.json  /api/swagger
/druid/           /actuator/     /debug/  /test/  /dev/
```
