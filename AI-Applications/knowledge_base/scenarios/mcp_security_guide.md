# MCP 安全策略指南

> 来源: OWASP AIVP MCP Safety + ASI Policy Enforcement

## 概览

MCP 安全模块提供两层保护：硬安全边界 (Safety Bounds) 和基于能力的策略执行 (Capability-based Policy)。

---

## 1. 硬安全边界 (Safety Bounds)

### 检查项

| 检查 | 限制 | 说明 |
|------|------|------|
| MCP_CALL 大小 | 4096 bytes | 拒绝过大的 MCP 调用块 |
| JSON 深度 | 5 层 | 防止深层嵌套 DoS |
| 副作用限制 | 1 次/调用 | 每个 turn 只允许一个 tool call |
| 工具白名单 | 按名称 | 只允许已知的 server tool |

### API 端点
```
POST /api/v1/mcp-safety/check-call-size       — 检查调用块大小
POST /api/v1/mcp-safety/check-params-depth    — 检查参数深度
POST /api/v1/mcp-safety/check-tool-allowlist  — 检查工具白名单
```

---

## 2. 基于能力的策略 (Capability-based Policy)

### 策略维度

| 维度 | 值 | 说明 |
|------|-----|------|
| **trust_level** | TRUSTED / BETA / UNTRUSTED / SHADOW | 服务器信任级别 |
| **required_scope** | read / read:token / write / admin | 工具需要的权限范围 |
| **granted_scope** | [read, write, admin] | 客户端被授予的权限范围 |
| **policy_mode** | OFF / DETECT / MITIGATE | 策略执行模式 |

### 策略规则

1. **SHADOW 服务器**: 策略开启时一律阻止
2. **UNTRUSTED + 高权限**: MITIGATE 模式阻止，DETECT 模式标记
3. **Scope 子集**: required_scope 必须被 granted_scope 覆盖
4. **身份绑定**: identity_bound 工具不允许冒充其他用户
5. **工具链保护**: chained + requires_approval → 阻止
6. **敏感工具**: MITIGATE 模式要求用户同意

### 决策类型

| 决策 | 含义 |
|------|------|
| `allowed` | 操作允许 |
| `detected` | 检测到异常但允许（DETECT 模式） |
| `blocked` | 操作被阻止 |
| `blocked: consent_required` | 需要用户同意 |

### 爆炸半径 (Blast Radius)

| 级别 | 影响范围 |
|------|---------|
| `none` | 无影响 |
| `single_resource` | 影响单个资源 |
| `cross_session` | 跨会话影响 |
| `full` | 完全系统访问 |

### API 端点
```
POST /api/v1/mcp-safety/policy-check          — 执行策略检查
```

### 参数
```
trust_level=UNTRUSTED        # TRUSTED | BETA | UNTRUSTED | SHADOW
required_scope=read          # read | read:token | write | admin
granted_scope=["read"]       # 客户端权限列表
policy_mode=DETECT           # OFF | DETECT | MITIGATE
identity_bound=false         # 是否绑定身份
requested_identity=null      # 请求的身份
active_identity=null         # 当前活跃身份
is_chained=false             # 是否工具链调用
requires_chain_approval=false # 是否需要链批准
is_sensitive=false           # 是否敏感工具
```

---

## 3. 输入清洗 (Input Sanitizer)

### ASI01: 不可信内容隔离

```
strip_injections(text) → 移除注入标记
wrap_untrusted(text) → 包装在 <untrusted_data> 标签中
sanitize_tool_output(name, text) → strip → wrap
```

#### 注入标记
- 指令覆写: `ignore previous`, `system:`, `you are now`, `disregard`
- HTML/XML 注入: `<!-- -->`
- Unicode 混淆: 零宽字符、双向控制字符

### RAG 摄入清洗

```
sanitize_rag_ingest(docs) → 清洗文档列表
```

自动过滤:
- HTML/JS 注入: `<script>`, `javascript:`, `onerror=`
- 提示注入: `ignore all previous`, `system: override`
- 角色操纵: `you are now the admin`

### ASI06: 记忆来源保护

```
guard_memory_write(key, value, source, confirm) → MemoryRecord | None
guard_memory_recall(records, key) → (executable, advisory)
```

信任级别:
- HIGH: USER_EXPLICIT + 交互确认
- MEDIUM: USER_EXPLICIT（无确认）
- LOW: TOOL_OUTPUT / INFERRED

敏感密钥（需要 HIGH 信任）:
`delivery_rule`, `forwarding_rule`, `password_reset_url`, `admin_url`

### API 端点
```
POST /api/v1/sanitizer/strip-injections        — 清洗注入标记
POST /api/v1/sanitizer/tool-output             — 清洗工具输出
POST /api/v1/sanitizer/rag-ingest              — 清洗 RAG 摄入
POST /api/v1/sanitizer/memory-write            — 记忆写入保护
```

---

## 4. OWASP 预防策略知识库

```
GET /api/v1/knowledge/owasp-prevention/{category}
```

每个风险类别包含:
- **architectural**: 架构级防护措施
- **detection**: 检测与监控措施
- **anti_patterns**: 常见错误做法

当前覆盖: LLM01 (Prompt Injection)
