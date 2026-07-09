# AI 安全系统实现指南

> 来源: OWASP AIVP (AI Vulnerabilities Playground) + MCP Attack Labs

## 概览

本目录包含教育性地暴露漏洞的 AI 安全系统实现，用于学习和理解 AI 安全风险。

---

## 1. 工具调用系统 (ToolSystem)

### 功能
- 模拟 GitHub API、Jira API、Slack API 的工具调用
- 支持工具链式调用（chain_tools）
- 完整的调用日志记录

### 安全隐患点 (⚠️)
| 漏洞点 | 风险等级 | 说明 |
|--------|---------|------|
| `get_tool_config()` | CRITICAL | 直接暴露所有 API 密钥 |
| `chain_tools()` | HIGH | 中间输出可能泄露配置密钥 |
| `get_tool_log(include_sensitive=True)` | HIGH | 可选的敏感日志暴露 |
| 错误响应未脱敏 | MEDIUM | 错误信息包含密钥前缀 |

### 防护建议
- 永远不要在日志中记录原始 API 密钥
- 使用密钥管理服务（AWS Secrets Manager / HashiCorp Vault）
- 实现输出脱敏中间件
- 错误响应中移除内部调试信息

### API 端点
```
GET  /api/v1/security-systems/tools/config          — 获取工具配置
POST /api/v1/security-systems/tools/call            — 调用工具
GET  /api/v1/security-systems/tools/log             — 获取调用日志
```

---

## 2. RBAC 系统 (RBACSystem)

### 功能
- 三种角色：SUPPORT / ADMIN / ANALYZER
- 基于角色的权限映射
- 管理员密钥管理

### 安全隐患点 (⚠️)
| 漏洞点 | 风险等级 | 说明 |
|--------|---------|------|
| `get_admin_key("Agent-Support")` | HIGH | 非管理员代理可获取管理员密钥前缀 |
| `get_agent_info(include_admin=True)` | CRITICAL | 可选的管理员密钥完整暴露 |
| 管理员密钥存储在 Agent 属性中 | MEDIUM | 数据未隔离 |

### 防护建议
- 实施严格的身份验证，而非基于角色名
- 敏感信息与 Agent 属性分离存储
- 审计所有权限提升尝试

### API 端点
```
GET  /api/v1/security-systems/rbac/agents            — 列出所有 Agent
GET  /api/v1/security-systems/rbac/agent/{id}         — 获取 Agent 信息
GET  /api/v1/security-systems/rbac/admin-key/{id}     — 获取管理员密钥
```

---

## 3. 会话系统 (SessionSystem)

### 功能
- 会话创建与管理（内存回退）
- 用户-会话令牌映射
- 会话状态持久化

### 安全隐患点 (⚠️)
| 漏洞点 | 风险等级 | 说明 |
|--------|---------|------|
| `get_all_sessions()` | HIGH | 返回所有活跃会话数据 |
| `get_session_by_user(user_id)` | HIGH | 可获取任意用户的会话令牌 |

### 防护建议
- 会话数据包含敏感信息时应加密
- 限制会话查询权限
- 实施会话过期和自动清理

### API 端点
```
POST /api/v1/security-systems/sessions               — 创建会话
GET  /api/v1/security-systems/sessions               — 列出所有会话
GET  /api/v1/security-systems/sessions/{token}        — 获取会话详情
```

---

## 4. 记忆系统 (MemorySystem)

### 功能
- 键值对存储（内存回退）
- 关键词搜索
- 用户机密数据存储

### 安全隐患点 (⚠️)
| 漏洞点 | 风险等级 | 说明 |
|--------|---------|------|
| `summarize()` | CRITICAL | 返回所有存储数据 |
| `search()` | HIGH | 可搜索其他用户的敏感记录 |
| 无访问控制 | CRITICAL | 所有记忆全局可读 |

### 防护建议
- 实现用户级隔离
- 敏感数据加密存储
- 访问控制列表（ACL）

### API 端点
```
POST /api/v1/security-systems/memory                 — 存储记忆
GET  /api/v1/security-systems/memory/search           — 搜索记忆
GET  /api/v1/security-systems/memory/summarize        — 汇总所有记忆
```

---

## 5. 编排系统 (OrchestrationSystem)

### 功能
- Agent 注册与目标管理
- 控制密钥认证
- 操作日志记录

### 安全隐患点 (⚠️)
| 漏洞点 | 风险等级 | 说明 |
|--------|---------|------|
| `get_orchestration_config()` | CRITICAL | 暴露主控制密钥 |
| `get_agent_info(include_control=True)` | CRITICAL | 可选的控制密钥暴露 |
| 日志含密钥前缀 | MEDIUM | 可推断密钥结构 |

### 防护建议
- 控制密钥不应通过 API 暴露
- 实现最小权限的 Agent 注册
- 日志脱敏

### API 端点
```
GET  /api/v1/security-systems/orchestration/config    — 获取编排配置
GET  /api/v1/security-systems/orchestration/log       — 获取控制日志
```

---

## 6. RAG 系统 (RAGSystem)

### 功能
- ChromaDB 向量数据库
- 文档查询与合成回答
- 访问码管理

### 安全隐患点 (⚠️)
| 漏洞点 | 风险等级 | 说明 |
|--------|---------|------|
| `query(return_raw=True)` | CRITICAL | 返回原始文档含访问码 |
| `get_all_documents()` | CRITICAL | 返回所有文档含秘密 |
| 无用户级文档隔离 | HIGH | 所有用户看到相同文档 |

### 防护建议
- 实施用户级文档访问控制
- 输出脱敏/过滤
- 永远不要将机密存储在可检索的文档中

### API 端点
```
POST /api/v1/security-systems/rag/query              — 查询 RAG
GET  /api/v1/security-systems/rag/documents           — 获取所有文档
POST /api/v1/security-systems/rag/hardened-prompt     — 构建加固提示
```

---

## 输出监控 (OutputMonitor)

### 功能
- 10 种泄漏模式检测
- HIGH → 拦截 / MEDIUM → 脱敏 / CLEAN → 放行

### 检测模式
| 模式 | 严重度 | 示例 |
|------|--------|------|
| API 密钥 | HIGH | `sk-*`, `AKIA*`, `ghp_*` |
| 本地 URL | HIGH | `localhost:8080` |
| SSN | HIGH | `123-45-6789` |
| 数据库连接字符串 | HIGH | `postgres://user:pass@host` |
| 薪资区间 | MEDIUM | `$50K-$70K` |
| 批量邮箱 | MEDIUM | 3+ 邮箱地址 |
| 系统提示泄露 | MEDIUM | "system prompt", "my instructions" |

### API 端点
```
POST /api/v1/defense/output/scan       — 扫描输出内容
POST /api/v1/defense/output/enforce    — 执行输出策略
```

---

## 记忆完整性保护 (MemoryIntegrityGuard)

### 功能
- HMAC-SHA256 签名每个记忆条目
- 读取时验证签名
- 签名无效的条目隔离

### 防护目标
- ASI06: 外部记忆投毒 → 完全阻止
- 攻击者直接写入 memory.json 无法生成有效 HMAC

---

## RAG 加固提示 (Hardened Prompt)

### 五层防御
1. **摄入清洗** — 去除注入模式
2. **访问控制检索** — 用户级文档过滤
3. **指令/上下文分离** — 明确的 data vs instruction 边界
4. **输出监控** — 泄漏检测与脱敏
5. **嵌入异常检测** — 余弦聚类异常检测
