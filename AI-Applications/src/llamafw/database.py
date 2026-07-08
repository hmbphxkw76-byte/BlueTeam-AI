"""AISecLab 数据库模块：基于 aiosqlite 的异步 SQLite 数据库操作。

提供用户、会话、对话、消息、产品、工单、知识库等完整的数据访问层。
"""

from __future__ import annotations

import json
import random
import string
from datetime import datetime, timezone
from typing import Any

import aiosqlite

from .config import DATABASE_PATH


def _generate_ticket_number() -> str:
    digits = ''.join(random.choices(string.digits, k=6))
    return f"TMC-{digits}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    """异步 SQLite 数据库操作封装。"""

    def __init__(self, db_path: str = "") -> None:
        self._db_path: str = str(db_path) if db_path else str(DATABASE_PATH)
        self._conn: aiosqlite.Connection | None = None

    async def _get_conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            self._conn = await aiosqlite.connect(self._db_path)
            self._conn.row_factory = aiosqlite.Row
            await self._conn.execute("PRAGMA journal_mode=WAL")
            await self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    # ═══════════════════════════════════════════════════════════
    #  初始化
    # ═══════════════════════════════════════════════════════════

    async def init_db(self) -> None:
        conn = await self._get_conn()
        await conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                email           TEXT UNIQUE NOT NULL,
                username        TEXT NOT NULL,
                password_hash   TEXT NOT NULL,
                role            TEXT DEFAULT 'customer' CHECK(role IN ('admin','customer','staff')),
                is_active       INTEGER DEFAULT 1,
                created_at      TEXT,
                last_login      TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id              TEXT PRIMARY KEY,
                user_id         INTEGER NOT NULL,
                token           TEXT NOT NULL,
                expires_at      TEXT NOT NULL,
                is_active       INTEGER DEFAULT 1,
                created_at      TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS conversations (
                id              TEXT PRIMARY KEY,
                user_id         INTEGER,
                title           TEXT DEFAULT '新会话',
                is_active       INTEGER DEFAULT 1,
                tags            TEXT DEFAULT '[]',
                satisfaction_rating INTEGER,
                escalated_to_human INTEGER DEFAULT 0,
                created_at      TEXT,
                updated_at      TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT NOT NULL,
                role            TEXT NOT NULL CHECK(role IN ('user','assistant','system')),
                content         TEXT NOT NULL,
                meta            TEXT,
                rag_sources     TEXT,
                tokens_used     INTEGER,
                confidence_score REAL,
                created_at      TEXT,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS products (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                sku             TEXT,
                name            TEXT NOT NULL,
                description     TEXT,
                category        TEXT,
                price           REAL,
                features        TEXT,
                specifications  TEXT,
                warranty_months INTEGER DEFAULT 12,
                image_url       TEXT
            );

            CREATE TABLE IF NOT EXISTS support_tickets (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_number   TEXT UNIQUE NOT NULL,
                user_id         INTEGER NOT NULL,
                conversation_id TEXT,
                subject         TEXT NOT NULL,
                description     TEXT,
                category        TEXT,
                priority        TEXT DEFAULT 'medium' CHECK(priority IN ('low','medium','high','urgent')),
                status          TEXT DEFAULT 'open' CHECK(status IN ('open','in_progress','resolved','closed')),
                assigned_agent  TEXT,
                escalation_level INTEGER DEFAULT 0,
                escalated_at    TEXT,
                escalation_reason TEXT,
                created_at      TEXT,
                updated_at      TEXT,
                resolved_at     TEXT,
                sla_deadline    TEXT,
                resolution_notes TEXT,
                customer_satisfaction INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS ticket_updates (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id       INTEGER NOT NULL,
                user_id         INTEGER,
                update_type     TEXT NOT NULL CHECK(update_type IN ('note','status_change','assignment','escalation','resolution')),
                message         TEXT,
                old_value       TEXT,
                new_value       TEXT,
                is_internal     INTEGER DEFAULT 0,
                created_at      TEXT,
                FOREIGN KEY (ticket_id) REFERENCES support_tickets(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS ticket_categories (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT NOT NULL,
                description     TEXT,
                default_priority TEXT DEFAULT 'medium',
                escalation_keywords TEXT,
                auto_assign_to  TEXT
            );

            CREATE TABLE IF NOT EXISTS knowledge_base (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                title           TEXT NOT NULL,
                content         TEXT NOT NULL,
                category        TEXT,
                subcategory     TEXT,
                tags            TEXT,
                document_type   TEXT DEFAULT 'article' CHECK(document_type IN ('article','faq','manual','policy')),
                source_file     TEXT,
                helpful_votes   INTEGER DEFAULT 0,
                created_at      TEXT,
                updated_at      TEXT
            );

            CREATE TABLE IF NOT EXISTS document_chunks (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id     INTEGER NOT NULL,
                chunk_index     INTEGER NOT NULL,
                content         TEXT NOT NULL,
                token_count     INTEGER DEFAULT 0,
                created_at      TEXT,
                FOREIGN KEY (document_id) REFERENCES knowledge_base(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS user_preferences (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         INTEGER UNIQUE NOT NULL,
                preferred_language TEXT DEFAULT 'zh-CN',
                email_notifications INTEGER DEFAULT 1,
                theme           TEXT DEFAULT 'dark',
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                kind            TEXT NOT NULL,
                detail          TEXT,
                created_at      TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id);
            CREATE INDEX IF NOT EXISTS idx_tickets_user ON support_tickets(user_id);
            CREATE INDEX IF NOT EXISTS idx_tickets_status ON support_tickets(status);
            CREATE INDEX IF NOT EXISTS idx_tickets_number ON support_tickets(ticket_number);
            CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
            CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit_events(kind);
            CREATE INDEX IF NOT EXISTS idx_chunks_doc ON document_chunks(document_id);
        """)
        await conn.commit()

        # ── 种子数据 ──
        await self._seed_ticket_categories(conn)
        await self._seed_products(conn)
        await self._seed_default_users(conn)

    async def _seed_ticket_categories(self, conn: aiosqlite.Connection) -> None:
        cursor = await conn.execute("SELECT COUNT(*) as cnt FROM ticket_categories")
        row = await cursor.fetchone()
        if row and row["cnt"] > 0:
            return

        categories = [
            ("技术支持", "产品使用、故障排除、兼容性问题", "medium",
             "bug,故障,不工作,错误,error,broke,broken,crash,无法,不能,help", "技术团队"),
            ("账户与账单", "账户管理、账单查询、订阅问题", "medium",
             "账单,付款,account,bill,payment,charge,退款,refund,收费,订阅", "客服团队"),
            ("产品信息", "产品规格、价格、库存查询", "low",
             "规格,参数,spec,多少钱,价格,price,cost,库存,stock,available", "销售团队"),
            ("服务请求", "安装、配置、迁移、定制服务", "medium",
             "安装,setup,install,配置,config,迁移,migrate,定制,custom,升级,upgrade", "服务团队"),
            ("投诉建议", "服务投诉、产品投诉、改进建议", "high",
             "投诉,complain,差,不满意,unsatisfied,manager,主管,经理,法律,lawyer,sue,起诉,angry,生气", "经理"),
        ]
        for name, desc, priority, keywords, assign_to in categories:
            await conn.execute(
                "INSERT INTO ticket_categories (name, description, default_priority, escalation_keywords, auto_assign_to) "
                "VALUES (?, ?, ?, ?, ?)",
                (name, desc, priority, keywords, assign_to),
            )
        await conn.commit()

    async def _seed_products(self, conn: aiosqlite.Connection) -> None:
        cursor = await conn.execute("SELECT COUNT(*) as cnt FROM products")
        row = await cursor.fetchone()
        if row and row["cnt"] > 0:
            return

        products = [
            ("ACC-001", "USB-C 高速数据线", "1米 USB-C to USB-C 高速数据线，支持 100W PD 快充和 10Gbps 数据传输", "USB-C 线缆",
             39.00, "100W PD 快充;10Gbps 数据传输;编织线材;E-Marker 芯片", "长度: 1m;接口: USB-C to USB-C;协议: USB 3.2 Gen2", 24),
            ("ACC-002", "HDMI 2.1 超高清线", "2米 HDMI 2.1 线缆，支持 8K@60Hz、4K@120Hz、HDR10+、eARC", "HDMI 线缆",
             69.00, "8K@60Hz;4K@120Hz;HDR10+;eARC;48Gbps 带宽;镀金接口", "长度: 2m;版本: HDMI 2.1;带宽: 48Gbps", 36),
            ("ACC-003", "无线充电板", "15W 快充无线充电板，兼容 Qi 标准，支持 iPhone/Android", "充电配件",
             89.00, "15W 快充;Qi 标准;LED 指示灯;防滑底座;过温保护", "输入: 5V2A/9V2A;输出: 15W Max;尺寸: 100mm x 10mm", 12),
            ("ACC-004", "USB-C 多合一集线器", "7合1 USB-C Hub，含 HDMI、USB-A、SD/TF 读卡器、PD 充电口", "集线器",
             129.00, "HDMI 4K@30Hz;3×USB-A 3.0;SD/TF 读卡器;PD 100W 充电;铝合金外壳", "接口: 1×HDMI, 3×USB-A, 1×USB-C PD, 1×SD, 1×TF", 18),
            ("ACC-005", "蓝牙降噪耳机", "主动降噪蓝牙耳机，支持 AAC/SBC 编码，续航 40 小时", "音频设备",
             249.00, "ANC 主动降噪;40小时续航;蓝牙 5.3;AAC/SBC;USB-C 充电;折叠设计", "驱动单元: 40mm;频率: 20Hz-20kHz;阻抗: 32Ω;重量: 250g", 24),
            ("ACC-006", "Lightning 快充线", "1.5米 Lightning to USB-A 快充线，MFi 认证，编织材质", "Lightning 线缆",
             29.00, "MFi 认证;快充支持;编织材质;不易缠绕", "长度: 1.5m;接口: Lightning to USB-A", 12),
            ("ACC-007", "USB-C to 3.5mm 音频适配器", "USB-C 转 3.5mm 音频适配器，Hi-Res 认证，内置 DAC", "适配器",
             49.00, "Hi-Res 认证;内置 DAC 芯片;铝合金外壳;兼容主流手机", "接口: USB-C to 3.5mm;DAC: 24bit/96kHz", 12),
        ]
        for sku, name, desc, cat, price, features, specs, warranty in products:
            await conn.execute(
                "INSERT INTO products (sku, name, description, category, price, features, specifications, warranty_months) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (sku, name, desc, cat, price, features, specs, warranty),
            )
        await conn.commit()

    async def _seed_default_users(self, conn: aiosqlite.Connection) -> None:
        cursor = await conn.execute("SELECT COUNT(*) as cnt FROM users")
        row = await cursor.fetchone()
        if row and row["cnt"] > 0:
            return

        from .config import hash_password

        admin_hash = hash_password("admin")
        customer_hash = hash_password("customer123")

        users = [
            ("admin@aiseclab.local", "admin", admin_hash, "admin"),
            ("customer@example.com", "测试客户", customer_hash, "customer"),
        ]
        for email, username, pw_hash, role in users:
            await conn.execute(
                "INSERT INTO users (email, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (email, username, pw_hash, role, _now_iso()),
            )
        await conn.commit()

    # ═══════════════════════════════════════════════════════════
    #  用户管理
    # ═══════════════════════════════════════════════════════════

    async def create_user(self, email: str, username: str, password_hash: str, role: str = "customer") -> dict[str, Any] | None:
        conn = await self._get_conn()
        try:
            cursor = await conn.execute(
                "INSERT INTO users (email, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (email, username, password_hash, role, _now_iso()),
            )
            await conn.commit()
            return await self.get_user_by_id(cursor.lastrowid)
        except aiosqlite.IntegrityError:
            return None

    async def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_user_by_id(self, user_id: int) -> dict[str, Any] | None:
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def list_users(self) -> list[dict[str, Any]]:
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT id, email, username, role, is_active, created_at, last_login FROM users ORDER BY id")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def update_user(self, user_id: int, **kwargs: Any) -> bool:
        if not kwargs:
            return False
        conn = await self._get_conn()
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [user_id]
        await conn.execute(f"UPDATE users SET {sets} WHERE id = ?", values)
        await conn.commit()
        return True

    # ═══════════════════════════════════════════════════════════
    #  会话管理
    # ═══════════════════════════════════════════════════════════

    async def create_session(self, session_id: str, user_id: int, token: str, expires_at: str) -> dict[str, Any]:
        conn = await self._get_conn()
        await conn.execute(
            "INSERT INTO sessions (id, user_id, token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            (session_id, user_id, token, expires_at, _now_iso()),
        )
        await conn.commit()
        return {"id": session_id, "user_id": user_id, "token": token, "expires_at": expires_at}

    async def get_session(self, token: str) -> dict[str, Any] | None:
        conn = await self._get_conn()
        cursor = await conn.execute(
            "SELECT * FROM sessions WHERE token = ? AND is_active = 1 AND expires_at > ?",
            (token, _now_iso()),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def invalidate_session(self, token: str) -> bool:
        conn = await self._get_conn()
        await conn.execute("UPDATE sessions SET is_active = 0 WHERE token = ?", (token,))
        await conn.commit()
        return True

    async def cleanup_expired_sessions(self) -> int:
        conn = await self._get_conn()
        cursor = await conn.execute("UPDATE sessions SET is_active = 0 WHERE expires_at <= ?", (_now_iso(),))
        await conn.commit()
        return cursor.rowcount

    # ═══════════════════════════════════════════════════════════
    #  对话管理
    # ═══════════════════════════════════════════════════════════

    async def create_conversation(self, conversation_id: str, user_id: int | None = None, title: str = "新会话") -> dict[str, Any]:
        conn = await self._get_conn()
        now = _now_iso()
        await conn.execute(
            "INSERT INTO conversations (id, user_id, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (conversation_id, user_id, title, now, now),
        )
        await conn.commit()
        return {"id": conversation_id, "user_id": user_id, "title": title, "created_at": now, "updated_at": now}

    async def get_conversation(self, conversation_id: str) -> dict[str, Any] | None:
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM conversations WHERE id = ?", (conversation_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        conv = dict(row)
        msgs = await conn.execute(
            "SELECT * FROM messages WHERE conversation_id = ? ORDER BY id", (conversation_id,)
        )
        conv["messages"] = [dict(m) for m in await msgs.fetchall()]
        return conv

    async def list_conversations(self, user_id: int | None = None) -> list[dict[str, Any]]:
        conn = await self._get_conn()
        if user_id is not None:
            cursor = await conn.execute(
                "SELECT * FROM conversations WHERE user_id = ? AND is_active = 1 ORDER BY updated_at DESC",
                (user_id,),
            )
        else:
            cursor = await conn.execute(
                "SELECT * FROM conversations WHERE is_active = 1 ORDER BY updated_at DESC"
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def update_conversation(self, conversation_id: str, **kwargs: Any) -> bool:
        if not kwargs:
            return False
        conn = await self._get_conn()
        kwargs["updated_at"] = _now_iso()
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [conversation_id]
        await conn.execute(f"UPDATE conversations SET {sets} WHERE id = ?", values)
        await conn.commit()
        return True

    async def add_message(
        self,
        conversation_id: str,
        role: str,
        content: str,
        meta: dict[str, Any] | None = None,
        rag_sources: list[str] | None = None,
        tokens_used: int = 0,
    ) -> dict[str, Any]:
        conn = await self._get_conn()
        now = _now_iso()
        meta_json = json.dumps(meta) if meta else None
        rag_json = json.dumps(rag_sources) if rag_sources else None
        cursor = await conn.execute(
            "INSERT INTO messages (conversation_id, role, content, meta, rag_sources, tokens_used, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (conversation_id, role, content, meta_json, rag_json, tokens_used, now),
        )
        await conn.execute(
            "UPDATE conversations SET updated_at = ? WHERE id = ?", (now, conversation_id)
        )
        await conn.commit()
        return {"id": cursor.lastrowid, "conversation_id": conversation_id, "role": role,
                "content": content, "meta": meta, "created_at": now}

    async def get_messages(self, conversation_id: str) -> list[dict[str, Any]]:
        conn = await self._get_conn()
        cursor = await conn.execute(
            "SELECT * FROM messages WHERE conversation_id = ? ORDER BY id", (conversation_id,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    # ═══════════════════════════════════════════════════════════
    #  产品管理
    # ═══════════════════════════════════════════════════════════

    async def list_products(self, category: str | None = None) -> list[dict[str, Any]]:
        conn = await self._get_conn()
        if category:
            cursor = await conn.execute(
                "SELECT * FROM products WHERE category = ? ORDER BY id", (category,)
            )
        else:
            cursor = await conn.execute("SELECT * FROM products ORDER BY id")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_product(self, product_id: int) -> dict[str, Any] | None:
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM products WHERE id = ?", (product_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_product_by_name(self, name: str) -> dict[str, Any] | None:
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{name}%",))
        row = await cursor.fetchone()
        return dict(row) if row else None

    # ═══════════════════════════════════════════════════════════
    #  工单管理
    # ═══════════════════════════════════════════════════════════

    async def create_ticket(
        self,
        user_id: int,
        subject: str,
        description: str,
        category: str = "技术支持",
        priority: str = "medium",
        conversation_id: str | None = None,
    ) -> dict[str, Any]:
        conn = await self._get_conn()
        ticket_number = _generate_ticket_number()
        now = _now_iso()

        # 计算 SLA 截止时间
        sla_hours = {"urgent": 2, "high": 8, "medium": 24, "low": 72}.get(priority, 24)
        from datetime import timedelta
        sla_deadline = (datetime.now(timezone.utc) + timedelta(hours=sla_hours)).isoformat()

        cursor = await conn.execute(
            "INSERT INTO support_tickets (ticket_number, user_id, conversation_id, subject, description, "
            "category, priority, status, sla_deadline, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)",
            (ticket_number, user_id, conversation_id, subject, description, category, priority, sla_deadline, now, now),
        )
        await conn.commit()

        ticket_id = cursor.lastrowid
        # 记录创建
        await self.add_ticket_update(ticket_id, user_id, "note", f"工单创建: {subject}")

        return await self.get_ticket(ticket_id) or {}

    async def get_ticket(self, ticket_id: int) -> dict[str, Any] | None:
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM support_tickets WHERE id = ?", (ticket_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        ticket = dict(row)
        ticket["updates"] = await self.get_ticket_updates(ticket_id)
        return ticket

    async def get_ticket_by_number(self, ticket_number: str) -> dict[str, Any] | None:
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM support_tickets WHERE ticket_number = ?", (ticket_number,))
        row = await cursor.fetchone()
        if not row:
            return None
        ticket = dict(row)
        ticket["updates"] = await self.get_ticket_updates(ticket["id"])
        return ticket

    async def list_tickets(
        self, user_id: int | None = None, status: str | None = None, page: int = 1, per_page: int = 20
    ) -> dict[str, Any]:
        conn = await self._get_conn()
        conditions = []
        params: list[Any] = []

        if user_id is not None:
            conditions.append("user_id = ?")
            params.append(user_id)
        if status:
            conditions.append("status = ?")
            params.append(status)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        # 总数
        cursor = await conn.execute(f"SELECT COUNT(*) as cnt FROM support_tickets {where}", params)
        row = await cursor.fetchone()
        total = row["cnt"] if row else 0

        offset = (page - 1) * per_page
        cursor = await conn.execute(
            f"SELECT * FROM support_tickets {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        )
        rows = await cursor.fetchall()
        return {
            "tickets": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": max(1, (total + per_page - 1) // per_page),
        }

    async def update_ticket(self, ticket_id: int, **kwargs: Any) -> bool:
        if not kwargs:
            return False
        conn = await self._get_conn()
        kwargs["updated_at"] = _now_iso()
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [ticket_id]
        await conn.execute(f"UPDATE support_tickets SET {sets} WHERE id = ?", values)
        await conn.commit()
        return True

    async def add_ticket_update(
        self,
        ticket_id: int,
        user_id: int | None,
        update_type: str,
        message: str,
        old_value: str | None = None,
        new_value: str | None = None,
        is_internal: bool = False,
    ) -> dict[str, Any]:
        conn = await self._get_conn()
        now = _now_iso()
        cursor = await conn.execute(
            "INSERT INTO ticket_updates (ticket_id, user_id, update_type, message, old_value, new_value, is_internal, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ticket_id, user_id, update_type, message, old_value, new_value, int(is_internal), now),
        )
        await conn.commit()
        return {"id": cursor.lastrowid, "ticket_id": ticket_id, "update_type": update_type, "message": message, "created_at": now}

    async def get_ticket_updates(self, ticket_id: int) -> list[dict[str, Any]]:
        conn = await self._get_conn()
        cursor = await conn.execute(
            "SELECT * FROM ticket_updates WHERE ticket_id = ? ORDER BY id", (ticket_id,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_ticket_stats(self) -> dict[str, Any]:
        conn = await self._get_conn()
        cursor = await conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_count,
                SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress_count,
                SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_count,
                SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END) as closed_count
            FROM support_tickets
        """)
        row = await cursor.fetchone()
        if not row:
            return {}
        return {
            "total": row["total"] or 0,
            "open": row["open_count"] or 0,
            "in_progress": row["in_progress_count"] or 0,
            "resolved": row["resolved_count"] or 0,
            "closed": row["closed_count"] or 0,
        }

    async def get_sla_metrics(self, ticket_id: int) -> dict[str, Any]:
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM support_tickets WHERE id = ?", (ticket_id,))
        row = await cursor.fetchone()
        if not row:
            return {}
        ticket = dict(row)
        now = _now_iso()
        is_breached = ticket.get("sla_deadline") and ticket["sla_deadline"] < now
        return {
            "ticket_number": ticket["ticket_number"],
            "status": ticket["status"],
            "sla_deadline": ticket.get("sla_deadline"),
            "is_breached": is_breached,
            "created_at": ticket.get("created_at"),
        }

    async def categorize_ticket_content(self, text: str) -> str | None:
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM ticket_categories")
        rows = await cursor.fetchall()
        text_lower = text.lower()
        best_category = None
        best_score = 0
        for row in rows:
            cat = dict(row)
            keywords = (cat.get("escalation_keywords") or "").split(",")
            score = sum(1 for kw in keywords if kw.strip().lower() in text_lower)
            if score > best_score:
                best_score = score
                best_category = cat["name"]
        return best_category

    async def list_ticket_categories(self) -> list[dict[str, Any]]:
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM ticket_categories ORDER BY id")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def needs_escalation(self, ticket_id: int) -> dict[str, Any]:
        ticket = await self.get_ticket(ticket_id)
        if not ticket:
            return {"needs_escalation": False, "reason": "ticket not found"}

        if ticket["status"] not in ("open", "in_progress"):
            return {"needs_escalation": False, "reason": "ticket not active"}

        # Check SLA breach
        if ticket.get("sla_deadline") and ticket["sla_deadline"] < _now_iso():
            return {"needs_escalation": True, "reason": "SLA deadline breached"}

        # Check escalation keywords in description
        escalation_keywords = ["urgent", "紧急", "immediate", "lawsuit", "法律", "complaint", "投诉", "manager", "经理"]
        desc_lower = (ticket.get("description") or "").lower()
        for kw in escalation_keywords:
            if kw in desc_lower:
                return {"needs_escalation": True, "reason": f"escalation keyword detected: {kw}"}

        return {"needs_escalation": False}

    # ═══════════════════════════════════════════════════════════
    #  知识库管理
    # ═══════════════════════════════════════════════════════════

    async def add_knowledge_document(
        self, title: str, content: str, category: str = "", tags: str = "", document_type: str = "article"
    ) -> dict[str, Any]:
        conn = await self._get_conn()
        now = _now_iso()
        cursor = await conn.execute(
            "INSERT INTO knowledge_base (title, content, category, tags, document_type, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (title, content, category, tags, document_type, now, now),
        )
        await conn.commit()
        return {"id": cursor.lastrowid, "title": title, "category": category, "document_type": document_type}

    async def list_knowledge_documents(self, category: str | None = None) -> list[dict[str, Any]]:
        conn = await self._get_conn()
        if category:
            cursor = await conn.execute("SELECT * FROM knowledge_base WHERE category = ? ORDER BY id", (category,))
        else:
            cursor = await conn.execute("SELECT * FROM knowledge_base ORDER BY id")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_knowledge_document(self, doc_id: int) -> dict[str, Any] | None:
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM knowledge_base WHERE id = ?", (doc_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def add_document_chunk(self, document_id: int, chunk_index: int, content: str) -> dict[str, Any]:
        conn = await self._get_conn()
        token_count = len(content) // 4
        cursor = await conn.execute(
            "INSERT INTO document_chunks (document_id, chunk_index, content, token_count, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (document_id, chunk_index, content, token_count, _now_iso()),
        )
        await conn.commit()
        return {"id": cursor.lastrowid, "document_id": document_id, "chunk_index": chunk_index}

    async def get_document_chunks(self, document_id: int) -> list[dict[str, Any]]:
        conn = await self._get_conn()
        cursor = await conn.execute(
            "SELECT * FROM document_chunks WHERE document_id = ? ORDER BY chunk_index", (document_id,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_all_document_chunks(self) -> list[dict[str, Any]]:
        conn = await self._get_conn()
        cursor = await conn.execute("""
            SELECT dc.*, kb.title as doc_title, kb.category as doc_category
            FROM document_chunks dc
            JOIN knowledge_base kb ON dc.document_id = kb.id
            ORDER BY dc.id
        """)
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    # ═══════════════════════════════════════════════════════════
    #  审计事件
    # ═══════════════════════════════════════════════════════════

    async def add_audit_event(self, kind: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
        conn = await self._get_conn()
        detail_json = json.dumps(detail) if detail else None
        now = _now_iso()
        cursor = await conn.execute(
            "INSERT INTO audit_events (kind, detail, created_at) VALUES (?, ?, ?)",
            (kind, detail_json, now),
        )
        await conn.commit()
        # 保留最近 2000 条
        await conn.execute("DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT 2000)")
        await conn.commit()
        return {"id": cursor.lastrowid, "kind": kind, "created_at": now}

    async def get_audit_events(self, limit: int = 200) -> list[dict[str, Any]]:
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,))
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    # ═══════════════════════════════════════════════════════════
    #  用户偏好
    # ═══════════════════════════════════════════════════════════

    async def get_user_preferences(self, user_id: int) -> dict[str, Any]:
        conn = await self._get_conn()
        cursor = await conn.execute("SELECT * FROM user_preferences WHERE user_id = ?", (user_id,))
        row = await cursor.fetchone()
        if not row:
            await conn.execute(
                "INSERT INTO user_preferences (user_id) VALUES (?)", (user_id,)
            )
            await conn.commit()
            cursor = await conn.execute("SELECT * FROM user_preferences WHERE user_id = ?", (user_id,))
            row = await cursor.fetchone()
        return dict(row) if row else {}

    async def update_user_preferences(self, user_id: int, **kwargs: Any) -> bool:
        if not kwargs:
            return False
        conn = await self._get_conn()
        # Ensure preferences row exists
        await self.get_user_preferences(user_id)
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [user_id]
        await conn.execute(f"UPDATE user_preferences SET {sets} WHERE user_id = ?", values)
        await conn.commit()
        return True

    # ═══════════════════════════════════════════════════════════
    #  清理
    # ═══════════════════════════════════════════════════════════

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None


# ── 模块级单例 ──

_db_instance: Database | None = None


async def get_db() -> Database:
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
        await _db_instance.init_db()
    return _db_instance


async def close_db() -> None:
    global _db_instance
    if _db_instance is not None:
        await _db_instance.close()
        _db_instance = None
