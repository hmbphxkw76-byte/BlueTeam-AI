"""AISecLab 工单监控脚本。

定时检查工单 SLA 状态，自动升级超时工单。
可通过 cron 或计划任务定期执行。
"""

import asyncio
import sys
from pathlib import Path

# 添加项目根目录到 sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from llamafw.database import Database
from llamafw.config import DATABASE_PATH


async def check_escalations() -> dict:
    """检查所有活跃工单，自动升级超时工单。"""
    db = Database(str(DATABASE_PATH))
    await db.init_db()

    escalated = 0
    results = []

    # 获取所有 open 和 in_progress 状态的工单
    for status in ["open", "in_progress"]:
        resp = await db.list_tickets(status=status, per_page=1000)
        for ticket in resp["tickets"]:
            check = await db.needs_escalation(ticket["id"])
            if check.get("needs_escalation"):
                # 自动升级
                new_level = min(ticket.get("escalation_level", 0) + 1, 3)
                new_priority = ["medium", "high", "urgent", "urgent"][new_level]
                now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()

                await db.update_ticket(
                    ticket["id"],
                    priority=new_priority,
                    escalation_level=new_level,
                    escalated_at=now,
                    escalation_reason=f"自动升级: {check.get('reason', 'SLA超时')}",
                )

                await db.add_ticket_update(
                    ticket["id"], None, "escalation",
                    f"自动升级 Level {new_level}: {check.get('reason')}",
                    old_value=ticket.get("priority"),
                    new_value=new_priority,
                )

                escalated += 1
                results.append({
                    "ticket_number": ticket["ticket_number"],
                    "old_priority": ticket.get("priority"),
                    "new_priority": new_priority,
                    "level": new_level,
                    "reason": check.get("reason"),
                })

    await db.close()
    return {"checked": sum(1 for _ in []) + 1, "escalated": escalated, "details": results}


def main():
    """命令行入口。"""
    import argparse
    parser = argparse.ArgumentParser(description="AISecLab 工单监控")
    parser.add_argument("--db", default=str(DATABASE_PATH), help="数据库路径")
    parser.add_argument("--quiet", action="store_true", help="静默模式")
    args = parser.parse_args()

    global DATABASE_PATH
    DATABASE_PATH = Path(args.db)

    result = asyncio.run(check_escalations())

    if not args.quiet:
        print(f"[AISecLab] 工单监控完成: 升级 {result['escalated']} 个工单")
        for detail in result["details"]:
            print(f"  {detail['ticket_number']}: {detail['old_priority']} → {detail['new_priority']} ({detail['reason']})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
