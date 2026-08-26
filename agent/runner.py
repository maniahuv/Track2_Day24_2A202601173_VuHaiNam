"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

_TICKET_ID_RE = re.compile(r"ticket-(\d+)")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _args_hash(args: dict) -> str:
    payload = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _ticket_id_from_filename(name: str) -> int | None:
    m = _TICKET_ID_RE.search(name)
    return int(m.group(1)) if m else None


def _log(ledger_path: Path, *, agent_id: str, run_id: str, tool: str,
          args: dict, classification: str, decision: str, reason: str) -> None:
    ledger.append(
        {
            "ts": _now(),
            "agent_id": agent_id,
            "run_id": run_id,
            "tool": tool,
            "args_hash": _args_hash(args),
            "classification": classification,
            "decision": decision,
            "reason": reason,
        },
        ledger_path,
    )


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = (log_dir or REPORTS_DIR) / "ledger.jsonl"
    run_id = uuid.uuid4().hex[:12]

    # --- Run A: untrusted content ONLY. Không gọi read_customer/http_post. ---
    run_a_id = f"run-a-{run_id}"
    ctx_a = policy.PolicyContext(
        data_classification="internal",
        request_purpose="search-tickets",
        agent_owner=run_a_id,
        delegation_depth=0,
        egress_enabled=False,
    )
    allow_a, reason_a = policy.check(ctx_a)
    _log(
        ledger_path,
        agent_id=run_a_id,
        run_id=run_a_id,
        tool="search_docs",
        args={"query": message},
        classification=ctx_a.data_classification,
        decision="allow" if allow_a else "deny",
        reason=reason_a,
    )
    if not allow_a:
        return "Yêu cầu bị chặn bởi policy trước khi tìm kiếm tài liệu."

    docs = tools.search_docs(message)

    # Chỉ trích TYPED ticket_id từ TÊN FILE — không bao giờ từ nội dung.
    ticket_ids = sorted({tid for d in docs if (tid := _ticket_id_from_filename(d["id"])) is not None})

    # find_injection() chỉ dùng để LOG bằng chứng injection đã bị "thấy" —
    # customer_ids/target_url nó trả về KHÔNG được dùng để quyết định gọi ai.
    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # --- Run B: private data ONLY. Nhận list[int] ticket_ids đã sanitize
    # từ Run A, tra customer_id qua related_tickets (nguồn tin cậy) — không
    # bao giờ tin customer_id mà attacker viết trong free text. ---
    run_b_id = f"run-b-{run_id}"
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))

    collected: list[dict] = []
    for customer in customers:
        related = set(customer.get("related_tickets", []))
        if not related & set(ticket_ids):
            continue

        customer_id = customer["customer_id"]
        ctx_b = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=run_b_id,
            delegation_depth=1,
            egress_enabled=False,
        )
        allow_b, reason_b = policy.check(ctx_b)
        _log(
            ledger_path,
            agent_id=run_b_id,
            run_id=run_b_id,
            tool="read_customer",
            args={"customer_id": customer_id},
            classification=ctx_b.data_classification,
            decision="allow" if allow_b else "deny",
            reason=reason_b,
        )
        if not allow_b:
            continue

        record = tools.read_customer(customer_id)
        collected.append(record)

    # --- Egress: nếu injection cố chỉ đạo POST dữ liệu ra ngoài, thử qua
    # policy với egress_enabled=True — rule tối thiểu trong policy.py phải
    # deny bất kỳ egress nào mang classification=restricted. ---
    if injected is not None and collected:
        ctx_egress = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="reconciliation",
            agent_owner=run_b_id,
            delegation_depth=1,
            egress_enabled=True,
        )
        allow_egress, reason_egress = policy.check(ctx_egress)
        _log(
            ledger_path,
            agent_id=run_b_id,
            run_id=run_b_id,
            tool="http_post",
            args={"url": injected.target_url, "customer_ids": [c["customer_id"] for c in collected]},
            classification=ctx_egress.data_classification,
            decision="allow" if allow_egress else "deny",
            reason=reason_egress,
        )
        if allow_egress:
            tools.http_post(injected.target_url, {"records": collected})

    return llm.summarize(docs)
