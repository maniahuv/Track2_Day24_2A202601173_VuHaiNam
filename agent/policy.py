"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc Guide.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input đúng slide §3.3 (đã định nghĩa sẵn, đừng đổi field):

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool


def check(context: PolicyContext) -> tuple[bool, str]:
    # Rule tối thiểu bắt buộc: dữ liệu restricted không bao giờ được đi
    # cùng 1 run có egress bật — đây chính là chân chặn exfil trong trifecta.
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, (
            f"deny: data_classification=restricted và egress_enabled=True "
            f"(agent_owner={context.agent_owner}, purpose={context.request_purpose}) "
            "— dữ liệu nhạy cảm không được rời hệ thống trong cùng run có egress."
        )

    # Siết thêm: delegation sâu (agent gọi agent, depth > 0) không được tự
    # ý bật egress cho dữ liệu restricted/internal — chỉ run gốc (depth=0)
    # mới được coi là có đủ ngữ cảnh người dùng để quyết định gửi đi.
    if context.delegation_depth > 0 and context.egress_enabled and context.data_classification != "public":
        return False, (
            f"deny: delegation_depth={context.delegation_depth} > 0 với egress_enabled=True "
            f"trên dữ liệu {context.data_classification} — run bị delegate không được tự ý gọi egress "
            f"(agent_owner={context.agent_owner})."
        )

    return True, (
        f"allow: classification={context.data_classification}, "
        f"egress_enabled={context.egress_enabled}, purpose={context.request_purpose} "
        f"— không khớp rule deny nào (agent_owner={context.agent_owner})."
    )
