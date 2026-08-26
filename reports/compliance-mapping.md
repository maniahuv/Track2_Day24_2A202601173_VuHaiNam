# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Chưa triển khai workflow xóa hoặc delete cascade; đây là khoảng trống được để lại cho stretch goal. | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Lập data-flow inventory và lưu evidence egress; replay dùng --mock nên không gọi provider. Chính sách retention 60 ngày chưa được cấu hình trong lab. | reports/dpia-lite.md §2–3; reports/ledger.jsonl:23 |
| ASI03 — privilege abuse | Định danh theo từng run/agent, PEP trước tool call và audit ledger append-only. TTL chưa được triển khai, nên không được coi là control hiện có. | agent/runner.py:85–104, 107, 142; agent/policy.py:39–60; agent/ledger.py:57–91 |
| ASI01 — goal hijack | Trifecta split: ticket_id lấy từ tên file, customer map qua related_tickets, rồi chặn egress restricted bằng policy. | agent/runner.py:132, 140–148, 180–199; reports/attack-after.log; reports/ledger.jsonl:23 |
| ISO 42001 Clause 5-6 | Policy-as-code có traceability trong Git và reason bắt buộc trong audit. Repo không có bằng chứng formal peer review, nên chỉ khẳng định traceability/version control. | agent/policy.py:39–60; git log --oneline -- agent/policy.py (commit 48cabd9); reports/ledger.jsonl:1–23 |
