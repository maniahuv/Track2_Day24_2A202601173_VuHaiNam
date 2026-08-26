# DPIA-lite — replay sau containment

## 1. Dữ liệu gì

- search_docs nhận câu hỏi của người dùng và đọc toàn văn các ticket khớp
  trong corpus. Đây là nội dung không tin cậy, có thể chứa prompt injection,
  customer_id hoặc PII do người ghi tài liệu đưa vào.
- read_customer truy cập dữ liệu restricted trong data/customers.json: mã
  khách hàng, tên, CCCD, số điện thoại, số tài khoản, email và related_tickets.
- Replay này dùng --mock, vì vậy không gọi API của model provider. Nếu chạy
  --model, RealLLM gửi toàn văn ticket khớp tới API Anthropic để tóm tắt
  (agent/llm.py:111–130); nội dung đó có thể gồm PII.
- Ledger lưu timestamp, agent_id/run_id, tool, classification, decision,
  reason và args_hash (agent/ledger.py:57–91). Evidence replay hiện tại không
  chứa giá trị PII thô trong args_hash. Hàm detect/redact ở agent/pii.py tồn tại
  nhưng runner chưa gọi nó, vì vậy không coi đây là redaction đang vận hành.

## 2. Mục đích gì

Run A chỉ dùng câu hỏi để tìm ticket và trích ticket_id đã kiểu-hoá từ tên
file. Run B chỉ map ticket_id sang customer qua related_tickets để phục vụ
ngữ cảnh support/reconciliation hợp lệ; nó không nhận customer_id từ nội dung
tự do của ticket. Với --mock, đầu ra quan sát được là bản tóm tắt ticket, còn
nguyên tắc truy cập dữ liệu restricted là tối thiểu cần thiết cho luồng hỗ trợ.
Toàn bộ dữ liệu trong lab là synthetic và replay được thực hiện chỉ cho mục
đích kiểm thử containment.

## 3. Chảy đi đâu

~~~text
User query + corpus không tin cậy
        │
        ▼
Run A: search_docs ──► typed ticket_id từ tên file
        │                         │
        │                         ▼
        │                 Run B: related_tickets ──► read_customer
        │                                                   │
        └──── injected egress request ◄────────────────────┘
                                                    │
                                                    ▼
                         PEP: restricted + egress = DENY
                                                    │
                                                    ├──► ledger append-only
                                                    └──► không gọi sink
~~~

Trong replay Bước 4, reports/attack-after.log là 0 B và
reports/ledger.jsonl:23 ghi http_post với decision=deny và reason không rỗng;
do đó không có dữ liệu khách hàng đi tới localhost:9999. Sink chỉ là đích
mô phỏng nội bộ của lab; hard allowlist của tool giúp giới hạn đích nhưng
containment dựa trên split và PEP, không dựa vào allowlist.

Với --model, ticket khớp có thể đi tới API provider ở nước ngoài, là luồng
xuyên biên giới cần được lập hồ sơ, xác định cơ sở chuyển dữ liệu, thời hạn
lưu giữ và biện pháp bảo vệ phù hợp trước khi dùng thật. Lab hiện chưa có cơ
chế retention 60 ngày hoặc TTL, nên không tuyên bố đáp ứng phần đó của NĐ 356.

## 4. Trả lời câu hỏi chốt buổi

1. Containment loại bỏ việc một run đồng thời nắm cả ba chân trifecta:
   Run A đọc nội dung không tin cậy nhưng không đọc dữ liệu khách hàng/egress;
   Run B chỉ nhận ticket_id đã kiểm soát và PEP không cho dữ liệu restricted
   đi cùng egress. Agent vẫn có thể phục vụ ticket hợp lệ.
2. Nếu attacker ghi được corpus, PEP chặn egress restricted và ledger vẫn ghi
   evidence. Split vẫn chặn customer_id nằm trong free text, nhưng tên file
   corpus là một trust boundary: cần ACL hoặc kiểm tra toàn vẹn tên file để
   tránh attacker giả ticket_id hợp lệ và kích hoạt read_customer.
3. Đối với replay này, mở reports/attack-after.log cùng reports/ledger.jsonl
   và chạy ledger.verify() để kiểm tra hash chain. Đây là bằng chứng cho run
   đã ghi, không phải tuyên bố tuyệt đối rằng hệ thống chưa từng egress ở mọi
   thời điểm.
