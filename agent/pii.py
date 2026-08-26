"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# Thứ tự ưu tiên khi 2 loại cùng khớp một vùng ký tự (áp dụng lúc lọc
# overlap): EMAIL/CCCD/PHONE là các mẫu "chắc chắn" hơn STK (chỉ là dãy số
# trần), nên STK bị loại nếu trùng vùng với 1 trong 3 loại kia.
_PRIORITY = {"EMAIL": 0, "VN_CCCD": 1, "VN_PHONE": 2, "VN_BANK_ACCOUNT": 3}

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# CCCD: đúng 12 chữ số liên tiếp, không đứng liền số/chữ khác 2 bên
# (word boundary số không hoạt động tốt vì \b coi chữ số là "word char" —
# dùng lookaround thủ công để tránh khớp vào giữa 1 dãy số dài hơn).
_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
# SĐT VN: bắt đầu bằng 0, tổng 10-11 chữ số, cho phép khoảng trắng/gạch nối
_PHONE_RE = re.compile(r"(?<!\d)0[\d\-\s]{8,10}\d(?!\d)")
# STK: 8-16 chữ số liên tiếp (rộng hơn CCCD/PHONE nên xử lý overlap sau)
_BANK_RE = re.compile(r"(?<!\d)\d{8,16}(?!\d)")


_BANK_CONTEXT_RE = re.compile(r"(stk|so tai khoan|tai khoan)", re.IGNORECASE)


def _has_bank_context(text: str, start: int) -> bool:
    window = text[max(0, start - 20) : start]
    normalized = window.lower().replace("ố", "o").replace("à", "a")
    return bool(_BANK_CONTEXT_RE.search(normalized)) or "stk" in window.lower()


def _raw_matches(text: str) -> list[dict]:
    matches: list[dict] = []
    for m in _EMAIL_RE.finditer(text):
        matches.append({"type": "EMAIL", "start": m.start(), "end": m.end()})
    for m in _CCCD_RE.finditer(text):
        # 12 chữ số ngay sau ngữ cảnh "STK"/"tài khoản" -> STK, không phải CCCD
        entity_type = "VN_BANK_ACCOUNT" if _has_bank_context(text, m.start()) else "VN_CCCD"
        matches.append({"type": entity_type, "start": m.start(), "end": m.end()})
    for m in _PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if len(digits) in (10, 11):
            matches.append({"type": "VN_PHONE", "start": m.start(), "end": m.end()})
    for m in _BANK_RE.finditer(text):
        matches.append({"type": "VN_BANK_ACCOUNT", "start": m.start(), "end": m.end()})
    return matches


def _overlaps(a: dict, b: dict) -> bool:
    return a["start"] < b["end"] and b["start"] < a["end"]


def detect(text: str) -> list[dict]:
    candidates = _raw_matches(text)
    # Sắp theo (span dài nhất trước, rồi priority) để khi loại overlap, giữ
    # lại ứng viên "chắc chắn" nhất cho mỗi vùng ký tự.
    candidates.sort(key=lambda e: (-(e["end"] - e["start"]), _PRIORITY[e["type"]]))

    kept: list[dict] = []
    for cand in candidates:
        if any(_overlaps(cand, k) for k in kept):
            continue
        kept.append(cand)

    kept.sort(key=lambda e: e["start"])
    return kept


def redact(text: str) -> str:
    entities = sorted(detect(text), key=lambda e: e["start"], reverse=True)
    for entity in entities:
        placeholder = f"[REDACTED_{entity['type']}]"
        text = text[: entity["start"]] + placeholder + text[entity["end"] :]
    return text
