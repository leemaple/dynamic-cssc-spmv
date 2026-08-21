from __future__ import annotations

from dynamic_cssc.cssc import build_cssc_layout


def test_cssc_proxy_sorts_rows_and_exposes_real_padding() -> None:
    layout = build_cssc_layout([1, 4, 2], effective_slots=8)
    assert layout.logical_row_order == (1, 2, 0)
    assert layout.ciphertext_count >= 1
    assert sum(len(slots) for slots in layout.padding_chunk_ids_by_logical_row) > 0


def test_cssc_proxy_rejects_too_tall_column() -> None:
    try:
        build_cssc_layout([1] * 9, effective_slots=8)
    except ValueError as exc:
        assert "exceeds effective slot capacity" in str(exc)
    else:
        raise AssertionError("expected capacity failure")
