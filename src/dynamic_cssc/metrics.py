from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class UnitCosts:
    label: str = "normalized-proxy-not-measured"
    encrypt: float = 8.0
    eval_mult: float = 24.0
    eval_rotate: float = 6.0
    eval_add: float = 1.0
    plaintext_mask: float = 3.0
    decrypt: float = 4.0
    client_merge: float = 0.1
    mask_random_element: float = 0.1
    mask_map_element: float = 0.01
    client_reorder_element: float = 0.01
    ciphertext_equivalent_bytes: float = 1.0


@dataclass(slots=True)
class StrategyMetrics:
    strategy: str
    category: str
    windows: int = 0
    queries: int = 0
    updates: int = 0
    update_encryptions: int = 0
    update_ciphertexts: int = 0
    compaction_ciphertexts: int = 0
    query_ciphertexts: int = 0
    result_ciphertexts: int = 0
    cc_multiplications: int = 0
    rotations: int = 0
    additions: int = 0
    plaintext_masks: int = 0
    blinding_mask_ciphertexts: int = 0
    blinding_dummy_ciphertexts: int = 0
    blinding_encryptions: int = 0
    blinding_additions: int = 0
    decryptions: int = 0
    client_merges: int = 0
    mask_random_elements: int = 0
    mask_mapped_elements: int = 0
    client_reorder_elements: int = 0
    metadata_units: int = 0
    overflow_updates: int = 0
    absorbed_updates: int = 0
    source: str = "predicted-proxy"

    def merge(self, other: StrategyMetrics) -> None:
        for field_name in self.__dataclass_fields__:
            if field_name in {"strategy", "category", "source"}:
                continue
            setattr(self, field_name, getattr(self, field_name) + getattr(other, field_name))

    def predicted_update_time(self, costs: UnitCosts) -> float:
        return self.update_encryptions * costs.encrypt

    def predicted_query_time(self, costs: UnitCosts) -> float:
        return (
            (self.query_ciphertexts + self.blinding_encryptions) * costs.encrypt
            + self.cc_multiplications * costs.eval_mult
            + self.rotations * costs.eval_rotate
            + (self.additions + self.blinding_additions) * costs.eval_add
            + self.plaintext_masks * costs.plaintext_mask
            + self.decryptions * costs.decrypt
            + self.client_merges * costs.client_merge
            + self.mask_random_elements * costs.mask_random_element
            + self.mask_mapped_elements * costs.mask_map_element
            + self.client_reorder_elements * costs.client_reorder_element
        )

    def predicted_query_time_per_query(self, costs: UnitCosts) -> float:
        if self.queries == 0:
            return 0.0
        return self.predicted_query_time(costs) / self.queries

    def predicted_time(self, costs: UnitCosts) -> float:
        return self.predicted_update_time(costs) + self.predicted_query_time(costs)

    def update_ct_equivalents(self) -> float:
        if self.updates == 0:
            return 0.0
        numerator = self.update_ciphertexts + self.compaction_ciphertexts
        return numerator / self.updates

    def to_record(self, costs: UnitCosts) -> dict[str, Any]:
        record = asdict(self)
        record["predicted_update_time"] = self.predicted_update_time(costs)
        record["predicted_query_time"] = self.predicted_query_time(costs)
        record["predicted_query_time_per_query"] = self.predicted_query_time_per_query(costs)
        record["predicted_normalized_time"] = self.predicted_time(costs)
        record["update_ct_equivalents_per_update"] = self.update_ct_equivalents()
        record["unit_cost_label"] = costs.label
        return record
