from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from icsfuzz.feedback.afl_shm import AFLSharedMemory


# Mirrors afl-fuzz.c's count_class_lookup8 (classify_counts()):
#   0 -> 0
#   1 -> 1
#   2 -> 2
#   3 -> 4
#   4-7 -> 8
#   8-15 -> 16
#   16-31 -> 32
#   32-127 -> 64
#   128+ -> 128
AFL_BUCKETS = bytearray(256)
for i in range(256):
    if i == 0:
        AFL_BUCKETS[i] = 0
    elif i == 1:
        AFL_BUCKETS[i] = 1
    elif i == 2:
        AFL_BUCKETS[i] = 2
    elif i == 3:
        AFL_BUCKETS[i] = 4
    elif i <= 7:
        AFL_BUCKETS[i] = 8
    elif i <= 15:
        AFL_BUCKETS[i] = 16
    elif i <= 31:
        AFL_BUCKETS[i] = 32
    elif i <= 127:
        AFL_BUCKETS[i] = 64
    else:
        AFL_BUCKETS[i] = 128
AFL_BUCKETS_BYTES = bytes(AFL_BUCKETS)

# Map any non-zero hit count to exactly 1 (distinct edge-slot presence, ignoring hitcounts).
EDGE_MASK = bytes([0] + [1] * 255)


class CoverageBitmap:
    """Tracks coverage using the AFL/AFLNet shared memory bitmap.

    Notes (aligned to this repo):
    - MAP_SIZE is 64KB (2^16).
    - SHIFT_SIZE is 32KB; AFLNet uses lower half for protocol-state coverage and
      shifts code coverage into the upper half.
    - AFL's "new bits" logic is based on *bucketed* counts (classify_counts).
    - "new edges / tuples" in the common sense corresponds to seeing a previously
      untouched byte position become non-zero at least once.
    """

    DEFAULT_SIZE = 1 << 16  # MAP_SIZE_POW2=16 in config.h
    DEFAULT_SHIFT_SIZE = 1 << 15  # SHIFT_SIZE in config.h

    def __init__(
        self,
        size: int = DEFAULT_SIZE,
        shm: "AFLSharedMemory | None" = None,
        *,
        clear_on_update: bool = False,
        shift_size: int = DEFAULT_SHIFT_SIZE,
    ):
        self.size = int(size)
        self.shift_size = int(shift_size)
        self.shm = shm
        self.clear_on_update = clear_on_update

        # Bucketed global coverage (hitcount buckets); used to mirror has_new_bits' "ret==1" condition.
        self._global_bucketed_int = 0

        # Presence-only global coverage (byte position ever non-zero); used for edge-slot totals.
        self._global_edges_int = 0

        self._total_edges = 0
        self._total_state_edges = 0
        self._total_code_edges = 0

    @property
    def total_edges(self) -> int:
        return self._total_edges

    @property
    def total_state_edges(self) -> int:
        """Coverage count for protocol-state coverage (lower SHIFT_SIZE bytes)."""
        return self._total_state_edges

    @property
    def total_code_edges(self) -> int:
        """Coverage count for code coverage (upper SHIFT_SIZE bytes)."""
        return self._total_code_edges

    def update(self, new_bitmap: bytes | None = None) -> int:
        """Update coverage from `new_bitmap` or from `shm`.

        Returns:
        - >0: number of newly discovered edge slots (byte positions that became non-zero globally).
        - 1:  if there is new bucketed coverage but no new edge slots (AFL has_new_bits() ret==1 analogue).
        - 0:  if no new bucketed coverage at all.
        """

        if new_bitmap is None and self.shm is not None:
            new_bitmap = self.shm.read_bitmap()

        if not new_bitmap:
            return 0

        # AFL always reasons over a fixed MAP_SIZE buffer.
        # If the producer gives fewer bytes, treat the rest as zeros (no coverage).
        raw = bytes(new_bitmap[: self.size])
        if len(raw) < self.size:
            raw = raw + (b"\x00" * (self.size - len(raw)))

        # (1) Bucket hit counts exactly like afl-fuzz.c classify_counts().
        bucketed = raw.translate(AFL_BUCKETS_BYTES)
        bucketed_int = int.from_bytes(bucketed, "little", signed=False)

        # New bucketed bits compared to global.
        new_bucketed_mask = bucketed_int & ~self._global_bucketed_int

        new_edges_count = 0

        if new_bucketed_mask:
            self._global_bucketed_int |= bucketed_int

            # (2) Presence-only bitmap: any non-zero -> 1 (so byte positions are counted once).
            edges = raw.translate(EDGE_MASK)
            edges_int = int.from_bytes(edges, "little", signed=False)
            new_edge_slots_mask = edges_int & ~self._global_edges_int

            if new_edge_slots_mask:
                self._global_edges_int |= edges_int

                bit_shift = self.shift_size * 8
                if bit_shift < 0 or bit_shift > self.size * 8:
                    raise ValueError(
                        f"shift_size={self.shift_size} is inconsistent with size={self.size}"
                    )

                state_mask = new_edge_slots_mask & ((1 << bit_shift) - 1)
                code_mask = new_edge_slots_mask >> bit_shift

                new_state = state_mask.bit_count()
                new_code = code_mask.bit_count()

                self._total_state_edges += new_state
                self._total_code_edges += new_code

                new_edges_count = new_state + new_code
                self._total_edges += new_edges_count

        # IMPORTANT: only clear if you *own* execution / SHM lifecycle.
        if self.shm is not None and self.clear_on_update:
            self.shm.clear()

        # Mirror AFL has_new_bits(): "1" means bucket change only.
        if new_bucketed_mask and new_edges_count == 0:
            return 1

        return new_edges_count

    def get_coverage_ratio(self) -> float:
        if self.size <= 0:
            return 0.0
        return self._total_edges / self.size

    def reset(self) -> None:
        self._global_bucketed_int = 0
        self._global_edges_int = 0
        self._total_edges = 0
        self._total_state_edges = 0
        self._total_code_edges = 0

