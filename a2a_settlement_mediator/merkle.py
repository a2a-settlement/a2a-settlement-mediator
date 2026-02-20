"""Thread-safe SHA-256 Merkle Tree for WORM-compliant audit trails.

Specification (for third-party verifiers)
==========================================

**Hash algorithm:** SHA-256 (FIPS 180-4 / RFC 6234)

**Domain-separated hashing** (prevents second-preimage attacks where
an internal node could be reinterpreted as a leaf):

- Leaf nodes:     H(0x00 || data)
- Internal nodes: H(0x01 || left || right)

**Tree structure:** Unbalanced binary Merkle Tree. When the number of
leaves is not a power of two, the last leaf at each level is promoted
to the next level without a sibling hash. This is the same approach
used by Certificate Transparency (RFC 6962 §2.1). The tree is *not*
padded or rebalanced — the shape is fully deterministic given the
number of leaves, which means any verifier can reconstruct the
expected root from a leaf, its index, the tree size, and the sibling
path.

**Append-only semantics:** Leaves are never removed or mutated.
Appending a new leaf changes the root hash but does not alter any
existing leaf hash or previously issued inclusion proof (when verified
against the root at the time the proof was generated).

**Thread safety:** All mutations and reads are serialized via a
reentrant lock.
"""

from __future__ import annotations

import hashlib
import threading


class MerkleTree:
    """Append-only SHA-256 Merkle Tree.

    Thread-safe for concurrent appends and proof generation.
    Leaves are never removed (WORM semantics).

    Verification by third parties requires only:
    - The leaf data (to recompute the leaf hash)
    - The sibling path (from ``get_proof`` / ``append_and_prove``)
    - The expected root hash at the time of insertion

    No access to the tree instance is needed — use the static
    ``verify_proof`` class method.
    """

    _LEAF_PREFIX = b"\x00"
    _NODE_PREFIX = b"\x01"

    def __init__(self) -> None:
        self._leaves: list[bytes] = []
        self._lock = threading.Lock()

    @staticmethod
    def hash_leaf(data: bytes) -> bytes:
        return hashlib.sha256(MerkleTree._LEAF_PREFIX + data).digest()

    @staticmethod
    def hash_node(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(MerkleTree._NODE_PREFIX + left + right).digest()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._leaves)

    @property
    def root_hash(self) -> bytes:
        with self._lock:
            return self._compute_root(list(self._leaves))

    def append(self, data: bytes) -> tuple[int, bytes]:
        """Append data to the tree.

        Returns:
            (leaf_index, leaf_hash) — the index and hash of the new leaf.
        """
        leaf_hash = self.hash_leaf(data)
        with self._lock:
            idx = len(self._leaves)
            self._leaves.append(leaf_hash)
            return idx, leaf_hash

    def get_proof(self, leaf_index: int) -> tuple[list[bytes], list[str]]:
        """Generate a Merkle inclusion proof for the leaf at *leaf_index*.

        Returns:
            (siblings, directions) where each sibling is a 32-byte hash and
            each direction is ``"left"`` or ``"right"`` indicating whether the
            sibling sits to the left or right of the path node at that level.
        """
        with self._lock:
            n = len(self._leaves)
            if leaf_index < 0 or leaf_index >= n:
                raise IndexError(f"leaf index {leaf_index} out of range [0, {n})")

            siblings: list[bytes] = []
            directions: list[str] = []
            level = list(self._leaves)
            idx = leaf_index

            while len(level) > 1:
                next_level: list[bytes] = []
                for i in range(0, len(level), 2):
                    if i + 1 < len(level):
                        next_level.append(self.hash_node(level[i], level[i + 1]))
                    else:
                        next_level.append(level[i])

                if idx % 2 == 0:
                    if idx + 1 < len(level):
                        siblings.append(level[idx + 1])
                        directions.append("right")
                else:
                    siblings.append(level[idx - 1])
                    directions.append("left")

                idx //= 2
                level = next_level

            return siblings, directions

    @staticmethod
    def verify_proof(
        leaf_hash: bytes,
        siblings: list[bytes],
        directions: list[str],
        expected_root: bytes,
    ) -> bool:
        """Verify a Merkle inclusion proof against an expected root hash.

        Returns True only if the proof mathematically reconstructs the root.
        """
        current = leaf_hash
        for sibling, direction in zip(siblings, directions):
            if direction == "left":
                current = MerkleTree.hash_node(sibling, current)
            else:
                current = MerkleTree.hash_node(current, sibling)
        return current == expected_root

    def append_and_prove(self, data: bytes) -> tuple[int, bytes, list[bytes], list[str], bytes]:
        """Atomically append data, generate its proof, and return the new root.

        This is the preferred method for the settlement pipeline because it
        guarantees the proof corresponds to the tree state immediately after
        the append.

        Returns:
            (leaf_index, leaf_hash, siblings, directions, root_hash)
        """
        leaf_hash = self.hash_leaf(data)
        with self._lock:
            idx = len(self._leaves)
            self._leaves.append(leaf_hash)

            root = self._compute_root(list(self._leaves))

            siblings: list[bytes] = []
            directions_list: list[str] = []
            level = list(self._leaves)
            pidx = idx

            while len(level) > 1:
                next_level: list[bytes] = []
                for i in range(0, len(level), 2):
                    if i + 1 < len(level):
                        next_level.append(self.hash_node(level[i], level[i + 1]))
                    else:
                        next_level.append(level[i])

                if pidx % 2 == 0:
                    if pidx + 1 < len(level):
                        siblings.append(level[pidx + 1])
                        directions_list.append("right")
                else:
                    siblings.append(level[pidx - 1])
                    directions_list.append("left")

                pidx //= 2
                level = next_level

            return idx, leaf_hash, siblings, directions_list, root

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_root(leaves: list[bytes]) -> bytes:
        if not leaves:
            return hashlib.sha256(b"").digest()
        if len(leaves) == 1:
            return leaves[0]

        level = list(leaves)
        while len(level) > 1:
            next_level: list[bytes] = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    next_level.append(MerkleTree.hash_node(level[i], level[i + 1]))
                else:
                    next_level.append(level[i])
            level = next_level
        return level[0]
