# audit.py

from utils import *
import time


class AuditAuthority:
    """
    Audit Authority (AA)

    Responsibilities:
    - Cross-epoch log verification
    - Merkle proof validation
    - Bulk integrity audit
    - Performance reporting
    """

    def __init__(self):
        self.audit_logs = []

    # =====================================================
    # MAIN AUDIT
    # =====================================================
    def audit(
        self,
        epoch_root,
        proofs,
        leaves=None,
        num_msgs=None
    ):
        """
        Verify batch proofs against epoch root

        Parameters:
        ----------
        epoch_root : bytes
            Root hash of epoch

        proofs : list
            List of proof objects

        leaves : list
            Corresponding leaf hashes

        num_msgs : int
            Optional count override
        """

        start = time.perf_counter()

        # -------------------------------------------------
        # Default leaf handling
        # -------------------------------------------------
        if leaves is None:
            leaves = []

            for p in proofs:
                if isinstance(p, dict) and "leaf" in p:
                    leaves.append(p["leaf"])
                else:
                    leaves.append(b"")

        total = len(leaves)

        if num_msgs is not None:
            total = num_msgs

        # -------------------------------------------------
        # Verification Loop
        # -------------------------------------------------
        valid_count = 0

        merkle = SimpleMerkle()

        for leaf, proof in zip(leaves, proofs):

            ok = merkle.verify(
                leaf,
                proof,
                epoch_root
            )

            if ok:
                valid_count += 1

        # -------------------------------------------------
        # Timing
        # -------------------------------------------------
        elapsed_ms = (
            time.perf_counter() - start
        ) * 1000

        all_valid = (valid_count == len(proofs))

        # -------------------------------------------------
        # Store log
        # -------------------------------------------------
        log_entry = {
            "verified": valid_count,
            "total": len(proofs),
            "elapsed_ms": round(elapsed_ms, 3),
            "result": all_valid
        }

        self.audit_logs.append(log_entry)

        # -------------------------------------------------
        # Output
        # -------------------------------------------------
        print("=" * 50)
        print("Audit Authority Report")
        print("=" * 50)
        print(f"Messages Checked : {total}")
        print(f"Valid Proofs     : {valid_count}/{len(proofs)}")
        print(f"Execution Time   : {elapsed_ms:.3f} ms")
        print(f"Final Result     : {'PASS' if all_valid else 'FAIL'}")
        print("=" * 50)

        return all_valid

    # =====================================================
    # HISTORY
    # =====================================================
    def get_logs(self):
        return self.audit_logs