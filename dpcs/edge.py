# edge.py

from utils import *
import numpy as np


class Edge:
    """
    Edge Compute Node (ECN)

    Responsibilities:
    - First-pass verification
    - Lightweight filtering
    - Early rejection of invalid signatures
    - Append accepted leaves to local Merkle chain
    """

    def __init__(self):
        self.merkle = SimpleMerkle()

    # =====================================================
    # PARTIAL VERIFY
    # =====================================================
    def verify_partial(
        self,
        sigma,
        pk,
        msg: bytes,
        timestamp: int
    ):
        """
        Partial verification before cloud forwarding
        """

        trust_flag = sigma["trust_flag"]

        # =================================================
        # CLASSICAL PATH CHECK
        # =================================================
        if trust_flag in ["FULL_HYBRID", "CL_FALLBACK"]:

            if sigma["sigma_CL"] is None:
                return False

            R, s, ch_CL = sigma["sigma_CL"]
            pk_CL = pk[0]

            # Recompute challenge exactly like signer
            challenge_bytes = (
                msg +
                b"".join(str(x).encode() for x in R) +
                sigma["node_id"].encode() +
                str(timestamp).encode()
            )

            ch_prime = int.from_bytes(
                shake_256(challenge_bytes).digest(8),
                "big"
            ) % Q_CL

            if ch_prime != ch_CL:
                return False

            # Verify equations
            for i in range(K):

                lhs = (
                    pow(G, int(s[i] * V[i]), P_CL) *
                    pow(pk_CL[i], ch_CL, P_CL)
                ) % P_CL

                if lhs != R[i]:
                    return False

        # =================================================
        # PQ PATH LIGHT CHECK
        # =================================================
        if trust_flag in ["FULL_HYBRID", "PQ_ONLY"]:

            if sigma["sigma_PQ"] is None:
                return False

            z1, z2, _, _, _ = sigma["sigma_PQ"]

            # Norm checks only (fast edge filtering)
            if np.linalg.norm(z1) > BETA:
                return False

            if np.linalg.norm(z2) > BETA:
                return False

        # =================================================
        # MERKLE APPEND
        # =================================================
        self.merkle.append_leaf(sigma["leaf"])

        return True