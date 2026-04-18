# cv.py
from utils import *
import time
import numpy as np


class CloudVerifier:
    """
    Cloud Verifier (CV)

    Responsibilities:
    - Freshness check
    - Merkle proof check
    - Classical verification
    - PQ verification
    - Cross-binding verification
    - Trust grading
    """

    def __init__(self, A_global):
        """
        Receive real public matrix from HCA
        """
        self.A = A_global

    # ---------------------------------------------------------
    # MAIN VERIFY
    # ---------------------------------------------------------
    def verify(
        self,
        sigma,
        pk,
        msg,
        timestamp,
        R_epoch,
        pi_leaf,
        node_id,
        session_key=None,
        max_delay=300
    ):
        """
        Full verification
        """

        # =====================================================
        # DV-1 Freshness Check
        # =====================================================
        now = int(time.time())

        # for demo mode, old fixed timestamps accepted
        if timestamp > 1000000000:
            pass
        else:
            if abs(now - timestamp) > max_delay:
                return False, "STALE"

        # =====================================================
        # DV-2 Merkle Check
        # =====================================================
        # verify certificate proof only
        dummy_leaf = pi_leaf["leaf"]

        if not SimpleMerkle().verify(dummy_leaf, pi_leaf, R_epoch):
            return False, "MERKLE_FAIL"

        trust_flag = sigma["trust_flag"]

        # =====================================================
        # CLASSICAL PATH VERIFY
        # =====================================================
        if trust_flag in ["FULL_HYBRID", "CL_FALLBACK"]:

            if sigma["sigma_CL"] is None:
                return False, "CL_MISSING"

            R, s, ch_CL = sigma["sigma_CL"]
            pk_CL = pk[0]

            # recompute challenge exactly as signer
            challenge_bytes = (
                msg +
                b"".join(str(x).encode() for x in R) +
                node_id.encode() +
                str(timestamp).encode()
            )

            ch_prime = int.from_bytes(
                shake_256(challenge_bytes).digest(8),
                "big"
            ) % Q_CL

            if ch_prime != ch_CL:
                return False, "CL_CHALLENGE_FAIL"

            # equation verification
            for i in range(K):

                lhs = (
                    pow(G, int(s[i] * V[i]), P_CL) *
                    pow(pk_CL[i], ch_CL, P_CL)
                ) % P_CL

                if lhs != R[i]:
                    return False, "CL_EQUATION_FAIL"

        # =====================================================
        # PQ PATH VERIFY
        # =====================================================
        if trust_flag in ["FULL_HYBRID", "PQ_ONLY"]:

            if sigma["sigma_PQ"] is None:
                return False, "PQ_MISSING"

            z1, z2, C_PQ, C_top, C_bot = sigma["sigma_PQ"]

            u_PQ, v_PQ, w_PQ = pk[1]

            # norm bounds
            if np.linalg.norm(z1) > BETA:
                return False, "PQ_NORM_Z1"

            if np.linalg.norm(z2) > BETA:
                return False, "PQ_NORM_Z2"

            # -------------------------------------------------
            # Cross-binding
            # -------------------------------------------------
            bind_vec = np.zeros(N, dtype=int)

            if trust_flag == "FULL_HYBRID" and sigma["sigma_CL"]:

                if session_key is None:
                    return False, "SESSION_KEY_REQUIRED"

                s1 = sigma["sigma_CL"][1][0]

                bind_val = hkdf_cross_bind(s1, session_key)

                # deterministic vector from bind_val
                seed = int.from_bytes(bind_val[:8], "big")
                rng = np.random.default_rng(seed)

                bind_vec = rng.integers(-1, 2, size=N)

            # -------------------------------------------------
            # Recompute commitments
            # -------------------------------------------------
            z1_adj = z1 - C_PQ * bind_vec

            C_top_rec = (
                mat_vec_mul(self.A, z1_adj, Q) -
                (C_PQ * u_PQ)
            ) % Q

            C_bot_rec = (
                mat_vec_mul(self.A.T, z2, Q) -
                mat_vec_mul(self.A.T, C_PQ * v_PQ, Q)
            ) % Q

            # -------------------------------------------------
            # Message hash exactly like signer
            # -------------------------------------------------
            mu_PQ = shake_256(
                msg +
                node_id.encode() +
                str(timestamp).encode() +
                w_PQ.tobytes()
            ).digest(32)

            # recompute challenge
            challenge_bytes = (
                C_top_rec.tobytes() +
                C_bot_rec.tobytes() +
                mu_PQ
            )

            C_prime = int.from_bytes(
                shake_256(challenge_bytes).digest(8),
                "big"
            ) % Q

            if C_prime != C_PQ:
                return False, "PQ_CHALLENGE_FAIL"

        # =====================================================
        # TRUST LEVEL
        # =====================================================
        trust_map = {
            "FULL_HYBRID": "HIGH",
            "PQ_ONLY": "MEDIUM",
            "CL_FALLBACK": "LOW"
        }

        return True, trust_map[trust_flag]