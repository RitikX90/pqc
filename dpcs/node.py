# node.py
from utils import *
import numpy as np
import secrets


class Node:
    """
    Industrial IoT Node (N_i)

    Responsibilities:
    - Classical key generation
    - PQ key generation
    - Adaptive 3-state signing
    - Cross-bound hybrid signatures
    """

    def __init__(self, id_i: str, hca):

        self.id_i = id_i
        self.hca = hca

        # Global parameters from HCA
        self.A = hca.A
        self.p_CL = hca.p_CL
        self.q_CL = hca.q_CL
        self.g = hca.g
        self.v = hca.v

        # Key Generation
        self.sk_CL, self.pk_CL = self._cl_keygen()
        self.sk_PQ, self.pk_PQ, self.session_key = self._pq_keygen()

        self.pk = (self.pk_CL, self.pk_PQ)

    # =========================================================
    # CLASSICAL KEYGEN
    # =========================================================
    def _cl_keygen(self):

        sk_CL = secrets.randbelow(self.q_CL)

        T = []

        for i in range(K):
            Ti = pow(
                self.g,
                int(sk_CL * self.v[i]),
                self.p_CL
            )
            T.append(Ti)

        pk_CL = tuple(T)

        return sk_CL, pk_CL

    # =========================================================
    # PQ KEYGEN
    # =========================================================
    def _pq_keygen(self):

        challenge = secrets.token_bytes(16)

        puf_val = puf_emulator(challenge)
        trng_val = secrets.token_bytes(32)

        session_key = bytes(
            a ^ b for a, b in zip(puf_val, trng_val)
        )

        # Secret vectors
        s_PQ = sample_vector(N, SIGMA)
        e_PQ = sample_vector(M, SIGMA / 2)

        u_PQ = mat_vec_mul(self.A, s_PQ, Q)

        # noise vector same dimension as u_PQ
        v_PQ = e_PQ % Q

        w_PQ = (u_PQ + v_PQ) % Q

        pk_PQ = (u_PQ, v_PQ, w_PQ)

        return (s_PQ, e_PQ), pk_PQ, session_key

    # =========================================================
    # MAIN SIGN
    # =========================================================
    def sign(
        self,
        msg: bytes,
        timestamp: int,
        battery_level: float
    ):

        # -----------------------------------------------------
        # Mode selection
        # -----------------------------------------------------
        if battery_level > 0.7:

            trust_flag = "FULL_HYBRID"

            sigma_CL = self._cl_sign(msg, timestamp)

            sigma_PQ = self._pq_sign(
                msg,
                timestamp,
                sigma_CL[1][0]   # first response value
            )

        elif battery_level > 0.3:

            trust_flag = "PQ_ONLY"

            sigma_CL = None

            sigma_PQ = self._pq_sign(
                msg,
                timestamp,
                None
            )

        else:

            trust_flag = "CL_FALLBACK"

            sigma_CL = self._cl_sign(msg, timestamp)

            sigma_PQ = None

        # -----------------------------------------------------
        # Merkle leaf
        # -----------------------------------------------------
        cl_bytes = b""
        pq_bytes = b""

        if sigma_CL:
            cl_bytes = str(sigma_CL).encode()

        if sigma_PQ:
            pq_bytes = sigma_PQ[0].tobytes()

        leaf = merkle_leaf(
            cl_bytes +
            pq_bytes +
            msg +
            self.id_i.encode() +
            str(timestamp).encode()
        )

        return {
            "node_id": self.id_i,
            "sigma_CL": sigma_CL,
            "sigma_PQ": sigma_PQ,
            "leaf": leaf,
            "trust_flag": trust_flag,
            "timestamp": timestamp
        }

    # =========================================================
    # CLASSICAL SIGN
    # =========================================================
    def _cl_sign(self, msg: bytes, timestamp: int):

        r = [
            secrets.randbelow(self.q_CL)
            for _ in range(K)
        ]

        R = []

        for i in range(K):
            Ri = pow(
                self.g,
                int(r[i] * self.v[i]),
                self.p_CL
            )
            R.append(Ri)

        challenge_bytes = (
            msg +
            b"".join(str(x).encode() for x in R) +
            self.id_i.encode() +
            str(timestamp).encode()
        )

        ch_CL = int.from_bytes(
            shake_256(challenge_bytes).digest(8),
            "big"
        ) % self.q_CL

        s = []

        for i in range(K):
            si = (
                r[i] -
                ch_CL * self.sk_CL
            ) % self.q_CL

            s.append(si)

        return (R, s, ch_CL)

    # =========================================================
    # PQ SIGN
    # =========================================================
    def _pq_sign(
        self,
        msg: bytes,
        timestamp: int,
        s1_cl
    ):

        while True:

            # -----------------------------------------------
            # Message digest
            # -----------------------------------------------
            mu_PQ = shake_256(
                msg +
                self.id_i.encode() +
                str(timestamp).encode() +
                self.pk_PQ[2].tobytes()
            ).digest(32)

            # -----------------------------------------------
            # Random masking vectors
            # -----------------------------------------------
            y1 = sample_vector(N, SIGMA_Y)
            y2 = sample_vector(M, SIGMA_Y)

            # -----------------------------------------------
            # Commitments
            # -----------------------------------------------
            C_top = mat_vec_mul(self.A, y1, Q)
            C_bot = mat_vec_mul(self.A.T, y2, Q)

            challenge_bytes = (
                C_top.tobytes() +
                C_bot.tobytes() +
                mu_PQ
            )

            C_PQ = int.from_bytes(
                shake_256(challenge_bytes).digest(8),
                "big"
            ) % Q

            # -----------------------------------------------
            # Deterministic Cross-binding
            # -----------------------------------------------
            bind_vec = np.zeros(N, dtype=int)

            if s1_cl is not None:

                bind_val = hkdf_cross_bind(
                    int(s1_cl),
                    self.session_key
                )

                seed = int.from_bytes(
                    bind_val[:8],
                    "big"
                )

                rng = np.random.default_rng(seed)

                bind_vec = rng.integers(
                    -1,
                    2,
                    size=N
                )

            # -----------------------------------------------
            # Responses
            # -----------------------------------------------
            z1 = y1 + C_PQ * (
                self.sk_PQ[0] + bind_vec
            )

            z2 = (
                y2 +
                C_PQ * self.sk_PQ[1]
            ) % Q

            # -----------------------------------------------
            # Rejection bounds
            # -----------------------------------------------
            if (
                np.linalg.norm(z1) <= BETA and
                np.linalg.norm(z2) <= BETA
            ):
                return (
                    z1,
                    z2,
                    C_PQ,
                    C_top,
                    C_bot
                )