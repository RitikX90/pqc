# hca.py

from utils import *
import time


class HCA:
    """
    Hybrid Certificate Authority (H-CA)

    Responsibilities:
    - Publish global parameters
    - Register devices
    - Issue dual certificates
    - Maintain epoch Merkle registry
    """

    def __init__(self):

        # =================================================
        # Global Public Parameters
        # =================================================
        self.A = sample_matrix(M, N, Q)

        self.p_CL = P_CL
        self.q_CL = Q_CL
        self.g = G
        self.v = V.copy()

        # =================================================
        # Certificate / Registry State
        # =================================================
        self.registry = {}
        self.merkle = SimpleMerkle()

    # =====================================================
    # ISSUE DUAL CERTIFICATE
    # =====================================================
    def issue_dual_cert(
        self,
        id_i: str,
        pk_CL: tuple,
        pk_PQ: tuple,
        epoch: int
    ):
        """
        Register node and issue hybrid certificate
        """

        issued_at = int(time.time())

        # -----------------------------------------------
        # Certificate payload
        # -----------------------------------------------
        cert_payload = {
            "node_id": id_i,
            "pk_CL": tuple(pk_CL),
            "epoch": epoch,
            "issued_at": issued_at
        }

        # PQ arrays converted for readable storage
        pq_payload = {
            "u": pk_PQ[0].tolist(),
            "v": pk_PQ[1].tolist(),
            "w": pk_PQ[2].tolist()
        }

        cert_payload["pk_PQ"] = pq_payload

        # -----------------------------------------------
        # Simulated CA signature
        # -----------------------------------------------
        cert_string = str(cert_payload).encode()

        ca_signature = shake_256(
            cert_string + b"HCA_ROOT"
        ).hexdigest(32)

        # -----------------------------------------------
        # Merkle leaf
        # -----------------------------------------------
        leaf = merkle_leaf(cert_string)

        idx = self.merkle.append_leaf(leaf)

        # simulated root / proof
        R_epoch = self._compute_epoch_root()
        pi_epoch = self.merkle.get_proof(idx)

        # -----------------------------------------------
        # Final certificate object
        # -----------------------------------------------
        certificate = {
            "payload": cert_payload,
            "ca_sig": ca_signature
        }

        # Save registry
        self.registry[id_i] = certificate

        return {
            "cert": certificate,
            "R_epoch": R_epoch,
            "pi_epoch": pi_epoch,
            "A_global": self.A
        }

    # =====================================================
    # ROOT COMPUTE
    # =====================================================
    def _compute_epoch_root(self):
        """
        Lightweight simulated Merkle root
        """
        if len(self.merkle.chain) == 0:
            return b"EMPTY_ROOT"

        combined = b"".join(self.merkle.chain)

        return shake_256(combined).digest(32)

    # =====================================================
    # LOOKUP CERTIFICATE
    # =====================================================
    def get_certificate(self, node_id: str):

        return self.registry.get(node_id, None)

    # =====================================================
    # VERIFY CERTIFICATE
    # =====================================================
    def verify_certificate(self, cert_obj):

        cert_payload = cert_obj["payload"]

        cert_string = str(cert_payload).encode()

        expected_sig = shake_256(
            cert_string + b"HCA_ROOT"
        ).hexdigest(32)

        return expected_sig == cert_obj["ca_sig"]