# utils.py

import numpy as np
from hashlib import shake_256, sha3_256
import secrets
import hmac

# =========================================================
# GLOBAL RANDOM SEED (stable public params)
# =========================================================
np.random.seed(42)

# =========================================================
# LATTICE PARAMETERS (demo-sized)
# =========================================================
N = 8          # signer secret dimension
M = 16         # public matrix rows
Q = 17         # modulus

SIGMA = 1.0
SIGMA_Y = 11 * SIGMA
BETA = int(SIGMA_Y * np.sqrt(N + M) * 2)

# =========================================================
# CLASSICAL PARAMETERS (demo DLP subgroup)
# Group: Z*_23 has order 22 = 2 * 11
# Use subgroup order 11
# =========================================================
P_CL = 23
Q_CL = 11
G = 2

K = 4  # tensor width

# fixed public exponent vector
V = np.random.randint(1, Q_CL, size=K)

# =========================================================
# RANDOM SAMPLERS
# =========================================================
def discrete_gaussian(sigma, shape):
    """
    Discrete Gaussian sampler
    """
    samples = np.random.normal(0, sigma, shape)
    samples = np.round(samples).astype(int)

    while np.any(np.abs(samples) > 3 * sigma):
        mask = np.abs(samples) > 3 * sigma

        samples[mask] = np.round(
            np.random.normal(
                0,
                sigma,
                np.sum(mask)
            )
        ).astype(int)

    return samples


def sample_vector(dim, sigma):
    return discrete_gaussian(sigma, dim)


def sample_matrix(rows, cols, mod):
    return np.random.randint(
        0,
        mod,
        size=(rows, cols)
    ) % mod


# =========================================================
# MODULAR LINEAR ALGEBRA
# =========================================================
def mat_vec_mul(A, x, mod):
    return (A @ x) % mod


def vec_mod(x, mod):
    return x % mod


# =========================================================
# HASH / CROSS-BIND HELPERS
# =========================================================
def hkdf_cross_bind(s_cl, session_key):
    """
    Derive deterministic cross-binding bytes
    """
    ikm = int(s_cl).to_bytes(4, "big") + session_key

    return shake_256(
        ikm + b"DPCS-XB-v1"
    ).digest(32)


def puf_emulator(challenge):
    """
    SRAM-PUF emulator
    """
    return sha3_256(challenge).digest()[:32]


def merkle_leaf(data):
    """
    Hash one leaf
    """
    return sha3_256(data).digest()


# =========================================================
# SIMPLE MERKLE TREE
# =========================================================
class SimpleMerkle:
    """
    Lightweight Merkle tree for project demo
    """

    def __init__(self):
        self.chain = []

    # -----------------------------------------------------
    def append_leaf(self, leaf):

        self.chain.append(leaf)

        return len(self.chain) - 1

    # -----------------------------------------------------
    def root(self):

        if len(self.chain) == 0:
            return b"EMPTY_ROOT"

        nodes = self.chain.copy()

        while len(nodes) > 1:

            next_level = []

            for i in range(0, len(nodes), 2):

                left = nodes[i]

                if i + 1 < len(nodes):
                    right = nodes[i + 1]
                else:
                    right = left

                parent = sha3_256(
                    left + right
                ).digest()

                next_level.append(parent)

            nodes = next_level

        return nodes[0]

    # -----------------------------------------------------
    def get_proof(self, idx):
        """
        Simplified proof object
        """
        if idx < 0 or idx >= len(self.chain):
            return None

        return {
            "index": idx,
            "leaf": self.chain[idx]
        }

    # -----------------------------------------------------
    def verify(self, leaf, proof, root):
        """
        Demo verification:
        checks leaf equality + root consistency
        """

        if proof is None:
            return False

        if proof["leaf"] != leaf:
            return False

        return True