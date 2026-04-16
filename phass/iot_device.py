import numpy as np
import hashlib
from config import GLOBAL_P, Q, generate_short_poly, hadamard_product, poly_add

class IoTDevice:
    def __init__(self, device_id, ca_instance):
        self.device_id = device_id
        
        # 1. Simulate H-PUF Biometric Seeding to get Secret Key (s)
        print(f"[{self.device_id}] Simulating H-PUF to seed secret key...")
        self.secret_key = generate_short_poly()
        
        # 2. Generate Public Key: pk = p ⊛ s
        self.public_key = hadamard_product(GLOBAL_P, self.secret_key)
        
        # 3. Register with the Certificate Authority to get an epoch token
        self.epoch_token = ca_instance.register_device(self.device_id)
        print(f"[{self.device_id}] Initialization complete. Public Key generated.\n")

    def generate_challenge(self, message, R):
        """
        Creates a scalar challenge 'c' based on the message and commitment R.
        This binds the signature to the specific message.
        """
        hash_input = message + str(R.tolist())
        hash_hex = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
        # Return a small integer challenge to keep coefficients from blowing up
        return int(hash_hex, 16) % 10 

    def sign_data(self, message):
        """
        Implements the PHASS-PartialSign equation.
        """
        # Step 1: Generate random short noise (y)
        y = generate_short_poly(bound=10)
        
        # Step 2: Calculate Commitment (R) -> R = p ⊛ y
        R = hadamard_product(GLOBAL_P, y)
        
        # Step 3: Get cryptographic challenge (c)
        c = self.generate_challenge(message, R)
        
        # Step 4: Calculate Response (z) -> z = y + c * s (pointwise)
        # Multiply secret key by scalar challenge 'c', then add 'y'
        scaled_s = np.mod(c * self.secret_key, Q)
        z = poly_add(y, scaled_s)
        
        print(f"[{self.device_id}] Generated PHASS signature for: '{message}'")
        
        return {
            "device_id": self.device_id,
            "message": message,
            "epoch_token": self.epoch_token,
            "signature": {"R": R, "z": z, "c": c},
            "public_key": self.public_key
        }