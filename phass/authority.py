# Generating the global parameters (which we already did in config.py with GLOBAL_P).

# Issuing certificates to devices and managing a Merkle accumulator for epoch tokens (which handles time-based validity or revocation).
import hashlib
import json
from config import GLOBAL_P, N, Q, generate_short_poly

class CertificateAuthority:
    def __init__(self):
        # The CA holds the public parameters
        self.public_p = GLOBAL_P
        
        # Simulating a database of registered devices and their epoch tokens
        self.registered_devices = {}
        
        # The root of our Merkle Accumulator
        self.merkle_root = None

    def hash_data(self, data):
        """Helper function to create a SHA-256 hash."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def register_device(self, device_id):
        """
        Registers a Consumer IoT Device.
        In PHASS, the device seeds its own secret polynomial s_i(x) using H-PUF.
        The CA issues a certificate/token for the current epoch.
        """
        print(f"[CA] Registering new device: {device_id}")
        
        # Generate an initial epoch token for the device
        epoch_token = self.hash_data(f"{device_id}_epoch_0")
        
        self.registered_devices[device_id] = {
            "status": "active",
            "epoch_token": epoch_token
        }
        
        # Update the Merkle Accumulator with the new device
        self.update_merkle_accumulator()
        
        return epoch_token

    def update_merkle_accumulator(self):
        """
        Simulates managing a Merkle accumulator for epoch tokens.
        Instead of a full binary tree, we aggregate all active tokens 
        into a single root hash to represent the current 'valid' state.
        """
        active_tokens = [
            info["epoch_token"] for info in self.registered_devices.values() 
            if info["status"] == "active"
        ]
        
        # Sort to ensure consistent hashing regardless of dictionary order
        active_tokens.sort()
        
        # Hash all active tokens together to create a new root
        accumulated_data = json.dumps(active_tokens)
        self.merkle_root = self.hash_data(accumulated_data)
        
        print(f"[CA] Merkle Accumulator updated. New Root: {self.merkle_root[:16]}...")

    def verify_device_token(self, epoch_token):
        """Checks if a device's token is currently valid in the system."""
        for info in self.registered_devices.values():
            if info["epoch_token"] == epoch_token and info["status"] == "active":
                return True
        return False

# Create a global instance of the CA for our simulation to use
ca_instance = CertificateAuthority()