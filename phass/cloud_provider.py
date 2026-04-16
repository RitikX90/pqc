import numpy as np
import hashlib
from config import GLOBAL_P, Q, hadamard_product, poly_sub, poly_add

class CloudProvider:
    def __init__(self):
        # Initialize the starting point for our database's Hash Chain
        self.hash_chain_tail = "GENESIS_BLOCK_HASH"
        self.database = []

    def verify_aggregate(self, aggregated_payload):
        """
        Verifies the aggregated signature using the PHASS Verify Eq.
        Equation for single: p ⊛ z - c * pk = R
        Equation for aggregate: (p ⊛ z_agg) - Sum(c_i * pk_i) = R_agg
        """
        print("\n[CSP] Verifying Level-1 Aggregated Signature...")
        
        sig = aggregated_payload["aggregate_signature"]
        z_agg = sig["z_agg"]
        R_agg = sig["R_agg"]
        c_list = sig["c_list"]
        pk_list = sig["pk_list"]

        # Step 1: Calculate (p ⊛ z_agg)
        p_z_agg = hadamard_product(GLOBAL_P, z_agg)

        # Step 2: Calculate the sum of all (c_i * pk_i)
        sum_c_pk = np.zeros(len(GLOBAL_P), dtype=int)
        for c, pk in zip(c_list, pk_list):
            # Scale public key by the challenge 'c'
            c_pk = np.mod(c * pk, Q)
            # Add it to the running total
            sum_c_pk = poly_add(sum_c_pk, c_pk)

        # Step 3: Subtract the sum from (p ⊛ z_agg)
        left_side_of_equation = poly_sub(p_z_agg, sum_c_pk)

        # Step 4: Check if the left side equals the aggregated commitment (R_agg)
        if np.array_equal(left_side_of_equation, R_agg):
            print("[CSP] ✅ Verification SUCCESS! All signatures are mathematically valid.")
            # If valid, securely store the data
            self.store_in_hash_chain(aggregated_payload["messages"])
            return True
        else:
            print("[CSP] ❌ Verification FAILED! Rejecting payload.")
            return False

    def store_in_hash_chain(self, messages):
        """
        Implements the 'Stores data with hash chain' role from the System Entities table.
        Each new piece of data is hashed together with the hash of the PREVIOUS piece of data.
        """
        for msg in messages:
            # Bind the new message with the previous hash
            chain_input = f"{self.hash_chain_tail}|{msg}"
            new_hash = hashlib.sha256(chain_input.encode('utf-8')).hexdigest()
            
            # Store in "database"
            self.database.append({
                "message": msg,
                "chain_hash": new_hash
            })
            
            # Update the tail for the next item
            self.hash_chain_tail = new_hash
            
        print(f"[CSP] Securely stored {len(messages)} messages in the Hash Chain.")