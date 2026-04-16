import numpy as np
from config import GLOBAL_P, Q, poly_add, hadamard_product

class HomeGateway:
    def __init__(self, ca_instance):
        self.ca_instance = ca_instance
        self.packet_buffer = []

    def receive_data(self, data_packet):
        """Receives a signed data packet from an IoT device."""
        device_id = data_packet["device_id"]
        epoch_token = data_packet["epoch_token"]

        # 1. Check with CA if the device is valid/not revoked
        if not self.ca_instance.verify_device_token(epoch_token):
            print(f"[HGW] REJECTED {device_id}: Invalid or expired epoch token.")
            return False

        print(f"[HGW] Received valid packet from {device_id}. Buffering...")
        self.packet_buffer.append(data_packet)
        return True

    def aggregate_signatures(self):
        """
        Combines multiple device signatures into a single 'Level-1 Aggregate'.
        Instead of sending 100 signatures to the cloud, it sends 1 math equation.
        """
        if not self.packet_buffer:
            print("[HGW] No packets to aggregate.")
            return None

        print(f"[HGW] Aggregating {len(self.packet_buffer)} signatures...")

        # Initialize empty arrays for aggregation
        z_agg = np.zeros(len(GLOBAL_P), dtype=int)
        R_agg = np.zeros(len(GLOBAL_P), dtype=int)
        
        c_list = []
        pk_list = []
        messages = []

        # Sum up the z and R values
        for packet in self.packet_buffer:
            sig = packet["signature"]
            z_agg = poly_add(z_agg, sig["z"])
            R_agg = poly_add(R_agg, sig["R"])
            
            c_list.append(sig["c"])
            pk_list.append(packet["public_key"])
            messages.append(packet["message"])

        # Create the Level-1 aggregated packet
        aggregated_payload = {
            "gateway_id": "HGW-01",
            "messages": messages,
            "aggregate_signature": {
                "z_agg": z_agg,
                "R_agg": R_agg,
                "c_list": c_list,
                "pk_list": pk_list
            }
        }

        # Clear the buffer after aggregation
        self.packet_buffer = []
        
        return aggregated_payload