Privacy-Preserving Homomorphic Authentication/Sharing Scheme, integrating lattice-based mathematics is a smart move to ensure the project is resistant to quantum computer attacks. 

In cryptography, "assuming" lattice-based math usually means you are relying on the Shortest Vector Problem (SVP) or Learning With Errors (LWE) as your core security hardness assumptions.

hadamard: pointwise
lattice: shortest vector in high dimentional 



The PHASS Code Structureconfig.py 
(The Mathematical Foundation)
Purpose: Acts as the shared rulebook for the entire system.
What it does: Defines the lattice cryptography parameters like $N$ (polynomial size) and $Q$ (modulus limit). It houses the core mathematical functions, specifically the fast Hadamard product (pointwise multiplication) and polynomial addition/subtraction. It also generates the global public polynomial $p(x)$ used by all entities.



authority.py (The Certificate Authority - CA)

Purpose: Manages trust and identity in the network.

What it does: Simulates a trusted server that registers new IoT devices and issues them time-based "epoch tokens." It manages a Merkle Accumulator (via hashing) to keep a verifiable record of which devices are currently active and which are revoked.




iot_device.py (Consumer IoT Device - $D_j$)

Purpose: Represents the lightweight edge sensors (like the 8-bit AVR ATmega2560).

What it does: Simulates H-PUF biometric seeding to generate a secret key ($s$) and computes its public key ($pk$). Crucially, it implements the PHASS-PartialSign logic to securely sign sensor data using the equations $R = p \circledast y$ and $z = y + c \cdot s$.


gateway.py (Home Gateway - HGW)

Purpose: Acts as the middleman (like a Raspberry Pi 4) to save network bandwidth.

What it does: Receives individual signatures from multiple IoT devices and first checks with the CA to ensure their tokens are valid. It then performs Level-1 Aggregation, mathematically crunching multiple individual signatures into a single, compact signature bundle before sending it to the cloud.




cloud_provider.py (Cloud Service Provider - CSP)

Purpose: The high-power backend server (like an Intel i9) that verifies and stores the data.

What it does: Performs the Level-2 Full Verification using the aggregated Hadamard equation to mathematically prove all bundled signatures are valid in one swift check. Once verified, it permanently stores the sensor data in a tamper-proof Hash Chain.




simulator.py (The Benchmarking Master)

Purpose: The main script you run to test the system and generate data for your graphs.

What it does: It imports all the modules above and simulates the full lifecycle: 10+ devices signing data, the gateway aggregating it, and the cloud verifying it. It uses Python's time and psutil libraries to track the exact Execution Time, CPU Usage, and Memory Consumed during the process.