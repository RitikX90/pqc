import time
import psutil
import os
import json
import subprocess
import sys

# Force UTF-8 for Windows emoji support
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from authority import ca_instance
from iot_device import IoTDevice
from gateway import HomeGateway
from cloud_provider import CloudProvider

def run_simulation(num_devices):
    process = psutil.Process(os.getpid())
    
    # Baseline Memory
    initial_mem = process.memory_info().rss / (1024 * 1024) # MB
    
    hgw = HomeGateway(ca_instance)
    csp = CloudProvider()
    devices = [IoTDevice(f"Device_{i+1}", ca_instance) for i in range(num_devices)]

    # Start timing and CPU monitoring
    start_time = time.perf_counter()
    psutil.cpu_percent(interval=None) # Reset CPU counter

    # Real PHASS workload
    for i, device in enumerate(devices):
        packet = device.sign_data(f"Data_{i}")
        hgw.receive_data(packet)

    aggregated_payload = hgw.aggregate_signatures()
    if aggregated_payload:
        csp.verify_aggregate(aggregated_payload)

    # Capture results
    end_time = time.perf_counter()
    cpu_usage = psutil.cpu_percent(interval=None)
    final_mem = process.memory_info().rss / (1024 * 1024)
    
    total_time_ms = (end_time - start_time) * 1000
    ram_used = max(0.1, final_mem - initial_mem) # Capture peak RAM delta

    return total_time_ms, cpu_usage, ram_used

def run_all_benchmarks():
    users = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    results = {"users": users, "phass_time": [], "phass_cpu": [], "phass_ram": []}
    
    print("\n🚀 Starting Full Performance Benchmark...")
    original_stdout = sys.stdout 
    
    for u in users:
        # Silent mode for math logs
        sys.stdout = open(os.devnull, 'w', encoding='utf-8') 
        t, c, r = run_simulation(u)
        sys.stdout = original_stdout 
        
        print(f"   [{u} Users] Time: {t:.2f}ms | CPU: {c}% | RAM: {r:.2f}MB")
        
        results["phass_time"].append(t)
        results["phass_cpu"].append(c)
        results["phass_ram"].append(r)

    with open("simulation_data.json", "w", encoding='utf-8') as f:
        json.dump(results, f)
    
    print("\n✅ Simulation Complete. Generating Graphs...")
    subprocess.run([sys.executable, "graph_generator.py"])

if __name__ == "__main__":
    run_all_benchmarks()