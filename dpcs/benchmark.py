# benchmark.py
"""
DPCS Performance Benchmark Suite

Measures:
1. CPU Usage vs Concurrent Users
2. RAM Usage vs Concurrent Users
3. Energy Consumption vs Concurrent Users
4. Network Usage vs Concurrent Users
5. Signing Time vs Concurrent Users
6. Verification Time vs Concurrent Users

Output:
- results.csv
- 6 PNG graphs

Install first:
pip install psutil matplotlib pandas numpy
"""

import time
import json
import psutil
import threading
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor

import hca
import node
import edge
import cv
import audit


# =========================================================
# CONFIG
# =========================================================
USER_COUNTS = [1, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
MESSAGE = b"temperature=36.5"

# Approx laptop CPU TDP watts (edit if desired)
CPU_WATTS = 15


# =========================================================
# SINGLE USER TASK
# =========================================================
def user_task(user_id, authority):

    mynode = node.Node(f"user-{user_id}", authority)
    myedge = edge.Edge()
    mycv = cv.CloudVerifier(authority.A)

    cert = authority.issue_dual_cert(
        mynode.id_i,
        mynode.pk_CL,
        mynode.pk_PQ,
        epoch=1
    )

    timestamp = int(time.time())

    # -------------------------------
    # Sign
    # -------------------------------
    t1 = time.perf_counter()

    sig = mynode.sign(
        MESSAGE,
        timestamp,
        battery_level=0.90
    )

    sign_time = time.perf_counter() - t1

    # -------------------------------
    # Edge verify
    # -------------------------------
    myedge.verify_partial(
        sig,
        mynode.pk,
        MESSAGE,
        timestamp
    )

    # -------------------------------
    # Cloud verify
    # -------------------------------
    t2 = time.perf_counter()

    valid, trust = mycv.verify(
        sigma=sig,
        pk=mynode.pk,
        msg=MESSAGE,
        timestamp=timestamp,
        R_epoch=cert["R_epoch"],
        pi_leaf=cert["pi_epoch"],
        node_id=mynode.id_i,
        session_key=mynode.session_key
    )

    verify_time = time.perf_counter() - t2

    # -------------------------------
    # Network bytes estimate
    # -------------------------------
    network_bytes = (
        len(str(cert).encode()) +
        len(str(sig).encode())
    )

    return sign_time, verify_time, network_bytes


# =========================================================
# BENCHMARK ONE USER COUNT
# =========================================================
def run_benchmark(concurrent_users):

    authority = hca.HCA()

    process = psutil.Process()

    # Baseline memory
    mem_before = process.memory_info().rss / (1024 * 1024)

    # Prime CPU measurement
    psutil.cpu_percent(interval=None)

    start_total = time.perf_counter()

    results = []

    with ThreadPoolExecutor(max_workers=concurrent_users) as executor:

        futures = [
            executor.submit(user_task, i, authority)
            for i in range(concurrent_users)
        ]

        for future in futures:
            results.append(future.result())

    total_elapsed = time.perf_counter() - start_total

    # CPU %
    cpu_percent = psutil.cpu_percent(interval=0.2)

    # Memory after
    mem_after = process.memory_info().rss / (1024 * 1024)

    ram_used = max(0, mem_after - mem_before)

    # Aggregate timings
    sign_times = [x[0] for x in results]
    verify_times = [x[1] for x in results]
    network = [x[2] for x in results]

    avg_sign = np.mean(sign_times)
    avg_verify = np.mean(verify_times)
    total_network = np.sum(network)

    # Energy estimate
    energy_joules = CPU_WATTS * total_elapsed * (cpu_percent / 100)

    return {
        "users": concurrent_users,
        "cpu_usage": cpu_percent,
        "ram_usage_mb": ram_used,
        "energy_j": energy_joules,
        "network_bytes": total_network,
        "sign_time_sec": avg_sign,
        "verify_time_sec": avg_verify
    }


# =========================================================
# PLOT GRAPH
# =========================================================
def plot_graph(df, x, y, title, ylabel, filename):

    plt.figure(figsize=(8, 5))
    plt.plot(df[x], df[y], marker='o', linewidth=2)
    plt.title(title)
    plt.xlabel("Concurrent Users")
    plt.ylabel(ylabel)
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(filename, dpi=300)
    plt.close()


# =========================================================
# MAIN
# =========================================================
def main():

    all_results = []

    print("=" * 65)
    print("DPCS BENCHMARK STARTED")
    print("=" * 65)

    for users in USER_COUNTS:

        print(f"Running benchmark for {users} users...")

        result = run_benchmark(users)

        all_results.append(result)

    df = pd.DataFrame(all_results)

    df.to_csv("result/results.csv", index=False)

    # -----------------------------------------------------
    # Graphs
    # -----------------------------------------------------
    plot_graph(
        df,
        "users",
        "cpu_usage",
        "CPU Usage vs Concurrent Users",
        "CPU %",
        "result/cpu_usage.png"
    )

    plot_graph(
        df,
        "users",
        "ram_usage_mb",
        "RAM Usage vs Concurrent Users",
        "RAM (MB)",
        "result/ram_usage.png"
    )

    plot_graph(
        df,
        "users",
        "energy_j",
        "Energy Consumption vs Concurrent Users",
        "Energy (Joules)",
        "result/energy_usage.png"
    )

    plot_graph(
        df,
        "users",
        "network_bytes",
        "Network Usage vs Concurrent Users",
        "Bytes",
        "result/network_usage.png"
    )

    plot_graph(
        df,
        "users",
        "sign_time_sec",
        "Signing Time vs Concurrent Users",
        "Seconds",
        "result/sign_time.png"
    )

    plot_graph(
        df,
        "users",
        "verify_time_sec",
        "Verification Time vs Concurrent Users",
        "Seconds",
        "result/verify_time.png"
    )

    print("=" * 65)
    print("Benchmark Completed")
    print("Saved:")
    print("result/results.csv")
    print("result/cpu_usage.png")
    print("result/ram_usage.png")
    print("result/energy_usage.png")
    print("result/network_usage.png")
    print("result/sign_time.png")
    print("result/verify_time.png")
    print("=" * 65)


if __name__ == "__main__":
    main()