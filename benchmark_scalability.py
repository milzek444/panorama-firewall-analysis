"""
(4) benchmark_scalability.py

Big-O performance scalability benchmarking; handles efficiency analysis requirements.
Benchmarks execution speeds across multiple rule volumes, maps the time to ms, and compares runtime trends
directly alongside theoretical Big-O complexity curves
"""

import time
import matplotlib.pyplot as plt
from unittest import mock
from generate_test_data import generate_synthetic_xml_and_csv
from data_processing import parse_xml, normalise_firewall_rules
from analysis import analyse_inter_firewall_policies, parse_objects, analyse_config_objects


def run_performance_benchmarks():
    """
    Measures the scalability of processing algorithms across increasing matrix scales
    Saves the data and builds performance curves
    :return:
    """
    scale_steps = [100, 1000, 5000, 10000]
    policy_runtimes = []
    object_runtimes = []

    print("Beginning performance benchmarking...")

    for size in scale_steps:
        # Generate target matrix scale metrics
        xml_data, csv_data, _ = generate_synthetic_xml_and_csv(num_rules=size, num_objects=size, flaw_ratio=0.05)

        raw_rules = parse_xml(xml_data)
        obj_reg = parse_objects(xml_data)

        # Inject structural multi-firewall boundaries into the dataclass profile objects
        # final_rules = parse_objects(raw_rules, obj_reg)
        final_rules = normalise_firewall_rules(raw_rules, obj_reg)
        for idx, r in enumerate(final_rules):
            r.firewall_name = "Sentry" if idx % 2 == 0 else "Internal-Downstream"  # !!!!! subject to change
                                                                                   # (not here though; this is for testing)

        # Benchmark 1: Policy contradiction checks
        start_time = time.perf_counter()
        analyse_inter_firewall_policies(final_rules, perimeter_name="Sentry") # !!!!! perimeter name subject to change
                                                                              # (not here though; this is for testing)
        end_time = time.perf_counter()

        policy_duration_ms = (end_time - start_time) * 1000.0
        policy_runtimes.append(policy_duration_ms)

        # Benchmark 2: Configuration object tracking via mock DNS
        with mock.patch('data_processing.reverse_dns', return_value="HOST-SRV-MOCK.campus.edu"):  # !!!!! Subject to change
            start_time = time.perf_counter()
            analyse_config_objects(xml_data, csv_data, final_rules)
            end_time = time.perf_counter()

            object_duration_ms = (end_time - start_time) * 1000.0
            object_runtimes.append(object_duration_ms)

        print(
            f"Scale {size:5d} elements -> "
            f"Policy Analysis: {policy_duration_ms:8.2f}ms | Object Validation: {object_duration_ms:8.2f}ms")

    # Plot performance results using matplotlib
    plt.figure(figsize=(10.0, 5.0))

    # Plotting the policy analysis curve
    plt.subplot(1, 2, 1)
    plt.plot(scale_steps, policy_runtimes, marker='o', colour='blue', label='Runtime')
    plt.title('Algorithm 1: Policy Scaling Trend')
    plt.xlabel('Number of Rules')
    plt.ylabel('Execution Time (ms)')
    plt.grid(True)

    # Add theoretical reference boundary marker notes
    plt.figtext(0.15, 0.02,
                "Theoretical Complexity: O(N * M) worst-case, reduced via segment grid grouping optimisations.",
                fontsize=8, colour='dimgray')

    # Object validation curve plotting
    plt.subplot(1, 2, 2)
    plt.plot(scale_steps, object_runtimes, marker='s', colour='orange', label='Runtime')
    plt.title('Algorithm 2: Object Validation Trend')
    plt.xlabel('Number of Address Objects')
    plt.ylabel('Execution Time (ms)')
    plt.grid(True)

    plt.tight_layout()
    plt.savefig('firewall_performance_scaling_profiles_test.png')
    print("\n[SUCCESS] Scalability chart compiled and saved as 'firewall_performance_scaling_profiles_test.png'")
    plt.show()
