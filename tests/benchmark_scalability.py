"""
benchmark_scalability.py

Big-O performance scalability benchmarking; handles efficiency analysis requirements.
Benchmarks execution speeds across multiple rule volumes, maps the time to ms, and compares runtime trends
directly alongside theoretical Big-O complexity curves
"""
import time
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from unittest import mock
from generate_test_data import generate_synthetic_xml_and_csv
from data_processing import parse_xml, normalise_firewall_rules, parse_service_objects
from analysis import analyse_inter_firewall_policies, parse_objects, analyse_config_objects


def run_performance_benchmarks():
    """
    Measures the scalability of processing algorithms across increasing matrix scales
    Saves the data and builds performance curves
    :return: Saved .png image showing two curves representing scalability performance
    """
    rule_steps = [100, 1000, 5000, 10000]
    object_steps = [25, 120, 600, 1200]

    policy_runtimes = []
    object_runtimes = []

    print("Beginning performance benchmarking...")

    # Iterate by index slot since each array scales at different rates
    for i in range(len(rule_steps)):
        r_size = rule_steps[i]
        o_size = object_steps[i]

        xml_data, csv_data, _ = generate_synthetic_xml_and_csv(num_rules=r_size, num_objects=o_size, flaw_ratio=0.05)

        raw_rules = parse_xml(xml_data)
        obj_reg = parse_objects(xml_data)
        service_reg = parse_service_objects(xml_data)

        # Inject structural multi-firewall boundaries into the dataclass profile objects
        final_rules = normalise_firewall_rules(raw_rules, service_reg, obj_reg)
        for idx, r in enumerate(final_rules):
            # Safely cycle through raw_rules indices using modulo (%)
            corresponding_raw = raw_rules[idx % len(raw_rules)]
            r.firewall_name = "Sentry" if "_P" in corresponding_raw["name"] else "Internal-Downstream"

        # Benchmark 1: Policy contradiction checks
        start_time = time.perf_counter()
        analyse_inter_firewall_policies(final_rules, perimeter_name="Sentry")
        end_time = time.perf_counter()

        policy_duration_ms = (end_time - start_time) * 1000.0
        policy_runtimes.append(policy_duration_ms)

        # Benchmark 2: Configuration object tracking via mock DNS
        with mock.patch('data_processing.reverse_dns', return_value="HOST-SRV-MOCK.campus.edu"):
            start_time = time.perf_counter()
            analyse_config_objects(xml_data, csv_data, final_rules)
            end_time = time.perf_counter()

            object_duration_ms = (end_time - start_time) * 1000.0
            object_runtimes.append(object_duration_ms)

        print(
            f"Rule Scale {r_size:5d} & Object Scale {o_size:5d} elements -> "
            f"Policy Analysis: {policy_duration_ms:8.2f}ms | Object Validation: {object_duration_ms:8.2f}ms")

    # Plot performance results using matplotlib
    plt.figure(figsize=(10.0, 5.0))

    # Plotting the policy analysis curve
    plt.subplot(1, 2, 1)
    plt.plot(rule_steps, policy_runtimes, marker='o', color='blue', label='Runtime')
    plt.title('Algorithm 1: Policy Scaling Trend')
    plt.xlabel('Number of Rules')
    plt.ylabel('Execution Time (ms)')
    plt.grid(True)
    plt.gca().yaxis.set_major_formatter(ticker.StrMethodFormatter('{x:,.0f}'))

    # Object validation curve plotting
    plt.subplot(1, 2, 2)
    plt.plot(object_steps, object_runtimes, marker='s', color='orange', label='Runtime')
    plt.title('Algorithm 2: Object Validation Trend')
    plt.xlabel('Number of Address Objects')
    plt.ylabel('Execution Time (ms)')
    plt.grid(True)
    plt.gca().yaxis.set_major_formatter(ticker.StrMethodFormatter('{x:,.0f}')) # Add vals w/ commas (e.g., "200,000")

    plt.tight_layout()
    plt.savefig('firewall_performance_scaling_profiles_test.png')
    print("\n[SUCCESS] Scalability chart compiled and saved as 'firewall_performance_scaling_profiles_test.png'")
    plt.show()

