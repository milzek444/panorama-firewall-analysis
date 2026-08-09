"""
testing.py

Contains framework testing. Split into two aspects:
1) Testing of the helper functions in data_processing.py
2) Testing of the program's collective functionality

Instructions to run:
1) Install required dependencies via pip install (pytest, matplotlib, unittest mock)
2) Run pytest testing.py -v (correctness verification & parser test suite)
"""

import random
import time
from unittest import mock
import plt
import pytest
from analysis import (PolicyContradiction, ObjectAnomaly, FirewallRule,
                      analyse_inter_firewall_policies, analyse_config_objects,
                      ReportingRemediationEngine)
from data_processing import ip_to_range_ints, port_to_range_ints, parse_objects, parse_xml

########################################################
###         1: SYNTHETIC TEST DATA GENERATOR
########################################################

def generate_synthetic_xml_and_csv(num_rules: int, num_objects: int, flaw_ratio: float = 0.1) -> tuple[str, str, dict]:
    """
    Generates pure string XML configs and CSV records for scale and accuracy auditing.
    Tracks exact anomalies created to serve as a formal 'Ground Truth' dictionary, used as final truth for comparison
    The outputted configuration tree, containing rules and objects, along with the dictionary, are then used for testing
    :param num_rules:
    :param num_objects:
    :param flaw_ratio:
    :return:
    """
    ground_truth = {
        "contradictions": 0,
        "decommissioned": 0,
        "mismatches": 0,
        "expected_contradictions": [],
        "expected_anomalies": []
    }

    # Generate Address Objects with discrete ITS tag profiles to flag flaws
    xml_objs = []
    csv_rows = ["Source address,Destination address,Source User,Destination User"]

    for i in range(num_objects):
        obj_name = f"HOST-SRV-{i:05d}"
        # Split IPv4 and IPv6 IPs safely; alternate between generating IPv4 and IPv4
        if i % 2 == 0:
            ip = f"10.0.{(i >> 8) & 0xFF}.{i & 0xFF}"
        else:
            ip = f"2001:db8::{i:x}"

        is_flawed = random.random() < flaw_ratio  # randomly decide if this should be flawed object or not

        if is_flawed:
            anomaly_type = random.choice(["decommissioned", "mismatch"]) #if chosen as flawed, randomly select type
            if anomaly_type == "decommissioned":
                # Decom./stale item: Left in configuration but completely absent from traffic
                xml_objs.append(
                    f'<entry name="{obj_name}"><ip-netmask>{ip}</ip-netmask><tag><member>HOST</member></tag></entry>')
                ground_truth["decommissioned"] += 1
                ground_truth["expected_anomalies"].append((obj_name, "Decommissioned Object"))
            else:
                # IP reuse: Present in traffic logs but DNS path fails verification
                # different asset is using IP than the one originally assigned in Panorama config
                xml_objs.append(
                    f'<entry name="{obj_name}"><ip-netmask>{ip}</ip-netmask><tag><member>HOST</member></tag></entry>')
                csv_rows.append(f"{ip},192.168.1.1,UserA,UserB")
                ground_truth["mismatches"] += 1
                ground_truth["expected_anomalies"].append((obj_name, "IP Reuse Mismatch"))
        else:
            # A normal object
            xml_objs.append(
                f'<entry name="{obj_name}"><ip-netmask>{ip}</ip-netmask><tag><member>HOST</member></tag></entry>')
            csv_rows.append(f"{ip},192.168.1.1,UserA,UserB")

    # 2. Build Firewall rule dimensions
    xml_rules_sentry = []
    xml_rules_internal = []

    for r in range(num_rules):
        rule_name = f"Rule-{r:05d}"
        introduce_flaw = random.random() < flaw_ratio

        if introduce_flaw:
            # Inject a verifiable flawed inter-firewall rule contradiction
            # Where Perimeter rules have broad ALLOW, but internal FW policy explicitly blocks subset
            xml_rules_sentry.append(
                f'<entry name="{rule_name}_P"><source><member>any</member></source>'
                f'<destination><member>10.0.0.0/16</member></destination>'
                f'<service><member>any</member></service><action>allow</action></entry>'
            )
            xml_rules_internal.append(
                f'<entry name="{rule_name}_I"><source><member>any</member></source>'
                f'<destination><member>10.0.5.0/24</member></destination>'
                f'<service><member>service-tcp-80</member></service><action>deny</action></entry>'
            )
            ground_truth["contradictions"] += 1
            ground_truth["expected_contradictions"].append(f"{rule_name}_P")
        else:
            # Cohesive rule paths
            xml_rules_sentry.append(
                f'<entry name="{rule_name}_P"><source><member>any</member></source>'
                f'<destination><member>10.1.0.0/24</member></destination>'
                f'<service><member>service-tcp-443</member></service><action>allow</action></entry>'
            )
            xml_rules_internal.append(
                f'<entry name="{rule_name}_I"><source><member>any</member></source>'
                f'<destination><member>10.1.0.0/24</member></destination>'
                f'<service><member>service-tcp-443</member></service><action>allow</action></entry>'
            )

    # 3. Assemble Output Configuration Tree Document Block
    xml_str = (
        f"<config><shared><address>{''.join(xml_objs)}</address>"
        f"<address-group></address-group>"
        f"<rulebase><security><rules>{''.join(xml_rules_sentry)}{''.join(xml_rules_internal)}</rules></security></rulebase>"
        f"</shared></config>"
    )

    return xml_str, "\n".join(csv_rows), ground_truth

# Add explicit pytest fixture injection to allow for switching between datasets
@pytest.fixture(params=["synthetic", "ironskillet"])


########################################################
###         2: TESTING THE PARSERS & HELPERS
########################################################
def test_ip_to_range_ints_ipv4():
    """
    Test correctness of helper by validating structural boundary calculations for classical 32-bit parameters
    :return:
    """
    start, end, version = ip_to_range_ints("192.168.1.1")
    assert version == 4
    assert start == end
    assert start == 3232235777


def test_ip_to_range_ints_ipv6():
    """
    Test correctness of helper by validating structural boundary calculations for full 128-bit fields
    without bit capping overflows
    :return:
    """
    start, end, version = ip_to_range_ints("2001:db8::1")
    assert version == 6
    assert start == end
    assert start > 2**32  # Confirms it scales beyond standard 32-bit limits cleanly


def test_ip_to_range_ints_any_handling():
    """
    Test correctness of helper by verifying that 'any' IP maps accurately based on protocol version profiles (v4/6)
    without mixing up between v4 and v6.
    :return:
    """
    start_v4, end_v4, v4 = ip_to_range_ints("any")
    assert v4 == 4
    assert end_v4 == 2**32 - 1

def test_parse_objects_filtering(xml_dataset):
    """
    Ensures parser only extracts objects matching the correct tag
    :param xml_dataset:
    :return:
    """
    registry = parse_objects(xml_dataset)
    assert isinstance(registry, dict)
    for name, meta in registry.items():
        assert "ip" in meta
        assert meta["type"] in ["ip-netmask", "ip-range", "ip-wildcard", "fqdn", "address-group"]

########################################################
###           3: TESTING ALGORITHMIC ACCURACY
########################################################
def test_analysis_pipeline_accuracy():
    """
    Computes a full confusion matrix (Precision, Recall, F1)
    against known ground-truth configuration rules.
    :return:
    """
    # Create a synthetic data set with a specified number of flaws
    xml_data, csv_data, truth = generate_synthetic_xml_and_csv(num_rules=50, num_objects=50, flaw_ratio=0.2)

    # Run the core functions; parsing the XML and objects
    raw_rules = parse_xml(xml_data)
    obj_reg = parse_objects(xml_data)

    # Distribute virtual firewall boundaries across rule attributes for proper multi-firewall routing simulation
    # !!!!! to be modified
    for idx, rule in enumerate(raw_rules):
        rule["firewall_name"] = "Sentry" if "_P" in rule["name"] else "Internal-Downstream"

    final_rules = parse_objects(raw_rules, obj_reg)
    for idx, r in enumerate(final_rules):
        r.firewall_name = "Sentry" if "_P" in raw_rules[idx // len(raw_rules)]["name"] else "Internal-Downstream"

    # Execute contradiction checks
    contradictions = analyse_inter_firewall_policies(final_rules, perimeter_name="Sentry")

    # Derive statistical confusion variables
    tp = len([c for c in contradictions if c.perimeter_rule.name in truth["expected_contradictions"]])
    fp = len(contradictions) - tp
    fn = truth["contradictions"] - tp
    tn = len(final_rules) - (tp + fp + fn)

    # Calculate performance metrics for accuracy, precision, and recall
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 1.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 1.0

    print(f"\n--- Algorithmic Accuracy Matrix Summary ---")
    print(f"Accuracy: {accuracy:.4f} | Precision: {precision:.4f} | Recall: {recall:.4f} | F1-Score: {f1_score:.4f}")

    # Core system health assertions
    assert precision >= 0.90, "PRECISION >= 90%: System is generating an excessive number of false-positive warnings"
    assert recall >= 0.90, "RECALL >= 90%: System has failed to detect & remediate true high-risk policy flaws"


########################################################
###            4: SCALABILITY
########################################################
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
        final_rules = parse_objects(raw_rules, obj_reg)
        for idx, r in enumerate(final_rules):
            r.firewall_name = "Sentry" if idx % 2 == 0 else "Internal-Downstream"  # !!!!! subject to change

        # Benchmark 1: Policy contradiction checks
        start_time = time.perf_counter()
        analyse_inter_firewall_policies(final_rules, perimeter_name="Sentry") # !!!!! perimeter name subject to change
        end_time = time.perf_counter()

        policy_duration_ms = (end_time - start_time) * 1000.0
        policy_runtimes.append(policy_duration_ms)

        # Benchmark 2: Configuration object tracking via mock DNS
        with mock.patch('main.reverse_dns_lookup', return_value="HOST-SRV-MOCK.campus.edu"):  # !!!!! Subject to change
            start_time = time.perf_counter()
            analyse_config_objects(xml_data, csv_data, final_rules)
            end_time = time.perf_counter()

            object_duration_ms = (end_time - start_time) * 1000.0
            object_runtimes.append(object_duration_ms)

        print(
            f"Scale {size:5d} elements -> "
            f"Policy Analysis: {policy_duration_ms:8.2f}ms | Object Validation: {object_duration_ms:8.2f}ms")

    # Plot performance results using matplotlib
    plt.figure(figsize=(10, 5))

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


########################################################
###        5: REPORTING & REMEDIATION ENGINE
########################################################
@pytest.fixture
def mock_anomalies():
    """
    Builds controlled policy flaws to check validation accuracy.
    :return:
    """
    rule_sample = FirewallRule(
        ip_version=4, protocol="tcp",
        src_ip_start=167772161, src_ip_end=167772161,  # 10.0.0.1
        dst_ip_start=3232235777, dst_ip_end=3232235777,
        src_port_start=0, src_port_end=65535,
        dst_port_start=80, dst_port_end=80,
        action="deny", src_expected_identity="CRITICAL-DB-HOST", dst_expected_identity=None,
        src_observed_identity=None, dst_observed_identity=None
    )

    con = PolicyContradiction(
        category="Broad Port Exposure",
        perimeter_rule=rule_sample,
        internal_rule=rule_sample,
        description="Perimeter allows unrestricted access to hidden blocks.",
        security_impact="Increases the reachable attack surface of internal components."
    )

    anom = ObjectAnomaly(
        category="Decommissioned Object",
        object_name="CRITICAL-DB-HOST",
        ip_address="10.0.0.1",
        expected_hostname="CRITICAL-DB-HOST",
        observed_hostname=None,
        affected_rules=[rule_sample]
    )
    return [con], [anom]


def test_reporting_engine_output_logic(mock_anomalies):
    """
    Verifies that generated reports correctly display the risk descriptions and XML configuration payloads
    :param mock_anomalies:
    :return:
    """
    contradictions, anomalies = mock_anomalies
    engine = ReportingRemediationEngine(contradictions, anomalies)

    # 1: Verify text report output strings
    report = engine.generate_final_report()
    assert "FIREWALL SECURITY & CONFIGURATION AUDIT REPORT" in report
    assert "Broad Port Exposure" in report
    assert "CRITICAL-DB-HOST" in report

    # 2: Verify generation of clean XML remediation payloads
    xml_payloads = engine.generate_panorama_payloads()
    assert "decommission_cleanup" in xml_payloads

    # Confirm structural authenticity of Panorama API XPath target values
    target_xpath = xml_payloads["decommission_cleanup"][0]
    assert "<delete xpath=" in target_xpath
    assert "@name='CRITICAL-DB-HOST'" in target_xpath