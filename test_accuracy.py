"""
(3) test_accuracy.py

Algorithm accuracy metric evaluation; checks accuracy using a confusion matrix to calculate performance scores,
aiming to minimise false-positive alerts on clean rules
"""
import pytest
from generate_test_data import generate_synthetic_xml_and_csv
from data_processing import parse_xml, parse_objects
from analysis import analyse_inter_firewall_policies

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

