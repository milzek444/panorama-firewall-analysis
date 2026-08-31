"""
test_accuracy.py

Algorithm accuracy metric evaluation; checks accuracy using a confusion matrix to calculate performance scores,
aiming to minimise false-positive alerts on clean rules
"""
from generate_test_data import generate_synthetic_xml_and_csv
from data_processing import parse_xml, parse_objects, normalise_firewall_rules, parse_service_objects
from analysis import analyse_inter_firewall_policies

def test_analysis_pipeline_accuracy():
    """
    Computes a full confusion matrix, Accuracy + (Precision, Recall, F1)
    against known ground-truth configuration rules.
    Accuracy) What proportion of classifications were correct?
    Precision) How many of the detected anomalies were true?
    Recall) Out of all the anomalies that exist in the system, how many did the system find?
    F1) Combined average of precision & recall
    Metric: 0.0 - 1.0 (0% - 100%)

    :return: The values of the four confusion matrix metrics
    """
    # Create a synthetic data set with a specified number of flaws
    xml_data, csv_data, truth = generate_synthetic_xml_and_csv(num_rules=50, num_objects=50, flaw_ratio=0.2)

    raw_rules = parse_xml(xml_data)
    obj_reg = parse_objects(xml_data)
    service_reg = parse_service_objects(xml_data)

    # Distribute virtual firewall boundaries across rule attributes for proper multi-firewall routing simulation
    for idx, rule in enumerate(raw_rules):
        rule["firewall_name"] = "Sentry" if "_P" in rule["name"] else "Internal-Downstream"

    final_rules = normalise_firewall_rules(raw_rules, service_reg, obj_reg)

    for idx, r in enumerate(final_rules):
        # Safely cycle through raw_rules indices using modulo (%)
        corresponding_raw = raw_rules[idx % len(raw_rules)]
        r.firewall_name = "Sentry" if "_P" in corresponding_raw["name"] else "Internal-Downstream"

    contradictions = analyse_inter_firewall_policies(final_rules, perimeter_name="Sentry")

    flagged_rule_names = set(c.perimeter_rule.rule_name for c in contradictions)


    expected_rule_names = set(truth["expected_contradictions"])

    # Derive statistical confusion variables (true & false positives/negatives)
    tp = len(flagged_rule_names.intersection(expected_rule_names))
    fp = len(flagged_rule_names - expected_rule_names)
    fn = len(expected_rule_names - flagged_rule_names)
    total_unique_raw_rules = len(set(r["name"] for r in raw_rules))
    tn = total_unique_raw_rules - (tp + fp + fn)

    # Calculate performance metrics for accuracy, precision, and recall
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 1.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0

    # If no contradictions exist + expected list is empty, recall is perfectly clean
    # Stops the code from defaulting to 0 if tp and fn are 0, which occurs with clean configs
    if tp == 0 and len(expected_rule_names) == 0:
        recall = 1.0
    else:
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0

    f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 1.0

    print(f"\n--- Algorithmic Confusion Matrix Summary ---")
    (print
     (f"ACCURACY: {float(accuracy) * 100:.2f}% | PRECISION: {precision * 100:.2f}% | "
      f"RECALL: {float(recall) * 100:.2f}% | F1-SCORE: {f1_score * 100:.2f}%"))

    # Core system health assertions
    assert precision >= 0.90, "PRECISION >= 90%: System is generating an excessive number of false-positive warnings"
    assert recall >= 0.90, "RECALL >= 90%: System has failed to detect & remediate true high-risk policy flaws"

