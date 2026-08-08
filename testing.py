"""
testing.py

Contains framework testing. Split into two aspects:
1) Testing of the helper functions in data_processing.py
2) Testing of the program's collective functionality
"""

import random


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
