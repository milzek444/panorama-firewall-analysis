"""
analysis.py

This module contains the primary methods for inter-firewall policy analysis and Panorama configuration analysis
"""
from dataclasses import dataclass, field
from collections import defaultdict
from data_processing import FirewallRule, parse_objects, search_traffic, reverse_dns

@dataclass
class PolicyContradiction:
    category: str
    perimeter_rule: FirewallRule
    internal_rule: FirewallRule
    description: str
    security_impact: str

@dataclass
class ObjectAnomaly:
    category: str
    object_name: str  # Holds the exact Panorama configuration object name (e.g., HR-Database-Server) <display-name>
    ip_address: str
    expected_hostname: str  # the name present in XML for that object
    observed_hostname: str | None  # the name present in CSV traffic logs / DNS resolve
    affected_rules: list[FirewallRule] = field(default_factory=list) # for a decom. object, stores the rules that are..
                                                                     # ..affected/broken because of this object change..
                                                                     # ..mostly rules that reference these objects


def analyse_inter_firewall_policies(all_rules: list[FirewallRule], perimeter_name: str) -> list[
    PolicyContradiction]:
    """
    Identifies policy contradictions where a perimeter ALLOW rule is blocked
    by an internal downstream firewall's non-ALLOW policy.
    :param all_rules: rules to be analysed
    :param perimeter_name: Name of perimeter firewall, e.g., "Sentry", "Perimeter"
    :return: list of policy contradictions, in dataclass format, across all firewalls
    """
    contradictions = []  # hold the contradictions

    # Create two lists; one for all the rules that say "allow" for perimeter FW, other for "Deny" rules in other FWs
    perimeter_allow_test: defaultdict[tuple[int, str], list[FirewallRule]] = defaultdict(list)
    internal_deny_test: defaultdict[tuple[int, str], list[FirewallRule]] = defaultdict(list)

    for rule in all_rules:
        is_perimeter = getattr(rule, 'firewall_name', perimeter_name) == perimeter_name

        key = (rule.ip_version, rule.protocol.lower())  # e.g., (IPv4, tcp) - used as key for dictionary
        # populate the two dictionaries (perimeter_allow & internal_deny) with the rules in all_rules
        # ensures that IPv4 perimeter rules are only ever compared to IPv4 internal rules, and same with IPv6
        if is_perimeter and rule.action.lower() == "allow":
            perimeter_allow_test[key].append(rule)
        elif not is_perimeter and rule.action.lower() in ["deny", "drop"]:
            internal_deny_test[key].append(rule)

    # Perform rule overlap checks
    for key, p_rules in perimeter_allow_test.items():
        i_rules = internal_deny_test.get(key, [])  # get a group of perimeter allow rules (e.g., IPv4, TCP),
                                                     # and finds corresponding group of internal deny rules (i_rules)
        if not i_rules:
            continue

        for p_rule in p_rules:
            for i_rule in i_rules:
                # Check destination IP range overlap
                dst_overlap = (max(p_rule.dst_ip_start, i_rule.dst_ip_start) <=
                               min(p_rule.dst_ip_end, i_rule.dst_ip_end))
                if not dst_overlap:
                    continue  # skips the rest of the code

                # 2. Check destination port (dst_port) range overlap
                port_overlap = (max(p_rule.dst_port_start, i_rule.dst_port_start) <= min(p_rule.dst_port_end,
                                                                                         i_rule.dst_port_end))
                if not port_overlap:
                    continue

                # 3. Classify the subcategory with a broad description, which is changed later if more details found
                category = "General Policy Contradiction"
                description = f"Perimeter allows traffic that downstream firewall blocks."
                security_impact = "Operational disruption or unexpected traffic drops for authorised services."

                # Evaluate port & subnet contradictions between perimeter and internal FWs
                p_port_span = p_rule.dst_port_end - p_rule.dst_port_start
                i_port_span = i_rule.dst_port_end - i_rule.dst_port_start

                p_ip_span = p_rule.dst_ip_end - p_rule.dst_ip_start
                i_ip_span = i_rule.dst_ip_end - i_rule.dst_ip_start


                # "p" is perimeter FW, "i" is internal FWs( i.e., all but perimeter)
                if p_port_span > i_port_span and p_rule.dst_port_start == 0 and p_rule.dst_port_end == 65535:
                    category = "Broad Port Exposure"
                    description = ("Perimeter firewall exposes ALL ports, while internal firewall"
                                   " restricts or blocks subsets.")
                    security_impact = ("Violates least privilege. Perimeter exposes services "
                                       "unnecessarily to internal blocks.")
                elif p_ip_span > i_ip_span:  # if perimeter IP range is greater than what internal FWs allow...
                    if p_rule.ip_version == 4:    # If the IPs are IPv4...
                        category = "Subnet Contradiction"
                    else:
                        category = "IP Range Contradiction"
                    description = \
                        ("Perimeter rules allow a wide network bracket, but downstream nodes explicitly "
                         "block nested nodes inside.")

                contradictions.append(PolicyContradiction(
                    # pair of rules where they overlap in protocol, dest_IP and dest_port, AND have conflicting actions
                    category=category,
                    perimeter_rule=p_rule,
                    internal_rule=i_rule,
                    description=description,
                    security_impact=security_impact
                ))
    return contradictions


def build_policy_tree(all_rules: list[FirewallRule]) -> dict:
    """
    Constructs an optimised multi-dimensional in-memory policy lookup tree with the following structure:
    Protocol -> Source IP range -> Destination IP range -> Destination port -> [Rules]
    :param all_rules: all rules across all firewalls
    :return: multi-dimensional tree structure
    """
    # Using nested lambda definitions to create auto-generating branch dictionary layers
    tree = lambda: defaultdict(tree)
    policy_tree = defaultdict(tree)

    for rule in all_rules:
        # Create unique identifier keys for the matrix nodes
        src_key = (rule.src_ip_start, rule.src_ip_end)
        dst_key = (rule.dst_ip_start, rule.dst_ip_end)
        port_key = (rule.dst_port_start, rule.dst_port_end)

        # Traverse the tree and append the rule object to leaf node array
        if "rules" not in policy_tree[rule.protocol][src_key][dst_key][port_key]:
            policy_tree[rule.protocol][src_key][dst_key][port_key]["rules"] = []
        policy_tree[rule.protocol][src_key][dst_key][port_key]["rules"].append(rule)

    return policy_tree


def analyse_config_objects(xml_data: str, csv_data: str, all_rules: list[FirewallRule]) -> list[ObjectAnomaly]:
    """
    Flags stale, decommissioned or mismatched Panorama Object identities by correlating running configuration data,
    traffic logs and parsed rules
    :param xml_data: XML Configuration data
    :param csv_data: CSV traffic log data
    :param all_rules: All firewall rules
    :return: list of object anomalies, describing category of anomaly, affected rules, etc.
    """
    anomalies = []

    # 1. Gather filtered HOST components using existing logic
    objects_registry = parse_objects(xml_data)   # get all objects from XML config doc and put in this
    policy_tree = build_policy_tree(all_rules)

    # Internal helper to find any rules in policy tree that use a given object, by running structural tree queries
    def find_affected_rules_in_tree(object_name: str) -> list[FirewallRule]:
        matched = []
        for proto in policy_tree.values():
            for src_range in proto.values():
                for dst_range in src_range.values():
                    for port_range in dst_range.values():
                        for rule in port_range.get("rules", []):
                            if rule.src_expected_identity == object_name or rule.dst_expected_identity == object_name:
                                matched.append(rule)
        return matched

    for obj_name, metadata in objects_registry.items():
        # objects_registry is a dictionary mapping an object's name to its details, "metadata" holds dictionary of
        # attributes for that object (e.g., raw IP value, object type, tags)
        ip_addr = metadata["ip"]
        if ip_addr == "Group Reference":
            continue

        # Correlate with traffic logs using search logic; for each obj, run search_traffic helper and return T/F if seen
        seen_in_traffic, _ = search_traffic(csv_data, ip_addr)

        if not seen_in_traffic:
            affected = find_affected_rules_in_tree(obj_name) # link all rules that use this object
            anomalies.append(ObjectAnomaly(
                category="Decommissioned Object",
                object_name=obj_name,
                ip_address=ip_addr,
                expected_hostname=obj_name,  # ITS Object name reflects expected identity
                observed_hostname=None,
                affected_rules=affected
            ))
        else:   # if the IP IS active in traffic, DNS querying used to find who current uses/owns it
            observed_dns = reverse_dns(ip_addr)
            if observed_dns:
                expected_clean = obj_name.lower().replace("-", "")
                observed_clean = observed_dns.lower().replace("-", "")
                if expected_clean not in observed_clean and observed_clean not in expected_clean:
                    affected = find_affected_rules_in_tree(obj_name)
                    anomalies.append(ObjectAnomaly(
                        category="IP Reuse Mismatch",
                        object_name=obj_name,
                        ip_address=ip_addr,
                        expected_hostname=obj_name,
                        observed_hostname=observed_dns,
                        affected_rules=affected
                    ))

    return anomalies


class ReportingRemediationEngine:
    """
    Holds the reporting and remediation functions.
    Consolidates findings from cross-firewall and configuration anomaly analysis into actionable reports and XML fixes
    for the administrator, and constructs valid Panorama XML API payloads for remediation.
    """
    def __init__(self, contradictions: list[PolicyContradiction], anomalies: list[ObjectAnomaly]):
        self.contradictions = contradictions
        self.anomalies = anomalies


    def generate_final_report(self) -> str:
        """
        Consolidates findings from cross-firewall and configuration anomaly analysis into actionable reports and XML
        fixes for the administrator.
        :return: Formatted report on findings plus remediation suggestions
        """
        report_output = []
        report_output.append("=" * 40)
        report_output.append("PANORAMA FIREWALL SECURITY & CONFIGURATION AUDIT REPORT")
        report_output.append("=" * 40 + "\n")
        # Section 1: Policy Contradiction; prints out list of policy contradictions

        report_output.append("1: INTER-FIREWALL POLICY CONTRADICTIONS")
        report_output.append("-" * 40)
        if not self.contradictions:
            report_output.append("No inter-firewall policy contradictions identified between the perimeter "
                                 "and downstream firewalls.\n")
        for idx, con in  enumerate(self.contradictions, 1):
            report_output.append(f"  [{idx}] Category: {con.category}")  # idx prints out index number [1], [2], etc.
            report_output.append(f"      Description: {con.description}")
            report_output.append(f"      Security Impact: {con.security_impact}")
            report_output.append(
                f"      Perimeter Rule Impacted: Source Object ({con.perimeter_rule.src_expected_identity}) -> Dst Object"
                f" ({con.perimeter_rule.dst_expected_identity})")
            report_output.append(f"      Internal Blocking Rule: Action ({con.internal_rule.action.upper()})\n")

        # Section 2: Asset inactivity & Identity Reassignments
        report_output.append("2. CONFIGURATION OBJECT & IDENTITY VALIDATION")
        report_output.append("-" * 40)
        if not self.anomalies:
            report_output.append("All parsed configuration host mappings match active network states.\n")
        for idx, anom in enumerate(self.anomalies, 1):
            report_output.append(f"  [{idx}] Category: {anom.category}")
            report_output.append(f"      Object Ref: {anom.object_name} ({anom.ip_address})")
            if anom.category == "Decommissioned Object":
                report_output.append(f"      Reason: Zero matching entries found across recent traffic data.")
                report_output.append(f"      Operational Risk: Orphaned rule configuration overhead.")
            else:
                report_output.append(f"      Expected Identity: {anom.expected_hostname}")
                report_output.append(f"      Observed Identity (DNS): {anom.observed_hostname}")
                report_output.append(
                    f"      Operational Risk: Threat vector. IP address reassigned without rule update.")
            report_output.append(f"      Impacted Policy Paths Count: {len(anom.affected_rules)} rules\n")

        return "\n".join(report_output)


    def generate_panorama_payloads(self) -> dict[str, list[str]]:
        """
        Constructs valid Panorama XML API payloads for remediation.
        :return: a dictionary of payloads, holding XML queries categorised based on object anomaly
        """
        payloads = defaultdict(list)
        for anom in self.anomalies:  # go through all panorama anomalies
            # 1: Remediation for decommissioned objects (API query for deletion)
            if anom.category == "Decommissioned Object":
                # Case 1: If asset is stale, build API delete request targeting that
                xml_delete = f"<delete xpath=\"/config/shared/address/entry[@name='{anom.object_name}']\"/>"
                payloads["decommission_cleanup"].append(xml_delete)

            elif anom.category == "IP Reuse Mismatch" and anom.observed_hostname:
                # Case 2: If asset has identity mismatch, build API set statement that adds tag onto object
                # FLAG-REUSED-IDENTITY tag on the object allows for administrators to easily isolate it in
                xml_tag_update = (
                    f"<set xpath=\"/config/shared/address/entry[@name='{anom.object_name}']/tag\">"
                    f"<member>FLAG-REUSED-IDENTITY</member>"
                    f"</set>"
                )
                payloads["identity_updates"].append(xml_tag_update)

        # 3: Remediation for policy/rule contradictions
        for con in self.contradictions:
            if con.category == "Broad Port Exp@osure":
                # Injecting safety comments or administrative logging rules for optimisation pipelines
                # For safety we tag rules requiring review instead of dropping policies automatically
                xml_policy_tag = (
                    # f"<set xpath=\"/config/shared/pre-rulebase/security/rules/entry[@name='Audit_Required']\">"
                    f"<set xpath=\"/config/shared/pre-rulebase/security/rules/entry[@name='{con.perimeter_rule.rule_name}']\">"
                    f"<tag><member>AUDIT-BROAD-PORT</member></tag>"
                    f"</set>"
                )
                payloads["policy_review_tags"].append(xml_policy_tag)

        return dict(payloads)

