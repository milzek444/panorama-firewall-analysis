"""
analysis.py

This module contains the primary methods for inter-firewall policy analysis and Panorama configuration analysis
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from collections import defaultdict
from data_processing import FirewallRule, parse_objects, search_traffic, reverse_dns

@dataclass
class PolicyContradiction:
    category: str  # "Broad Port Exposure", "Subnet Contradiction", etc.
    perimeter_rule: FirewallRule   # the perimeter & internal rule (below) which contradict each other
    internal_rule: FirewallRule
    description: str   # description of the contradiction
    security_impact: str

@dataclass
class ObjectAnomaly:
    category: str  # One of two; "Decommissioned Object", "IP Reuse Mismatch"
    object_name: str
    ip_address: str
    expected_hostname: str  # the name present in XML for that object
    observed_hostname: str | None  # the name present in CSV traffic logs / DNS resolve
    affected_rules: list[FirewallRule] = field(default_factory=list)


def analyse_inter_firewall_policies(all_rules: list[FirewallRule], perimeter_name: str = "Sentry") -> list[
    PolicyContradiction]:
    """
    Identifies policy contradictions where a perimeter ALLOW rule is blocked
    by an internal downstream firewall's non-ALLOW policy.
    """
    contradictions = []  # hold the contradictions

    # Create two lists; one for all the rules that say "allow" for perimeter FW, other for "Deny" rules in other FWs
    # Group the rules in dicts efficiently based on (ip_version, protocol) to minimise redundant iterations
    # for defaultdict, if you try to access a key that doesn't exist yet, it will be created & assigned empty list
    # No need to check if the key exists first
    perimeter_allow = defaultdict(list)
    internal_deny = defaultdict(list)

    for rule in all_rules:   # go through all collected firewall rules
        # This line of code defaults to assuming everything is a perimeter rule unless a field says otherwise
        is_perimeter = getattr(rule, 'firewall_name', perimeter_name) == perimeter_name

        key = (rule.ip_version, rule.protocol.lower())  # e.g., (IPv4, tcp) - used as key for dictionary
        # populate the two dictionaries (perimeter_allow & internal_deny) with the rules in all_rules
        # ensures that IPv4 perimeter rules are only ever compared to IPv4 internal rules, and same with IPv6
        if is_perimeter and rule.action.lower() == "allow":
            perimeter_allow[key].append(rule)
        elif not is_perimeter and rule.action.lower() in ["deny", "drop"]:
            internal_deny[key].append(rule)

    # Perform rule overlap checks
    for key, p_rules in perimeter_allow.items():  # iterate through all perimeter FW rules with "allow" action
        i_rules = internal_deny.get(key, [])  # get a group of perimeter allow rules (e.g., IPv4, TCP),
                                                     # and finds corresponding group of internal deny rules (i_rules)
        if not i_rules:  # if no internal deny rules match for that specific perimeter_allow rule thing, skip
            continue

        for p_rule in p_rules:
            for i_rule in i_rules:
                # Check destination IP range overlap
                dst_overlap = (max(p_rule.dst_start, i_rule.dst_start) <= min(p_rule.dst_end, i_rule.dst_end))
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

                p_ip_span = p_rule.dst_end - p_rule.dst_start
                i_ip_span = i_rule.dst_end - i_rule.dst_start


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



def analyse_config_objects(xml_data: str, csv_data: str, all_rules: list[FirewallRule]) -> list[ObjectAnomaly]:
    """
    Flags stale, decommissioned or mismatched Panorama Object identities by correlating running configuration data,
    traffic logs and parsed rules
    :param xml_data:
    :param csv_data:
    :param all_rules:
    :return:
    """
    anomalies = []

    # 1. Gather filtered HOST components using existing logic
    objects_registry = parse_objects(xml_data)   # get all objects from XML config doc and put in this
    policy_tree = build_policy_tree(all_rules)  # build_policy_tree to be added afterwards

    # Internal helper to find any rules in policy tree that use a given object, by running structural tree queries
    def find_affected_rules_in_tree(object_name: str) -> list[FirewallRule]:
        matched = []
        for proto in policy_tree.values():
            for src_range in proto.values():
                for dst_range in src_range.values():
                    for port_range in dst_range.values():
                        for rule in port_range.get("rules", []):
                            if rule.src_xml_object == object_name or rule.dst_xml_object == object_name:
                                matched.append(rule)
        return matched

    for obj_name, metadata in objects_registry.items():
        ip_addr = metadata["ip"] # metadata holds dictionary of attributes for that object, e.g., raw IP value, obj type
        if ip_addr == "Group Reference":
            continue  # Bypass address group structural headers, target individual hosts only

        # Correlate with traffic logs using search logic; for each obj, run search_traffic helper and return T/F if seen
        seen_in_traffic, _ = search_traffic(csv_data, ip_addr)

        if not seen_in_traffic:  # if the object is not found in CSV, then it's probably inactive or decommissioned
            # Classify as potentially inactive or decommissioned
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
                # Basic ITS baseline check: Verify if object name matches or is contained inside DNS string
                # e.g., if object name is "ITS-WEB-SRV01" but resolves to "honeypot.campus.edu"
                expected_clean = obj_name.lower().replace("-", "")
                observed_clean = observed_dns.lower().replace("-", "")
                # if the expected identity holding object (from Panorama) != observed one from DNS, IP likely reassigned
                # but still points to old name, so it's assigned an "IP reuse mismatch" anomaly
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

def generate_final_report(contradictions: list[PolicyContradiction], anomalies: list[ObjectAnomaly]) -> str:
    """
    Consolidates findings from cross-firewall and configuration anomaly analysis into actionable reports and XML fixes
    for the administrator.
    """
    report_output = []
    report_output.append("=" * 40)
    report_output.append("PANORAMA FIREWALL SECURITY & CONFIGURATION AUDIT REPORT")
    report_output.append("=" * 40 + "\n")
    # Section 1: Policy Contradiction
    report_output.append("1: INTER-FIREWALL POLICY CONTRADICTIONS")
    report_output.append("-" * 40)
    if not contradictions:
        report_output.append("No inter-firewall policy contradictions identified between the perimeter "
                             "and downstream firewalls.\n")
    for idx, con in enumerate(contradictions, 1):  # go through each inter-firewall contradiction found
        report_output.append(f"  [{idx}] Category: {con.category}")
        report_output.append(f"      Description: {con.description}")
        report_output.append(f"      Security Impact: {con.security_impact}")
        report_output.append(
            #f"      Perimeter Rule Impacted: Source Object ({con.perimeter_rule.src_xml_object}) -> Dst Object ({con.perimeter_rule.dst_xml_object})")
            f"      Perimeter Rule Impacted: Source Object ({con.perimeter_rule.src_expected_identity}) -> Dst Object"
            f" ({con.perimeter_rule.dst_expected_identity})")
        report_output.append(f"      Internal Blocking Rule: Action ({con.internal_rule.action.upper()})\n")

    # Section 2: Asset inactivity & Identity Reassignments
    report_output.append("2. CONFIGURATION OBJECT & IDENTITY VALIDATION")
    report_output.append("-" * 40)
    if not anomalies:
        report_output.append("All parsed configuration host mappings match active network states.\n")
    for idx, anom in enumerate(anomalies, 1):
        report_output.append(f"  [{idx}] Category: {anom.category}")
        report_output.append(f"      Object Ref: {anom.object_name} ({anom.ip_address})")
        if anom.category == "Decommissioned Object":
            report_output.append(f"      Reason: Zero matching entries found across recent traffic data.")
            report_output.append(f"      Operational Risk: Orphaned rule configuration overhead.")
        else:
            report_output.append(f"      Expected Identity: {anom.expected_hostname}")
            report_output.append(f"      Observed Identity (DNS): {anom.observed_hostname}")
            report_output.append(f"      Operational Risk: Threat vector. IP address reassigned without rule update.")
        report_output.append(f"      Impacted Policy Paths Count: {len(anom.affected_rules)} rules\n")

    return "\n".join(report_output)

def generate_panorama_payloads(self) -> dict[str, list[str]]:
    """
    Constructs valid Panorama XML API payloads for remediation.
    Returns a dictionary mapping object groups to XML elements.
    """
    payloads = defaultdict(list)  # benefits of defaultdict mentioned earlier

    #1: Remediation for decommissioned objects (API query for deletion)

    #2: Remediation for reused IP for objects (generate tracking Tag updates to isolate entry)

    #3: Remediation for policy/rule contradictions (generate safety audit log tags for rule grouping)
