"""
analysis.py

This module contains the primary methods for inter-firewall policy analysis and Panorama configuration analysis
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from collections import defaultdict
from data_processing import FirewallRule

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