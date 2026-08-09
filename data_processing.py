"""
data_processing.py

This module provides reusable utility functions that conduct  parsing, validating and preprocessing
on firewall XML configuration and CSV traffic data prior to main  analysis

"""
import io
import ipaddress  # for handling IP addresses
import socket  # for reverse DNS queries
import csv    # for handling traffic logs
from dataclasses import dataclass   # for firewall rule dataclass
import xml.etree.ElementTree as ET   # for parsing XML
# For the following imports, must have pan-os-python SDK installed using pip
from panos.panorama import Panorama
from panos.errors import PanDeviceError

dns_cache = {}    # store information about queried IPs and their observed identities

@dataclass()
class FirewallRule:
    src_ip_start: int
    src_ip_end: int
    dst_ip_start: int
    dst_ip_end: int
    src_port_start: int
    src_port_end: int
    dst_port_start: int
    dst_port_end: int
    action: str   # allow / deny
    protocol: str
    ip_version: int   # 4 or 6, used to prevent cross-protocol mixing
    src_expected_identity: str | None    # from XML, e.g., "Finance-Server", aka src_xml_object
    dst_expected_identity: str | None
    src_observed_identity: str | None    # !! this may NOT BE NEEDED; we can use the DNS cache instead
    dst_observed_identity: str | None    # (p2) hostname from reverse DNS, e.g.,"finance-01.york.ac.uk"
                                         # if IP is in traffic logs, expected = observed
                                         # else, do reverse DNS, then record that as observed

def ip_to_range_ints(ip_str: str) -> tuple[int, int, int]:
    """
    Converts IP Strings into a pair of integers representing the start and end of the range
    Static single IP addresses have identical start and end values
    :param ip_str: IP address
    :return: (start_integer, end_integer, ip_version), where ip_version is either 4 (ipv4) or 6 (ipv6)
    """
    ip_str = ip_str.strip()
    if not ip_str:  # if the string is blank
        return 0, 0, 4

    is_ipv6 = ":" in ip_str   # check if IPv4 or IPv6
    version = 6 if is_ipv6 else 4
    if is_ipv6:
        max_int = 2**128 - 1
    else:
        max_int = 2**32 - 1

    if ip_str.lower() == "any":
        return 0, max_int, version

    # "-" means ranged IP string. here, get the two integers from start and end of the range.
    if '-' in ip_str:
        try:
            start, end = ip_str.split('-')
            return int(ipaddress.ip_address(start.strip())), int(ipaddress.ip_address(end.strip())), version
        except ValueError:   # invalid arg value but correct data type
            pass

    try:  # Convert IP into a network object and convert the first and last IPs into integers
        net = ipaddress.ip_network(ip_str, strict=False)
        return int(net.network_address), int(net.broadcast_address), version
        # single IP addresses have identical network and broadcast addresses
    except ValueError:
        return 0, 0, version


def port_to_range_ints(port_str: str) -> tuple[int, int]:
    """
    Converts a port string or range into a pair of integers representing the start and end of the range
    Single port values have identical start and end values
    :param port_str: the port value or range
    :return: (start_port, end_port)
    """
    port_str = port_str.strip()
    if not port_str or port_str.lower() == "any":   # "any" port / not specified
        return 0, 65535

    if "-" in port_str:   # ranged port
        try:
            start, end = port_str.split('-', 1)
            return int(start.strip()), int(end.strip())
        except ValueError:
            pass

    try:  # single port value
        p = int(port_str)
        return p, p
    except ValueError:
        return 0, 65535


def parse_xml(xml_data: str) -> list[dict]:
    """
    Parses the Panorama XML running configuration and extracts relevant firewall policy and configuration data.
    :param: xml file
    :return:
    for P1: all data in format of (protocol, sourceIP, destinationIP, destinationPort, action)
    for P2: all data in format of (protocol, sourceIP, destinationIP, destinationPort, action), and if object is used
    for sourceIP, object's name recorded in panorama (which links to sourceIP)

    and for considering CIDR:

    CIDR subnets, variable IP & port ranges: python libraries like ipaddress can convert CIDR subnets into ranged
    numerical integers, also consisting of a start and end value.
    """
    print("Calling parse_xml...")
    root = ET.fromstring(xml_data)   #turn raw XML string into a live, searchable tree in memory
    # root becomes root node of entire config tree
    raw_rules = []
    for rule in root.findall(".//security/rules/entry"):   # .// is XPath syntax; search anywhere at any depth
        # extract rule attributes and put into dictionary "rule_data"
        # this dictionary is then used as an arg for function to normalise
        rule_data = {
            "name": rule.get("name"),
            "protocol": "tcp",
            "sources": [m.text for m in rule.findall(".//source/member")],  # get all source IPs wrapped in <member>
            "destinations": [m.text for m in rule.findall(".//destination/member")],
            "src_ports": ["any"],
            "dst_ports": [m.text for m in rule.findall(".//service/member")],
            "action": rule.findtext("action", "allow")  # look for <action> tags, if missing from XML,
                                                                    # then default to "allow"
        }
        raw_rules.append(rule_data)

    return raw_rules

def parse_objects(xml_data: str) -> dict[str, dict]:
    """
    Extracts and processes Address objects & Address Group objects from the running configuration
    :param xml_data:
    :return:
    """
    root = ET.fromstring(xml_data)
    objects_registry = {}
    group_tags = {}

    def get_tags(elem):
        return [t.text for t in elem.findall(".//tag/member")]

    for addr in root.findall(".//address/entry"):  # go through all addr. object entries, get their names and tags
        name = addr.get("name")
        tags = get_tags(addr)

        if "HOST" in tags:   # ITS regulations say that "HOST" tagged devices can be
                             # searched for reassignment/decommissioned
            obj_type = None
            ip_val = None
            for child in addr:
                if child.tag in ["ip-netmask", "ip-range", "ip-wildcard", "fqdn"]:  # as per ITServices regs
                    obj_type = child.tag
                    ip_val = child.text
                    break
            if name and ip_val:
                objects_registry[name] = {"ip": ip_val, "type": obj_type}

    for group in root.findall(".//address-group/entry"):  # repeat for address groups & AG objects
        name = group.get("name")
        group_tags[name] = get_tags(group)

    for group in root.findall(".//address-group/entry"):
        group_name = group.get("name")
        g_tags = group_tags.get(group_name, [])

        if "HOST" in g_tags:
            for member in group.findall(".//static/member"):
                mem_name = member.text
                if mem_name in group_tags and "HOST-COMPONENT" in group_tags[mem_name]:
                    objects_registry[mem_name] = {"ip": "Group Reference", "type": "address-group"}

    return objects_registry


def normalise_firewall_rules(raw_rules: list[dict], objects_registry: dict) -> list[FirewallRule]:
    """
    Transforms raw parsed rule strings into complete FirewallRule dataclass instances
    :param: utilises
    :return: List of all objects that fit the required tags, + their required info: IP, etc.
    """
    print("Calling rule normalisation...")
    normalised_rules = []

    for raw in raw_rules:   # produced by parse_xml function
        for src in raw["sources"]:  # all source IPs
            for dst in raw["destinations"]:  # all destination IPs
                for dst_port in raw["dst_ports"]:
                    src_xml_object = src if src in objects_registry else None
                    dst_xml_object = dst if dst in objects_registry else None
                    src_ip_raw = objects_registry[src]["ip"] if src_xml_object else src
                    dst_ip_raw = objects_registry[src]["ip"] if dst_xml_object else dst
                    src_start, src_end, src_version = ip_to_range_ints(src_ip_raw)
                    dst_start, dst_end, dst_version = ip_to_range_ints(dst_ip_raw)

                    protoc = "tcp"
                    if "udp" in dst_port.lower():
                        protoc = "udp"

                    s_port_start, s_port_end = port_to_range_ints(raw["src_ports"])
                    d_port_start, d_port_end = port_to_range_ints(dst_port)

                    rule_obj = FirewallRule(
                        ip_version=src_version,
                        protocol=protoc,
                        src_ip_start=src_start,
                        src_ip_end=src_end,
                        dst_ip_start=dst_start,
                        dst_ip_end=dst_end,
                        src_port_start=s_port_start,
                        src_port_end=s_port_end,
                        dst_port_start=d_port_start,
                        dst_port_end=d_port_end,
                        action=raw["action"],
                        src_expected_identity=src_xml_object,
                        dst_expected_identity=dst_xml_object
                    )
                    normalised_rules.append(rule_obj)
    return normalised_rules

def search_traffic(csv_data: str, target_ip: str) -> tuple[bool, str | None]:
    """
    Searches through firewall traffic log CSV data to identify recent activity associated with objects.
    :param: CSV file, IP from some given tuple
    :return: return if IP is present (True/False) + if IP is present, the observed identity
    The tuple return is boolean (true/false, if the IP is present), then observed identity if present, else nothing
    """
    print("Calling search_traffic...")
    csv_file = io.StringIO(csv_data.strip())  # set up the reader
    reader = csv.DictReader(csv_file)

    try:
        target_obj = ipaddress.ip_address(target_ip.strip())   # set the target_ip passed in as the search target
    except ValueError:
        return False, None

    for row in reader:
        # get source and dest. address fields from each row
        src_ip_str = row.get("Source address", row.get("source", "")).strip()
        dst_ip_str = row.get("Destination address", row.get("destination", "")).strip()

        for current_log_ip in [src_ip_str, dst_ip_str]:  # go through each of the two IPs
            try:
                if current_log_ip and ipaddress.ip_address(current_log_ip) == target_obj: # if current IP present in row
                    if current_log_ip == src_ip_str: #...and the current IP is the source IP, return it
                        return True, row.get("Source User", row.get("src_object", "Matched Source"))
                    else:
                        return True, row.get("Destination User", row.get("dst_object", "Matched Destination"))
            except ValueError:
                continue

    return False, None



def reverse_dns(ip: str) -> str | None:
    """
    Performs reverse DNS lookups to resolve IP addresses to their corresponding hostnames for validation.
    :param: object IP (for IPs not present in traffic)
    :return: object name (observed identity)
    """
    print("Calling reverse_dns...")
    ip = ip.strip()
    if not ip or ip.lower() == 'any':
        return None

    try:
        ip = str(ipaddress.ip_address(ip))  # use.exploded on the end if any issues occur here
    except ValueError:
        pass

    if ip in dns_cache:
        return dns_cache[ip]

    try:
        socket.setdefaulttimeout(1.0)
        hostname, aliases, ips = socket.gethostbyaddr(ip)
        dns_cache[ip] = hostname
        return hostname
    except (socket.herror, socket.timeout):
        dns_cache[ip] = None
        return None



