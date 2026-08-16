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

dns_cache = {}    # store information about queried IPs and their observed identities

@dataclass()
class FirewallRule:
    rule_name: str | None   # Present in the XML running config file
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
    firewall_name: str | None
    src_expected_identity: str | None    # from XML, e.g., "Finance-Server", aka src_xml_object
    dst_expected_identity: str | None
    src_observed_identity: str | None    # !! this may NOT BE NEEDED; we can use the DNS cache instead ==> no problem
                                         # ANS) no problem in keeping it for now unless issues appear
    dst_observed_identity: str | None    # (p2) hostname from reverse DNS, e.g.,"finance-01.york.ac.uk"
                                         # if IP is in traffic logs, expected = observed
                                         # else, do reverse DNS, then record that as observed


# translating common <service> tag values in <rules> that are not raw port values
SERVICE_PORT_MAPPING = {
    "application-default": (0, 65535), # Evaluated dynamically or kept broad for safety
    "any": (0, 65535),
    "smtp": (25, 25),
    "http": (80, 80),
    "https": (443, 443),
    "dns": (53, 53),
    "ssh": (22, 22),
    "telnet": (23, 23),
    "ftp": (21, 21),
    "ntp": (123, 123),
    "snmp": (161, 162),
    "bgp": (179, 179),
    "ldaps": (636, 636),
    "ldap": (389, 389),
    "rdp": (3389, 3389),
    "smb": (445, 445),
    "oracle": (1521, 1521),
    "mysql": (3306, 3306),
    "ms-sql-s": (1433, 1433)
}


def parse_service_objects(xml_data: str) -> dict[str, tuple[int, int]]:
    """
    Parses custom service objects defined in the XML using XPaths, complementary to SERVICE_PORT_MAPPING dictionary
    Maps service object names to their true (start_port, end_port) integer ranges.
    :param xml_data:
    :return:
    """
    root = ET.fromstring(xml_data)
    service_registry = {}

    # Locating XPath
    for service in root.findall(".//service/entry"):
        name = service.get("name")
        if not name:
            continue

        # Service entries explicitly detail the protocol layout block (tcp or udp)
        for proto in ['tcp', 'udp']: # why only tcp & udp????
            port_elem = service.find(f"./protocol/{proto}/port")
            if port_elem is not None and port_elem.text:
                raw_port_text = port_elem.text.strip()

                # Extract integer boundaries directly from the configuration definition
                start, end = port_to_range_ints(raw_port_text, proto)
                service_registry[name] = (start, end)
                break  # Stop searching protocols once mapped

    return service_registry


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


def port_to_range_ints(port_str: str, protocol: str) -> tuple[int, int]:
    """
    Converts a port string or range into a pair of integers representing the start and end of the range
    Single port values have identical start and end values
    :param port_str: the port value or range
    :return: (start_port, end_port)
    """
    port_str = port_str.strip().lower()

    if not port_str or port_str == "any" or port_str == 'application-default':   # "any" port / not specified
        return 0, 65535

    # Strip protocol prefixes cleanly e.g., 'tcp/80' becomes 80
    if '/' in port_str:
        prefix, port_str = port_str.split('/', 1)
        port_str = port_str.strip()

    if port_str in SERVICE_PORT_MAPPING:
        return SERVICE_PORT_MAPPING[port_str]

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

    !!! maybe this should return list[some other data type]???
    """
    print("Calling parse_xml...")
    root = ET.fromstring(xml_data)   #turn raw XML string into a live, searchable tree in memory
    # root becomes root node of entire config tree
    raw_rules = []
    for rule in root.findall(".//security/rules/entry"):   # .// is XPath syntax; search anywhere at any depth
        # extract rule attributes and put into dictionary "rule_data"
        # this dictionary is then used as an arg for function to normalise
        if rule.findtext("disabled") == "yes":
            continue  # Skip disabled rules; they are inactive

        negate_src = rule.findtext("negate-source") == "yes"
        negate_dst = rule.findtext("negate-destination") == "yes"

        rule_data = {
            "name": rule.get("name"),
            "protocol": "tcp",
            "sources": [m.text for m in rule.findall(".//source/member")],  # get all source IPs wrapped in <member>
            "destinations": [m.text for m in rule.findall(".//destination/member")],
            "src_ports": ["any"],
            "dst_ports": [m.text for m in rule.findall(".//service/member")],
            "action": rule.findtext("action", "allow"),  # look for <action> tags, if missing from XML,
                                                                    # then default to "allow"
            "negate_source": negate_src,
            "negate_dest": negate_dst
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
    # group_tags = {}
    #
    # def get_tags(elem):
    #     return [t.text for t in elem.findall(".//tag/member")]

    for addr in root.findall(".//address/entry"):  # go through all addr. object entries, get their names and tags
        name = addr.get("name")
        # tags = get_tags(addr)
        if not name:
            continue

        # if "HOST" in tags:   # ITS regulations say that "HOST" tagged devices can be
        #                      # searched for reassignment/decommissioned
        obj_type = None
        ip_val = None
        for child in addr:
            if child.tag in ["ip-netmask", "ip-range", "ip-wildcard", "fqdn"]:  # as per ITServices regs
                obj_type = child.tag
                ip_val = child.text
                break

        if ip_val: #name and ip_val:
            objects_registry[name] = {"ip": ip_val, "type": obj_type}

    # for group in root.findall(".//address-group/entry"):  # repeat for address groups & AG objects
    #     name = group.get("name")
    #     group_tags[name] = get_tags(group)

    for group in root.findall(".//address-group/entry"):
        group_name = group.get("name")
        # g_tags = group_tags.get(group_name, [])
        if not group_name:
            continue


        for member in group.findall(".//static/member"):
            mem_name = member.text
            if mem_name and mem_name not in objects_registry:
                objects_registry[mem_name] = {"ip": "Group Reference", "type": "address-group"}

    return objects_registry


def get_negated_ranges(start: int, end: int, max_int: int) -> list[tuple[int, int]]:
    """
    Helper that returns the inverse space of a given range, when <negate-source> or
    <negate-destination> are true for a given rule

    e.g., if it negates 10.0.0.0/24 (integer range A to B), generate two windows of allowed values:
    (0, A-1) and (B+1, max_int)
    :param start:
    :param end:
    :param max_int:
    :return:
    """
    ranges = []
    if start > 0:
        ranges.append((0, start - 1))
    if end < max_int:
        ranges.append((end + 1, max_int))
    return ranges


def normalise_firewall_rules(raw_rules: list[dict], service_registry: dict, objects_registry: dict) -> list[FirewallRule]:
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
                    dst_ip_raw = objects_registry[dst]["ip"] if dst_xml_object else dst
                    src_start, src_end, src_version = ip_to_range_ints(src_ip_raw)
                    dst_start, dst_end, dst_version = ip_to_range_ints(dst_ip_raw)
                    #!!!!! how about getting the src&dst observed identities

                    protoc = "tcp"
                    if "udp" in dst_port.lower():
                        protoc = "udp"

                    s_port_start, s_port_end = port_to_range_ints(raw["src_ports"][0], protoc)
                        # ^^^ raw["..."] evaluates to a list, ['any']
                        # but raw["..."][0] extracts first value inside that list 'any', returns string
                    # s_port_start, s_port_end = port_to_range_ints(raw["src_ports"], protoc)
                    # d_port_start, d_port_end = port_to_range_ints(dst_port, protoc)
                    # check service registry
                    if dst_port in service_registry:
                        d_port_start, d_port_end = service_registry[dst_port]
                    else:
                        d_port_start, d_port_end = port_to_range_ints(dst_port, protoc)

                    rule_obj = FirewallRule(
                        firewall_name=None,
                        src_observed_identity=None,
                        dst_observed_identity=None,
                        rule_name=raw["name"],
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
                        # ignore observed src/dst identities; normaliser doesnt have access to
                        # traffic logs or DNS cache needed to discover this observed identity
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



