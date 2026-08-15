"""main.py"""
from panos.panorama import Panorama
from panos.errors import PanDeviceError
import xml.etree.ElementTree as ET

from analysis import analyse_inter_firewall_policies, ReportingRemediationEngine, analyse_config_objects
from data_processing import parse_objects, parse_xml, normalise_firewall_rules, parse_service_objects


class PanoramaConnection:
    # Managing secure operational connections and data collection layers with the correct intended Panorama instance.
    def __init__(self, hostname: str, api_key: str):
        self.hostname = hostname
        self._api_key = api_key
        self.pan_device = None   # the Panorama device

    def connect(self) -> bool:
        try:
            self.pan_device = Panorama(self.hostname, api_key=self._api_key)
            self.pan_device.refresh_system_info()
            return True
        except PanDeviceError as e:
            raise ConnectionError(f"Authentication failed or Panorama unreachable: {e}")
        except Exception as e:
            raise ConnectionError(f"Network connection failure: {e}")

    def download_running_config(self) -> str:
        # Requests and returns the active running configuration as an XML string
        if not self.pan_device:
            raise RuntimeError("Cannot request configuration: device is not connected.")
        try:
            xml_response_element = self.pan_device.op(cmd="show config running", cmd_xml=False)
            return ET.tostring(xml_response_element, encoding='utf-8').decode('utf-8')
        except PanDeviceError as e:
            raise RuntimeError(f"API Error fetching running config: {e}")

    def download_traffic_logs(self) -> str:
        """Asynchronously requests traffic logs over a rolling day timeframe window, returning a CSV string."""
        if not self.pan_device:
            raise RuntimeError("Cannot request traffic logs. Device is not connected.")

        log_query = f"( receive_time geq '$current_time - 45 days' )"
        try:
            print(f"Requesting traffic logs...")
            log_job = self.pan_device.log(
                log_type="traffic",
                filter=log_query,
                nlogs=5000
            )

            csv_output = ["Source address,Destination address,Source User,Destination User"]
            for log_entry in log_job:
                src = log_entry.get('src', '')
                dst = log_entry.get('dst', '')
                src_user = log_entry.get('srcuser', '')
                dst_user = log_entry.get('dstuser', '')
                csv_output.append(f"{src},{dst},{src_user},{dst_user}")

            return "\n".join(csv_output)
        except PanDeviceError as e:
            raise RuntimeError(f"Traffic log generation failed or was disabled: {e}")

    def disconnect(self):
        """Cleans up internal connection handles safely."""
        self.pan_device = None


def main():
    print("Calling entry method...")

    # connect_to_panorama()
    panorama_ip = input("Enter Panorama Address: ").strip()
    api_k = input("Enter valid API key: ").strip()

    # days = 45   # traffic log should be 45 days

    # Initialise connection manager
    connection = PanoramaConnection(hostname=panorama_ip, api_key=api_k)

    try:
        connection.connect()
        print("SUCCESS: Connection has been authenticated.")

        # Retrieve XML config & CSV traffic logs from Panorama, then disconnect
        running_config_xml = connection.download_running_config()
        traffic_logs_csv = connection.download_traffic_logs()
        connection.disconnect()

        print("\nINITIALISING PROCESSING PHASE.....")

        print("\nExtracting structural objects context...")
        objects_registry = parse_objects(running_config_xml)

        print("\nExtractive service objects....")
        service_registry = parse_service_objects(running_config_xml)

        print("Gathering active rule blocks from policy engine...")
        raw_rules = parse_xml(running_config_xml)

        print("Generating normalised firewall rules...")
        final_rules = normalise_firewall_rules(raw_rules, objects_registry, service_registry)

        # List the existing firewalls from the configuration
        # This reads the 'firewall_name' attribute directly from the FirewallRule dataclass
        discovered_fws = set(getattr(r, 'firewall_name', 'Unknown-FW') for r in final_rules)

        print("\nFirewalls present in your Panorama configuration:")
        for fw in discovered_fws:
            print(f" - {fw}")

        # Then present the user prompt, asking for which firewall is the perimeter one
        perimeter_input = input("\nEnter the exact name of the perimeter Firewall [Default: Sentry]: ").strip()

        # If the user just presses Enter, it safely defaults to "Sentry"
        perimeter_name = perimeter_input if perimeter_input else "Sentry"
        print(f"--> Using '{perimeter_name}' as the perimeter firewall between the network and public internet .")

        # Now execute core analysis algorithms (rules + objects + reporting)
        print("[PROCESSING] Algorithm 1: Inter-Firewall matrix validation...")
        contradictions = analyse_inter_firewall_policies(final_rules, perimeter_name=perimeter_name)

        print("[PROCESSING] Algorithm 2: Correlating traffic logs and DNS cache...")
        anomalies = analyse_config_objects(running_config_xml, traffic_logs_csv, final_rules)

        print("[PROCESSING] Sorting final report and remediations....")
        engine = ReportingRemediationEngine(contradictions, anomalies)

        # Print the final report details to terminal plus payload
        print("\n" + "=" * 50)
        print("\nFINAL REPORT:")
        print(engine.generate_final_report())
        print("=" * 50)

        xml_payloads = engine.generate_panorama_payloads()
        total_commands = sum(len(commands_list) for commands_list in xml_payloads.values())
        print(f"\nGenerated {total_commands} ready XML remediation payload strings.")

    except (ConnectionError, RuntimeError) as err:
        print(f"\n[ERROR] Execution halted: {err}")


if __name__ == "__main__":
    main()