"""main.py"""
from panos.panorama import Panorama
from panos.errors import PanDeviceError
import xml.etree.ElementTree as ET
from data_processing import parse_objects, parse_xml

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


def connect_to_panorama():
    """
    A separate method which will hold the code for connecting to Panorama, which may or may not be needed
    """
    panorama_ip = input("Enter Panorama Address: ").strip()
    api_k = input("Enter valid API key: ").strip()

    # days = 45   # traffic log should be 45 days

    connection = PanoramaConnection(hostname=panorama_ip, api_key=api_k)

    try:
        connection.connect()
        print("SUCCESS: Connection has been authenticated.")

        running_config_xml = connection.download_running_config()
        traffic_logs_csv = connection.download_traffic_logs(days=45)
        connection.disconnect()

        print("\nINITIALISING PROCESSING PHASE.....")
        print("\nExtracting structural objects context...")
        objects_registry = parse_objects(running_config_xml)

        print("Gathering active rule blocks from policy engine...")
        raw_rules = parse_xml(running_config_xml)

        print("Generating normalised firewall rules...")
        final_rules = parse_objects(raw_rules, objects_registry)

        print(f"\n===================================================")
        print(f"PROCESS COMPLETE: processed {len(final_rules)} firewall rule dimensions successfully.")
        print(f"===================================================")

    except (ConnectionError, RuntimeError) as err:
        print(f"\n[CRITICAL ERROR] Run execution halted: {err}")

def main():
    print("Calling entry method...")


if __name__ == "__main__":
    main()