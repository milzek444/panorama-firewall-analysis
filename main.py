"""
main.py

This module contains the main code for the project, including parsing functions, drift
detection, and reporting.

TODO: Later on, determine whether the code requires splitting into separate modules (if it becomes too difficult to
read)
"""
def main():
    print("Calling entry method...")


def connect_to_panorama():
    """
    A separate method which will hold the code for connecting to Panorama, which may or may not be needed
    """
    panorama_ip = input("Enter Panorama Address: ").strip()
    api_k = input("Enter valid API key: ").strip()

    days = 45   # traffic log should be 45 days

    connection = PanoramaConnection(hostname=panorama_ip, api_key=api_k)

    try:
        connection.connect()
        print("SUCCESS: Connection has been authenticated.")

        running_config_xml = connection.download_running_config()
        traffic_logs_csv = connection.download_traffic_logs(days=days)
        connection.disconnect()

        print("\nINITIALISING PROCESSING PHASE.....")
        print("\nExtracting structural objects context...")
        objects_registry = parse_objects(running_config_xml)

        print("Gathering active rule blocks from policy engine...")
        raw_rules = parse_xml_policies(running_config_xml)

        print("Generating normalized firewall rules...")
        final_rules = normalise_firewall_rules(raw_rules, objects_registry)

        print(f"\n===================================================")
        print(f"PROCESS COMPLETE: processed {len(final_rules)} firewall rule dimensions successfully.")
        print(f"===================================================")

    except (ConnectionError, RuntimeError) as err:
        print(f"\n[CRITICAL ERROR] Run execution halted: {err}")


if __name__ == "__main__":
    main()