import socket
import ipaddress
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp
import threading

# Setup logging
logging.basicConfig(
    filename="network_scanner.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Thread-safe file lock
lock = threading.Lock()

# Output file paths
IP_MAC_LOG_FILE = "ip_mac_log.txt"
PORT_LOG_FILE = "open_ports_log.txt"
ERROR_LOG_FILE = "scan_errors.log"

def scan_ip(target_ip, ip_mac_header_written):
    """
    Sends an ARP request to the specified IP address.
    Logs the IP and MAC address if the host responds.
    """
    try:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        answered, _ = srp(packet, timeout=1, verbose=False)

        for _, received in answered:
            entry = f"{received.psrc}\t\t{received.hwsrc}\n"
            logging.info(f"Discovered: {entry.strip()}")

            with lock:
                if not ip_mac_header_written[0]:
                    with open(IP_MAC_LOG_FILE, "w") as f:
                        f.write("IP Address\t\tMAC Address\n")
                        f.write("-" * 40 + "\n")
                    ip_mac_header_written[0] = True

                with open(IP_MAC_LOG_FILE, "a") as f:
                    f.write(entry)

    except Exception as e:
        error_msg = f"Error scanning IP {target_ip}: {e}"
        logging.error(error_msg)
        with lock:
            with open(ERROR_LOG_FILE, "a") as err:
                err.write(f"[{datetime.now()}] {error_msg}\n")

def scan_ports(target_ip, ports):
    """
    Scans the specified IP address for open TCP ports.
    Returns a list of open ports.
    """
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((target_ip, port)) == 0:
                    open_ports.append(port)
        except Exception as e:
            error_msg = f"Port scan error on {target_ip}:{port} - {e}"
            logging.error(error_msg)
            with lock:
                with open(ERROR_LOG_FILE, "a") as err:
                    err.write(f"[{datetime.now()}] {error_msg}\n")
    return open_ports

def scan_network(network_range, ports):
    """
    Scans all hosts in the given subnet for live systems and open ports.
    """
    logging.info(f"Starting scan for subnet: {network_range}")
    try:
        network = ipaddress.ip_network(network_range, strict=False)
    except ValueError as e:
        logging.error(f"Invalid network range: {e}")
        return

    ip_mac_header_written = [False]  # Shared flag to write header once

    # Run ARP discovery in parallel
    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(lambda ip: scan_ip(str(ip), ip_mac_header_written), network.hosts())

    logging.info(f"Completed ARP scan for {network_range}")

    # Read discovered hosts from file
    try:
        with open(IP_MAC_LOG_FILE, "r") as f:
            lines = f.readlines()[2:]
            live_hosts = [line.split()[0] for line in lines if line.strip()]
    except FileNotFoundError:
        logging.warning("IP/MAC log file not found. Skipping port scan.")
        return

    open_ports_written = False
    for ip in live_hosts:
        ports_found = scan_ports(ip, ports)
        if ports_found:
            log_entry = f"{ip} open ports: {', '.join(map(str, ports_found))}"
            logging.info(log_entry)
            with lock:
                if not open_ports_written:
                    with open(PORT_LOG_FILE, "w") as f:
                        f.write("Open Ports Scan Results\n")
                        f.write("=" * 40 + "\n")
                    open_ports_written = True

                with open(PORT_LOG_FILE, "a") as f:
                    f.write(f"{log_entry}\n")

def get_subnets_input():
    """
    Prompts the user for one or more CIDR subnets (comma-separated).
    Returns a list of validated CIDR ranges.
    """
    while True:
        user_input = input("Enter one or more CIDR ranges (comma-separated): ").strip()
        ranges = [r.strip() for r in user_input.split(",")]
        try:
            for subnet in ranges:
                ipaddress.ip_network(subnet, strict=False)
            return ranges
        except ValueError as e:
            print(f"❌ Invalid input: {e}")
            logging.warning(f"Invalid subnet input: {e}")

if __name__ == "__main__":
    print("\n🌐 Network Scanner Started")
    subnets = get_subnets_input()
    ports_to_scan = range(1, 1025)

    for subnet in subnets:
        scan_network(subnet, ports_to_scan)

    print("\n✅ Scan complete. Results saved in:")
    print(f"  - {IP_MAC_LOG_FILE}")
    print(f"  - {PORT_LOG_FILE} (if applicable)")
    print(f"  - {ERROR_LOG_FILE} (if any errors occurred)")
