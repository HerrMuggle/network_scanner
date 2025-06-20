# Network Scanner

A Python script that scans IP addresses in a specified network range and logs open ports. This tool is useful for network administrators and security professionals to discover live hosts and identify open ports on a network.

## Features

- **Host Discovery:** Uses ARP requests to find live hosts on a specified network range.
- **Port Scanning:** Checks for open ports on discovered hosts.
- **Multithreading:** Speeds up the scanning process by using multiple threads.
- **Logging:** Logs IP and MAC addresses to `ip_mac_log.txt` and open ports to `open_ports_log.txt`.

## Usage

1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/network_scanner.git
   cd network_scanner
   ```

## Run 

1. Change permissions and run the script
   ```sh
   sudo chmod +x network_scanner.py
   python3 network_scanner.py 
   ```

## Results

- IP and MAC Addresses: Saved in `ip_mac_log.txt.`
- Open Ports: Saved in `open_ports_log.txt.`

## Example

```sh
Enter one or more CIDR ranges (comma-separated): 192.168.2.0/24
```

## What I Learned

Building this network scanner taught me a lot about network protocols, subprocess management, and error handling. Here are some key takeaways:

- Network Protocols: I gained a deeper understanding of ARP requests and how they work at the network layer.
- Subprocess Management: I learned how to manage multiple subprocesses efficiently using Python's concurrent.futures module.
- Error Handling: I implemented robust error handling to ensure the script can deal with various exceptions gracefully.
- Logging: I improved my skills in logging important information and errors for better traceability and debugging.
- File Handling: I practiced safe file handling techniques to ensure that multiple threads can write to files without causing data corruption.

## Contributing

Feel free to fork the repository and submit pull requests with improvements or additional features.

## License

This project is licensed under the MIT License.
