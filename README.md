# Network Discovery Tool in C

## Description

This C program is a network discovery tool that identifies active devices on a local network. It uses ARP (Address Resolution Protocol) requests to find devices and retrieves their IP and MAC addresses.

## Features

* **Network Scanning:** Sends ARP requests to all possible IP addresses in a specified subnet (default: /24).
* **Device Identification:** Receives ARP replies from active devices and extracts their IP and MAC addresses.
* **Multithreading:** Uses pthreads to send ARP requests concurrently, significantly speeding up the discovery process.
* **Interface Selection:** Allows you to specify the network interface to use for scanning (e.g., `eth0`, `wlan0`).
* **ARP Request Sending:** Uses either libpcap or raw sockets to send ARP requests.
* **Error Handling:** Includes error handling for socket creation, ARP request sending, and reply receiving.
* **Clear Output:** Prints the IP and MAC addresses of discovered devices to the console.

## Prerequisites

* **Linux Operating System:** This program is designed for Linux systems.
* **Root Privileges:** Running this program requires root privileges because sending raw network packets is involved.
* **libpcap (Optional):** If you have libpcap installed, the program can use it to send ARP requests, which is the recommended approach.  If libpcap is not found, the program will use raw sockets.
* **Compiler:** A C compiler (e.g., GCC).

## Installation

1.  **Clone the repository (if applicable) or download the code.**
2.  **Compile the program:**

    * **With libpcap:**
        ```bash
        gcc network_scanner.c -o network_scanner -lpcap -pthread
        ```
    * **Without libpcap:**
        ```bash
        gcc network_scanner.c -o network_scanner -pthread
        ```

3.  **Ensure you have root privileges to run the program.**

## Usage

Run the program from the command line:

```bash
sudo ./network_scanner [interface]
