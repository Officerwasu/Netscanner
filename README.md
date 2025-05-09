# Network Discovery Tool in C

## Description

This C program is a network discovery tool that identifies active devices on a local network. It uses ARP (Address Resolution Protocol) requests to find devices and retrieves their IP and MAC addresses.


## Requirements
* **Root Privileges**
* **libpcap** 
* **Compiler**

## Usage

**Compile the program:**

```bash
gcc Scan.C -o network_scanner -lpthread
```

**Scan your network**

```bash
sudo ./network_scanner [interface]
```
