# NetScanner

```
 _   _      _   ____                                  
| \ | | ___| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __ 
|  \| |/ _ \ __\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |\  |  __/ |_ ___) | (_| (_| | | | | | | |  __/ |   
|_| \_|\___|\__|____/ \___\__,_|_| |_|_| |_|\___|_|   
```

A fast, lightweight network scanner for host discovery and port scanning with basic OS detection.

## 🚀 Features

- **Smart Host Discovery**: Multiple discovery modes (Ping, ARP, or both)
- **OS Detection**: Automatic Linux/Windows classification via TTL analysis
- **Flexible Port Scanning**: Single ports, ranges, or full 65535 port scan
- **Parallel Processing**: Configurable batch processing for optimal performance
- **Multiple Output Formats**: Screen, file, or nmap-compatible format
- **CIDR Support**: Scan entire networks with /24, /16, etc.
- **Color-Coded Output**: Clear visual distinction between OS types and open ports
- **Zero Dependencies**: Pure bash implementation

## 🔧 Installation

### 🐧 Linux

```bash
# Clone or download
wget https://github.com/maariooors/net-tools

# Make executable
chmod +x netscan.sh

# Optional: Move to PATH
sudo mv netscan.sh /usr/local/bin/netscan
```

### 🪟 Windows

    Soon

## 📖 Usage

### Basic Syntax

```bash
./netscan.sh <ip[/cidr]> [-p ports] [options]
```

## 🎛️ Command Reference

### Flags

| Flag | Description | Example |
|------|-------------|---------|
| `-p <ports>` | Scan specific ports | `-p 80,443` or `-p 80-100` |
| `-p-` | Scan all 65535 ports | `-p-` |
| `-i, --interface <iface>` | Use IP from network interface | `-i eth0` |
| `-o, --output <file>` | Save results to file | `-o results.txt` |
| `-v, --verbose` | Show detailed progress | `-v` |
| `-nc, --no-color` | Disable colored output | `-nc` |
| `--nmap` | Output in nmap format | `--nmap` |
| `--batch <n>` | Set parallel port scans | `--batch 50` |
| `--timeout <seconds>` | Set port scan timeout | `--timeout 2` |
| `--ping` | Use ping only | `--ping` |
| `--arp` | Use ARP only | `--arp` |
| `-h, --help` | Show help message | `-h` |

## 🎯 Discovery Modes

NetScanner supports three host discovery modes:

| Mode | Flag | Speed | Coverage | Best For |
|------|------|-------|----------|----------|
| **Ping + ARP** | Default | Medium | High | General scanning |
| **Ping Only** | `--ping` | Fast | Medium | Remote networks |
| **ARP Only** | `--arp` | Very Fast | Local only | Local network scans |

### Examples

```bash
# Default: Ping + ARP (most complete)
./netscan.sh 192.168.1.0/24

# Ping only (faster, misses silent hosts)
./netscan.sh 192.168.1.0/24 --ping

# ARP only (fastest, local network only)
./netscan.sh 192.168.1.0/24 --arp
```

## 🎨 OS Detection

NetScanner automatically detects operating systems based on TTL values:

- **Red** = Linux/Unix (TTL <= 64)
- **Blue** = Windows (TTL > 64 or ARP-detected)


## 🌐 Network Interface Selection

Instead of manually specifying an IP address, you can use the `-i` or `--interface` flag to automatically detect and use the IP from a network interface:

```bash
# Use IP from eth0 interface
./netscan.sh -i eth0

# Use IP from wlan0 interface
./netscan.sh -i wlan0 -p 80,443

# Combine with other options
./netscan.sh -i eth0 -p- --batch 50 -v
```

This is especially useful when:
- Working with multiple network interfaces
- IP addresses change dynamically (DHCP)
- Scripting automated scans

## 🔍 Port Scanning

### Port Specification Formats

```bash
# Single port
./netscan.sh 192.168.1.10 -p 80

# Multiple ports (comma-separated)
./netscan.sh 192.168.1.10 -p 22,80,443,3306

# Port range
./netscan.sh 192.168.1.10 -p 1-1000

# All ports (1-65535)
./netscan.sh 192.168.1.10 -p-
```

### Performance Tuning

Control parallel port scanning with `--batch`:

```bash
# Default: 100 parallel scans
./netscan.sh 192.168.1.0/24 -p-

# Low-resource systems: 50 parallel scans
./netscan.sh 192.168.1.0/24 -p- --batch 50

# High-performance systems: 200 parallel scans
./netscan.sh 192.168.1.0/24 -p- --batch 200
```

### Port Scan Timeout

Adjust the connection timeout for port scanning with `--timeout` (default: 1 second):

```bash
# Default timeout: 1 second
./netscan.sh 192.168.1.10 -p 80,443

# Faster scans: 0.5 seconds timeout (for fast networks)
./netscan.sh 192.168.1.10 -p- --timeout 1

# Slower scans: 3 seconds timeout (for slow/unreliable networks)
./netscan.sh 192.168.1.10 -p 1-1000 --timeout 3
```

## 📊 Output Options

### Save to File

```bash
# Save results to file
./netscan.sh 192.168.1.0/24 -p 80,443 -o results.txt
```

### Nmap Format

Generate nmap-compatible command format for further scanning:

```bash
./netscan.sh 192.168.1.0/24 -p 80,443 --nmap

# Output:
# -p 445 192.168.1.144
# -p 53,80,443 192.168.1.1
```

### Verbose Mode

Show detailed progress information:

```bash
./netscan.sh 192.168.1.0/24 -p 80,443 -v
```

### Disable Colors

For piping or logging:

```bash
./netscan.sh 192.168.1.0/24 -nc
```

## 📝 Output Examples

### Host Discovery Output

```
================================
Network: 192.168.1.0
Netmask: 255.255.255.0
================================

[+] 192.168.1.1 is up
[+] 192.168.1.10 is up
[+] 192.168.1.15 is up
```

### Port Scanning Output

```
================================
Target: 192.168.1.10
Port scan: 22,80,443
================================

[+] 192.168.1.10 is up

  [+] Port 22 is open
  [+] Port 80 is open
  [+] Port 443 is open
```

### Nmap Format Output

```
Nmap command format:

-p 445 192.168.1.144
-p 445 192.168.1.137
-p 53,80,443 192.168.1.1
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/maariooors/net-tools/blob/main/LICENSE) file for details.

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing only. Always obtain proper authorization before scanning networks you do not own.
