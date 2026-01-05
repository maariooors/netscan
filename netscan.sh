#!/bin/bash

# NetScanner - Fast Network Discovery and Port Scanning Tool
# Author:      maariooors
# Version:     1.0.0
# License:     MIT
# Repository:  https://github.com/maariooors/net-tools
#
# Warning:     Only scan networks you own or have authorization to scan.
#              Unauthorized network scanning may be illegal in your jurisdiction.
#
# Copyright (c) 2026 maariooors. All rights reserved.

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
USE_COLOR="yes"

echo -e "${CYAN}"
echo " _   _      _   ____"
echo "| \\ | | ___| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __"
echo "|  \\| |/ _ \\ __\\___ \\ / __/ _\` | '_ \\| '_ \\ / _ \\ '__|"
echo "| |\\  |  __/ |_ ___) | (_| (_| | | | | | | |  __/ |"
echo "|_| \\_|\\___|\\__|____/ \\___\\__,_|_| |_|_| |_|\\___|_|"
echo -e "${NC}"

# ============================================================================
# FUNCTIONS
# ============================================================================

cleanup() {
    echo ""
    echo "Interrupted. Terminating background processes..."
    kill $(jobs -p) 2>/dev/null
    [ -f /tmp/hosts_$$.tmp ] && rm /tmp/hosts_$$.tmp
    [ -f /tmp/open_ports_$$.tmp ] && rm /tmp/open_ports_$$.tmp
    rm -f /tmp/ports_*_$$.tmp 2>/dev/null
    rm -f /tmp/netscan_output_$$.lock 2>/dev/null
    exit 0
}

show_basic_usage() {
    echo "Use: $0 <ip[/cidr]> [-p ports] [options]"
    echo "Try '$0 -h' for more information."
    exit 1
}

show_usage() {
    echo "Use: $0 <ip[/cidr]> [-p ports] [options]"
    echo ""
    echo "Flags:"
    echo "  -p-                      Scan all 65535 ports on discovered hosts"
    echo "  -p <ports>               Scan specific ports (comma-separated: 80,443 OR range: 80-100)"
    echo "  -o, --output <f>         Save results to file"
    echo "  -v, --verbose            Show scan progress in real-time"
    echo "  -nc, --no-color          Disable colored output"
    echo "  --nmap                   Print nmap command format at the end (-p ports IP)"
    echo "  --batch <n>              Set max parallel port scans (default: 100)"
    echo "  --ping                   Use ping only for host discovery"
    echo "  --arp                    Use ARP only for host discovery"
    echo "  -h, --help               Show this help message and exit"
    echo "  -i, --interface <iface>  Use IP from specified network interface"
    echo "  --timeout <seconds>      Set port scan timeout in seconds (default: 1)"
    echo ""
    echo "Discovery modes (default: Ping + ARP):"
    echo "  Default           Ping + ARP fallback (most complete)"
    echo "  --ping            ICMP ping only (detects responding hosts)"
    echo "  --arp             ARP table only (fast, detects local hosts)"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.0/24                  Host discovery on network (ping + ARP)"
    echo "  $0 -i eth0                         Scan IP from interface eth0"
    echo "  $0 192.168.1.0/24 --ping           Host discovery using ping only"
    echo "  $0 192.168.1.10 -p 80-100          Scan port range"
    echo "  $0 192.168.1.10 -p 80,443,22       Scan specific ports"
    echo "  $0 192.168.1.0/24 -p- --nmap       Full port scan + nmap format"
    echo "  $0 192.168.1.0/24 -p- --batch 50   Full port scan with 50 parallel processes"
    exit 1
}

# ============================================================================
# Validation functions
# ============================================================================

validate_ip() {
    local ip=$1
    
    # Check basic format: must have exactly 4 parts separated by dots
    if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 1
    fi
    
    # Validate each octet (0-255)
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    
    for octet in "$o1" "$o2" "$o3" "$o4"; do
        # Check if octet is a valid number in range 0-255
        if [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
            return 1
        fi
        # Reject leading zeros (except for "0" itself)
        if [ "${#octet}" -gt 1 ] && [ "${octet:0:1}" = "0" ]; then
            return 1
        fi
    done
    
    return 0
}

validate_cidr() {
    local cidr=$1
    
    # Check if it's a number
    if ! [[ "$cidr" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    
    # Check range 0-32
    if [ "$cidr" -lt 0 ] || [ "$cidr" -gt 32 ]; then
        return 1
    fi
    
    return 0
}

validate_port() {
    local port=$1
    
    # Check if it's a number
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        echo "Error: Port '$port' is not a valid number"
        return 1
    fi
    
    # Check range 1-65535
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo "Error: Port '$port' is out of range (1-65535)"
        return 1
    fi
    
    return 0
}

validate_ports() {
    local ports=$1
    
    # Check if it's a range (contains - but not at start/end)
    if [[ "$ports" == *"-"* ]] && [[ ! "$ports" == "-"* ]] && [[ ! "$ports" == *"-" ]]; then
        # Port range mode
        local start_port=$(echo "$ports" | cut -d'-' -f1)
        local end_port=$(echo "$ports" | cut -d'-' -f2)
        
        if ! validate_port "$start_port"; then
            echo "Error: Invalid start port in range: $start_port"
            return 1
        fi
        if ! validate_port "$end_port"; then
            echo "Error: Invalid end port in range: $end_port"
            return 1
        fi
        if [ "$start_port" -ge "$end_port" ]; then
            echo "Error: Start port must be less than end port"
            return 1
        fi
    else
        # Comma-separated ports mode
        IFS=',' read -ra PORT_ARRAY <<< "$ports"
        for port in "${PORT_ARRAY[@]}"; do
            # Remove whitespace
            port=$(echo "$port" | xargs)
            if ! validate_port "$port"; then
                return 1
            fi
        done
    fi
    
    return 0
}

# ============================================================================
# Conversion functions
# ============================================================================

cidr_to_mask() {
    local cidr=$1
    local mask=""
    local full_octets=$((cidr / 8))
    local partial_octet=$((cidr % 8))

    for ((i=0; i<4; i++)); do
        if [ $i -lt $full_octets ]; then
            mask="${mask}255"
        elif [ $i -eq $full_octets ]; then
            mask="${mask}$((256 - 2**(8-partial_octet)))"
        else
            mask="${mask}0"
        fi
        [ $i -lt 3 ] && mask="${mask}."
    done
    echo "$mask"
}

ip2int() {
    local IFS=.
    read -r i1 i2 i3 i4 <<< "$1"
    local result=$(( (i1 * 256 + i2) * 256 + i3 ))
    result=$(( result * 256 + i4 ))
    echo $result
}

int2ip() {
    echo "$(( ($1 >> 24) & 255 )).$(( ($1 >> 16) & 255 )).$(( ($1 >> 8) & 255 )).$(( $1 & 255 ))"
}

output() {
    echo -e "$@"
    if [ -n "$OUTPUT_FILE" ]; then
        # Remove color codes and write
        printf '%b\n' "$@" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTPUT_FILE"
    fi
}

# ============================================================================
# HOST DISCOVERY FUNCTIONS
# ============================================================================

check_host_ping() {
    local ip=$1
    local use_output=$2  # "output" for output(), "echo" for echo -e
    local buffer_file=$3  # Optional: buffer file path

    ping_output=$(ping -c 1 -W 1 "$ip" 2>&1)
    if echo "$ping_output" | grep -q "1 received\|1 packets received"; then
        ttl=$(echo "$ping_output" | grep -oi 'ttl=[0-9]*' | cut -d= -f2 | head -1)
        
        if [ -n "$buffer_file" ]; then
            # Write to buffer
            if [ -n "$ttl" ]; then
                if [ "$ttl" -le 64 ]; then
                    echo "COLOR:RED" > "$buffer_file"
                else
                    echo "COLOR:BLUE" > "$buffer_file"
                fi
            else
                echo "COLOR:BLUE" > "$buffer_file"
            fi
        else
            # Output directly
            if [ -n "$ttl" ]; then
                if [ "$ttl" -le 64 ]; then
                    output "${RED}[+] $ip is up${NC}"
                else
                    output "${BLUE}[+] $ip is up${NC}"
                fi
            else
                output "+] $ip is up"
            fi
        fi
        
        echo "$ip" >> /tmp/hosts_$$.tmp
        return 0
    fi
    return 1
}

check_host_arp() {
    local ip=$1
    local use_output=$2  # "output" for output(), "echo" for echo -e
    local buffer_file=$3  # Optional: buffer file path

    if arp -n "$ip" 2>/dev/null | grep -q "ether"; then
        if [ -n "$buffer_file" ]; then
            # Write to buffer
            echo "COLOR:BLUE" > "$buffer_file"
        else
            # Output directly
            output "${BLUE}[+] $ip is up${NC}"
        fi
        
        echo "$ip" >> /tmp/hosts_$$.tmp
        return 0
    fi
    return 1
}

discover_host() {
    local ip=$1
    local use_output=$2  # "output" for single host, "silent" for network scan with port scan
    local buffer_file=$3  # Optional: buffer file for silent mode

    case "$DISCOVERY_MODE" in
        arp)
            check_host_arp "$ip" "$use_output" "$buffer_file"
            ;;
        ping)
            check_host_ping "$ip" "$use_output" "$buffer_file"
            ;;
        all)
            if ! check_host_ping "$ip" "$use_output" "$buffer_file"; then
                [ "$use_output" = "silent" ] && sleep 0.1
                check_host_arp "$ip" "$use_output" "$buffer_file"
            fi
            ;;
    esac
}

# ============================================================================
# PORT SCANNING FUNCTIONS
# ============================================================================

scan_port() {
    local ip=$1
    local port=$2
    local buffer_file=$3

    timeout $PORT_TIMEOUT bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "$port" >> "$buffer_file"
        echo "$ip:$port" >> /tmp/open_ports_$$.tmp
    fi
}

scan_ports_on_host() {
    local host=$1
    local buffer_file="/tmp/ports_${host//\./_}_$$.tmp"
    local lockfile="/tmp/netscan_output_$$.lock"

    if [ "$PORTS" = "all" ]; then
        # Scan all ports
        for ((port=1; port<=65535; port++)); do
            (scan_port "$host" "$port" "$buffer_file") &

            if [ $((port % MAX_PARALLEL_PORTS)) -eq 0 ]; then
                wait
            fi
        done
    else
        # Scan specific ports
        local count=0

        # Check if it's a range (contains - but not at start/end)
        if [[ "$PORTS" == *"-"* ]] && [[ ! "$PORTS" == "-"* ]] && [[ ! "$PORTS" == *"-" ]]; then
            # Port range mode
            start_port=$(echo "$PORTS" | cut -d'-' -f1)
            end_port=$(echo "$PORTS" | cut -d'-' -f2)

            for ((port=start_port; port<=end_port; port++)); do
                (scan_port "$host" "$port" "$buffer_file") &

                ((count++))
                if [ $((count % MAX_PARALLEL_PORTS)) -eq 0 ]; then
                    wait
                fi
            done
        else
            # Comma-separated ports mode
            IFS=',' read -ra PORT_ARRAY <<< "$PORTS"
            for port in "${PORT_ARRAY[@]}"; do
                # Remove whitespace
                port=$(echo "$port" | xargs)
                (scan_port "$host" "$port" "$buffer_file") &

                ((count++))
                if [ $((count % MAX_PARALLEL_PORTS)) -eq 0 ]; then
                    wait
                fi
            done
        fi
    fi

    wait
    
    # Print results for this host atomically using flock
    (
        flock -x 200
        
        if [ -f "$buffer_file" ]; then
            # Read the first line to get the color
            local color_line=$(head -n 1 "$buffer_file")
            local color="$BLUE"
            
            if [[ "$color_line" == COLOR:RED ]]; then
                color="$RED"
            elif [[ "$color_line" == COLOR:BLUE ]]; then
                color="$BLUE"
            fi
            
            # Check if there are any ports (lines after line 1)
            local has_ports=$(tail -n +2 "$buffer_file" | grep -c .)
            
            if [ "$has_ports" -gt 0 ]; then
                output "\n${color}[+] $host is up${NC}\n"
                
                # Print ports (skip first line which contains color info)
                tail -n +2 "$buffer_file" | sort -n | while read -r port; do
                    if [ -n "$port" ]; then
                        output "${GREEN}  [+] Port $port is open${NC}"
                    fi
                done
                
                output ""
            else
                output "${color}[+] $host is up${NC}"
            fi
            
            rm "$buffer_file"
        fi
    ) 200>"$lockfile"
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

# Trap signals
trap cleanup SIGINT SIGTERM

# Check arguments
if [ $# -lt 1 ]; then
    show_basic_usage
fi

# Configuration variables
MAX_PARALLEL_PORTS=100
PORT_TIMEOUT=1
DISCOVERY_MODE="all"

# Parse arguments
IP=""
MASK=""
SINGLE_HOST=""
PORT_SCAN=""
PORTS=""
CIDR=""
NMAP_FORMAT=""
OUTPUT_FILE=""
VERBOSE=""
NO_COLOR=""

# ============================================================================
# Parameter parsing
# ============================================================================

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_usage
            ;;
        --nmap)
            NMAP_FORMAT="yes"
            shift
            ;;
        -v|--verbose)
            VERBOSE="yes"
            shift
            ;;
        -nc|--no-color)
            NO_COLOR="yes"
            shift
            ;;
        --ping)
            DISCOVERY_MODE="ping"
            shift
            ;;
        --arp)
            DISCOVERY_MODE="arp"
            shift
            ;;
        --batch)
            shift
            if [ -z "$1" ]; then
                echo "Error: --batch requires a number"
                show_basic_usage
            fi
            if ! [[ "$1" =~ ^[0-9]+$ ]] || [ "$1" -lt 1 ]; then
                echo "Error: --batch must be a positive integer"
                show_basic_usage
            fi
            MAX_PARALLEL_PORTS="$1"
            shift
            ;;
        --timeout)
            shift
            if [ -z "$1" ]; then
                echo "Error: --timeout requires a number"
                show_basic_usage
            fi
            if ! [[ "$1" =~ ^[0-9]+$ ]] || [ "$1" -lt 1 ]; then
                echo "Error: --timeout must be a positive integer"
                show_basic_usage
            fi
            PORT_TIMEOUT="$1"
            shift
            ;;
        -o|--output)
            shift
            if [ -z "$1" ]; then
                echo "Error: -o/--output requires a filename"
                show_basic_usage
            fi
            OUTPUT_FILE="$1"
            shift
            ;;
        -p)
            shift
            if [ -z "$1" ]; then
                echo "Error: -p requires an argument"
                show_basic_usage
            fi
            # Validate ports
            if ! validate_ports "$1"; then
                exit 1
            fi
            PORT_SCAN="yes"
            PORTS="$1"
            shift
            ;;
        -p-)
            PORT_SCAN="yes"
            PORTS="all"
            shift
            ;;
        -i | --interface)
            shift
            if [ -z "$1" ]; then
                echo "Error: -i/--interface requires an interface name"
                show_basic_usage
            fi
            IP_WITH_CIDR="$(ip addr show $1 2>/dev/null | grep 'inet ' | awk '{print $2}' | head -1)"
            if [ -z "$IP_WITH_CIDR" ]; then
                echo "Error: Interface '$1' is not available or has no IP address"
                exit 1
            fi
            # Extract IP and CIDR
            IP=$(echo "$IP_WITH_CIDR" | cut -d'/' -f1)
            CIDR=$(echo "$IP_WITH_CIDR" | cut -d'/' -f2)
            
            # Validate extracted IP and CIDR
            if ! validate_ip "$IP"; then
                echo "Error: Invalid IP address obtained from interface: $IP"
                exit 1
            fi
            if ! validate_cidr "$CIDR"; then
                echo "Error: Invalid CIDR obtained from interface: $CIDR"
                exit 1
            fi
            
            MASK=$(cidr_to_mask "$CIDR")
            shift
            ;;
        *)
            # Check if it looks like a flag
            if [[ "$1" == -* ]]; then
                echo "Error: Unknown flag '$1'"
                show_basic_usage
            fi

            if [ -z "$IP" ]; then
                # Check if IP contains CIDR notation
                if [[ "$1" == *"/"* ]]; then
                    IP=$(echo "$1" | cut -d'/' -f1)
                    CIDR=$(echo "$1" | cut -d'/' -f2)
                    
                    # Validate IP and CIDR
                    if ! validate_ip "$IP"; then
                        echo "Error: Invalid IP address format: $IP"
                        exit 1
                    fi
                    if ! validate_cidr "$CIDR"; then
                        echo "Error: Invalid CIDR value (must be 0-32): $CIDR"
                        exit 1
                    fi
                    
                    MASK=$(cidr_to_mask "$CIDR")
                else
                    # No CIDR notation = single host
                    IP="$1"
                    
                    # Validate IP
                    if ! validate_ip "$IP"; then
                        echo "Error: Invalid IP address format: $IP"
                        exit 1
                    fi
                    
                    SINGLE_HOST="yes"
                    MASK="255.255.255.255"
                fi
            else
                echo "Error: Unexpected argument '$1'"
                show_basic_usage
            fi
            shift
            ;;
    esac
done

# ============================================================================
# Basic validations
# ============================================================================

if [ -z "$IP" ]; then
    show_basic_usage
fi

# Disable colors if not outputting to terminal or -nc flag
if [ ! -t 1 ] || [ -n "$NO_COLOR" ]; then
    RED=''
    GREEN=''
    BLUE=''
    CYAN=''
    NC=''
fi

# Initialize output file if specified
if [ -n "$OUTPUT_FILE" ]; then
    > "$OUTPUT_FILE"
fi

# Calculate network parameters
IFS=. read -r i1 i2 i3 i4 <<< "$IP"
IFS=. read -r m1 m2 m3 m4 <<< "$MASK"
network_addr=$(printf "%d.%d.%d.%d" "$((i1 & m1))" "$((i2 & m2))" "$((i3 & m3))" "$((i4 & m4))")

mask_int=$(ip2int "$MASK")
network_int=$(ip2int "$network_addr")
broadcast_int=$((network_int | ~mask_int & 0xFFFFFFFF))

# ============================================================================
# Print scan configuration
# ============================================================================

output "================================"
if [ -n "$SINGLE_HOST" ]; then
    output "Target: $IP"
else
    output "Network: $network_addr"
    output "Netmask: $MASK"
fi
if [ -n "$PORT_SCAN" ]; then
    if [ "$PORTS" = "all" ]; then
        output "Port scan: All ports (1-65535)"
    else
        output "Port scan: $PORTS"
    fi
fi
if [ -n "$VERBOSE" ]; then
    output "Mode: Verbose"
fi
if [ -n "$OUTPUT_FILE" ]; then
    output "Output file: $OUTPUT_FILE"
fi
output "================================"

# ============================================================================
# Host discovery and port scanning phase
# ============================================================================

if [ -n "$SINGLE_HOST" ]; then
    # Single host mode
    if [ -n "$PORT_SCAN" ]; then
        # With port scan: use buffer
        buffer_file="/tmp/ports_${IP//\./_}_$$.tmp"
        if discover_host "$IP" "silent" "$buffer_file"; then
            scan_ports_on_host "$IP"
        else
            output "[-] $IP is down or unreachable"
        fi
    else
        # Without port scan: direct output
        if discover_host "$IP" "output"; then
            :
        else
            output "[-] $IP is down or unreachable"
        fi
    fi
else
    # Network scan mode
    if [ -n "$PORT_SCAN" ]; then
        # Mode: Discover host and scan ports immediately
        for ((ip_int=network_int+1; ip_int<broadcast_int; ip_int++)); do
            current_ip=$(int2ip $ip_int)
            (
                buffer_file="/tmp/ports_${current_ip//\./_}_$$.tmp"
                if discover_host "$current_ip" "silent" "$buffer_file"; then
                    scan_ports_on_host "$current_ip"
                fi
            ) &
        done
        wait
    else
        # Mode: Only host discovery (no port scan)
        for ((ip_int=network_int+1; ip_int<broadcast_int; ip_int++)); do
            current_ip=$(int2ip $ip_int)
            (
                discover_host "$current_ip" "echo"
            ) &
        done
        wait
    fi
fi

# ============================================================================
# Print results summary
# ============================================================================

HOST_COUNT=0
if [ -f /tmp/hosts_$$.tmp ]; then
    HOST_COUNT=$(wc -l < /tmp/hosts_$$.tmp)
fi

if [ -z "$SINGLE_HOST" ] && [ -n "$VERBOSE" ]; then
    output "\n================================"
    output "$HOST_COUNT host(s) discovered"
    if [ -n "$PORT_SCAN" ]; then
        PORT_COUNT=0
        if [ -f /tmp/open_ports_$$.tmp ]; then
            PORT_COUNT=$(wc -l < /tmp/open_ports_$$.tmp)
        fi
        output "$PORT_COUNT open port(s) discovered"
    fi
fi

# ============================================================================
# Print in nmap format
# ============================================================================

if [ -n "$NMAP_FORMAT" ] && [ -f /tmp/open_ports_$$.tmp ]; then
    output "\n================================\nNmap command format:\n"

    # Group ports by host
    declare -A host_ports
    while IFS=':' read -r host port; do
        if [ -z "${host_ports[$host]}" ]; then
            host_ports[$host]="$port"
        else
            host_ports[$host]="${host_ports[$host]},$port"
        fi
    done < /tmp/open_ports_$$.tmp

    # Print nmap format for each host
    for host in "${!host_ports[@]}"; do
        output "-p ${host_ports[$host]} $host"
    done
fi

# Cleanup temp files
[ -f /tmp/hosts_$$.tmp ] && rm /tmp/hosts_$$.tmp
[ -f /tmp/open_ports_$$.tmp ] && rm /tmp/open_ports_$$.tmp
rm -f /tmp/ports_*_$$.tmp 2>/dev/null
rm -f /tmp/netscan_output_$$.lock 2>/dev/null

exit 0