# WIFI SECURITY ASSESSMENT TOOL (Python) v1.0
# Author: h4cker_fawad
# Description: Discover nearby Wi-Fi networks and analyze security details.

# ===== 1. IMPORT LIBRARIES & PROJECT SETUP =====
import os
import sys
import time
import csv
import json
import re
import subprocess
from datetime import datetime

# Try to import optional libraries
try:
    from tabulate import tabulate
except ImportError:
    print('[!] tabulate module not found. Install it using: pip install tabulate')
    tabulate = None

try:
    from scapy.all import *
    from scapy.layers.dot11 import *
except ImportError:
    print('[!] scapy module not found. Install it using: pip install scapy')
    print('[!] Some features may not work without scapy.')

# ===== PROJECT FOLDERS =====
DATA_DIR = 'data'
LOGS_DIR = 'logs'
REPORTS_DIR = 'reports'
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# ===== CONFIGURATION =====
DEFAULT_INTERFACE = None
SCAN_TIMEOUT = 10
LOG_FILE = os.path.join(LOGS_DIR, 'wifi_tool.log')
RESULTS_FILE = os.path.join(DATA_DIR, 'networks.csv')

# ===== TOOL INFORMATION =====
TOOL_NAME = "WIFI SECURITY ASSESSMENT TOOL"
TOOL_VERSION = "1.0"
AUTHOR = "h4cker_fawad"
DESCRIPTION = "Discover nearby Wi-Fi networks and analyze security details."


# ===== 2. WI-FI NETWORK DISCOVERY & INFORMATION =====

def get_wifi_interfaces():
    """Get list of available Wi-Fi interfaces."""
    interfaces = []
    try:
        for iface in os.listdir('/sys/class/net'):
            if iface != 'lo':
                interfaces.append(iface)
    except FileNotFoundError:
        # For non-Linux systems, try using iwconfig
        try:
            result = subprocess.check_output(['iwconfig'], stderr=subprocess.DEVNULL)
            for line in result.decode().split('\n'):
                if line and not line.startswith(' '):
                    iface = line.split()[0]
                    if iface != 'lo':
                        interfaces.append(iface)
        except:
            pass
    return interfaces


def parse_network_info(cell):
    """Parse network information from scan output."""
    network = {}
    
    # Extract BSSID
    bssid_match = re.search(r'Address:\s*([0-9A-Fa-f:]{17})', cell)
    network['BSSID'] = bssid_match.group(1) if bssid_match else 'N/A'
    
    # Extract ESSID
    essid_match = re.search(r'ESSID:"([^"]*)"', cell)
    network['ESSID'] = essid_match.group(1) if essid_match else 'Unknown'
    
    # Extract Channel
    channel_match = re.search(r'Channel:(\d+)', cell)
    network['Channel'] = channel_match.group(1) if channel_match else 'N/A'
    
    # Extract Frequency
    freq_match = re.search(r'Frequency:([\d.]+)', cell)
    network['Frequency'] = freq_match.group(1) if freq_match else 'N/A'
    
    # Extract Quality
    quality_match = re.search(r'Quality=(\d+)/(\d+)', cell)
    if quality_match:
        network['Quality'] = quality_match.group(1)
        network['Max_Quality'] = quality_match.group(2)
    else:
        quality_match2 = re.search(r'Quality:\s*(\d+)/(\d+)', cell)
        if quality_match2:
            network['Quality'] = quality_match2.group(1)
            network['Max_Quality'] = quality_match2.group(2)
        else:
            network['Quality'] = '0'
            network['Max_Quality'] = '100'
    
    # Extract Signal
    signal_match = re.search(r'Signal level=([-\d]+)', cell)
    network['Signal'] = signal_match.group(1) if signal_match else '0'
    
    # Detect Encryption
    network['Encryption'] = detect_encryption(cell)
    
    return network


def detect_encryption(cell):
    """Detect encryption type from scan output."""
    if 'WPA3' in cell:
        return 'WPA3'
    elif 'WPA2' in cell:
        return 'WPA2'
    elif 'WPA' in cell:
        return 'WPA'
    elif 'WEP' in cell:
        return 'WEP'
    elif 'Privacy' in cell:
        return 'WPA'
    else:
        return 'OPEN'


def scan_wifi(interface, timeout=10):
    """Scan for nearby Wi-Fi networks."""
    networks = []
    print(f'[+] Scanning on {interface} ... Please wait {timeout}s')
    
    try:
        # Perform scan
        result = subprocess.check_output(
            ['iwlist', interface, 'scan'],
            stderr=subprocess.DEVNULL,
            timeout=timeout
        )
        data = result.decode(errors='ignore')
        
        # Split into cells
        cells = data.split('Cell ')
        
        for cell in cells:
            if 'ESSID:' in cell:
                network = parse_network_info(cell)
                if network and network['ESSID'] != 'Unknown':
                    networks.append(network)
        
        print(f'[+] Found {len(networks)} networks')
        
    except subprocess.TimeoutExpired:
        print('[-] Scan timeout expired')
    except FileNotFoundError:
        print('[-] iwlist command not found. Install wireless-tools package.')
    except Exception as e:
        print(f'[-] Error during scan: {e}')
    
    return networks


# ===== 3. ANALYZE SIGNAL, CHANNEL & MANAGE RESULTS =====

def analyze_signal(networks):
    """Convert signal to quality percentage."""
    for net in networks:
        try:
            signal_db = int(net.get('Signal', -100))
            # Convert dBm to quality (0-100%)
            quality = max(0, min(100, 2 * (signal_db + 100)))
            net['Quality (%)'] = quality
        except:
            net['Quality (%)'] = 0
    return networks


def analyze_channels(networks):
    """Count networks per channel."""
    channel_count = {}
    for net in networks:
        ch = net.get('Channel', 'N/A')
        channel_count[ch] = channel_count.get(ch, 0) + 1
    return channel_count


def filter_networks(networks, security=None, ssid=None, min_quality=0):
    """Filter networks by security, SSID or min quality."""
    filtered = []
    for net in networks:
        if security and net.get('Encryption', '') != security:
            continue
        if ssid and ssid.lower() not in net.get('ESSID', '').lower():
            continue
        if int(net.get('Quality (%)', 0)) < min_quality:
            continue
        filtered.append(net)
    return filtered


def display_results(networks):
    """Show networks in a clean table."""
    if not networks:
        print('[-] No networks found to display.')
        return
    
    headers = ['#', 'ESSID', 'BSSID', 'Ch', 'Encryption', 'Signal', 'Quality(%)']
    print('=' * 100)
    print(f'{headers[0]:<4} {headers[1]:<25} {headers[2]:<20} {headers[3]:<4} {headers[4]:<12} {headers[5]:<8} {headers[6]:<10}')
    print('=' * 100)
    
    for i, net in enumerate(networks, 1):
        print(f'{i:<4} {net.get("ESSID", ""):<25} {net.get("BSSID", ""):<20} '
              f'{net.get("Channel", ""):<4} {net.get("Encryption", ""):<12} '
              f'{net.get("Signal", ""):<8} {net.get("Quality (%)", ""):<10}')


# ===== 4. SECURITY ASSESSMENT & REPORT GENERATION =====

def assess_security(network):
    """Determine security level based on encryption."""
    enc = network.get('Encryption', '').upper()
    if 'WPA3' in enc:
        return 'SECURE (WPA3)'
    elif 'WPA2' in enc:
        return 'MODERATE (WPA2)'
    elif 'WEP' in enc:
        return 'WEAK (WEP)'
    elif enc == 'OPEN' or enc == '':
        return 'UNSECURED (OPEN)'
    else:
        return 'UNKNOWN'


def security_assessment(networks):
    """Create security assessment report."""
    for net in networks:
        net['Security Level'] = assess_security(net)
    return networks


def print_report(networks):
    """Display report in table format."""
    if not networks:
        print('[-] No data to report.')
        return
    
    print('\n========== WIFI SECURITY ASSESSMENT REPORT ==========\n')
    
    if tabulate:
        table_data = []
        headers = ['No', 'ESSID', 'BSSID', 'Channel', 'Signal(%)', 'Encryption', 'Security Level']
        table_data.append(headers)
        
        for i, net in enumerate(networks, 1):
            table_data.append([
                i,
                net.get('ESSID', ''),
                net.get('BSSID', ''),
                net.get('Channel', ''),
                net.get('Quality (%)', ''),
                net.get('Encryption', ''),
                net.get('Security Level', '')
            ])
        
        print(tabulate(table_data, headers='firstrow', tablefmt='grid'))
    else:
        display_results(networks)


def save_report(networks, filename='wifi_report.csv'):
    """Save report to CSV file."""
    if not networks:
        print('[-] No data to save.')
        return
    
    fields = ['ESSID', 'BSSID', 'Channel', 'Encryption', 'Signal', 'Quality (%)', 'Security Level']
    
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in networks:
            writer.writerow(row)
    
    print(f'[+] Report saved to {filename}')


# ===== 5. EXPORT, WORKFLOW, USAGE & NOTES =====

def export_to_csv(networks, filename='wifi_results.csv'):
    """Export results to CSV."""
    if not networks:
        print('[-] No data to export.')
        return
    
    fields = ['ESSID', 'BSSID', 'Channel', 'Encryption', 'Signal', 'Quality (%)', 'Security Level']
    
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in networks:
            writer.writerow(row)
    
    print(f'[+] Data exported to {filename}')


def export_to_json(networks, filename='wifi_results.json'):
    """Export results to JSON."""
    if not networks:
        print('[-] No data to export.')
        return
    
    with open(filename, 'w') as f:
        json.dump(networks, f, indent=4)
    
    print(f'[+] Data exported to {filename}')


def list_interfaces():
    """List available Wi-Fi interfaces."""
    interfaces = get_wifi_interfaces()
    if interfaces:
        print('\nAvailable Wi-Fi Interfaces:')
        print('-' * 30)
        for i, iface in enumerate(interfaces, 1):
            print(f'{i}. {iface}')
        print('-' * 30)
    else:
        print('[-] No Wi-Fi interface found.')
    return interfaces


def view_saved_results():
    """View previously saved results."""
    if os.path.exists(RESULTS_FILE):
        try:
            with open(RESULTS_FILE, 'r') as f:
                reader = csv.DictReader(f)
                networks = list(reader)
                display_results(networks)
        except Exception as e:
            print(f'[-] Error reading saved results: {e}')
    else:
        print('[-] No saved results found.')


# ===== MAIN MENU =====

def show_menu():
    """Display main menu."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=" * 60)
    print(f" {TOOL_NAME} v{TOOL_VERSION}")
    print("=" * 60)
    print(f" Author: {AUTHOR}")
    print(f" {DESCRIPTION}")
    print("=" * 60)
    print("1. List Wireless Interfaces")
    print("2. Scan Wi-Fi Networks")
    print("3. Analyze Selected Network")
    print("4. Export Results (CSV)")
    print("5. View Saved Results")
    print("6. Exit")
    print("=" * 60)


def main():
    """Main workflow."""
    networks = []
    
    while True:
        show_menu()
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == '1':
            list_interfaces()
            input("\nPress Enter to continue...")
        
        elif choice == '2':
            interfaces = get_wifi_interfaces()
            if not interfaces:
                print('[-] No Wi-Fi interface found.')
                input("\nPress Enter to continue...")
                continue
            
            print('\nSelect interface:')
            for i, iface in enumerate(interfaces, 1):
                print(f'{i}. {iface}')
            
            try:
                sel = int(input('Enter number: ')) - 1
                if 0 <= sel < len(interfaces):
                    networks = scan_wifi(interfaces[sel], SCAN_TIMEOUT)
                    if networks:
                        networks = analyze_signal(networks)
                        networks = security_assessment(networks)
                        display_results(networks)
                        
                        # Auto-save to results file
                        save_report(networks, RESULTS_FILE)
                    else:
                        print('[-] No networks found.')
                else:
                    print('[-] Invalid selection.')
            except ValueError:
                print('[-] Invalid input.')
            
            input("\nPress Enter to continue...")
        
        elif choice == '3':
            if not networks:
                print('[-] No networks to analyze. Please scan first.')
                input("\nPress Enter to continue...")
                continue
            
            print_report(networks)
            
            # Show channel analysis
            channel_count = analyze_channels(networks)
            print('\n--- Channel Distribution ---')
            for ch, count in sorted(channel_count.items()):
                print(f'Channel {ch}: {count} networks')
            
            input("\nPress Enter to continue...")
        
        elif choice == '4':
            if not networks:
                print('[-] No networks to export. Please scan first.')
                input("\nPress Enter to continue...")
                continue
            
            choice_fmt = input("Export format (csv/json): ").strip().lower()
            if choice_fmt == 'csv':
                export_to_csv(networks)
            elif choice_fmt == 'json':
                export_to_json(networks)
            else:
                print('[-] Invalid format. Use csv or json.')
            
            input("\nPress Enter to continue...")
        
        elif choice == '5':
            view_saved_results()
            input("\nPress Enter to continue...")
        
        elif choice == '6':
            print("\n[+] Scan completed. Stay secure!")
            print("=" * 60)
            break
        
        else:
            print('[-] Invalid option. Please choose 1-6.')
            input("\nPress Enter to continue...")


if __name__ == '__main__':
    main()