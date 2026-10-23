#!/usr/bin/env python3
# WIFI SECURITY ASSESSMENT TOOL (Python) v1.3
# Author: Mdsy
# Description: Discover nearby Wi-Fi networks and analyze security details.
#
# Works on:
#   - Linux   : uses `iw` (preferred, detects WPA3 correctly) or `iwlist`  -> run with sudo
#   - Windows : uses `netsh wlan`                                          -> normal terminal
#   - WSL     : uses Windows' netsh.exe through interop (WSL itself cannot see the Wi-Fi card)
#
# Requirements:
#   Linux : sudo apt install iw wireless-tools
#   Any   : pip install tabulate          (optional, for nicer tables)
# Run:
#   Linux   : sudo python3 wifi_tool_fixed.py
#   Windows : python wifi_tool_fixed.py

import os
import sys
import csv
import json
import re
import time
import html
import shutil
import logging
import platform
import subprocess
from datetime import datetime

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None  # optional: falls back to a plain-text table

# ===== PROJECT FOLDERS =====
DATA_DIR = 'data'
LOGS_DIR = 'logs'
REPORTS_DIR = 'reports'

# ===== CONFIGURATION =====
SCAN_TIMEOUT = 30          # seconds to wait for the scan command
SCAN_RETRIES = 3           # retries when the interface is busy
LOG_FILE = os.path.join(LOGS_DIR, 'wifi_tool.log')
RESULTS_FILE = os.path.join(DATA_DIR, 'networks.csv')
CSV_FIELDS = ['ESSID', 'BSSID', 'Channel', 'Frequency', 'Encryption',
              'Signal', 'Quality (%)', 'Security Level']

# ===== COLORS (turned off automatically when output is piped or NO_COLOR is set) =====
USE_COLOR = sys.stdout.isatty() and not os.environ.get('NO_COLOR')
if USE_COLOR and os.name == 'nt':
    os.system('')  # switches on ANSI escape support in the Windows console

ANSI = {'red': '31', 'green': '32', 'yellow': '33', 'cyan': '36',
        'grey': '90', 'bold_red': '1;31', 'bold': '1'}


def paint(text, color):
    """Wrap text in an ANSI color (does nothing when colors are off)."""
    if not USE_COLOR or color not in ANSI:
        return text
    return f'\033[{ANSI[color]}m{text}\033[0m'


def level_color(level):
    """Color that matches a 'Security Level' value."""
    level = (level or '').upper()
    if level.startswith(('SECURE', 'GOOD')):
        return 'green'
    if level.startswith('MODERATE'):
        return 'yellow'
    if level.startswith('WEAK'):
        return 'red'
    if level.startswith('UNSECURED'):
        return 'bold_red'
    return 'grey'


# ===== TOOL INFORMATION =====
TOOL_NAME = "WIFI SECURITY ASSESSMENT TOOL"
TOOL_VERSION = "1.3"
AUTHOR = "Mdsy"
DESCRIPTION = "Discover nearby Wi-Fi networks and analyze security details."

RECOMMENDATIONS = {
    'OPEN': 'No encryption: anyone nearby can read the traffic. Enable WPA2/WPA3.',
    'OWE': 'Enhanced Open: no password, but traffic is encrypted per client. OK for guest Wi-Fi.',
    'WEP': 'WEP can be broken in minutes. Switch to WPA2 (AES) or WPA3.',
    'WPA': 'Original WPA/TKIP is obsolete. Switch to WPA2 (AES) or WPA3.',
    'WPA/WPA2': 'Mixed mode allows TKIP clients. Use WPA2-only (AES) or WPA3.',
    'WPA2': 'Acceptable. Use a long passphrase; consider upgrading to WPA3.',
    'WPA2/WPA3': 'Good. Transition mode; move to WPA3-only when all devices support it.',
    'WPA3': 'Best current option. Keep the firmware up to date.',
    'UNKNOWN': 'Could not determine encryption. Verify with another tool (iw / nmcli / netsh).',
}


def setup_project():
    """Create folders and logging (called once from main, not at import time)."""
    for folder in (DATA_DIR, LOGS_DIR, REPORTS_DIR):
        os.makedirs(folder, exist_ok=True)
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
    )


# ===== 0. PLATFORM / BACKEND DETECTION =====

def is_wsl():
    """True when running inside Windows Subsystem for Linux."""
    try:
        return 'microsoft' in platform.uname().release.lower()
    except Exception:
        return False


def get_backend():
    """Pick the scan command available on this machine.

    Returns 'netsh' (Windows), 'netsh.exe' (WSL), 'iw', 'iwlist' or None.
    """
    if os.name == 'nt':
        return 'netsh' if shutil.which('netsh') else None
    if sys.platform.startswith('linux'):
        if is_wsl() and shutil.which('netsh.exe'):
            return 'netsh.exe'
        if shutil.which('iw'):
            return 'iw'
        if shutil.which('iwlist'):
            return 'iwlist'
    return None


def backend_missing_message():
    if os.name == 'nt':
        return 'netsh was not found. It ships with Windows - check your PATH.'
    if sys.platform.startswith('linux'):
        return 'No scan tool found. Install one with: sudo apt install iw wireless-tools'
    return 'Unsupported OS. This tool supports Windows and Linux.'


def run_cmd(cmd, timeout):
    """Run a command and return (returncode, stdout, stderr) as clean text."""
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          errors='ignore', timeout=timeout)
    return (proc.returncode,
            (proc.stdout or '').replace('\r', ''),
            (proc.stderr or '').replace('\r', ''))


# ===== 1. WI-FI INTERFACES =====

def _linux_interfaces():
    """Return only real wireless interfaces (not eth0, docker0, etc.)."""
    interfaces = []
    sys_net = '/sys/class/net'

    if os.path.isdir(sys_net):
        for iface in sorted(os.listdir(sys_net)):
            base = os.path.join(sys_net, iface)
            if os.path.isdir(os.path.join(base, 'wireless')) or \
               os.path.isdir(os.path.join(base, 'phy80211')):
                interfaces.append(iface)
        return interfaces

    # Fallback if /sys/class/net does not exist
    if shutil.which('iwconfig'):
        try:
            out = subprocess.check_output(['iwconfig'], stderr=subprocess.STDOUT,
                                          text=True, errors='ignore', timeout=5)
            for line in out.splitlines():
                if line and not line.startswith(' ') and 'no wireless extensions' not in line:
                    interfaces.append(line.split()[0])
        except Exception:
            pass
    return interfaces


def _netsh_interfaces(exe):
    """Wi-Fi adapter names on Windows (or WSL through netsh.exe)."""
    try:
        _, out, _ = run_cmd([exe, 'wlan', 'show', 'interfaces'], 10)
    except Exception as e:
        logging.error('netsh interfaces failed: %s', e)
        return []
    return re.findall(r'(?m)^[ \t]*(?:Name|Nama)[ \t]*:[ \t]*(.+?)[ \t]*$', out)


def get_wifi_interfaces():
    backend = get_backend()
    if backend and backend.startswith('netsh'):
        return _netsh_interfaces(backend)
    return _linux_interfaces()


# ===== 2. PARSERS =====

def _quality_from_dbm(dbm):
    return max(0, min(100, 2 * (dbm + 100)))


def _finalize(unique):
    """Sort strongest signal first."""
    return sorted(unique.values(), key=lambda n: n['Quality (%)'], reverse=True)


# ---- 2a. iwlist (Linux, legacy) ----

def parse_network_info(cell):
    """Parse one 'Cell' block of `iwlist scan` output."""
    net = {}

    m = re.search(r'Address:\s*([0-9A-Fa-f:]{17})', cell)
    net['BSSID'] = m.group(1).upper() if m else 'N/A'

    m = re.search(r'^\s*ESSID:"(.*)"\s*$', cell, re.M)
    essid = m.group(1) if m else ''
    if not essid or re.fullmatch(r'(\\x00)+', essid):
        essid = '<hidden>'
    net['ESSID'] = essid

    m = re.search(r'^\s*Channel:(\d+)', cell, re.M) or re.search(r'\(Channel (\d+)\)', cell)
    net['Channel'] = m.group(1) if m else 'N/A'

    m = re.search(r'Frequency:([\d.]+)\s*GHz', cell)
    net['Frequency'] = m.group(1) if m else 'N/A'

    # Signal can be reported in dBm or as a ratio depending on the driver
    dbm = re.search(r'Signal level[=:]\s*(-?\d+)\s*dBm', cell)
    ratio = re.search(r'Signal level[=:]\s*(\d+)\s*/\s*(\d+)', cell)
    qual = re.search(r'Quality[=:]\s*(\d+)\s*/\s*(\d+)', cell)

    if dbm:
        signal = int(dbm.group(1))
        net['Signal'] = str(signal)
        net['Quality (%)'] = _quality_from_dbm(signal)
    elif ratio and int(ratio.group(2)) > 0:
        net['Signal'] = f'{ratio.group(1)}/{ratio.group(2)}'
        net['Quality (%)'] = round(int(ratio.group(1)) / int(ratio.group(2)) * 100)
    elif qual and int(qual.group(2)) > 0:
        net['Signal'] = 'N/A'
        net['Quality (%)'] = round(int(qual.group(1)) / int(qual.group(2)) * 100)
    else:
        net['Signal'] = 'N/A'
        net['Quality (%)'] = 0

    net['Encryption'] = detect_encryption(cell)
    return net


def detect_encryption(cell):
    """Detect encryption from 'Encryption key' and 'IE:' lines only (not from the SSID text).

    Note: old wireless-tools versions do not know the SAE (WPA3) key type, so WPA3
    networks may show up as WPA2 here. Install `iw` for accurate WPA3 detection.
    """
    if re.search(r'Encryption key:\s*off', cell, re.I):
        return 'OPEN'

    ie_text = ' '.join(re.findall(r'^\s*IE:[ \t]*(.*)$', cell, re.M))
    auth_text = ' '.join(re.findall(r'Authentication Suites.*?:[ \t]*(.*)$', cell, re.M))

    has_sae = 'SAE' in auth_text or 'WPA3' in ie_text
    has_psk = 'PSK' in auth_text
    wpa2 = 'WPA2' in ie_text or '802.11i' in ie_text
    wpa1 = re.search(r'\bWPA Version', ie_text) is not None

    if has_sae:
        return 'WPA2/WPA3' if has_psk else 'WPA3'
    if wpa2 and wpa1:
        return 'WPA/WPA2'
    if wpa2:
        return 'WPA2'
    if wpa1:
        return 'WPA'
    if re.search(r'Encryption key:\s*on', cell, re.I):
        return 'WEP'      # key required but no WPA/RSN information element
    return 'UNKNOWN'


def parse_iwlist_output(data):
    """Turn raw `iwlist scan` text into a list of networks (deduplicated by BSSID)."""
    cells = re.split(r'(?m)^\s*Cell \d+ - ', data)[1:]
    unique = {}
    for cell in cells:
        net = parse_network_info(cell)
        if net['BSSID'] != 'N/A':
            unique[net['BSSID']] = net
    return _finalize(unique)


# ---- 2b. iw (Linux, modern) ----

def _freq_to_channel(mhz):
    mhz = int(round(mhz))
    if mhz == 2484:
        return 14
    if 2412 <= mhz <= 2472:
        return (mhz - 2407) // 5
    if 5000 <= mhz < 5950:
        return (mhz - 5000) // 5
    if 5955 <= mhz <= 7115:
        return (mhz - 5950) // 5
    return 'N/A'


def _iw_section(block, name):
    """Return the text under a top-level attribute such as 'RSN' or 'WPA' (or None)."""
    m = re.search(r'(?m)^\t' + name + r':(.*?)(?=^\t\S|\Z)', block, re.S)
    return m.group(1) if m else None


def _iw_encryption(block):
    rsn = _iw_section(block, 'RSN')
    wpa = _iw_section(block, 'WPA')

    if rsn is None and wpa is None:
        cap = re.search(r'(?m)^\tcapability:(.*)$', block)
        return 'WEP' if cap and 'Privacy' in cap.group(1) else 'OPEN'

    if rsn is not None:
        suites = ' '.join(re.findall(r'Authentication suites:[ \t]*(.*)', rsn))
        if re.search(r'\bOWE\b', suites):
            return 'OWE'
        has_sae = 'SAE' in suites
        has_psk = 'PSK' in suites
        if has_sae:
            return 'WPA2/WPA3' if has_psk else 'WPA3'
        return 'WPA/WPA2' if wpa is not None else 'WPA2'

    return 'WPA'


def parse_iw_output(data):
    """Turn raw `iw dev <if> scan` text into a list of networks."""
    unique = {}
    for block in re.split(r'(?m)^BSS ', data)[1:]:
        m = re.match(r'([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})', block)
        if not m:
            continue
        net = {'BSSID': m.group(1).upper()}

        m = re.search(r'(?m)^\tSSID:[ \t]*(.*)$', block)
        essid = m.group(1).strip() if m else ''
        if not essid or re.fullmatch(r'(\\x00)+', essid):
            essid = '<hidden>'
        net['ESSID'] = essid

        freq_mhz = None
        m = re.search(r'(?m)^\tfreq:[ \t]*([\d.]+)', block)
        if m:
            freq_mhz = float(m.group(1))
        net['Frequency'] = f'{freq_mhz / 1000:g}' if freq_mhz else 'N/A'

        m = (re.search(r'DS Parameter set: channel (\d+)', block)
             or re.search(r'primary channel: (\d+)', block))
        if m:
            net['Channel'] = m.group(1)
        elif freq_mhz:
            net['Channel'] = str(_freq_to_channel(freq_mhz))
        else:
            net['Channel'] = 'N/A'

        dbm = re.search(r'(?m)^\tsignal:[ \t]*(-?[\d.]+)[ \t]*dBm', block)
        ratio = re.search(r'(?m)^\tsignal:[ \t]*(\d+)[ \t]*/[ \t]*(\d+)', block)
        if dbm:
            signal = int(round(float(dbm.group(1))))
            net['Signal'] = str(signal)
            net['Quality (%)'] = _quality_from_dbm(signal)
        elif ratio and int(ratio.group(2)) > 0:
            net['Signal'] = f'{ratio.group(1)}/{ratio.group(2)}'
            net['Quality (%)'] = round(int(ratio.group(1)) / int(ratio.group(2)) * 100)
        else:
            net['Signal'] = 'N/A'
            net['Quality (%)'] = 0

        net['Encryption'] = _iw_encryption(block)
        unique[net['BSSID']] = net
    return _finalize(unique)


# ---- 2c. netsh (Windows / WSL) ----

def netsh_encryption(auth, cipher):
    """Map netsh 'Authentication' / 'Encryption' values to our encryption names."""
    a = auth.lower()
    c = cipher.lower()
    if re.search(r'\bowe\b', a) or 'enhanced open' in a:
        return 'OWE'
    if 'wpa3' in a:
        return 'WPA3'
    if 'wpa2' in a:
        return 'WPA2'
    if 'wpa' in a:
        return 'WPA'
    if 'wep' in a or 'shared' in a:
        return 'WEP'
    if a.startswith('open'):
        return 'WEP' if 'wep' in c else 'OPEN'
    return 'UNKNOWN'


def parse_netsh_output(data):
    """Turn raw `netsh wlan show networks mode=bssid` text into a list of networks.

    Fields are read by position (not by label) so it also works on translated Windows.
    """
    data = data.replace('\r', '')
    unique = {}

    for block in re.split(r'(?m)^[ \t]*SSID\s+\d+[ \t]*:', data)[1:]:
        parts = re.split(r'(?m)^[ \t]*BSSID\s+\d+[ \t]*:', block)
        header, bss_parts = parts[0], parts[1:]

        lines = header.split('\n')
        essid = lines[0].strip() or '<hidden>'
        values = [ln.split(':', 1)[1].strip() for ln in lines[1:] if ':' in ln]
        # order in netsh output: Network type, Authentication, Encryption
        auth = values[1] if len(values) > 1 else ''
        cipher = values[2] if len(values) > 2 else ''
        encryption = netsh_encryption(auth, cipher)

        for bss in bss_parts:
            blines = bss.split('\n')
            bssid = blines[0].strip().upper()
            if not bssid:
                continue
            body = '\n'.join(blines[1:])

            net = {'ESSID': essid, 'BSSID': bssid, 'Encryption': encryption}

            m = (re.search(r'(?m)^[ \t]*(?:Channel|Saluran|Kanal)[ \t]*:[ \t]*(\d+)', body)
                 or re.search(r'(?m)^[ \t]*[^:\n]+:[ \t]*(\d+)[ \t]*$', body))
            channel = int(m.group(1)) if m else None
            net['Channel'] = str(channel) if channel else 'N/A'

            m = re.search(r'(\d(?:\.\d)?)\s*GHz', body)
            if m:
                net['Frequency'] = m.group(1)
            elif channel:
                net['Frequency'] = '2.4' if channel <= 14 else '5'
            else:
                net['Frequency'] = 'N/A'

            # Windows reports signal quality in %, convert to an approximate dBm
            m = re.search(r'(\d+)\s*%', body)
            if m:
                pct = max(0, min(100, int(m.group(1))))
                net['Quality (%)'] = pct
                net['Signal'] = str(round(pct / 2 - 100))
            else:
                net['Quality (%)'] = 0
                net['Signal'] = 'N/A'

            unique[bssid] = net
    return _finalize(unique)


# ===== 3. SCANNING =====

def scan_wifi(interface, timeout=SCAN_TIMEOUT):
    """Scan for nearby Wi-Fi networks with whichever backend is available."""
    backend = get_backend()
    if backend is None:
        print('[-] ' + backend_missing_message())
        return []

    if backend in ('iw', 'iwlist') and hasattr(os, 'geteuid') and os.geteuid() != 0:
        print('[!] Not running as root - the scan may be empty or incomplete.')
        print('    Re-run with: sudo python3 wifi_tool_fixed.py')

    if backend.startswith('netsh'):
        cmd = [backend, 'wlan', 'show', 'networks', 'mode=bssid']
        parser = parse_netsh_output
    elif backend == 'iw':
        cmd = ['iw', 'dev', interface, 'scan']
        parser = parse_iw_output
    else:
        cmd = ['iwlist', interface, 'scan']
        parser = parse_iwlist_output

    print(f'[+] Scanning on {interface} using {backend} ... (up to {timeout}s)')
    output = ''
    attempt = 0
    while attempt < SCAN_RETRIES:
        attempt += 1
        try:
            code, out, err = run_cmd(cmd, timeout)
        except subprocess.TimeoutExpired:
            print('[-] Scan timeout expired')
            logging.warning('Scan timeout on %s', interface)
            return []
        except Exception as e:
            print(f'[-] Error during scan: {e}')
            logging.error('Scan error on %s: %s', interface, e)
            return []

        if code == 0:
            output = out
            break

        msg = (err or out).strip()
        low = msg.lower()

        # iw without root: fall back to the kernel's cached scan results
        if backend == 'iw' and 'not permitted' in low and cmd[-1] == 'scan':
            print('[!] No permission for a fresh scan - showing cached results instead.')
            cmd = ['iw', 'dev', interface, 'scan', 'dump']
            attempt -= 1
            continue

        if 'busy' in low and attempt < SCAN_RETRIES:
            print(f'[!] Interface busy, retrying ({attempt}/{SCAN_RETRIES}) ...')
            time.sleep(2)
            continue

        print(f'[-] Scan failed: {msg or "unknown error"}')
        if backend in ('iw', 'iwlist') and 'network is down' in low:
            print(f'    Try: sudo ip link set {interface} up')
        logging.error('Scan failed on %s: %s', interface, msg)
        return []

    networks = parser(output)

    if not networks:
        if backend.startswith('netsh'):
            snippet = [ln.strip() for ln in output.splitlines() if ln.strip()][:3]
            if snippet:
                print('[!] netsh said:')
                for ln in snippet:
                    print('    ' + ln)
            print('    Check: Wi-Fi is turned on, the "WLAN AutoConfig" service is running,')
            print('    and on Windows 11 Settings > Privacy & security > Location is enabled.')
        else:
            print('[!] The scan returned no networks. Try again with sudo, or check that')
            print(f'    {interface} is up and Wi-Fi is not blocked (rfkill list).')

    print(f'[+] Found {len(networks)} networks')
    logging.info('Scan on %s via %s found %d networks', interface, backend, len(networks))
    return networks


# ===== 4. ANALYZE CHANNEL & FILTER =====

def analyze_channels(networks):
    """Count networks per channel."""
    channel_count = {}
    for net in networks:
        ch = str(net.get('Channel', 'N/A'))
        channel_count[ch] = channel_count.get(ch, 0) + 1
    return channel_count


def _quality(net):
    try:
        return int(net.get('Quality (%)', 0))
    except (TypeError, ValueError):
        return 0


def filter_networks(networks, security=None, ssid=None, min_quality=0, only_weak=False):
    """Filter networks by encryption, SSID text, minimum quality or 'needs attention'."""
    filtered = []
    for net in networks:
        if security and net.get('Encryption', '') != security:
            continue
        if ssid and ssid.lower() not in net.get('ESSID', '').lower():
            continue
        if only_weak and not str(net.get('Security Level', '')).startswith(('WEAK', 'UNSECURED')):
            continue
        if _quality(net) < min_quality:
            continue
        filtered.append(net)
    return filtered


# Worst first, so sorting by security puts the riskiest networks on top
SECURITY_ORDER = ['OPEN', 'WEP', 'WPA', 'WPA/WPA2', 'WPA2', 'WPA2/WPA3', 'OWE', 'WPA3', 'UNKNOWN']


def sort_networks(networks, by='signal'):
    """Sort by 'signal' (strongest first), 'ssid', 'channel' or 'security' (worst first)."""
    if by == 'ssid':
        return sorted(networks, key=lambda n: str(n.get('ESSID', '')).casefold())
    if by == 'channel':
        def channel_key(n):
            ch = str(n.get('Channel', ''))
            return (0, int(ch)) if ch.isdigit() else (1, 0)
        return sorted(networks, key=channel_key)
    if by == 'security':
        def security_key(n):
            enc = n.get('Encryption', 'UNKNOWN')
            return SECURITY_ORDER.index(enc) if enc in SECURITY_ORDER else len(SECURITY_ORDER)
        return sorted(networks, key=security_key)
    return sorted(networks, key=_quality, reverse=True)


def _band(net):
    """Return '2.4', '5' or '6' (GHz) for a network, or None when unknown."""
    try:
        ghz = float(net.get('Frequency'))
    except (TypeError, ValueError):
        ghz = None
    if ghz is not None:
        if ghz < 3:
            return '2.4'
        if ghz < 5.9:
            return '5'
        return '6'
    ch = str(net.get('Channel', ''))
    if ch.isdigit() and int(ch) <= 14:
        return '2.4'
    return None


def channel_congestion(networks):
    """Return {band: {channel: number_of_networks}}."""
    result = {}
    for net in networks:
        band = _band(net)
        ch = str(net.get('Channel', ''))
        if band and ch.isdigit():
            per_band = result.setdefault(band, {})
            per_band[int(ch)] = per_band.get(int(ch), 0) + 1
    return result


def recommend_channel_24(networks):
    """Pick the least crowded of the non-overlapping 2.4 GHz channels (1, 6, 11).

    Returns (best_channel, {channel: score}) or None when there is no 2.4 GHz data.
    Channels within 4 numbers of each other overlap, and stronger networks count more.
    """
    nets = [n for n in networks if _band(n) == '2.4' and str(n.get('Channel', '')).isdigit()]
    if not nets:
        return None
    scores = {}
    for candidate in (1, 6, 11):
        scores[candidate] = sum(0.2 + _quality(n) / 100 for n in nets
                                if abs(int(n['Channel']) - candidate) <= 4)
    best = min(scores, key=lambda c: (scores[c], c))
    return best, scores


def print_channel_analysis(networks):
    """Show how many networks use each channel, plus a channel suggestion."""
    data = channel_congestion(networks)
    print('\n--- Channel Distribution ---')
    if not data:
        print('No channel information available.')
        return
    for band in ('2.4', '5', '6'):
        if band not in data:
            continue
        print(f'{band} GHz:')
        for ch in sorted(data[band]):
            count = data[band][ch]
            print(f'  Channel {ch:<4} {"#" * min(count, 40)} {count}')
    rec = recommend_channel_24(networks)
    if rec:
        best, scores = rec
        detail = ', '.join(f'ch {c}: {scores[c]:.1f}' for c in sorted(scores))
        print(f'\n[+] Least crowded 2.4 GHz channel: {best}')
        print(f'    (congestion score, lower is better - {detail})')


def _names(items, limit=5):
    items = sorted(set(items))
    text = ', '.join(items[:limit])
    if len(items) > limit:
        text += f' (+{len(items) - limit} more)'
    return text


def build_findings(networks):
    """Return a list of (severity, text) things worth fixing or double-checking."""
    findings = []
    groups = [
        ('OPEN', 'HIGH', 'no encryption, anyone nearby can read the traffic'),
        ('WEP', 'HIGH', 'WEP can be cracked in minutes'),
        ('WPA', 'MEDIUM', 'original WPA/TKIP is obsolete'),
        ('WPA/WPA2', 'MEDIUM', 'mixed mode still accepts old TKIP devices'),
        ('UNKNOWN', 'LOW', 'encryption could not be determined, verify manually'),
    ]
    for enc, severity, why in groups:
        hits = [n for n in networks if n.get('Encryption') == enc]
        if hits:
            names = _names(n.get('ESSID', '') for n in hits)
            findings.append((severity, f'{len(hits)} access point(s) using {enc} ({why}): {names}'))

    by_ssid = {}
    for n in networks:
        ssid = n.get('ESSID', '')
        if ssid and ssid != '<hidden>':
            by_ssid.setdefault(ssid, set()).add(n.get('Encryption', 'UNKNOWN'))
    mixed = [s for s, encs in by_ssid.items() if len(encs) > 1]
    if mixed:
        findings.append(('MEDIUM', 'Same network name with different security types: '
                         f'{_names(mixed)} (could be a transition setup, or a look-alike '
                         'access point - verify)'))

    hidden = sum(1 for n in networks if n.get('ESSID') == '<hidden>')
    if hidden:
        findings.append(('INFO', f'{hidden} hidden network(s) - hiding the name adds no real security.'))

    if not any(sev in ('HIGH', 'MEDIUM') for sev, _ in findings):
        findings.insert(0, ('INFO', 'No obvious weaknesses found among the visible networks.'))

    rank = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
    return sorted(findings, key=lambda f: rank[f[0]])


SEVERITY_COLOR = {'HIGH': 'bold_red', 'MEDIUM': 'yellow', 'LOW': 'cyan', 'INFO': 'grey'}


def print_findings(networks):
    print('\n--- Findings ---')
    for severity, text in build_findings(networks):
        label = f'[{severity}]'.ljust(9)
        print(f'{paint(label, SEVERITY_COLOR[severity])}{text}')


def display_results(networks):
    """Show networks in a plain-text table."""
    if not networks:
        print('[-] No networks found to display.')
        return

    line = '=' * 105
    print(line)
    print(f'{"#":<4} {"ESSID":<25} {"BSSID":<18} {"Ch":<4} {"Encryption":<11} '
          f'{"Signal":<8} {"Qual(%)":<8} {"Security Level":<20}')
    print(line)
    for i, net in enumerate(networks, 1):
        level = net.get('Security Level', '')
        print(f'{i:<4} {str(net.get("ESSID", ""))[:24]:<25} {net.get("BSSID", ""):<18} '
              f'{str(net.get("Channel", "")):<4} {net.get("Encryption", ""):<11} '
              f'{str(net.get("Signal", "")):<8} {str(net.get("Quality (%)", "")):<8} '
              + paint(f'{level:<20}', level_color(level)))


# ===== 5. SECURITY ASSESSMENT & REPORT =====

def assess_security(network):
    """Determine security level based on encryption."""
    enc = network.get('Encryption', '').upper()
    if enc == 'WPA3':
        return 'SECURE (WPA3)'
    if enc == 'WPA2/WPA3':
        return 'GOOD (WPA2/WPA3)'
    if enc == 'OWE':
        return 'GOOD (OWE)'
    if enc == 'WPA2':
        return 'MODERATE (WPA2)'
    if enc == 'WPA/WPA2':
        return 'WEAK (WPA/WPA2)'
    if enc == 'WPA':
        return 'WEAK (WPA)'
    if enc == 'WEP':
        return 'WEAK (WEP)'
    if enc == 'OPEN':
        return 'UNSECURED (OPEN)'
    return 'UNKNOWN'


def security_assessment(networks):
    """Add a 'Security Level' to every network."""
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
        headers = ['No', 'ESSID', 'BSSID', 'Channel', 'Signal(%)', 'Encryption', 'Security Level']
        rows = [[i, n.get('ESSID', ''), n.get('BSSID', ''), n.get('Channel', ''),
                 n.get('Quality (%)', ''), n.get('Encryption', ''),
                 paint(n.get('Security Level', ''), level_color(n.get('Security Level', '')))]
                for i, n in enumerate(networks, 1)]
        print(tabulate(rows, headers=headers, tablefmt='grid'))
    else:
        display_results(networks)

    # Summary
    summary = {}
    for n in networks:
        level = n.get('Security Level', 'UNKNOWN')
        summary[level] = summary.get(level, 0) + 1
    print('\n--- Summary ---')
    for level, count in sorted(summary.items()):
        print(paint(f'{level}: {count}', level_color(level)))
    print_findings(networks)


def print_network_detail(net):
    """Show details and a recommendation for one network."""
    print('\n--- Network Detail ---')
    for key in ('ESSID', 'BSSID', 'Channel', 'Frequency', 'Signal', 'Quality (%)',
                'Encryption', 'Security Level'):
        print(f'{key:<15}: {net.get(key, "N/A")}')
    print(f'{"Recommendation":<15}: {RECOMMENDATIONS.get(net.get("Encryption", "UNKNOWN"), "-")}')


# ===== 6. EXPORT =====

def _write_csv(networks, filename):
    folder = os.path.dirname(filename)
    if folder:
        os.makedirs(folder, exist_ok=True)
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        # extrasaction='ignore' prevents ValueError when a dict has extra keys
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction='ignore', restval='')
        writer.writeheader()
        for row in networks:
            writer.writerow(row)


def save_report(networks, filename=RESULTS_FILE):
    """Save report to CSV file."""
    if not networks:
        print('[-] No data to save.')
        return
    _write_csv(networks, filename)
    print(f'[+] Report saved to {filename}')


def export_to_csv(networks, filename=None):
    """Export results to CSV (timestamped file in reports/ by default)."""
    if not networks:
        print('[-] No data to export.')
        return
    filename = filename or os.path.join(REPORTS_DIR, f'wifi_{datetime.now():%Y%m%d_%H%M%S}.csv')
    _write_csv(networks, filename)
    print(f'[+] Data exported to {filename}')


def export_to_json(networks, filename=None):
    """Export results to JSON (timestamped file in reports/ by default)."""
    if not networks:
        print('[-] No data to export.')
        return
    filename = filename or os.path.join(REPORTS_DIR, f'wifi_{datetime.now():%Y%m%d_%H%M%S}.json')
    os.makedirs(os.path.dirname(filename) or '.', exist_ok=True)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(networks, f, indent=4, ensure_ascii=False)
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
        return interfaces

    backend = get_backend()
    if backend is None:
        print('[-] ' + backend_missing_message())
    elif backend.startswith('netsh'):
        print('[-] No Wi-Fi adapter found.')
        print('    Check that Wi-Fi is turned on and the "WLAN AutoConfig" service is running.')
    else:
        print('[-] No Wi-Fi interface found.')
        if is_wsl():
            print('    WSL cannot see the Wi-Fi card. Run this script with Windows Python instead,')
            print('    or install the tool in Windows: python wifi_tool_fixed.py')
        else:
            print('    (Running in a VM? It usually cannot see the host Wi-Fi card.)')
    return interfaces


def view_saved_results():
    """View previously saved results."""
    if not os.path.exists(RESULTS_FILE):
        print('[-] No saved results found.')
        return
    try:
        with open(RESULTS_FILE, 'r', newline='', encoding='utf-8') as f:
            networks = list(csv.DictReader(f))
        display_results(networks)
    except Exception as e:
        print(f'[-] Error reading saved results: {e}')


# ===== MAIN MENU =====

def show_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=" * 60)
    print(f" {TOOL_NAME} v{TOOL_VERSION}")
    print("=" * 60)
    print(f" Author: {AUTHOR}")
    print(f" {DESCRIPTION}")
    print("=" * 60)
    print("1. List Wireless Interfaces")
    print("2. Scan Wi-Fi Networks")
    print("3. Analyze Networks / Network Detail")
    print("4. Export Results (CSV/JSON)")
    print("5. View Saved Results")
    print("6. Exit")
    print("=" * 60)


def pause():
    input("\nPress Enter to continue...")


def main():
    setup_project()
    networks = []

    while True:
        show_menu()
        choice = input("\nEnter your choice (1-6): ").strip()

        if choice == '1':
            list_interfaces()
            pause()

        elif choice == '2':
            interfaces = get_wifi_interfaces()
            if not interfaces:
                list_interfaces()
                pause()
                continue

            if len(interfaces) == 1:
                iface = interfaces[0]
                print(f'\n[+] Using interface: {iface}')
            else:
                print('\nSelect interface:')
                for i, name in enumerate(interfaces, 1):
                    print(f'{i}. {name}')
                try:
                    sel = int(input('Enter number: ')) - 1
                except ValueError:
                    print('[-] Invalid input.')
                    pause()
                    continue
                if not 0 <= sel < len(interfaces):
                    print('[-] Invalid selection.')
                    pause()
                    continue
                iface = interfaces[sel]

            found = scan_wifi(iface, SCAN_TIMEOUT)
            if found:
                networks = security_assessment(found)
                display_results(networks)
                save_report(networks, RESULTS_FILE)
            else:
                print('[-] No networks found.')
            pause()

        elif choice == '3':
            if not networks:
                print('[-] No networks to analyze. Please scan first.')
                pause()
                continue

            print_report(networks)
            print('\n--- Channel Distribution ---')
            counts = analyze_channels(networks)
            for ch in sorted(counts, key=lambda c: (not c.isdigit(), int(c) if c.isdigit() else 0)):
                print(f'Channel {ch}: {counts[ch]} networks')

            sel = input('\nEnter network number for details (or press Enter to skip): ').strip()
            if sel.isdigit() and 1 <= int(sel) <= len(networks):
                print_network_detail(networks[int(sel) - 1])
            pause()

        elif choice == '4':
            if not networks:
                print('[-] No networks to export. Please scan first.')
                pause()
                continue

            fmt = input("Export format (csv/json): ").strip().lower()
            if fmt == 'csv':
                export_to_csv(networks)
            elif fmt == 'json':
                export_to_json(networks)
            else:
                print('[-] Invalid format. Use csv or json.')
            pause()

        elif choice == '5':
            view_saved_results()
            pause()

        elif choice == '6':
            print("\n[+] Done. Stay secure!")
            print("=" * 60)
            break

        else:
            print('[-] Invalid option. Please choose 1-6.')
            pause()


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print('\n[+] Interrupted. Bye!')