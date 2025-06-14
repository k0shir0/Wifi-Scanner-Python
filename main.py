import os
import sys
import socket
import subprocess
import json
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import colorama
from tqdm import tqdm

colorama.init()
GREEN = colorama.Fore.GREEN
RED = colorama.Fore.RED
YELLOW = colorama.Fore.YELLOW
CYAN = colorama.Fore.CYAN
RESET = colorama.Fore.RESET

def clear_screen():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def get_timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def get_interfaces():
    interfaces = []
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs and netifaces.AF_LINK in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                mac = addrs[netifaces.AF_LINK][0]['addr']
                interfaces.append({'interface': iface, 'ip': ip, 'mac': mac})
    except ImportError:
        print(f"{YELLOW}netifaces module not installed. Using basic interface detection.{RESET}")
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        interfaces.append({'interface': 'default', 'ip': ip, 'mac': 'FF:FF:FF:FF:FF:FF'})
    return interfaces

def scan_wifi():
    networks = []
    system = platform.system()
    try:
        if system == "Windows":
            cmd = ['netsh', 'wlan', 'show', 'networks', 'mode=bssid']
            output = subprocess.check_output(cmd, text=True, errors='ignore')
            current = None
            signal = channel = auth = None
            for line in output.splitlines():
                line = line.strip()
                if line.startswith('SSID ') and ':' in line and not 'BSSID' in line:
                    current = line.split(':', 1)[1].strip()
                elif line.startswith('Signal') and current:
                    signal = line.split(':', 1)[1].strip().replace('%', '')
                elif line.startswith('Channel') and current:
                    channel = line.split(':', 1)[1].strip()
                elif line.startswith('Authentication') and current:
                    auth = line.split(':', 1)[1].strip()
                    networks.append({
                        'ssid': current,
                        'signal': f"{signal}%",
                        'channel': channel,
                        'encryption': auth
                    })
                    current = None
        elif system == "Darwin":
            cmd = ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s']
            output = subprocess.check_output(cmd, text=True)
            for line in output.splitlines()[1:]:
                if line.strip():
                    parts = line.split()
                    ssid = ' '.join(parts[:-5])
                    bssid = parts[-5]
                    rssi = parts[-4]
                    channel = parts[-3]
                    security = parts[-1]
                    networks.append({
                        'ssid': ssid,
                        'signal': rssi,
                        'channel': channel,
                        'encryption': security
                    })
        elif system == "Linux":
            cmd = ['nmcli', '-t', '-f', 'SSID,SIGNAL,CHAN,SECURITY', 'dev', 'wifi']
            output = subprocess.check_output(cmd, text=True)
            for line in output.splitlines():
                if line:
                    ssid, signal, channel, security = line.split(':', 3)
                    networks.append({
                        'ssid': ssid,
                        'signal': f"{signal}%",
                        'channel': channel,
                        'encryption': security
                    })
    except (subprocess.CalledProcessError, FileNotFoundError, PermissionError):
        print(f"{RED}WiFi scanning not supported on this platform or requires admin privileges{RESET}")
    return networks

def ping_host(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout = '-w' if platform.system().lower() == 'windows' else '-W'
    command = ['ping', param, '1', timeout, '1', ip] if platform.system().lower() == 'windows' else ['ping', param, '1', timeout, '1', ip]
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def device_discovery():
    active_devices = []
    gateway = None
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(['ipconfig'], text=True)
            for line in output.splitlines():
                if 'Default Gateway' in line:
                    gateway = line.split(':')[-1].strip()
                    break
        else:
            output = subprocess.check_output(['ip', 'route', 'show', 'default'], text=True)
            gateway = output.split()[2]
    except Exception:
        gateway = None

    interfaces = get_interfaces()
    if not interfaces:
        print(f"{RED}No active interfaces found{RESET}")
        return []

    ip_parts = interfaces[0]['ip'].split('.')
    base_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."
    ip_range = [f"{base_ip}{i}" for i in range(1, 255)]
    print(f"{CYAN}Scanning local network... (This may take 20-30 seconds){RESET}")
    with ThreadPoolExecutor(max_workers=50) as exec:
        results = list(tqdm(exec.map(ping_host, ip_range), total=len(ip_range), desc="Scanning", unit="IP"))
    for i, alive in enumerate(results):
        if alive:
            ip = ip_range[i]
            device = {'ip': ip, 'mac': 'Unknown', 'hostname': 'Unknown', 'is_gateway': (ip == gateway)}
            try:
                device['hostname'] = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                pass
            active_devices.append(device)
    return active_devices

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((ip, port))
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def port_scan(target_ip, ports):
    open_ports = []
    print(f"{CYAN}Scanning {target_ip}...{RESET}")
    with ThreadPoolExecutor(max_workers=100) as exec:
        futures = {exec.submit(scan_port, target_ip, p): p for p in ports}
        for f in tqdm(futures, total=len(ports), desc="Ports", unit="port"):
            port = futures[f]
            if f.result():
                open_ports.append(port)
    return open_ports

def save_results(data, format='txt'):
    timestamp = get_timestamp()
    filename = f"network_audit_{timestamp}.{format}"
    try:
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
        else:
            with open(filename, 'w') as f:
                for section, content in data.items():
                    f.write(f"=== {section.upper()} ===\n")
                    if isinstance(content, list):
                        for item in content:
                            f.write(str(item) + '\n')
                    else:
                        f.write(str(content) + '\n')
                    f.write('\n')
        print(f"{GREEN}Results saved to {filename}{RESET}")
    except Exception as e:
        print(f"{RED}Error saving file: {e}{RESET}")

def main_menu():
    while True:
        clear_screen()
        print(f"{CYAN}╔{'═' * 50}╗")
        print(f"║{'NETWORK AUDITOR':^50}║")
        print(f"╠{'═' * 50}╣")
        print(f"║ {GREEN}1{RESET}. Scan nearby WiFi networks          {CYAN}║")
        print(f"║ {GREEN}2{RESET}. List network interfaces           {CYAN}║")
        print(f"║ {GREEN}3{RESET}. Discover devices on local network {CYAN}║")
        print(f"║ {GREEN}4{RESET}. Port scan a specific IP          {CYAN}║")
        print(f"║ {GREEN}5{RESET}. Run comprehensive audit          {CYAN}║")
        print(f"║ {GREEN}6{RESET}. Exit                             {CYAN}║")
        print(f"╚{'═' * 50}╝{RESET}")
        choice = input("\nSelect an option: ")
        results = {}
        if choice == '1':
            print(f"\n{YELLOW}Scanning WiFi networks...{RESET}")
            wifi_networks = scan_wifi()
            if wifi_networks:
                print(f"\n{GREEN}Found {len(wifi_networks)} WiFi networks:{RESET}")
                for n in wifi_networks:
                    print(f"SSID: {n['ssid']}")
                    print(f"  Signal: {n['signal']}, Channel: {n['channel']}, Security: {n['encryption']}")
                results['wifi_scan'] = wifi_networks
            else:
                print(f"{RED}No WiFi networks found or scanning not supported{RESET}")
        elif choice == '2':
            interfaces = get_interfaces()
            if interfaces:
                print(f"\n{GREEN}Active network interfaces:{RESET}")
                for i in interfaces:
                    print(f"Interface: {i['interface']}")
                    print(f"  IP: {i['ip']}, MAC: {i['mac']}")
                results['interfaces'] = interfaces
            else:
                print(f"{RED}No active interfaces found{RESET}")
        elif choice == '3':
            devices = device_discovery()
            if devices:
                print(f"\n{GREEN}Active devices on network:{RESET}")
                for d in devices:
                    gateway = f"{YELLOW} (Gateway){RESET}" if d.get('is_gateway') else ""
                    print(f"IP: {d['ip']}{gateway}")
                    print(f"  Hostname: {d['hostname']}")
                results['devices'] = devices
            else:
                print(f"{RED}No active devices found{RESET}")
        elif choice == '4':
            target_ip = input("Enter target IP: ")
            ports = [21,22,23,25,53,80,110,135,139,143,443,445,8080,8443]
            open_ports = port_scan(target_ip, ports)
            if open_ports:
                print(f"\n{GREEN}Open ports on {target_ip}:{RESET}")
                for p in open_ports:
                    print(f"Port {p} is open")
                results['port_scan'] = {'target': target_ip, 'open_ports': open_ports}
            else:
                print(f"{RED}No open ports found{RESET}")
        elif choice == '5':
            print(f"\n{YELLOW}Starting comprehensive audit...{RESET}")
            results['wifi_scan'] = scan_wifi()
            results['interfaces'] = get_interfaces()
            results['devices'] = device_discovery()
            print(f"{GREEN}Comprehensive audit completed!{RESET}")
        elif choice == '6':
            print(f"{CYAN}Exiting...{RESET}")
            sys.exit(0)
        else:
            print(f"{RED}Invalid choice!{RESET}")
            input("Press Enter to continue...")
            continue
        if results:
            save_choice = input("\nSave results? (y/n): ").lower()
            if save_choice == 'y':
                fmt = input("Format (txt/json): ").lower()
                save_results(results, fmt if fmt in ['txt','json'] else 'txt')
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{RED}Operation cancelled by user.{RESET}")
        sys.exit(0)
